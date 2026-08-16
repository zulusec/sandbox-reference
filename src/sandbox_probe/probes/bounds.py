"""Invariant 4: bounded and disposable.

Caps are read from the sandbox's own cgroup view rather than tested by
exhaustion. Allocating memory until the kernel intervenes would be a denial
of service against the machine running the harness, and the question is
whether a limit is configured, which is directly readable from
/sys/fs/cgroup without ever touching the ceiling.

Cgroup v2 reports an unlimited resource as the literal string "max" in a
single file (memory.max, pids.max). Cgroup v1 has no such sentinel: an
unlimited memory.limit_in_bytes reads back as a very large integer (close to
LONG_MAX rounded to a page boundary, roughly 9.2e18 on a 64-bit host)
instead. Both are treated as uncapped; anything else, including 256 MiB
worth of bytes, reads as capped because it sits far below that sentinel.

There is no cgroup file for wall-clock time; cgroups bound memory, PIDs, and
CPU shares, not elapsed real time. A wall-clock bound genuinely does not
live inside the sandbox: it lives in whatever invokes the task, an agent
framework's task timeout, a Kubernetes activeDeadlineSeconds, a CI job
timeout. That is not a gap in the invariant, it is a fact about where the
control sits. So this is modeled the way reset_command already is: as a
target-declared capability, Target.wallclock_limit_seconds. If the target
declares one, the invariant is satisfied; if not, wallclock_uncapped fires.
The harness cannot verify a declared limit is actually enforced without
deliberately hanging a task for the full duration, which would be a
terrible thing to put in a test suite and would hang forever against a
target with no limit, so the finding says the target declares no wall-clock
bound, never that one was tested and found wanting.

Disposability is tested by writing a marker, requesting a reset, and looking
again. Persistence across runs is what turns one bad task into a foothold,
and it is the specific failure the July 2026 incident's agent used to keep a
foothold across evaluation runs. A target with no reset path at all reports
that as its own finding rather than skipping quietly, because a sandbox
nobody can reset carries state from one task to the next by definition.

That test has two preconditions, and both are read back out of the payload
rather than assumed. The marker has to have been written, or the reset
disposed of nothing and the absence of a marker afterward is not evidence:
a read-only workspace would otherwise read as perfect disposability. And
the workspace must not already have held a marker before this run wrote
one, or a marker found afterward belongs to some earlier run and this run
cannot attribute its survival to its own write. Either way the disposability
half did not happen, so it is reported as unmeasured, with the positive
control failed, rather than answered.

The marker this probe writes is always removed before the probe finishes,
on every path: the compliant path where the reset itself wipes it, the
leaky path where it survives the reset and must be deleted explicitly, the
no-reset path where nothing will ever clean it up but this probe, and the
failed-reset path where the target's disposability could not be
demonstrated at all. A removal failure is never swallowed; it is reported
as its own error alongside whatever finding or error the run already
produced.
"""

from __future__ import annotations

from sandbox_probe.evidence import BOOL, safe_text, shape_problem_detail
from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60
_MARKER_NAME = ".sandbox_probe_persistence_marker"

_CGROUP_MAX = "max"

# The keys every exec of this payload fills in, and the shape each has to
# arrive in. Both cap keys are read with a falsy default, so a result
# missing one would read as an uncapped sandbox rather than an unanswered
# question, and marker_present missing would read as a marker that did not
# survive. The two conditional keys are added by _execute for the exec that
# asked for them: a key the harness did not request is not one it can
# require an answer to.
_RESULT_SHAPE = {
    "memory_capped": BOOL,
    "pids_capped": BOOL,
    "marker_present": BOOL,
}

PAYLOAD_BODY = f"""
def read_first(paths):
    for path in paths:
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            continue
    return None

def cgroup_capped(value):
    if not value or value == {_CGROUP_MAX!r}:
        return False
    try:
        return int(value) < (1 << 62)
    except ValueError:
        return False

memory = read_first(['/sys/fs/cgroup/memory.max',
                     '/sys/fs/cgroup/memory/memory.limit_in_bytes'])
result['memory_capped'] = cgroup_capped(memory)

pids = read_first(['/sys/fs/cgroup/pids.max', '/sys/fs/cgroup/pids/pids.max'])
result['pids_capped'] = bool(pids and pids != {_CGROUP_MAX!r})

marker = os.path.join(os.getcwd(), {_MARKER_NAME!r})
result['marker_present'] = os.path.exists(marker)

if os.environ.get('PROBE_WRITE_MARKER') == '1':
    try:
        with open(marker, 'w') as handle:
            handle.write('x')
        result['marker_written'] = True
    except OSError:
        result['marker_written'] = False

if os.environ.get('PROBE_REMOVE_MARKER') == '1':
    if os.path.exists(marker):
        try:
            os.remove(marker)
            result['marker_removed'] = True
        except OSError:
            result['marker_removed'] = False
    else:
        result['marker_removed'] = True
"""


def _exec_failure_detail(base: str, executed: ExecResult) -> str:
    """Fold the exec result's returncode and stderr into an error detail.

    Without this, a dead container, a timeout, and a genuine protocol
    violation all collapse into the same message, "inner payload produced
    no marked result line", and an operator cannot tell a target-side
    problem from a probe-side one.

    stderr is the widest channel the system under test has into this
    report: it chooses every byte of it, and an error detail is written to
    the same terminal a finding is. So it goes through the same cleaning
    and the same length bound every other target-supplied value does.
    Errors are not Findings, but they render identically, so the rule that
    covers one has to cover the other.
    """
    detail = base
    if executed.returncode != 0:
        detail += f" (exit code {executed.returncode})"
    if executed.stderr.strip():
        detail += f"; stderr: {safe_text(executed.stderr.strip())}"
    return detail


class BoundsProbe:
    probe_id = "bounds"

    def run(self, target: Target) -> ProbeOutcome:
        first = self._execute(target, write_marker=True)
        if isinstance(first, ProbeOutcome):
            return first

        findings: list[Finding] = []
        if not first.get("memory_capped"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="memory_uncapped", severity=Severity.MEDIUM,
                title="No memory limit is configured",
                evidence=(
                    "The sandbox cgroup reports no memory ceiling, so one task "
                    "can exhaust the host."
                ),
            ))
        if not first.get("pids_capped"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="pids_uncapped", severity=Severity.MEDIUM,
                title="No process count limit is configured",
                evidence=(
                    "The sandbox cgroup reports no pids ceiling, so one task "
                    "can fork-bomb the host."
                ),
            ))
        if target.wallclock_limit_seconds is None:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="wallclock_uncapped", severity=Severity.MEDIUM,
                title="No wall-clock limit is configured",
                evidence=(
                    "The target declares no wall-clock bound. A wall-clock cap "
                    "is enforced by whatever invokes the task (an agent "
                    "framework's task timeout, a scheduler deadline, a CI job "
                    "timeout), not by the sandbox itself, and nothing here "
                    "declares one."
                ),
            ))

        if target.reset_command is None:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="no_reset_configured", severity=Severity.HIGH,
                title="The sandbox has no reset path",
                evidence=(
                    "No reset command is configured for this target, so "
                    "disposability cannot be demonstrated and state carries "
                    "from one task to the next."
                ),
            ))
            return ProbeOutcome(
                findings=findings,
                errors=self._cleanup(target),
                control_ok=False,
            )

        # Both halves of the disposability precondition, read from the first
        # exec's own result rather than assumed from the fact that the exec
        # returned. A write that did not happen and a marker that was
        # already there both mean the same thing: whatever the reset does
        # next, this run cannot read the answer as its own measurement.
        disposability_errors = []
        if first.get("marker_written") is not True:
            disposability_errors.append(ProbeError(
                self.probe_id, target.name, "marker",
                f"{_MARKER_NAME} could not be written into the workspace, so the "
                "reset had nothing of this run's to dispose of. Disposability was "
                "not measured here, and no result about it is reported.",
            ))
        if first.get("marker_present"):
            disposability_errors.append(ProbeError(
                self.probe_id, target.name, "marker",
                f"{_MARKER_NAME} was already in the workspace before this run wrote "
                "one, so it was left by an earlier run. A marker found after the "
                "reset could not be attributed to this run's write.",
            ))
        if disposability_errors:
            disposability_errors.extend(self._cleanup(target))
            return ProbeOutcome(
                findings=findings,
                errors=disposability_errors,
                control_ok=False,
            )

        reset = target.reset()
        if reset.returncode != 0:
            errors = [ProbeError(
                self.probe_id, target.name, "reset",
                # The reset command's stderr is target-supplied text on its
                # way to a terminal, exactly like the exec's.
                safe_text(reset.stderr.strip()) if reset.stderr.strip()
                else f"reset command failed (exit code {reset.returncode})",
            )]
            errors.extend(self._cleanup(target))
            return ProbeOutcome(findings=findings, errors=errors, control_ok=False)

        second = self._execute(target, write_marker=False, remove_marker=True)
        if isinstance(second, ProbeOutcome):
            return ProbeOutcome(
                findings=findings,
                errors=list(second.errors),
                control_ok=False,
            )

        errors = []
        if second.get("marker_present"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="persists_across_runs", severity=Severity.HIGH,
                title="Sandbox state survives a reset",
                evidence=(
                    f"{_MARKER_NAME} written before the reset was still present "
                    "afterward. A sandbox that keeps state lets one compromised "
                    "task become a foothold."
                ),
            ))
        cleanup_error = self._marker_cleanup_error(target, second)
        if cleanup_error is not None:
            errors.append(cleanup_error)

        return ProbeOutcome(findings=findings, errors=errors, control_ok=True)

    def _cleanup(self, target: Target) -> list[ProbeError]:
        """Remove the marker this probe wrote, on a path that never got a
        chance to via the normal post-reset check (no reset configured, or
        the reset command itself failed). A parse failure on this call is
        surfaced exactly like any other exec failure, never swallowed."""
        cleanup = self._execute(target, write_marker=False, remove_marker=True)
        if isinstance(cleanup, ProbeOutcome):
            return list(cleanup.errors)
        error = self._marker_cleanup_error(target, cleanup)
        return [error] if error is not None else []

    def _marker_cleanup_error(self, target: Target, inner: dict) -> ProbeError | None:
        # marker_removed is required by the shape whenever removal was
        # requested, so this is never reading a default for a question that
        # was asked. It is absent only on an exec that did not ask.
        if inner.get("marker_removed", True):
            return None
        return ProbeError(
            self.probe_id, target.name, "cleanup",
            f"wrote {_MARKER_NAME} into the workspace to test disposability but "
            "could not remove it afterward; the marker may remain on the target.",
        )

    def _execute(self, target: Target, write_marker: bool, remove_marker: bool = False):
        # Direct assignment, not setdefault: the environment inside the sandbox
        # belongs to the system under test, and a preset PROBE_* name there
        # must never be allowed to choose what this probe measures instead of
        # what the target actually specifies.
        payload = emit(
            f"os.environ['PROBE_WRITE_MARKER'] = {'1' if write_marker else '0'!r}\n"
            f"os.environ['PROBE_REMOVE_MARKER'] = {'1' if remove_marker else '0'!r}\n"
            + PAYLOAD_BODY
        )
        executed = target.run_inside([payload], timeout=_TIMEOUT)
        try:
            inner = parse_inner(executed.stdout)
        except InnerProtocolError as error:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    _exec_failure_detail(str(error), executed),
                )],
                control_ok=False,
            )

        if not isinstance(inner, dict):
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    f"inner result was not a JSON object: {safe_text(inner)}",
                )],
                control_ok=False,
            )

        # The two marker keys are required only of the exec that asked for
        # them, so the shape is built from what this call requested rather
        # than from a fixed list that would demand an answer to a question
        # nobody put.
        expected = dict(_RESULT_SHAPE)
        if write_marker:
            expected["marker_written"] = BOOL
        if remove_marker:
            expected["marker_removed"] = BOOL
        problem = shape_problem_detail(inner, expected)
        if problem is not None:
            return ProbeOutcome(
                errors=[ProbeError(self.probe_id, target.name, "result", problem)],
                control_ok=False,
            )

        return inner


register(BoundsProbe())
