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
CPU shares, not elapsed real time, and neither the reference nor the leaky
compose file configures a `cpus:` quota that could stand in for one. The
actual mechanism that bounds how long a task may run here is the harness's
own exec deadline (Target.run_inside's timeout argument), so this probe
reports on that rather than inventing a sandbox-side signal that does not
exist. That is a live-verification concern carried forward rather than
silently assumed: see the task report for the full reasoning.

Disposability is tested by writing a marker, requesting a reset, and looking
again. Persistence across runs is what turns one bad task into a foothold,
and it is the specific failure the July 2026 incident's agent used to keep a
foothold across evaluation runs. A target with no reset path at all reports
that as its own finding rather than skipping quietly, because a sandbox
nobody can reset carries state from one task to the next by definition.

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

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60
_MARKER_NAME = ".sandbox_probe_persistence_marker"

_CGROUP_MAX = "max"

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

result['wallclock_capped'] = os.environ.get('PROBE_WALLCLOCK_LIMIT') is not None

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
    """
    detail = base
    if executed.returncode != 0:
        detail += f" (exit code {executed.returncode})"
    if executed.stderr.strip():
        detail += f"; stderr: {executed.stderr.strip()}"
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
        if not first.get("wallclock_capped"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="wallclock_uncapped", severity=Severity.MEDIUM,
                title="No wall-clock limit is configured",
                evidence=(
                    "No execution deadline was in force for this task, so it "
                    "could have run indefinitely."
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

        reset = target.reset()
        if reset.returncode != 0:
            errors = [ProbeError(
                self.probe_id, target.name, "reset",
                reset.stderr.strip() or f"reset command failed (exit code {reset.returncode})",
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
            f"os.environ['PROBE_WALLCLOCK_LIMIT'] = {str(_TIMEOUT)!r}\n"
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
                    f"inner result was not a JSON object: {inner!r}",
                )],
                control_ok=False,
            )

        return inner


register(BoundsProbe())
