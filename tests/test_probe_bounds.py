import json
import os
import stat
import tempfile

import pytest

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.bounds import PAYLOAD_BODY, BoundsProbe
from sandbox_probe.target import ExecResult, Target


def _target(inner_sequence, reset_ok=True, reset_configured=True, wallclock_limit_seconds=60):
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="a.invalid", blocked_host="b.invalid",
        reset_command=["true"] if reset_configured else None,
        wallclock_limit_seconds=wallclock_limit_seconds,
    )
    calls = {"n": 0}

    def _run_inside(argv, timeout):
        inner = inner_sequence[min(calls["n"], len(inner_sequence) - 1)]
        calls["n"] += 1
        return ExecResult(0, f"{MARKER} {json.dumps(inner)}\n", "")

    object.__setattr__(target, "run_inside", _run_inside)
    object.__setattr__(
        target, "reset",
        lambda timeout=60: ExecResult(0 if reset_ok else 1, "", ""),
    )
    return target


def _keys(outcome):
    return {f.rule_key for f in outcome.findings}


# wallclock_capped is deliberately absent here: whether wallclock_uncapped
# fires is driven by Target.wallclock_limit_seconds (a target-declared
# capability, like reset_command), never by anything read out of the
# sandbox. See bounds.py's module docstring for why: cgroups have no
# wall-clock primitive, and a wall-clock bound is enforced by whatever
# invokes the task, not by the sandbox itself.
#
# marker_written is what makes the disposability half of this probe a
# measurement rather than an assumption. The first exec writes the marker and
# says whether the write succeeded; without that key, a workspace that
# refused the write is indistinguishable from a sandbox that disposed of it.
_BOUNDED = {"memory_capped": True, "pids_capped": True, "cpu_capped": True,
            "marker_present": False, "marker_written": True, "marker_removed": True}


def test_bounded_and_disposable_sandbox_is_clean():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED]))
    assert outcome.findings == []
    assert outcome.errors == []
    assert outcome.control_ok is True


def test_uncapped_memory_is_a_finding():
    inner = dict(_BOUNDED, memory_capped=False)
    assert "memory_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


def test_uncapped_pids_is_a_finding():
    inner = dict(_BOUNDED, pids_capped=False)
    assert "pids_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


def test_uncapped_cpu_is_a_finding():
    inner = dict(_BOUNDED, cpu_capped=False)
    assert "cpu_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


def test_declared_wallclock_limit_avoids_the_finding():
    """The reference target declares wallclock_limit_seconds, so the sandbox
    that inherits its shape must not be flagged."""
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED], wallclock_limit_seconds=300))
    assert "wallclock_uncapped" not in _keys(outcome)


def test_undeclared_wallclock_limit_is_a_finding():
    """The leaky target declares no wallclock_limit_seconds at all, the
    shape fixtures/leaky/target.json actually has."""
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED], wallclock_limit_seconds=None))
    assert "wallclock_uncapped" in _keys(outcome)


def test_marker_surviving_a_reset_is_a_finding():
    """Persistence across runs is what let the July 2026 agent keep its foothold."""
    second = dict(_BOUNDED, marker_present=True)
    outcome = BoundsProbe().run(_target([_BOUNDED, second]))
    assert "persists_across_runs" in _keys(outcome)


def test_no_reset_command_is_reported_rather_than_skipped():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED], reset_configured=False))
    assert "no_reset_configured" in _keys(outcome)
    assert not outcome.control_ok


def test_failed_reset_is_an_error():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED], reset_ok=False))
    assert outcome.errors
    assert not outcome.control_ok


# --- The disposability positive control.
#
# The marker write is what this probe's disposability half rests on. If the
# write did not happen, the reset had nothing to dispose of, and the absence
# of a surviving marker afterward is not evidence of anything. A control
# whose value is measured, sent across the boundary, and then discarded is a
# control that does not control anything.

def _run_payload_marker_block(workspace: str, write: bool = True) -> dict:
    """Run the payload's own marker code against a real directory.

    The payload is a single source string piped into an interpreter inside
    the target, so exercising it here means exec'ing it with the same
    namespace emit() gives it. What comes back is the real result dict,
    including whether the write actually succeeded.
    """
    namespace: dict = {"os": os, "result": {}}
    previous = os.getcwd()
    os.chdir(workspace)
    try:
        os.environ["PROBE_WRITE_MARKER"] = "1" if write else "0"
        os.environ["PROBE_REMOVE_MARKER"] = "0"
        exec(PAYLOAD_BODY, namespace)  # noqa: S102 -- the payload's own source
    finally:
        os.chdir(previous)
        os.environ.pop("PROBE_WRITE_MARKER", None)
        os.environ.pop("PROBE_REMOVE_MARKER", None)
    return namespace["result"]


def test_a_read_only_workspace_reports_the_marker_write_as_failed():
    """The payload half: a workspace that refuses the write says so."""
    with tempfile.TemporaryDirectory() as workspace:
        os.chmod(workspace, stat.S_IRUSR | stat.S_IXUSR)
        try:
            if os.access(workspace, os.W_OK):  # pragma: no cover - root only
                pytest.skip("this user can write to a read-only directory")
            result = _run_payload_marker_block(workspace)
        finally:
            os.chmod(workspace, stat.S_IRWXU)
    assert result["marker_written"] is False
    assert result["marker_present"] is False


def test_a_read_only_workspace_fails_the_disposability_control():
    """The harness half, driven by the result a real read-only workspace
    produces. No marker was written, so the reset disposed of nothing and
    this run measured nothing about disposability. It must not read clean."""
    with tempfile.TemporaryDirectory() as workspace:
        os.chmod(workspace, stat.S_IRUSR | stat.S_IXUSR)
        try:
            if os.access(workspace, os.W_OK):  # pragma: no cover - root only
                pytest.skip("this user can write to a read-only directory")
            first = _run_payload_marker_block(workspace)
        finally:
            os.chmod(workspace, stat.S_IRWXU)

    outcome = BoundsProbe().run(_target([dict(_BOUNDED, **first), _BOUNDED]))

    assert outcome.control_ok is False
    assert outcome.errors
    assert "persists_across_runs" not in _keys(outcome)
    assert any("marker" in error.detail for error in outcome.errors)


def test_a_failed_marker_write_is_never_a_clean_disposability_result():
    outcome = BoundsProbe().run(_target([dict(_BOUNDED, marker_written=False), _BOUNDED]))
    assert outcome.control_ok is False
    assert outcome.errors


# --- The CPU ceiling, read the same way the memory one is.
#
# A cap the site claims and the harness does not read is a claim nobody can
# check, which is the one failure this project cannot afford. cpu.max is
# readable from inside a container in exactly the way memory.max is, so
# there is no reason for CPU to be the asserted member of the list.


def _payload_namespace() -> dict:
    """The payload's own function definitions, in the namespace emit() gives
    them.

    The payload is one source string piped into an interpreter inside the
    target, so exercising its parsing here means exec'ing it. Its marker
    block writes to the working directory, so this runs in a temporary one
    and leaves nothing behind.
    """
    namespace: dict = {"os": os, "result": {}}
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as workspace:
        os.chdir(workspace)
        try:
            exec(PAYLOAD_BODY, namespace)  # noqa: S102 -- the payload's own source
        finally:
            os.chdir(previous)
    return namespace


def test_cpu_capped_reads_the_quota_and_not_the_share():
    """Both cgroup v2 strings below came out of a real container: one run
    with `--cpus 0.5`, one run with no CPU limit at all. The v1 pair is
    cpu.cfs_quota_us, which is -1 when nothing is configured.

    A share weight is deliberately not consulted. cpu.weight decides who
    wins a contended host and bounds nothing on an idle one, so reading it
    as a ceiling would report a cap that does not exist.
    """
    cpu_capped = _payload_namespace()["cpu_capped"]
    assert cpu_capped("50000 100000") is True
    assert cpu_capped("max 100000") is False
    assert cpu_capped("100000") is True
    assert cpu_capped("-1") is False
    assert cpu_capped("0") is False
    assert cpu_capped(None) is False
    assert cpu_capped("") is False
    assert cpu_capped("   ") is False
    assert cpu_capped("nonsense") is False


def test_the_payload_reads_a_cpu_answer_out_of_this_machines_cgroup():
    """Whatever this host reports, the key has to arrive. A missing one is
    read with a falsy default further up, so a payload that stopped
    answering would look like an uncapped sandbox rather than an
    unanswered question."""
    assert isinstance(_payload_namespace()["result"]["cpu_capped"], bool)


# --- Errors render to the same terminal findings do, and the target chooses
# every byte of the stderr an error quotes. This probe has two such channels,
# the exec and the reset command, and both reach the report.

_FORGERY = "\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_a_forged_exec_stderr_cannot_repaint_the_report():
    target = _target([_BOUNDED, _BOUNDED])
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(1, "", _FORGERY + "padding" * 900),
    )
    outcome = BoundsProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_a_forged_reset_stderr_cannot_repaint_the_report():
    target = _target([_BOUNDED, _BOUNDED])
    object.__setattr__(
        target, "reset",
        lambda timeout=60: ExecResult(1, "", _FORGERY + "padding" * 900),
    )
    outcome = BoundsProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_an_enormous_non_dict_inner_result_is_bounded():
    target = _target([_BOUNDED, _BOUNDED])
    payload = f"{MARKER} {json.dumps('a' * 300000)}\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = BoundsProbe().run(target)
    assert outcome.errors
    assert len(outcome.errors[0].detail) < 500
    assert not outcome.control_ok


def test_a_marker_left_by_an_earlier_run_is_not_attributed_to_this_one():
    """marker_present on the first exec means an earlier run left a marker
    behind. A marker surviving the reset then proves nothing about this
    run's write, so the run says so rather than reporting a HIGH finding
    attributable to nothing."""
    first = dict(_BOUNDED, marker_present=True)
    second = dict(_BOUNDED, marker_present=True)
    outcome = BoundsProbe().run(_target([first, second]))
    assert outcome.control_ok is False
    assert any("earlier run" in error.detail for error in outcome.errors)


# --- The result's shape is checked before anything is read out of it. Every
# measurement is an inner.get with a falsy default, so a key that never came
# back reads exactly like a cgroup with no ceiling configured, or like a
# marker that did not survive.

def test_an_empty_result_is_an_error_not_a_clean_verdict():
    outcome = BoundsProbe().run(_target([{}, {}]))
    assert outcome.errors
    assert outcome.control_ok is False
    assert "memory_capped is missing" in outcome.errors[0].detail


def test_a_missing_marker_written_key_is_an_error():
    """The key the harness asked for by setting PROBE_WRITE_MARKER. Without
    it there is no answer about whether the write happened, which is not the
    same as an answer of no."""
    inner = dict(_BOUNDED)
    del inner["marker_written"]
    outcome = BoundsProbe().run(_target([inner, _BOUNDED]))
    assert outcome.errors
    assert outcome.control_ok is False


def test_a_wrong_typed_cap_is_an_error_not_an_uncapped_sandbox():
    outcome = BoundsProbe().run(_target([dict(_BOUNDED, memory_capped="yes"), _BOUNDED]))
    assert outcome.errors
    assert outcome.control_ok is False
    assert "memory_uncapped" not in _keys(outcome)


# --- The marker this probe writes is always removed before it finishes, on
# every path. A removal that failed must be reported: a stray file left in a
# target's workspace by a posture tool is the tool's own mess, and one that
# nobody is told about is worse than one that is.

def test_a_marker_that_survived_removal_is_reported_as_an_error():
    outcome = BoundsProbe().run(_target([_BOUNDED, dict(_BOUNDED, marker_removed=False)]))
    assert any(error.operation == "cleanup" for error in outcome.errors)
    detail = next(e.detail for e in outcome.errors if e.operation == "cleanup")
    assert "could not remove it" in detail


def test_a_failed_cleanup_on_the_no_reset_path_is_reported():
    """No reset command means nothing else will ever clean this marker up,
    so a failed removal there is the one that matters most."""
    outcome = BoundsProbe().run(_target(
        [_BOUNDED, dict(_BOUNDED, marker_removed=False)], reset_configured=False))
    assert "no_reset_configured" in _keys(outcome)
    assert any(error.operation == "cleanup" for error in outcome.errors)


def test_a_failed_cleanup_on_the_failed_reset_path_is_reported():
    outcome = BoundsProbe().run(_target(
        [_BOUNDED, dict(_BOUNDED, marker_removed=False)], reset_ok=False))
    assert any(error.operation == "cleanup" for error in outcome.errors)
    assert any(error.operation == "reset" for error in outcome.errors)


def test_a_successful_cleanup_reports_nothing():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED]))
    assert [e for e in outcome.errors if e.operation == "cleanup"] == []
