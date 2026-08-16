import json

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.bounds import BoundsProbe
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
_BOUNDED = {"memory_capped": True, "pids_capped": True, "marker_present": False}


def test_bounded_and_disposable_sandbox_is_clean():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED]))
    assert outcome.findings == []


def test_uncapped_memory_is_a_finding():
    inner = dict(_BOUNDED, memory_capped=False)
    assert "memory_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


def test_uncapped_pids_is_a_finding():
    inner = dict(_BOUNDED, pids_capped=False)
    assert "pids_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


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
