import json

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.bounds import BoundsProbe
from sandbox_probe.target import ExecResult, Target


def _target(inner_sequence, reset_ok=True, reset_configured=True):
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="a.invalid", blocked_host="b.invalid",
        reset_command=["true"] if reset_configured else None,
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


_BOUNDED = {"memory_capped": True, "wallclock_capped": True, "marker_present": False}


def test_bounded_and_disposable_sandbox_is_clean():
    outcome = BoundsProbe().run(_target([_BOUNDED, _BOUNDED]))
    assert outcome.findings == []


def test_uncapped_memory_is_a_finding():
    inner = dict(_BOUNDED, memory_capped=False)
    assert "memory_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


def test_uncapped_wallclock_is_a_finding():
    inner = dict(_BOUNDED, wallclock_capped=False)
    assert "wallclock_uncapped" in _keys(BoundsProbe().run(_target([inner, inner])))


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
