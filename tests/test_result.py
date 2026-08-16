from sandbox_probe.finding import Finding, Severity
from sandbox_probe.result import ProbeError, ProbeOutcome, merge_outcomes


def _finding():
    return Finding(probe_id="network", subject="sandbox", rule_key="egress",
                   severity=Severity.HIGH, title="t", evidence="e")


def _error():
    return ProbeError(probe_id="network", subject="sandbox",
                      operation="exec", detail="target unreachable")


def test_clean_run_is_complete_and_exits_zero():
    report = merge_outcomes({"network": ProbeOutcome([], [], control_ok=True)})
    assert report.complete
    assert report.exit_code == 0


def test_findings_exit_three():
    report = merge_outcomes({"network": ProbeOutcome([_finding()], [], control_ok=True)})
    assert report.complete
    assert report.exit_code == 3


def test_error_makes_the_run_incomplete():
    report = merge_outcomes({"network": ProbeOutcome([], [_error()], control_ok=True)})
    assert not report.complete
    assert report.exit_code == 2


def test_failed_positive_control_makes_the_run_incomplete():
    report = merge_outcomes({"network": ProbeOutcome([], [], control_ok=False)})
    assert not report.complete
    assert report.controls_failed == ["network"]
    assert report.exit_code == 2


def test_incomplete_outranks_findings():
    """A run that could not see everything is not reportable as findings-only."""
    report = merge_outcomes(
        {"network": ProbeOutcome([_finding()], [_error()], control_ok=True)}
    )
    assert report.exit_code == 2


def test_findings_are_sorted_across_probes():
    low = Finding(probe_id="a", subject="s", rule_key="k",
                  severity=Severity.LOW, title="t", evidence="e")
    high = Finding(probe_id="z", subject="s", rule_key="k",
                   severity=Severity.HIGH, title="t", evidence="e")
    report = merge_outcomes({
        "a": ProbeOutcome([low], [], control_ok=True),
        "z": ProbeOutcome([high], [], control_ok=True),
    })
    assert report.findings == [high, low]
