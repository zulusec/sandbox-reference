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


def test_an_absent_control_is_neither_a_pass_nor_a_failure():
    report = merge_outcomes({
        "credentials": ProbeOutcome([], [], control_ok=None),
        "network": ProbeOutcome([], [], control_ok=True),
        "bounds": ProbeOutcome([], [], control_ok=False),
    })
    assert report.controls_absent == ["credentials"]
    assert report.controls_failed == ["bounds"]
    assert report.exit_code == 2


def test_a_run_whose_only_unusual_control_is_absent_is_still_complete():
    report = merge_outcomes({"credentials": ProbeOutcome([], [], control_ok=None)})
    assert report.complete
    assert report.exit_code == 0


def test_the_report_records_which_probes_produced_an_outcome():
    """An empty finding list means nothing without the set of probes that
    produced it. The report carries that set rather than leaving the caller
    to assume its own selection ran."""
    report = merge_outcomes({
        "network": ProbeOutcome([], [], control_ok=True),
        "bounds": ProbeOutcome([], [_error()], control_ok=True),
    })
    assert report.probes_ran == ["bounds", "network"]


def test_a_report_covers_only_the_probes_that_produced_an_outcome():
    report = merge_outcomes({"network": ProbeOutcome([], [], control_ok=True)})
    assert report.covers(["network"])
    assert not report.covers(["network", "bounds"])
    assert not merge_outcomes({}).covers(["network"])


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
