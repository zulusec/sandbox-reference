import pytest

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, parse_inner
from sandbox_probe.result import ProbeOutcome
from sandbox_probe.runner import run_all
from sandbox_probe.target import Target

_TARGET = Target(name="t", exec_command=["true"],
                 allowed_host="a.invalid", blocked_host="b.invalid")


class _Probe:
    def __init__(self, probe_id, outcome=None, boom=None):
        self.probe_id = probe_id
        self._outcome = outcome or ProbeOutcome()
        self._boom = boom

    def run(self, target):
        if self._boom:
            raise self._boom
        return self._outcome


def test_parse_inner_reads_the_json_line():
    assert parse_inner('noise\n@@SANDBOX_PROBE@@ {"ok": true}\n') == {"ok": True}


def test_parse_inner_rejects_output_without_the_marker():
    with pytest.raises(InnerProtocolError):
        parse_inner("no marker here")


def test_parse_inner_rejects_malformed_json():
    with pytest.raises(InnerProtocolError):
        parse_inner("@@SANDBOX_PROBE@@ {nope}")


def test_run_all_merges_outcomes():
    finding = Finding("p", "s", "k", Severity.HIGH, "t", "e")
    report = run_all(_TARGET, [_Probe("p", ProbeOutcome([finding]))])
    assert report.findings == [finding]
    assert report.exit_code == 3


def test_a_probe_that_raises_becomes_an_error_not_a_crash():
    """One broken probe must not silently shrink the coverage of the run."""
    report = run_all(_TARGET, [_Probe("p", boom=RuntimeError("kaboom"))])
    assert not report.complete
    assert report.errors[0].probe_id == "p"
    assert "kaboom" in report.errors[0].detail
    assert report.exit_code == 2


def test_probes_run_in_stable_order_regardless_of_registration():
    seen = []

    class Recording(_Probe):
        def run(self, target):
            seen.append(self.probe_id)
            return ProbeOutcome()

    run_all(_TARGET, [Recording("z"), Recording("a")])
    assert seen == ["a", "z"]
