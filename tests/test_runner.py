import pytest

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
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


def test_a_raising_probe_also_fails_its_positive_control():
    """The recorded error already makes the run incomplete, so this is the
    belt beside the braces. It is the line that says the probe proved
    nothing, rather than only that something went wrong, and without a test
    it can be cut without anything noticing."""
    report = run_all(_TARGET, [_Probe("p", boom=RuntimeError("kaboom"))])
    assert report.controls_failed == ["p"]
    assert report.probes_ran == ["p"]


# --- emit writes the marker into the payload source itself, so any exec
# wrapper that echoes its stdin (a docker exec without -T, a logging shim)
# puts marker-carrying lines on stdout ahead of the real result. Anchoring
# the match to the start of the line is what makes that safe.

def test_parse_inner_ignores_a_marker_that_is_not_at_the_start_of_a_line():
    forged = 'echo: @@SANDBOX_PROBE@@ {"forged": true}\n@@SANDBOX_PROBE@@ {"ok": true}\n'
    assert parse_inner(forged) == {"ok": True}


def test_an_echoed_payload_does_not_hide_the_real_result():
    """The exact shape of the problem: the payload's own source, echoed back
    on stdout, followed by the result the payload printed."""
    echoed = emit("result['ok'] = True")
    assert parse_inner(echoed + '@@SANDBOX_PROBE@@ {"ok": true}\n') == {"ok": True}
