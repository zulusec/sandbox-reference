import json

from sandbox_probe import render
from sandbox_probe.finding import Finding, Severity
from sandbox_probe.result import ProbeError, ProbeOutcome, merge_outcomes


def _finding():
    return Finding(probe_id="network", subject="sandbox", rule_key="dns_canary",
                   severity=Severity.HIGH, title="DNS resolution succeeded",
                   evidence="resolved canary.invalid via 10.0.0.53")


def _report(findings=(), errors=(), control_ok=True):
    return merge_outcomes({
        "network": ProbeOutcome(list(findings), list(errors), control_ok=control_ok)
    })


def test_findings_json_excludes_metadata():
    payload = json.loads(render.findings_json([_finding()]))
    assert isinstance(payload, list)
    assert set(payload[0]) == {
        "probe_id", "subject", "rule_key", "severity", "title", "evidence"
    }


def test_to_json_separates_metadata_from_findings():
    text = render.to_json(_report([_finding()]), {"mode": "reference"})
    payload = json.loads(text)
    assert payload["metadata"]["mode"] == "reference"
    assert len(payload["findings"]) == 1


def test_to_json_reports_incompleteness_in_metadata():
    error = ProbeError("network", "sandbox", "exec", "unreachable")
    payload = json.loads(render.to_json(_report(errors=[error]), {}))
    assert payload["metadata"]["complete"] is False
    assert payload["metadata"]["errors"][0]["operation"] == "exec"


def test_to_json_reports_failed_controls():
    payload = json.loads(render.to_json(_report(control_ok=False), {}))
    assert payload["metadata"]["controls_failed"] == ["network"]


def test_table_says_contained_when_clean():
    assert "CONTAINED" in render.to_table(_report())


def test_table_never_says_contained_when_incomplete():
    error = ProbeError("network", "sandbox", "exec", "unreachable")
    table = render.to_table(_report(errors=[error]))
    assert "CONTAINED" not in table
    assert "INCOMPLETE RUN" in table


def test_table_warns_when_a_positive_control_failed():
    table = render.to_table(_report(control_ok=False))
    assert "CONTAINED" not in table
    assert "POSITIVE CONTROL FAILED" in table


def test_table_shows_each_finding():
    table = render.to_table(_report([_finding()]))
    assert "dns_canary" in table
    assert "DNS resolution succeeded" in table
