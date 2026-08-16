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


def test_to_json_distinguishes_an_absent_control_from_a_passed_one():
    """A probe that has no positive control and a probe whose control ran
    and held are two different things, and only one of them is evidence
    that the probe was measuring something."""
    report = merge_outcomes({"credentials": ProbeOutcome(control_ok=None)})
    payload = json.loads(render.to_json(report, {}))
    assert payload["metadata"]["controls_absent"] == ["credentials"]
    assert payload["metadata"]["controls_failed"] == []
    assert payload["metadata"]["complete"] is True


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


def test_table_without_metadata_behaves_as_full_coverage():
    assert "CONTAINED" in render.to_table(_report())


def test_table_names_partial_selection_and_never_says_contained():
    metadata = {"probes_selected": ["filesystem"],
                "probes_registered": ["filesystem", "network"]}
    table = render.to_table(_report(), metadata)
    assert "CONTAINED" not in table
    assert "PARTIAL RUN" in table
    assert "filesystem" in table


def test_table_says_contained_when_selection_matches_registry():
    metadata = {"probes_selected": ["network"], "probes_registered": ["network"]}
    assert "CONTAINED" in render.to_table(_report(), metadata)


# --- The two renderers describe one run, so they have to describe it the
# same way. Automation reads the JSON and never sees the table, which makes
# the JSON the more dangerous of the two to let drift.

def _partial_metadata():
    return {"probes_selected": ["network"],
            "probes_registered": ["filesystem", "network"]}


def test_json_partial_run_is_not_complete():
    """One probe of two ran clean. The table refuses CONTAINED for it, so a
    field named complete must not say true beside an empty findings list."""
    payload = json.loads(render.to_json(_report(), _partial_metadata()))
    assert payload["metadata"]["complete"] is False
    assert payload["metadata"]["coverage_complete"] is False


def test_json_and_table_agree_about_a_partial_run():
    report = _report()
    metadata = _partial_metadata()
    payload = json.loads(render.to_json(report, metadata))
    table = render.to_table(report, metadata)
    assert ("CONTAINED" in table) is (
        payload["metadata"]["complete"] and not payload["findings"]
    )


def test_json_names_the_probes_that_produced_a_result():
    payload = json.loads(render.to_json(_report(), _partial_metadata()))
    assert payload["metadata"]["probes_ran"] == ["network"]


def test_json_full_coverage_stays_complete():
    metadata = {"probes_selected": ["network"], "probes_registered": ["network"]}
    payload = json.loads(render.to_json(_report(), metadata))
    assert payload["metadata"]["complete"] is True
    assert payload["metadata"]["coverage_complete"] is True
