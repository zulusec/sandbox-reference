from sandbox_probe.finding import Finding, Severity, sort_findings


def _finding(probe_id="network", subject="sandbox", rule_key="egress",
             severity=Severity.HIGH, title="t", evidence="e"):
    return Finding(probe_id=probe_id, subject=subject, rule_key=rule_key,
                   severity=severity, title=title, evidence=evidence)


def test_to_dict_carries_exactly_the_stable_fields():
    assert set(_finding().to_dict()) == {
        "probe_id", "subject", "rule_key", "severity", "title", "evidence"
    }


def test_severity_serializes_as_its_value():
    assert _finding().to_dict()["severity"] == "HIGH"


def test_sort_is_worst_first_then_stable_keys():
    low = _finding(severity=Severity.LOW, rule_key="a")
    high = _finding(severity=Severity.HIGH, rule_key="z")
    assert sort_findings([low, high]) == [high, low]


def test_sort_is_independent_of_input_order():
    a = _finding(rule_key="a")
    b = _finding(rule_key="b")
    assert sort_findings([a, b]) == sort_findings([b, a])


def test_sort_is_total_over_findings_that_share_every_grouping_key():
    """rule_key is not unique: one key covers several distinct signals, and
    the leaky fixture produces four findings sharing probe_id, subject,
    rule_key and severity. Ordering only on those four leaves them to
    Python's stable sort plus the order a probe happened to append them in,
    which is determinism by coincidence. Determinism is a headline claim,
    so the order has to come from the fields themselves."""
    a = _finding(rule_key="outside_workspace", title="A", evidence="/etc was written")
    b = _finding(rule_key="outside_workspace", title="A", evidence="/usr was written")
    c = _finding(rule_key="outside_workspace", title="B", evidence="/ was written")
    assert sort_findings([c, b, a]) == sort_findings([a, b, c]) == [a, b, c]


def test_findings_differing_only_in_evidence_still_have_distinct_sort_keys():
    a = _finding(evidence="/etc")
    b = _finding(evidence="/usr")
    assert a.sort_key != b.sort_key
