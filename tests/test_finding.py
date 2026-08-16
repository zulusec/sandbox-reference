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
