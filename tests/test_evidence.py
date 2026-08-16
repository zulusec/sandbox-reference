"""The bound between a hostile target and an operator's terminal.

Everything here is written from the attacker's side: the values a sandbox
that is already compromised would choose to put in front of whoever is
reading the report.
"""

from sandbox_probe.evidence import (
    LIST_LIMIT,
    TEXT_LIMIT,
    bounded,
    overflow_finding,
    safe_text,
)
from sandbox_probe.finding import Severity

# Clear the screen, move the cursor home, then print a clean verdict. A
# report that renders this verbatim has been rewritten by the thing it is
# reporting on.
_FORGERY = "\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_an_escape_sequence_cannot_reach_the_terminal():
    cleaned = safe_text(_FORGERY)
    assert "\x1b" not in cleaned
    assert "\x1b[2J" not in cleaned
    assert all(char.isprintable() for char in cleaned)


def test_stripped_characters_are_counted_not_hidden():
    """A cleaned string that says nothing about being cleaned reads as the
    value the target sent. The count is what tells the reader otherwise."""
    cleaned = safe_text("host\r\n\tname")
    assert "3 unprintable characters removed" in cleaned
    assert "hostname" in cleaned


def test_a_single_stripped_character_reads_naturally():
    assert "1 unprintable character removed" in safe_text("host\x00")


def test_carriage_returns_and_newlines_cannot_forge_extra_report_lines():
    """Evidence is rendered as one indented line. A value carrying newlines
    would otherwise let the target inject whole lines of its own."""
    cleaned = safe_text("a\nHIGH    network  blocked_egress\nb")
    assert "\n" not in cleaned


def test_a_long_value_is_capped_and_says_what_it_was_capped_from():
    cleaned = safe_text("a" * 20000)
    assert len(cleaned) < TEXT_LIMIT + 60
    assert "truncated from 20000 characters" in cleaned


def test_a_value_at_the_limit_is_not_marked_as_truncated():
    cleaned = safe_text("a" * TEXT_LIMIT)
    assert cleaned == "a" * TEXT_LIMIT


def test_truncation_happens_after_cleaning_so_control_bytes_cannot_eat_the_budget():
    """Control characters first, length second. The other order lets a run
    of escapes consume the whole budget and push the real value out of the
    report while still reading as a complete value."""
    cleaned = safe_text("\x1b" * 500 + "paste.invalid")
    assert "paste.invalid" in cleaned


def test_an_empty_value_is_named_rather_than_rendered_as_nothing():
    assert safe_text("") == "(an empty value)"
    assert "(an empty value)" in safe_text("\x00\x00")


def test_a_non_string_is_shown_as_the_wrong_shape_not_flattened():
    assert safe_text({"host": "x"}) == "{'host': 'x'}"
    assert safe_text(None) == "None"


def test_a_list_is_capped_and_reports_how_many_were_cut():
    shown, dropped = bounded([f"host{n}.invalid" for n in range(20000)])
    assert len(shown) == LIST_LIMIT
    assert dropped == 20000 - LIST_LIMIT


def test_a_short_list_drops_nothing():
    shown, dropped = bounded(["a", "b"])
    assert (shown, dropped) == (["a", "b"], 0)


def test_elements_of_a_list_are_cleaned_too():
    shown, _ = bounded([_FORGERY])
    assert "\x1b" not in shown[0]


def test_a_string_is_not_walked_character_by_character():
    """The payload's contract is a list. A bare string arriving here must
    not become one finding per character."""
    assert bounded("paste.invalid") == ([], 0)
    assert bounded(None) == ([], 0)
    assert bounded({"a": 1}) == ([], 0)


def test_the_overflow_finding_carries_the_count_and_nothing_from_the_values():
    finding = overflow_finding(
        probe_id="network", subject="t", rule_key="c2_channel",
        severity=Severity.HIGH, dropped=19984, kind="reachable staging hosts",
    )
    assert finding.rule_key == "c2_channel"
    assert finding.severity is Severity.HIGH
    assert "19984" in finding.evidence
    assert "reachable staging hosts" in finding.title
