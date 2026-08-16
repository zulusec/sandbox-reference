"""Bounds and cleaning for values that came from the system under test.

Most probes interpolate values they read out of the sandbox into
`Finding.evidence`, and `render.to_table` writes evidence straight to an
operator's terminal. A sandbox already under an adversary's control chooses
those values, and left alone they are three separate weapons: an escape
sequence that clears the screen and repaints the report as a clean one, a
single string long enough to bury everything above it, and a list long
enough to bury the report in findings.

So nothing that came back from inside the sandbox reaches a Finding without
passing through here. This is a deliberate exception to the rule that probes
are independent: independence is about probe logic, not about each probe
writing its own copy of one security control, and five copies of a control
is how four of them end up wrong. Probes must not import each other, so this
sits beside them rather than inside one of them.

What this does not do is make a value true. A target can still put plausible
words in front of a reader; what it can no longer do is move the reader's
cursor, clear the screen, or bury the report. A cleaned value stays inside
the sentence that says where it came from, which is what keeps it readable
as a quotation from the system under test rather than as the report's own
voice.

Nothing is dropped silently. A truncated string says what it was truncated
from, a cleaned string says how many characters were removed, and a capped
list hands back the number of values that did not fit so the caller can
report that count rather than swallow it. A thing quietly removed from a
report is, to whoever reads the report, a thing that was never measured.
"""

from __future__ import annotations

from sandbox_probe.finding import Finding, Severity

# One line of a terminal is about this wide, and no legitimate hostname,
# path, or variable name comes close. A value longer than this is either
# broken or hostile, and either way the report says so rather than printing
# it.
TEXT_LIMIT = 200

# How many elements of a target-supplied list get their own finding before
# the rest are summarized as a count. The same bound covers the filesystem
# probe's uid list, so there is one number rather than one per probe.
LIST_LIMIT = 16


def safe_text(value: object, limit: int = TEXT_LIMIT) -> str:
    """One report-safe line from a value the system under test supplied.

    Unprintable characters go first, which covers every C0 and C1 control,
    the escape that starts an ANSI sequence, and the invisible formatting
    characters that reorder text after the fact. Truncation comes second, so
    a long run of control characters cannot eat the whole length budget and
    push the real content out of the report.

    Anything that is not a string is rendered with repr rather than str, so
    a dict or a list arriving where a hostname was expected is visible as
    the wrong shape instead of being flattened into something that reads
    like a value.
    """
    text = value if isinstance(value, str) else repr(value)
    kept = "".join(char for char in text if char.isprintable())
    removed = len(text) - len(kept)
    if len(kept) > limit:
        kept = f"{kept[:limit]} (truncated from {len(kept)} characters)"
    if not kept:
        kept = "(an empty value)"
    if removed:
        noun = "character" if removed == 1 else "characters"
        kept = f"{kept} ({removed} unprintable {noun} removed)"
    return kept


def bounded(value: object, limit: int = LIST_LIMIT) -> tuple[list[str], int]:
    """Report-safe elements of a target-supplied list, and how many were cut.

    Returns (shown, dropped). A value that is not a list at all yields no
    elements: the payload's contract is a list, and a caller must not be
    handed the characters of a string as though they were entries.
    """
    if not isinstance(value, list):
        return [], 0
    shown = [safe_text(item) for item in value[:limit]]
    return shown, max(len(value) - limit, 0)


def overflow_finding(
    *,
    probe_id: str,
    subject: str,
    rule_key: str,
    severity: Severity,
    dropped: int,
    kind: str,
) -> Finding:
    """The count of values that were measured but not listed.

    A capped list that says nothing about what it cut reads exactly like a
    short list, which would make a report understate what the run found. So
    the remainder is reported as its own finding under the same rule key,
    carrying the number and nothing from the values themselves.
    """
    noun = "value" if dropped == 1 else "values"
    return Finding(
        probe_id=probe_id,
        subject=subject,
        rule_key=rule_key,
        severity=severity,
        title=f"More {kind} were reported than this report lists",
        evidence=(
            f"{dropped} further {noun} of this kind came back from the sandbox and "
            f"are not listed individually. The list is capped at {LIST_LIMIT} entries "
            "because its contents come from the system under test, which can return "
            "as many as it likes. The count is reported rather than dropped so this "
            "report never reads shorter than what was measured."
        ),
    )
