"""Serialization of probe results.

findings_json is the surface the determinism test compares. It excludes run
metadata on purpose, because metadata legitimately varies between runs while
findings must not.

The word CONTAINED appears only when every registered probe ran and found
nothing. A reader must never be able to mistake an incomplete run, or a run
that only covered a subset of the registered probes, for a sandbox that
held.

Which probes ran comes from the report, not from the metadata: report.probes_
ran is the set that produced an outcome, while metadata's probes_selected is
only what the caller intended. Coverage is judged by comparing what came
back against the registered set, so a run that quietly produced fewer
outcomes than were asked for cannot render as a full assessment no matter
what the caller believed it was doing. Both renderers ask the same question
of the same data: a table that refuses CONTAINED while the JSON beside it
says complete is a report that lies to machines and tells the truth to
people, and automation reads the JSON.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sandbox_probe.finding import Finding
from sandbox_probe.result import RunReport

_JSON_ARGS = {"indent": 2, "sort_keys": True, "separators": (",", ": ")}


def findings_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], **_JSON_ARGS) + "\n"


def to_json(report: RunReport, metadata: dict) -> str:
    gap = _coverage_gap(report, metadata)
    payload = {
        "metadata": dict(
            metadata,
            # complete carries both halves, because a consumer gating on
            # `metadata.complete && !findings.length` is reading it as the
            # JSON spelling of CONTAINED and must get the same answer the
            # table gives. coverage_complete is separate so a reader can
            # still tell a partial run from an errored one.
            complete=report.complete and gap is None,
            coverage_complete=gap is None,
            probes_ran=sorted(report.probes_ran),
            errors=[error.to_dict() for error in report.errors],
            controls_failed=list(report.controls_failed),
            # A probe with no positive control is not a probe whose control
            # passed. Naming the absence is what lets a reader tell them
            # apart without reading the source.
            controls_absent=list(report.controls_absent),
        ),
        "findings": [finding.to_dict() for finding in report.findings],
    }
    return json.dumps(payload, **_JSON_ARGS) + "\n"


def to_table(report: RunReport, metadata: dict | None = None) -> str:
    gap = _coverage_gap(report, metadata)
    blocks = []
    if gap is not None:
        blocks.append(_partial_block(*gap))
    if report.errors:
        blocks.append(_incomplete_block(report))
    if report.controls_failed:
        blocks.append(_control_block(report))
    blocks.append(_findings_block(report, is_partial=gap is not None))
    return "\n".join(blocks)


def _coverage_gap(
    report: RunReport, metadata: dict | None
) -> tuple[list[str], list[str], list[str]] | None:
    """None means full coverage, or no coverage information at all.

    Otherwise (ran, registered, missing): the probes that produced an
    outcome, the probes the tool knows about, and the probes the caller
    selected that produced nothing. The last of those is the dangerous
    case, because it is the one that cannot be explained by an operator
    asking for a subset.
    """
    if not metadata:
        return None
    registered = metadata.get("probes_registered")
    if registered is None:
        return None
    ran = sorted(set(report.probes_ran))
    selected = metadata.get("probes_selected")
    missing = sorted(set(selected) - set(ran)) if selected is not None else []
    if set(ran) == set(registered) and not missing:
        return None
    return ran, sorted(registered), missing


def _partial_block(ran: list[str], registered: list[str], missing: list[str]) -> str:
    names = ", ".join(ran) if ran else "none"
    lines = [
        f"PARTIAL RUN: {len(ran)} of {len(registered)} probes produced a result ({names}).",
    ]
    if missing:
        lines.append(
            f"Selected but produced no outcome: {', '.join(missing)}. A probe "
            "that was asked for and returned nothing is not a clean result."
        )
    unrun = sorted(set(registered) - set(ran) - set(missing))
    if unrun:
        lines.append(f"Not run: {', '.join(unrun)}.")
    lines.extend([
        "This is not a full assessment. A pipeline must not read this run's",
        "exit code as containment.",
        "",
    ])
    return "\n".join(lines)


def _incomplete_block(report: RunReport) -> str:
    noun = "probe" if len(report.errors) == 1 else "probes"
    lines = [
        f"INCOMPLETE RUN: {len(report.errors)} {noun} could not be completed.",
        "The results below do not cover them. This is not a clean result",
        "for the checks listed here.",
        "",
    ]
    for error in report.errors:
        lines.append(
            f"        {error.probe_id}  {error.subject}  "
            f"{error.operation}: {error.detail}"
        )
    lines.append("")
    return "\n".join(lines)


def _control_block(report: RunReport) -> str:
    names = ", ".join(report.controls_failed)
    return "\n".join([
        f"POSITIVE CONTROL FAILED: {names}",
        "These probes could not confirm they were testing a reachable target.",
        "An empty result from them means nothing was measured, not that",
        "nothing was found.",
        "",
    ])


def _findings_block(report: RunReport, is_partial: bool = False) -> str:
    if not report.findings:
        if report.complete and not is_partial:
            return "CONTAINED. Every probe ran, no findings.\n"
        return "No findings in what could be measured.\n"

    lines = []
    for finding in report.findings:
        lines.append(
            f"{finding.severity.value:<6}  {finding.probe_id}  {finding.rule_key}"
        )
        lines.append(f"        {finding.title}")
        lines.append(f"        {finding.evidence}")
        lines.append("")
    return "\n".join(lines)
