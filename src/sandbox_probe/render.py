"""Serialization of probe results.

findings_json is the surface the determinism test compares. It excludes run
metadata on purpose, because metadata legitimately varies between runs while
findings must not.

The word CONTAINED appears only when every probe ran and found nothing. A
reader must never be able to mistake an incomplete run for a sandbox that
held.
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
    payload = {
        "metadata": dict(
            metadata,
            complete=report.complete,
            errors=[error.to_dict() for error in report.errors],
            controls_failed=list(report.controls_failed),
        ),
        "findings": [finding.to_dict() for finding in report.findings],
    }
    return json.dumps(payload, **_JSON_ARGS) + "\n"


def to_table(report: RunReport) -> str:
    blocks = []
    if report.errors:
        blocks.append(_incomplete_block(report))
    if report.controls_failed:
        blocks.append(_control_block(report))
    blocks.append(_findings_block(report))
    return "\n".join(blocks)


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


def _findings_block(report: RunReport) -> str:
    if not report.findings:
        if report.complete:
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
