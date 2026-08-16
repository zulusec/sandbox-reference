"""Runs every probe against one target.

A probe that raises is recorded as an error rather than allowed to abort the
run or, worse, to quietly reduce coverage while the report still reads clean.
"""

from __future__ import annotations

from sandbox_probe.probes import Probe
from sandbox_probe.result import ProbeError, ProbeOutcome, RunReport, merge_outcomes
from sandbox_probe.target import Target


def run_all(target: Target, probes: list[Probe]) -> RunReport:
    outcomes: dict[str, ProbeOutcome] = {}
    for probe in sorted(probes, key=lambda item: item.probe_id):
        try:
            outcomes[probe.probe_id] = probe.run(target)
        except Exception as error:  # noqa: BLE001
            outcomes[probe.probe_id] = ProbeOutcome(
                errors=[
                    ProbeError(
                        probe_id=probe.probe_id,
                        subject=target.name,
                        operation="run",
                        detail=f"{type(error).__name__}: {error}",
                    )
                ],
                control_ok=False,
            )
    return merge_outcomes(outcomes)
