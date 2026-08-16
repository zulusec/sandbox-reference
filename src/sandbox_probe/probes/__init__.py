"""Probe registry.

Probes are independent modules behind one interface, so a seventh is
additive rather than invasive.
"""

from __future__ import annotations

from typing import Protocol

from sandbox_probe.result import ProbeOutcome
from sandbox_probe.target import Target


class Probe(Protocol):
    probe_id: str

    def run(self, target: Target) -> ProbeOutcome: ...


_REGISTRY: dict[str, Probe] = {}


def register(probe: Probe) -> Probe:
    _REGISTRY[probe.probe_id] = probe
    return probe


def all_probes() -> list[Probe]:
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]
