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
    # A duplicate id must not overwrite the incumbent. The newcomer would
    # replace it, the registry would still hold six ids, and every check
    # that counts or names the registered probes would still pass while one
    # probe had silently stopped running. A probe that never runs and a
    # probe that ran and found nothing must never look the same.
    if probe.probe_id in _REGISTRY:
        raise ValueError(
            f"a probe with id {probe.probe_id!r} is already registered. "
            "Registering a second one would replace the first, and the "
            "registry would still look complete."
        )
    _REGISTRY[probe.probe_id] = probe
    return probe


def all_probes() -> list[Probe]:
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]
