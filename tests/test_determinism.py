"""Determinism is a product claim, so it is asserted mechanically.

The in-process checks prove determinism within one interpreter. They cannot
catch a value that is constant for the life of a process yet varies between
invocations, so the cross-process checks shell out to the installed console
script twice, the way a reader running the README actually would.
"""

import json

from conftest import PROBE_IDS, run_probe

# Importing the CLI is what registers the probes: registration happens on
# module import and nothing else in the package imports the probe modules.
# This import is what makes test_probe_registration_order_is_stable below
# meaningful when this module is run on its own. It does NOT carry that
# guarantee during a full-suite run, because sibling test modules import all
# six probe modules at collection time and the registry is already populated
# by the time anything here executes. The check that holds in every case,
# including a future one where this import is deleted, is
# test_list_probes_names_every_registered_probe, which asks a separate
# process what it registered.
from sandbox_probe import (
    cli,  # noqa: F401  (imported for registration)
    render,
)
from sandbox_probe.finding import Finding, Severity, sort_findings
from sandbox_probe.probes import all_probes
from sandbox_probe.result import ProbeOutcome, merge_outcomes

_STABLE_KEYS = {"probe_id", "subject", "rule_key", "severity", "title", "evidence"}


def _findings():
    return [
        Finding("network", "t", "dns_canary", Severity.HIGH, "a", "b"),
        Finding("bounds", "t", "memory_uncapped", Severity.MEDIUM, "c", "d"),
    ]


def test_repeated_serialization_is_byte_identical():
    assert render.findings_json(_findings()) == render.findings_json(_findings())


def test_serialization_is_independent_of_input_order():
    forward = render.findings_json(sort_findings(_findings()))
    backward = render.findings_json(sort_findings(list(reversed(_findings()))))
    assert forward == backward


def test_findings_carry_no_volatile_fields():
    for finding in _findings():
        assert set(finding.to_dict()) == _STABLE_KEYS


def test_report_json_findings_block_excludes_metadata():
    report = merge_outcomes({"network": ProbeOutcome(_findings())})
    payload = json.loads(render.to_json(report, {"target": "t"}))
    for entry in payload["findings"]:
        assert set(entry) == _STABLE_KEYS


def test_probe_registration_order_is_stable():
    first = [probe.probe_id for probe in all_probes()]
    second = [probe.probe_id for probe in all_probes()]
    assert first == second == sorted(first)
    # A registry missing three probes would satisfy the line above just as
    # well as a complete one, so the contents are asserted too.
    assert first == sorted(PROBE_IDS)


def test_list_probes_is_byte_identical_across_processes():
    first = run_probe("--list-probes")
    second = run_probe("--list-probes")
    assert first.returncode == 0
    assert first.stdout
    assert first.stdout == second.stdout


def test_list_probes_names_every_registered_probe():
    completed = run_probe("--list-probes")
    assert completed.returncode == 0
    assert completed.stdout.decode().split() == sorted(PROBE_IDS)
