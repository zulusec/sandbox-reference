"""The harness against both fixtures.

A test suite whose tests always pass proves nothing, so every assertion here
comes in a pair: the reference sandbox must be clean, and the leaky one must
fail the same probe. Skipped as a unit when Docker is unavailable.

The runs are module scoped and shared. Each full run costs six execs into a
live container plus a container restart, and re-running the whole harness
once per parametrized case would buy nothing: the questions the cases ask
are about one run's findings surface, not about six separate runs. Two
repeats do measure something a single run cannot, and each is its own
fixture: a second consecutive run against the same live reference stack,
because the attribution and detection probes read append-only broker logs
and a stale entry from the first run is exactly what would make the second
one falsely clean; and a second invocation against the leaky fixture,
because determinism across processes is only testable on a findings
surface that has something in it.
"""

import json
import shutil
import subprocess

import pytest
from conftest import PROBE_IDS, REPO_ROOT, require_docker, run_probe

# Skip locally when Docker is absent, and never skip in CI. Every reason this
# module might decline to run goes through require_docker, so adding a second
# condition later cannot quietly reintroduce a green check over an unverified
# containment claim. conftest's session hook is the backstop for a skip raised
# from anywhere else, including inside a test body.
if shutil.which("docker") is None:
    require_docker("docker is not installed")

_REFERENCE = "reference/docker-compose.yml"
_LEAKY = "fixtures/leaky/docker-compose.yml"

_REFERENCE_TARGET = "reference/target.json"
_LEAKY_TARGET = "fixtures/leaky/target.json"

# Every pair the leaky fixture is expected to trip, with the probe each one
# must come from. Naming the probe keeps a case honest: a rule key that
# appeared from somewhere unexpected would satisfy a bare membership check
# while proving something other than what the case is named for.
_LEAK_PAIRS = [
    ("network", "blocked_egress"),
    ("credentials", "env_secret"),
    ("filesystem", "outside_workspace"),
    ("filesystem", "runtime_socket"),
    ("attribution", "no_request_log"),
    ("detection", "no_event_channel"),
]


def _compose(path: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", path, *args],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False,
    )


def _probe(target: str) -> tuple[int, dict]:
    completed = run_probe("--target", target, "--json")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:  # pragma: no cover - diagnostic path
        raise AssertionError(
            f"sandbox-probe did not emit JSON for {target}: {error}\n"
            f"exit {completed.returncode}\n"
            f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
        ) from error
    return completed.returncode, payload


def _rule_keys(payload: dict) -> set:
    return {finding["rule_key"] for finding in payload["findings"]}


def _pairs(payload: dict) -> set:
    return {(finding["probe_id"], finding["rule_key"]) for finding in payload["findings"]}


@pytest.fixture(scope="module", autouse=True)
def _stacks():
    reference_up = _compose(_REFERENCE, "up", "-d", "--build")
    assert reference_up.returncode == 0, reference_up.stderr
    leaky_up = _compose(_LEAKY, "up", "-d")
    assert leaky_up.returncode == 0, leaky_up.stderr
    yield
    _compose(_REFERENCE, "down", "-v")
    _compose(_LEAKY, "down", "-v")


@pytest.fixture(scope="module")
def reference_run(_stacks):
    # _stacks is autouse and pytest orders autouse fixtures first at a given
    # scope, but naming it here makes the dependency explicit rather than
    # relying on ordering for something that would fail confusingly.
    return _probe(_REFERENCE_TARGET)


@pytest.fixture(scope="module")
def reference_second_run(reference_run):
    """A second full run against the same live stack, with no restart in
    between. The broker's request and event logs are append-only and still
    hold the first run's lines, so a probe comparing against the whole log
    rather than its own window would read clean here for the wrong reason,
    or a probe scoping its window wrongly would read dirty. Depending on
    reference_run is what guarantees this really is the second one."""
    return _probe(_REFERENCE_TARGET)


@pytest.fixture(scope="module")
def leaky_run(_stacks):
    return _probe(_LEAKY_TARGET)


@pytest.fixture(scope="module")
def leaky_second_run(leaky_run):
    """A second invocation against the leaky fixture, for the determinism
    comparison. It has to be this fixture rather than the reference: the
    reference's findings surface is empty, and two empty lists are equal
    whatever the harness does to them."""
    return _probe(_LEAKY_TARGET)


def test_reference_sandbox_is_contained(reference_run):
    code, payload = reference_run
    assert payload["metadata"]["complete"] is True, payload["metadata"]
    assert payload["findings"] == [], _rule_keys(payload)
    assert code == 0


def test_reference_sandbox_ran_every_probe_and_every_control_held(reference_run):
    """Zero findings only means containment if every probe actually ran and
    every positive control confirmed it was measuring a reachable target."""
    _, payload = reference_run
    metadata = payload["metadata"]
    assert metadata["probes_selected"] == sorted(PROBE_IDS)
    assert metadata["probes_registered"] == sorted(PROBE_IDS)
    assert metadata["errors"] == []
    assert metadata["controls_failed"] == []


def test_reference_sandbox_stays_clean_on_a_second_consecutive_run(
    reference_run, reference_second_run
):
    _, first = reference_run
    code, second = reference_second_run
    assert second["findings"] == [], _rule_keys(second)
    assert second["metadata"]["complete"] is True, second["metadata"]
    assert second["metadata"]["controls_failed"] == []
    assert code == 0
    assert second["findings"] == first["findings"]


def test_findings_surface_is_identical_across_two_separate_invocations(
    leaky_run, leaky_second_run
):
    """Determinism against a live target, across two separate processes.

    Run against the leaky fixture on purpose. The reference's findings
    surface is empty, and comparing one empty list to another would assert
    nothing at all. Fifteen findings, their order, their severities and
    their evidence strings all have to come back the same from a second
    process for this to hold.

    Only the findings block is compared. Run metadata legitimately varies
    between runs and is excluded by the project's determinism contract.

    No sort_keys on the re-serialization. json.loads preserves the order the
    keys arrived in, so comparing without normalizing means a between-process
    difference in key ordering fails here rather than being smoothed away.
    """
    _, first = leaky_run
    _, second = leaky_second_run
    assert first["findings"]
    assert json.dumps(first["findings"]) == json.dumps(second["findings"])


def test_leaky_sandbox_fails_and_the_run_is_still_complete_enough_to_report(leaky_run):
    code, payload = leaky_run
    assert code in (2, 3)
    assert payload["findings"]


def test_leaky_run_covered_every_probe(leaky_run):
    """The leaky findings have to come from a full assessment too, or the
    pairs below would only prove that the probes that happened to run found
    something."""
    _, payload = leaky_run
    assert payload["metadata"]["probes_selected"] == sorted(PROBE_IDS)
    assert payload["metadata"]["probes_registered"] == sorted(PROBE_IDS)


def test_leaky_controls_fail_only_where_the_failure_is_itself_the_finding(leaky_run):
    """A leak reported by a probe that could not prove it saw anything is
    not evidence. Three controls do fail here, and each one fails because
    of an omission this fixture makes on purpose and reports as a finding:
    no request log, no reset path, no event channel. The network probe is
    not among them: it reaches `authorized` first, which is what makes its
    `blocked_egress` finding a measurement rather than a coincidence.
    """
    _, payload = leaky_run
    assert payload["metadata"]["controls_failed"] == ["attribution", "bounds", "detection"]


@pytest.mark.parametrize(("probe_id", "rule_key"), _LEAK_PAIRS)
def test_each_invariant_trips_on_the_leaky_fixture_and_not_on_the_reference(
    probe_id, rule_key, leaky_run, reference_run
):
    _, leaky = leaky_run
    _, reference = reference_run
    assert (probe_id, rule_key) in _pairs(leaky)
    assert rule_key not in _rule_keys(reference)


def test_reference_sandbox_logs_and_alerts_on_separate_channels(reference_run):
    _, payload = reference_run
    assert "channel_not_separated" not in _rule_keys(payload)


def test_subset_run_against_the_reference_never_claims_containment():
    """The exit contract's other half, checked against a live target rather
    than a stub: a clean subset run is still not an assessment."""
    completed = run_probe("--target", _REFERENCE_TARGET, "--probe", "credentials")
    assert completed.returncode == 2
    table = completed.stdout.decode()
    assert "PARTIAL RUN: 1 of 6 probes produced a result (credentials)." in table
    assert "CONTAINED" not in table
