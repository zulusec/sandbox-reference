"""Helpers shared by the determinism and end-to-end suites.

Both suites shell out to the installed console script rather than calling
main() in process. An in-process check cannot see a value that is constant
for the life of one interpreter yet varies between invocations, and that is
exactly the class of non-determinism worth catching.

Both also need the repository root. The target configs name their Compose
files by a path relative to it, so a run started from anywhere else would
fail for a reason that has nothing to do with containment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# When this is set, an end-to-end test that does not run is an error rather
# than a skip. CI sets it. A skipped containment check is a green tick over
# an unverified claim, which is this project's central failure mode wearing
# a CI hat.
REQUIRE_DOCKER_ENV = "SANDBOX_PROBE_REQUIRE_DOCKER"

_E2E_MODULE = "test_end_to_end"

PROBE_IDS = ("attribution", "bounds", "credentials", "detection", "filesystem", "network")


def probe_command() -> list[str]:
    """The installed console script, however this interpreter was started.

    PATH finds it when the environment is activated; the interpreter's own
    bin directory finds it when the suite is run as `.venv/bin/python -m
    pytest` with no activation.
    """
    script = shutil.which("sandbox-probe")
    if script is None:
        candidate = Path(sys.executable).parent / "sandbox-probe"
        if candidate.exists():
            script = str(candidate)
    assert script, "sandbox-probe console script not found; install with `pip install -e .`"
    return [script]


def run_probe(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run the console script from the repository root, capturing bytes.

    Bytes, not text, because the determinism assertions compare output byte
    for byte and decoding first would hide a difference in line endings.
    """
    return subprocess.run(
        probe_command() + list(args),
        capture_output=True,
        cwd=REPO_ROOT,
        timeout=timeout,
        check=False,
    )


def _docker_required() -> bool:
    return os.environ.get(REQUIRE_DOCKER_ENV) == "1"


def require_docker(reason: str) -> None:
    """Decline to run the end-to-end tests, loudly where it matters.

    Locally, no Docker means a skip, which is right: a contributor without a
    daemon should still be able to run the unit suite. In CI a skip would be
    a passing build that never checked the one claim this repository exists
    to make, so the same condition raises instead.
    """
    if _docker_required():
        raise RuntimeError(
            f"{REQUIRE_DOCKER_ENV}=1 but the end-to-end tests cannot run: {reason}. "
            "The reference sandbox's containment claim must not pass unverified."
        )
    pytest.skip(reason, allow_module_level=True)


def pytest_sessionfinish(session, exitstatus):
    """Backstop: fail the session if any end-to-end test was skipped.

    require_docker covers the conditions this module knows about today. This
    covers the ones it does not: a skip raised from inside a test body, a
    marker added later, a fixture calling pytest.skip. Whatever the route, a
    skipped end-to-end test under CI must not leave a green build.
    """
    if not _docker_required():
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    skipped = sorted({
        report.nodeid for report in reporter.stats.get("skipped", [])
        if _E2E_MODULE in getattr(report, "nodeid", "")
    })
    if not skipped:
        return
    session.config.pluginmanager.get_plugin("terminalreporter").write_line(
        f"{REQUIRE_DOCKER_ENV}=1 but these end-to-end tests were skipped, so the "
        f"containment claim went unverified: {', '.join(skipped)}",
        red=True,
    )
    session.exitstatus = 1
