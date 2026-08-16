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

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

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
