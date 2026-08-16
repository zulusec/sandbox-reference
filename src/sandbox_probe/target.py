"""How the harness reaches the sandbox under test.

The harness does not know what a sandbox is. It knows how to run a command
inside one, and how to read the broker's request log and event channel from
outside. Everything vendor-specific lives in a target config file, which is
why the same probes work against Compose, a cluster, or anything else that
can exec.

The inner payload is delivered on stdin rather than as an argument, so the
harness never has to quote code through someone else's exec wrapper.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_REQUIRED = ("name", "exec_command", "allowed_host", "blocked_host")


class TargetConfigError(Exception):
    """The target config is missing or malformed."""


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Target:
    name: str
    exec_command: list[str]
    allowed_host: str
    blocked_host: str
    c2_hosts: list[str] = field(default_factory=list)
    request_log_command: list[str] | None = None
    events_command: list[str] | None = None
    reset_command: list[str] | None = None
    proxy: str | None = None
    wallclock_limit_seconds: int | None = None

    def run_inside(self, payload_argv: list[str], timeout: int) -> ExecResult:
        """Run the inner payload inside the sandbox and capture its output."""
        return _run(self.exec_command, stdin="\n".join(payload_argv), timeout=timeout)

    def read_request_log(self, timeout: int = 30) -> ExecResult:
        return self._read(self.request_log_command, timeout)

    def read_events(self, timeout: int = 30) -> ExecResult:
        return self._read(self.events_command, timeout)

    def reset(self, timeout: int = 60) -> ExecResult:
        return self._read(self.reset_command, timeout)

    @staticmethod
    def _read(command: list[str] | None, timeout: int) -> ExecResult:
        if command is None:
            return ExecResult(returncode=1, stdout="", stderr="not configured")
        return _run(command, stdin=None, timeout=timeout)


def _run(command: list[str], stdin: str | None, timeout: int) -> ExecResult:
    try:
        completed = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExecResult(returncode=124, stdout="", stderr=f"timed out after {timeout}s")
    except OSError as error:
        return ExecResult(returncode=125, stdout="", stderr=f"could not exec: {error}")
    return ExecResult(completed.returncode, completed.stdout, completed.stderr)


def load_target(path: str | Path) -> Target:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise TargetConfigError(f"no target config at {path}") from error
    except json.JSONDecodeError as error:
        raise TargetConfigError(f"target config at {path} is not valid JSON: {error}") from error

    if not isinstance(raw, dict):
        raise TargetConfigError(f"target config at {path} must be a JSON object")

    for key in _REQUIRED:
        if key not in raw:
            raise TargetConfigError(f"target config is missing required key: {key}")

    for key in ("exec_command", "request_log_command", "events_command", "reset_command"):
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise TargetConfigError(f"{key} must be a list of strings")

    proxy = raw.get("proxy")
    if proxy is not None and not isinstance(proxy, str):
        raise TargetConfigError("proxy must be a string")

    # bool is a subclass of int in Python, so it is excluded explicitly:
    # True/False must not silently pass as valid second counts.
    wallclock_limit_seconds = raw.get("wallclock_limit_seconds")
    if wallclock_limit_seconds is not None and (
        isinstance(wallclock_limit_seconds, bool)
        or not isinstance(wallclock_limit_seconds, int)
    ):
        raise TargetConfigError("wallclock_limit_seconds must be an integer")

    return Target(
        name=raw["name"],
        exec_command=raw["exec_command"],
        allowed_host=raw["allowed_host"],
        blocked_host=raw["blocked_host"],
        c2_hosts=list(raw.get("c2_hosts", [])),
        request_log_command=raw.get("request_log_command"),
        events_command=raw.get("events_command"),
        reset_command=raw.get("reset_command"),
        proxy=proxy,
        wallclock_limit_seconds=wallclock_limit_seconds,
    )
