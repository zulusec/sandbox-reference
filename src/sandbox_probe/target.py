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

import ipaddress
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_REQUIRED = ("name", "exec_command", "allowed_host", "blocked_host")

# An address literal, so the check that carries invariant 1 needs no name
# resolution and therefore has no vacuous failure mode. 1.1.1.1:443 is a
# public anycast address that answers TLS from anywhere with a route out,
# which makes "the connection opened" mean "this sandbox has ambient
# network" and nothing else.
DEFAULT_BLOCKED_ENDPOINT = "1.1.1.1:443"

# A name reserved by IANA for documentation that nonetheless has real A and
# AAAA records, so it resolves for anything with DNS egress and belongs to
# nobody who could be surprised by the lookup.
DEFAULT_DNS_CANARY_HOST = "example.com"


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
    blocked_endpoint: str = DEFAULT_BLOCKED_ENDPOINT
    dns_canary_host: str = DEFAULT_DNS_CANARY_HOST
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


def _validate_blocked_endpoint(value: object) -> str:
    """An `IP:port` literal, or a config error naming the key.

    A hostname is refused rather than accepted, because accepting one would
    put name resolution back in front of the one check that is supposed to
    survive without it. If the name did not exist, the connection would fail
    the same way it fails for a sandbox with no route, and the probe would
    once again be unable to tell an enforced boundary from a name nobody
    ever registered.
    """
    if not isinstance(value, str):
        raise TargetConfigError("blocked_endpoint must be a string")
    if value.startswith("["):
        address, _, rest = value[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        address, separator, port_text = value.rpartition(":")
        if not separator:
            address, port_text = "", ""
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise TargetConfigError(
            f"blocked_endpoint must be an address literal and a port, "
            f"as in {DEFAULT_BLOCKED_ENDPOINT}, not {value!r}: {error}"
        ) from error
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise TargetConfigError(
            f"blocked_endpoint must end in a port between 1 and 65535, not {value!r}"
        )
    return value


def _validate_dns_canary_host(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TargetConfigError("dns_canary_host must be a non-empty string")
    return value


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

    for key in ("name", "allowed_host", "blocked_host"):
        if not isinstance(raw[key], str):
            raise TargetConfigError(f"{key} must be a string")

    # A bare string here is the dangerous case, because it is accepted
    # silently and measures nothing: list("paste.example") is thirteen
    # single-character hostnames, none of which is the host the operator
    # meant, and the c2 check then reports clean having probed thirteen
    # names that do not exist. A config typo must fail loudly rather than
    # produce a clean result from an unrun check.
    c2_hosts = raw.get("c2_hosts", [])
    if not isinstance(c2_hosts, list) or not all(isinstance(item, str) for item in c2_hosts):
        raise TargetConfigError("c2_hosts must be a list of strings")

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
        blocked_endpoint=_validate_blocked_endpoint(
            raw.get("blocked_endpoint", DEFAULT_BLOCKED_ENDPOINT)
        ),
        dns_canary_host=_validate_dns_canary_host(
            raw.get("dns_canary_host", DEFAULT_DNS_CANARY_HOST)
        ),
        c2_hosts=list(c2_hosts),
        request_log_command=raw.get("request_log_command"),
        events_command=raw.get("events_command"),
        reset_command=raw.get("reset_command"),
        proxy=proxy,
        wallclock_limit_seconds=wallclock_limit_seconds,
    )
