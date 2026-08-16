"""A deliberately small egress broker.

This is layer three material: disposable, dated, and here to be read rather
than deployed. A production deployment uses a real proxy. What this shows is
the shape, which is that egress is a decision made outside the sandbox by a
component that holds no credentials.

Two output channels, on purpose. requests.log records every decision and is
what makes a run reconstructable afterward. events.log carries only policy
violations and is what something is supposed to alert on. A system that
produces the first without the second can tell you what happened and cannot
tell you while it matters.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
import urllib.parse

ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "/etc/broker/allowlist.json")
REQUEST_LOG = os.environ.get("REQUEST_LOG", "/var/log/broker/requests.log")
EVENT_LOG = os.environ.get("EVENT_LOG", "/var/log/broker/events.log")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "3128"))

_LOCK = threading.Lock()


def host_of(authority: str) -> str:
    """Strip any port and lowercase. Accepts 'host', 'host:port', or a URL."""
    if "://" in authority:
        authority = urllib.parse.urlsplit(authority).netloc
    if authority.startswith("["):  # IPv6 literal
        return authority.split("]")[0].lstrip("[").lower()
    return authority.split(":")[0].strip().lower()


def decide(host: str, allowlist: list[str]) -> bool:
    """True when the host is allowed.

    A wildcard entry matches exactly one additional label, so *.pypi.invalid
    covers files.pypi.invalid but neither pypi.invalid nor the suffix
    impostor evilpypi.invalid. Suffix matching on a bare string is the
    classic way an allowlist becomes an open door.
    """
    host = host_of(host)
    for entry in allowlist:
        entry = entry.strip().lower()
        if entry.startswith("*."):
            suffix = entry[1:]  # ".pypi.invalid"
            if host.endswith(suffix) and host.count(".") == entry.count("."):
                return True
        elif host == entry:
            return True
    return False


def _load_allowlist() -> list[str]:
    with open(ALLOWLIST_PATH, encoding="utf-8") as handle:
        return json.load(handle)["allow"]


def _write(path: str, record: dict) -> None:
    with _LOCK, open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()


def log_decision(host: str, method: str, allowed: bool) -> None:
    _write(REQUEST_LOG, {"host": host, "method": method,
                         "decision": "allow" if allowed else "deny"})
    if not allowed:
        _write(EVENT_LOG, {"severity": "HIGH", "event": "egress_denied",
                           "host": host, "method": method})


class Handler(http.server.BaseHTTPRequestHandler):
    """Every method the client can send is routed through _handle.

    No do_METHOD is defined by name. BaseHTTPRequestHandler dispatches a
    request by looking up 'do_' + self.command; __getattr__ below answers
    that lookup for any command at all, so CONNECT, GET, POST, an
    unrecognized verb, all of it reaches decide() and log_decision(). A
    fixed set of named do_ methods would let anything outside that set
    fall through to BaseHTTPRequestHandler's default 501, unlogged in
    both requests.log and events.log despite the module docstring's claim
    that requests.log records every decision.

    The body is drained before responding for the same reason: on a
    persistent HTTP/1.1 connection, a response sent before an unread
    request body is consumed leaves that body to be misread as the start
    of the next request line, which silently drops the next request from
    both logs too.
    """

    protocol_version = "HTTP/1.1"

    def _drain_body(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

    def _handle(self, method: str) -> None:
        self._drain_body()
        host = host_of(self.path)
        allowed = decide(host, _load_allowlist())
        log_decision(host, method, allowed)
        self.send_response(403 if not allowed else 502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            method = name[len("do_"):]
            return lambda: self._handle(method)
        raise AttributeError(name)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("broker: " + fmt % args + "\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    for path in (REQUEST_LOG, EVENT_LOG):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "a", encoding="utf-8").close()
    with Server(("0.0.0.0", LISTEN_PORT), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
