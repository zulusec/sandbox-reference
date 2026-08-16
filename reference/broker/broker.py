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
import socket
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
    with _LOCK:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()


def log_decision(host: str, method: str, allowed: bool) -> None:
    _write(REQUEST_LOG, {"host": host, "method": method,
                         "decision": "allow" if allowed else "deny"})
    if not allowed:
        _write(EVENT_LOG, {"severity": "HIGH", "event": "egress_denied",
                           "host": host, "method": method})


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self, method: str) -> None:
        host = host_of(self.path)
        allowed = decide(host, _load_allowlist())
        log_decision(host, method, allowed)
        if not allowed:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._handle("CONNECT")

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

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
