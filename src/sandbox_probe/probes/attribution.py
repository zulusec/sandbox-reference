"""Invariant 5: attributable.

Generate a known set of boundary crossings, then read the broker's request
log and check that each one is there with a decision attached. In the July
2026 OpenAI and Hugging Face incident, roughly 17,600 attacker actions were
reconstructed from logs like these, and that reconstruction is the only
reason anyone knows what happened.

A target with no request log fails here rather than passing quietly.
Nothing to read is the worst possible result, not the cleanest one.

The crossings have to actually traverse something that logs them. A raw TCP
connect to allowed_host or blocked_host never reaches the broker in the
reference sandbox: there is no route to anything else, the connection
attempt fails before it gets anywhere, and a compliant sandbox would then
report every crossing as unlogged, which is exactly backwards for a
containment check. So this payload does what network.py's positive control
already does: it opens target.proxy and issues an HTTP request in
absolute-URI form for each host, the same shape a proxied client actually
sends. That reaches the broker, which logs a host, a method, and a decision
regardless of whether the host is on the allowlist. A target with no proxy
configured falls back to a direct connection attempt, which is honest about
what it can prove: without a broker in front of it, this probe has no way
to manufacture a crossing that anything is positioned to log, so if nothing
shows up, that is reported as a genuine crossing_unlogged finding rather
than silently skipped.
"""

from __future__ import annotations

import json

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60

PAYLOAD_BODY = """
def parse_proxy(value):
    # 'host:port', or '[ipv6]:port' the way the reference broker's own
    # host_of parses IPv6 literals. No default port: a proxy value is
    # always 'host:port' by contract, and guessing a port for a malformed
    # value would silently connect to the wrong service instead of failing
    # closed for a reason the target config can be fixed to address.
    if value.startswith('['):
        host, _, rest = value[1:].partition(']')
        port_text = rest[1:] if rest.startswith(':') else ''
    else:
        host, sep, port_text = value.rpartition(':')
        if not sep:
            host, port_text = value, ''
    return host, int(port_text)

def cross_via_proxy(proxy, host, timeout=3):
    # Send the crossing as an absolute-URI proxy request, the form the
    # reference broker expects. Origin form would make it log the request
    # path as the hostname instead of the host this crossing is about.
    # Everything that can go wrong here, an unparseable proxy value, a
    # refused or timed-out connection, is caught and fails closed: the
    # attempt still counts as made even when it could not be delivered, and
    # a broker that never saw it is exactly the crossing_unlogged case this
    # probe exists to catch.
    try:
        proxy_host, proxy_port = parse_proxy(proxy)
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
            sock.sendall(('GET http://' + host + '/ HTTP/1.0\\r\\n\\r\\n').encode())
    except (OSError, ValueError):
        pass

def cross_direct(host, port=80, timeout=3):
    # No proxy configured: this is the only crossing this payload can
    # attempt, and against a genuinely contained sandbox it will not reach
    # anything a request log records. That is expected, not a bug in the
    # probe: a target that offers a request log without a proxy has not
    # given us a believable route to it, and this attempt is what proves
    # that gap rather than assuming it away.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        pass

hosts = json.loads(os.environ['PROBE_CROSSING_HOSTS'])
proxy = os.environ.get('PROBE_PROXY') or None

for host in hosts:
    if proxy:
        cross_via_proxy(proxy, host)
    else:
        cross_direct(host)

result['attempted'] = hosts
"""


def _exec_failure_detail(base: str, executed: ExecResult) -> str:
    """Fold the exec result's returncode and stderr into an error detail.

    Without this, a dead container, a timeout, and a genuine protocol
    violation all collapse into the same message, "inner payload produced
    no marked result line", and an operator cannot tell a target-side
    problem from a probe-side one.
    """
    detail = base
    if executed.returncode != 0:
        detail += f" (exit code {executed.returncode})"
    if executed.stderr.strip():
        detail += f"; stderr: {executed.stderr.strip()}"
    return detail


def _parse_log(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


class AttributionProbe:
    probe_id = "attribution"

    def run(self, target: Target) -> ProbeOutcome:
        hosts = [target.allowed_host, target.blocked_host]
        # Direct assignment, not setdefault: the environment inside the sandbox
        # belongs to the system under test, and a preset PROBE_* name there
        # must never be allowed to choose what this probe measures instead of
        # what the target actually specifies.
        payload = emit(
            f"os.environ['PROBE_CROSSING_HOSTS'] = {json.dumps(hosts)!r}\n"
            f"os.environ['PROBE_PROXY'] = {(target.proxy or '')!r}\n"
            + PAYLOAD_BODY
        )
        executed = target.run_inside([payload], timeout=_TIMEOUT)
        try:
            inner = parse_inner(executed.stdout)
        except InnerProtocolError as error:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    _exec_failure_detail(str(error), executed),
                )],
                control_ok=False,
            )

        if not isinstance(inner, dict):
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    f"inner result was not a JSON object: {inner!r}",
                )],
                control_ok=False,
            )

        if target.request_log_command is None:
            return ProbeOutcome(
                findings=[Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="no_request_log", severity=Severity.HIGH,
                    title="The target has no request log",
                    evidence=(
                        "No request log is configured for this target. Boundary "
                        "crossings cannot be reconstructed afterward, which is "
                        "the difference between an incident and a mystery."
                    ),
                )],
                control_ok=False,
            )

        read = target.read_request_log()
        if read.returncode != 0:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "read_request_log",
                    _exec_failure_detail("could not read the request log", read),
                )],
                control_ok=False,
            )

        entries = _parse_log(read.stdout)
        logged_hosts = {entry.get("host") for entry in entries}
        attempted = inner.get("attempted", [])

        findings = []
        for host in attempted:
            if host not in logged_hosts:
                findings.append(Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="crossing_unlogged", severity=Severity.HIGH,
                    title="A boundary crossing does not appear in the request log",
                    evidence=(
                        f"the sandbox attempted a crossing to {host} and the "
                        "request log has no entry for it"
                    ),
                ))
        for entry in entries:
            if entry.get("host") in attempted and "decision" not in entry:
                findings.append(Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="decision_missing", severity=Severity.MEDIUM,
                    title="A logged crossing records no decision",
                    evidence=(
                        f"the entry for {entry.get('host')} does not say whether "
                        "the request was allowed or denied"
                    ),
                ))

        return ProbeOutcome(findings=findings, control_ok=True)


register(AttributionProbe())
