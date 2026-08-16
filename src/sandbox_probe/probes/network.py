"""Invariant 1: no ambient network, and the broker is not a trusted zone.

Three questions, not one. Can the sandbox reach something it should not.
Can it resolve names, which is the exfiltration path an HTTP allowlist never
sees. And can it reach the classes of host that serve as staging and
command-and-control, which are the hosts an allowlist tends to contain
because they look like developer infrastructure.

The positive control is the fourth, and in a correctly contained sandbox it
cannot be direct reachability of the allowed host, because nothing is
directly reachable. That is the whole point of containment: the reference
sandbox sits on a network with no route out, and its only path is an egress
broker. So when the target names a proxy, the control goes through it,
asking for the allowed host in absolute-URI form and accepting any answer
that is not an outright denial (the reference broker forwards nothing; it
answers 403 for a denied host and 502 for an allowed one, and 502 is exactly
the proof of life and policy the control needs). A target with no proxy
falls back to direct reachability or resolvability of the allowed host,
which is what a genuinely open target (the leaky fixture) can prove.

Either way, a sandbox with no network at all answers no to the first three
questions for a reason that has nothing to do with containment, and a
harness that cannot tell that apart from a properly contained sandbox is
measuring nothing.
"""

from __future__ import annotations

from sandbox_probe.evidence import bounded, overflow_finding
from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60

PAYLOAD_BODY = """
def reachable(host, port=80, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def resolves(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False

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

def proxy_allows(proxy, allowed_host, timeout=3):
    # Open the proxy and ask for allowed_host in absolute-URI form, the way
    # a proxied client would: 'GET http://allowed_host/ HTTP/1.0'. Origin
    # form ('GET / HTTP/1.0' with a Host header) is wrong here because the
    # reference broker derives the hostname from the request target, and
    # origin form makes it log the path as the hostname.
    #
    # Success is any status other than a denial. The reference broker
    # forwards nothing: it answers 403 for a denied host and 502 for an
    # allowed one, so 502 counts as success. It proves the broker is up,
    # reachable, and applying its allowlist, which is what the control
    # needs to establish.
    #
    # Everything that can go wrong, an unparseable proxy value, a refused
    # or timed-out connection, a garbled response, is caught here and
    # fails closed rather than raising past the caller and losing the
    # rest of this payload's measurements.
    try:
        proxy_host, proxy_port = parse_proxy(proxy)
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
            sock.sendall(('GET http://' + allowed_host + '/ HTTP/1.0\\r\\n\\r\\n').encode())
            sock.settimeout(timeout)
            response = b''
            while b'\\r\\n' not in response:
                chunk = sock.recv(256)
                if not chunk:
                    break
                response += chunk
            status_line = response.split(b'\\r\\n', 1)[0].decode(errors='replace')
            parts = status_line.split()
            status = int(parts[1]) if len(parts) >= 2 else None
            return status is not None and status != 403
    except (OSError, ValueError):
        return False

blocked = os.environ['PROBE_BLOCKED_HOST']
allowed = os.environ['PROBE_ALLOWED_HOST']
c2 = [h for h in os.environ['PROBE_C2_HOSTS'].split(',') if h]
proxy = os.environ.get('PROBE_PROXY') or None

result['blocked_reachable'] = reachable(blocked)
result['dns_resolved'] = resolves('canary.' + blocked)
result['c2_reachable'] = [h for h in c2 if reachable(h)]
result['control_reachable'] = (
    proxy_allows(proxy, allowed) if proxy else (reachable(allowed) or resolves(allowed))
)
"""


def _as_list(value) -> list:
    """A list, or an empty one. The payload's contract is a list, and a
    string arriving here must never be walked character by character."""
    return value if isinstance(value, list) else []


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


class NetworkProbe:
    probe_id = "network"

    def run(self, target: Target) -> ProbeOutcome:
        # Direct assignment, not setdefault: the environment inside the sandbox
        # belongs to the system under test, and a preset PROBE_* name there
        # must never be allowed to choose what this probe measures instead of
        # what the target actually specifies.
        payload = emit(
            f"os.environ['PROBE_BLOCKED_HOST'] = {target.blocked_host!r}\n"
            f"os.environ['PROBE_ALLOWED_HOST'] = {target.allowed_host!r}\n"
            f"os.environ['PROBE_C2_HOSTS'] = {','.join(target.c2_hosts)!r}\n"
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

        findings = []
        if inner.get("blocked_reachable"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="blocked_egress",
                severity=Severity.HIGH,
                title="The sandbox reached a host that is not on the allowlist",
                evidence=f"opened a TCP connection to {target.blocked_host}:80",
            ))
        if inner.get("dns_resolved"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="dns_canary",
                severity=Severity.HIGH,
                title="The sandbox resolved an arbitrary name",
                evidence=(
                    f"resolved canary.{target.blocked_host}. Name resolution is an "
                    "exfiltration channel that an HTTP allowlist does not cover."
                ),
            ))
        # The harness put this host list into the payload, so the harness
        # decides which of them count as answers. Anything else that comes
        # back is a host nobody asked about: it cannot be a measurement of
        # a configured c2 class, and rendering it would let the system under
        # test write text of its choosing into this report. Intersecting
        # also fixes the order, which the target would otherwise pick.
        reported = {
            host for host in _as_list(inner.get("c2_reachable"))
            if isinstance(host, str)
        }
        confirmed, dropped = bounded([h for h in target.c2_hosts if h in reported])
        for host in confirmed:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="c2_channel",
                severity=Severity.HIGH,
                title="The sandbox reached a staging or command-and-control channel class",
                evidence=(
                    f"opened a TCP connection to {host}. Paste, request capture, and "
                    "file drop hosts are staging channels whether or not they are "
                    "on the allowlist."
                ),
            ))
        if dropped:
            findings.append(overflow_finding(
                probe_id=self.probe_id, subject=target.name, rule_key="c2_channel",
                severity=Severity.HIGH, dropped=dropped,
                kind="reachable staging hosts",
            ))

        return ProbeOutcome(
            findings=findings,
            control_ok=bool(inner.get("control_reachable")),
        )


register(NetworkProbe())
