"""Invariant 1: no ambient network, and the broker is not a trusted zone.

Four questions, not one, and the first one is the one that cannot be
dodged. Can the sandbox open a TCP connection to a bare address literal.
That question needs no name resolution, so there is no state of the world in
which it silently fails to run: either the connection opened, or the stack
answered that it was refused or unroutable, and both of those are
measurements. It is the check that carries this invariant.

A deadline that expires with nothing coming back is neither of those, and
it gets its own state rather than being folded into a denial. A firewall
that drops instead of rejecting, a loaded runner and a congested bridge all
produce the same silence from inside the sandbox, so a timeout says the
route was not established, never that it was refused. The reason
reachable() reports four states rather than two is that collapsing "no
answer" into "denied" is how a harness certifies an uncontained sandbox,
and a timeout is that collapse wearing a different error class.

The other three are name-based, and every name-based check has a failure
mode the first one does not. Can the sandbox reach a host it should not, can
it resolve a name at all, which is the exfiltration path an HTTP allowlist
never sees, and can it reach the classes of host that serve as staging and
command-and-control. A name that does not resolve makes all three fail for a
reason that has nothing to do with containment, which is why each of them
reports why it did not fire rather than reporting a bare no.

The positive control is the fourth kind of question, and in a correctly
contained sandbox it cannot be direct reachability of the allowed host,
because nothing is directly reachable. That is the whole point of
containment: the reference sandbox sits on a network with no route out, and
its only path is an egress broker. So when the target names a proxy, the
control goes through it, asking for the allowed host in absolute-URI form
and accepting any answer that is not an outright denial (the reference
broker forwards nothing; it answers 403 for a denied host and 502 for an
allowed one, and 502 is exactly the proof of life and policy the control
needs). A target with no proxy falls back to direct reachability or
resolvability of the allowed host, which is what a genuinely open target
(the leaky fixture) can prove.

Either way, a sandbox with no network at all answers no to every question
for a reason that has nothing to do with containment, and a harness that
cannot tell that apart from a properly contained sandbox is measuring
nothing.
"""

from __future__ import annotations

from sandbox_probe.evidence import (
    BOOL,
    MAPPING,
    TEXT,
    bounded,
    overflow_finding,
    safe_text,
    shape_problem_detail,
)
from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60

# The two answers that settle the address-literal question. 'timeout' means
# the attempt was made and nothing came back, and everything else means the
# check never ran at all. Both are errors, with different details, because
# neither is an answer about routability.
_MEASURED = ("connected", "denied")

# What the payload has to answer, and in what shape. Every measurement below
# is read with a falsy default, so a key that never arrived would produce
# exactly what a check reporting no egress produces. Declaring the shape is
# what keeps a missing answer an error rather than a clean line.
#
# c2 is declared like the rest. It is tempting to argue that a malformed c2
# result can only lose a finding, because blocked_endpoint carries the clean
# verdict. That is wrong, and the counter-example is the case this check
# exists for: an egress policy that denies raw routes and permits the hosts
# that look like developer infrastructure. There blocked_endpoint is
# honestly 'denied', every other check is honestly negative, and c2 is the
# only signal there is. Reading it with a falsy default would turn a
# malformed answer into exit 0.
_RESULT_SHAPE = {
    "blocked_endpoint": TEXT,
    "blocked_host": TEXT,
    "dns_canary": TEXT,
    "c2": MAPPING,
    "control_reachable": BOOL,
}

PAYLOAD_BODY = """
def reachable(host, port=80, timeout=3):
    # Four answers, not two. The original two-answer version caught OSError
    # and returned False, which made 'the name does not exist' and 'the
    # route was denied' the same answer. Only the second one is a
    # measurement of containment, and collapsing them is how a harness
    # certifies a sandbox with unrestricted egress as contained: every name
    # it was told to try happened to be one that resolves for nobody.
    #
    # 'timeout' is the same argument applied to the same line from the
    # other side. ECONNREFUSED, ENETUNREACH and EHOSTUNREACH are the stack
    # reporting a decision; a deadline that expired is the absence of one,
    # and a dropping firewall, a loaded runner and a congested bridge are
    # indistinguishable from here. So it is reported as its own state and
    # never counted as a denial.
    #
    # socket.gaierror and socket.timeout are both OSError subclasses
    # (socket.timeout has been an alias of the builtin TimeoutError since
    # Python 3.10), so both have to be caught ahead of it.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 'connected'
    except socket.gaierror:
        return 'unresolved'
    except TimeoutError:
        return 'timeout'
    except OSError:
        return 'denied'

def resolves(host):
    try:
        socket.getaddrinfo(host, None)
        return 'resolved'
    except OSError:
        return 'unresolved'

def parse_host_port(value):
    # 'host:port', or '[ipv6]:port' the way the reference broker's own
    # host_of parses IPv6 literals. No default port: a proxy or endpoint
    # value is always 'host:port' by contract, and guessing a port for a
    # malformed value would silently connect to the wrong service instead
    # of failing closed for a reason the target config can be fixed to
    # address.
    if value.startswith('['):
        host, _, rest = value[1:].partition(']')
        port_text = rest[1:] if rest.startswith(':') else ''
    else:
        host, sep, port_text = value.rpartition(':')
        if not sep:
            host, port_text = value, ''
    return host, int(port_text)

def endpoint_status(value, timeout=3):
    # The address literal. The config validator guarantees this is an
    # address and a port, so create_connection performs no name lookup and
    # the answer is about the route and nothing else.
    #
    # 'unattempted' rather than 'denied' when the value will not parse: a
    # value the payload could not use is a check that did not run, and the
    # probe turns that into an error rather than a clean line.
    try:
        host, port = parse_host_port(value)
    except (ValueError, AttributeError):
        return 'unattempted'
    return reachable(host, port, timeout)

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
        proxy_host, proxy_port = parse_host_port(proxy)
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
endpoint = os.environ['PROBE_BLOCKED_ENDPOINT']
canary = os.environ['PROBE_DNS_CANARY_HOST']
allowed = os.environ['PROBE_ALLOWED_HOST']
c2 = [h for h in os.environ['PROBE_C2_HOSTS'].split(',') if h]
proxy = os.environ.get('PROBE_PROXY') or None

result['blocked_endpoint'] = endpoint_status(endpoint)
result['blocked_host'] = reachable(blocked)
result['dns_canary'] = resolves(canary)
result['c2'] = dict((h, reachable(h)) for h in c2)
result['control_reachable'] = (
    proxy_allows(proxy, allowed) if proxy else (
        reachable(allowed) == 'connected' or resolves(allowed) == 'resolved'
    )
)
"""


def _exec_failure_detail(base: str, executed: ExecResult) -> str:
    """Fold the exec result's returncode and stderr into an error detail.

    Without this, a dead container, a timeout, and a genuine protocol
    violation all collapse into the same message, "inner payload produced
    no marked result line", and an operator cannot tell a target-side
    problem from a probe-side one.

    stderr is the widest channel the system under test has into this
    report: it chooses every byte of it, and an error detail is written to
    the same terminal a finding is. So it goes through the same cleaning
    and the same length bound every other target-supplied value does.
    Errors are not Findings, but they render identically, so the rule that
    covers one has to cover the other.
    """
    detail = base
    if executed.returncode != 0:
        detail += f" (exit code {executed.returncode})"
    if executed.stderr.strip():
        detail += f"; stderr: {safe_text(executed.stderr.strip())}"
    return detail


def build_payload(target: Target) -> str:
    """The inner payload for this target.

    Module level rather than inline in run() so the end-to-end suite can
    send exactly this payload into a live sandbox and read the raw
    per-check statuses, which is the only way to show that a clean network
    result rests on checks that were attempted.
    """
    # Direct assignment, not setdefault: the environment inside the sandbox
    # belongs to the system under test, and a preset PROBE_* name there
    # must never be allowed to choose what this probe measures instead of
    # what the target actually specifies.
    return emit(
        f"os.environ['PROBE_BLOCKED_HOST'] = {target.blocked_host!r}\n"
        f"os.environ['PROBE_BLOCKED_ENDPOINT'] = {target.blocked_endpoint!r}\n"
        f"os.environ['PROBE_DNS_CANARY_HOST'] = {target.dns_canary_host!r}\n"
        f"os.environ['PROBE_ALLOWED_HOST'] = {target.allowed_host!r}\n"
        f"os.environ['PROBE_C2_HOSTS'] = {','.join(target.c2_hosts)!r}\n"
        f"os.environ['PROBE_PROXY'] = {(target.proxy or '')!r}\n"
        + PAYLOAD_BODY
    )


class NetworkProbe:
    probe_id = "network"

    def run(self, target: Target) -> ProbeOutcome:
        executed = target.run_inside([build_payload(target)], timeout=_TIMEOUT)
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
                    f"inner result was not a JSON object: {safe_text(inner)}",
                )],
                control_ok=False,
            )

        problem = shape_problem_detail(inner, _RESULT_SHAPE)
        if problem is not None:
            return ProbeOutcome(
                errors=[ProbeError(self.probe_id, target.name, "result", problem)],
                control_ok=False,
            )

        findings = []
        errors = []

        # The address literal, first, because it is the check the rest of
        # this probe leans on. It needs no DNS, so 'connected' means the
        # sandbox has a route off its own network and 'denied' means the
        # stack said otherwise. 'timeout' is neither, and it is reported as
        # a gap rather than quietly counted as the second one.
        endpoint_status = inner.get("blocked_endpoint")
        if endpoint_status == "connected":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="blocked_egress",
                severity=Severity.HIGH,
                title="The sandbox has a route to the public internet",
                evidence=(
                    f"opened a TCP connection to {target.blocked_endpoint}, an address "
                    "literal that needs no name resolution. Ambient egress, whatever "
                    "the allowlist says."
                ),
            ))
        elif endpoint_status == "timeout":
            errors.append(ProbeError(
                self.probe_id, target.name, "blocked_endpoint",
                f"the address-literal reachability check timed out against "
                f"{target.blocked_endpoint}. A firewall that drops rather than "
                "rejects, a loaded host and a congested path all look like this "
                "from inside the sandbox, so nothing was established about raw "
                "routability and this run cannot report the network clean.",
            ))
        elif endpoint_status not in _MEASURED:
            errors.append(ProbeError(
                self.probe_id, target.name, "blocked_endpoint",
                f"the address-literal reachability check did not run "
                f"(status {endpoint_status!r} for {target.blocked_endpoint}). "
                "This is the check that measures raw routability without DNS, "
                "so nothing else here adds up to a containment result.",
            ))

        # The name-based reach check. 'unresolved' and 'timeout' are not
        # passes and are not counted as ones: each is a check that measured
        # nothing, and the only reason neither is an error is that
        # blocked_endpoint above asked the same question without a name in
        # it and got an answer. Delete that check and this branch becomes
        # the hole that let a sandbox with unrestricted egress and working
        # public DNS report CONTAINED.
        if inner.get("blocked_host") == "connected":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="blocked_egress",
                severity=Severity.HIGH,
                title="The sandbox reached a host that is not on the allowlist",
                evidence=f"opened a TCP connection to {target.blocked_host}:80",
            ))

        # Same rule for the canary. It resolves on anything with DNS egress,
        # so 'resolved' is proof; 'unresolved' is either containment or an
        # environment with no DNS at all, and the two are indistinguishable
        # from inside. Unmeasured, therefore never reported as clean.
        if inner.get("dns_canary") == "resolved":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="dns_canary",
                severity=Severity.HIGH,
                title="The sandbox resolved a public name",
                evidence=(
                    f"resolved {target.dns_canary_host}. Name resolution is an "
                    "exfiltration channel that an HTTP allowlist does not cover."
                ),
            ))

        # The harness put this host list into the payload, so the harness
        # decides which of them count as answers. Anything else that comes
        # back is a host nobody asked about: it cannot be a measurement of
        # a configured c2 class, and rendering it would let the system under
        # test write text of its choosing into this report. Reading the
        # statuses in the config's order also fixes the order, which the
        # target would otherwise pick.
        # A dict by the time it gets here: the declared shape above is what
        # guarantees it, rather than a local default that would swallow the
        # wrong shape.
        reported = inner["c2"]
        confirmed, dropped = bounded([
            host for host in target.c2_hosts if reported.get(host) == "connected"
        ])
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
            errors=errors,
            control_ok=bool(inner.get("control_reachable")),
        )


register(NetworkProbe())
