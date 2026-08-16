"""Invariant 5: attributable.

Generate a known set of boundary crossings, then read the broker's request
log and check that each one is there with a decision attached. In the July
2026 OpenAI and Hugging Face incident, roughly 17,600 attacker actions were
reconstructed from logs like these, and that reconstruction is the only
reason anyone knows what happened.

A target with no request log fails here rather than passing quietly.
Nothing to read is the worst possible result, not the cleanest one.

This probe's ground truth comes from outside the sandbox. The crossings are
generated inside, but what counts as evidence is the broker's request log,
read on a host the sandbox has no route to. The detection probe reads its
event channel the same way; the other four measure by asking the sandbox
about itself. So the comparison here is made against the crossing list this
harness supplied, never against anything the payload reports back. The
payload's marked line proves only that it ran to completion.

requests.log is append-only and nothing resets it between runs, so a whole-
log comparison is satisfiable by a stale entry: a host logged by an earlier
run stays in the log forever, and a later run whose crossing genuinely
failed to reach the broker would still find that host present and report
clean. That is a false clean, the worst failure mode this harness has. So
the log is read once before the crossings run and once after, and only the
lines appended in between are compared against this run's attempted hosts.
The log not existing yet on the first read counts as zero prior lines, not
an error, since that is the ordinary shape of a target's very first run.
The second read failing, or coming back with fewer lines than the first
(rotation, truncation), is a condition this probe cannot measure through,
so it is surfaced as a ProbeError rather than read as an empty, and
therefore clean, delta.

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

from sandbox_probe.evidence import safe_text
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
    #
    # The response is read before returning, the way network.py's
    # proxy_allows already does. Without this, the harness's read of the
    # request log after this payload exits is racing the broker's own
    # write of its log line, with nothing but incidental exec latency
    # keeping the order right. Reading a full status line back proves the
    # broker finished handling the request, log line included, before this
    # function hands control back.
    try:
        proxy_host, proxy_port = parse_proxy(proxy)
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
            sock.sendall(('GET http://' + host + '/ HTTP/1.0\\r\\n\\r\\n').encode())
            sock.settimeout(timeout)
            response = b''
            while b'\\r\\n' not in response:
                chunk = sock.recv(256)
                if not chunk:
                    break
                response += chunk
    except (OSError, ValueError):
        pass

def cross_direct(host, port=80, timeout=3):
    # No proxy configured: this is the only crossing this payload can
    # attempt, and against a genuinely contained sandbox it will not reach
    # anything a request log records. That is expected, not a bug in the
    # probe: a target that offers a request log without a proxy has not
    # given us a believable route to it, and this attempt is what proves
    # that gap rather than assuming it away.
    #
    # Returns whether the connection opened. Nothing in this payload acts
    # on the answer, because the crossing counts as attempted either way,
    # but a function that reports what it did can be tested against a real
    # listener rather than only inspected for its name.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

hosts = json.loads(os.environ['PROBE_CROSSING_HOSTS'])
proxy = os.environ.get('PROBE_PROXY') or None

for host in hosts:
    if proxy:
        cross_via_proxy(proxy, host)
    else:
        cross_direct(host)
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


def _lines(text: str) -> list[str]:
    """Non-empty, stripped raw lines, kept as text so a line count taken
    before the crossings run and one taken after can be compared directly,
    before any line is parsed as JSON."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def _parse_lines(lines: list[str]) -> list[dict]:
    entries = []
    for line in lines:
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

        # Baseline read, before this run's crossings exist. A non-zero
        # returncode here counts as zero prior lines rather than an error:
        # the ordinary shape of a target's very first run is a request log
        # that does not exist yet. If the read is broken for a real reason
        # rather than a missing file, the second read below will fail the
        # same way and that failure is not forgiven.
        before = target.read_request_log()
        before_lines = _lines(before.stdout) if before.returncode == 0 else []

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

        # Second read, after this run's crossings ran. Its failure is a real
        # error: the request log was reachable enough for the baseline read
        # or crossings would not have been worth running, so a failure now
        # is a target-side problem this probe cannot see past.
        after = target.read_request_log()
        if after.returncode != 0:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "read_request_log",
                    _exec_failure_detail("could not read the request log", after),
                )],
                control_ok=False,
            )

        after_lines = _lines(after.stdout)
        if len(after_lines) < len(before_lines):
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "read_request_log",
                    f"the request log had {len(before_lines)} lines before this run's "
                    f"crossings and only {len(after_lines)} after; it appears to have "
                    "been rotated or truncated, and this run's crossings cannot be "
                    "attributed against a log that shrank",
                )],
                control_ok=False,
            )

        # Only the lines this run appended. requests.log is append-only and
        # nothing resets it between runs, so comparing against the whole log
        # would let a stale entry from an earlier run mask a crossing that
        # this run's payload never actually got logged.
        entries = _parse_lines(after_lines[len(before_lines):])
        logged_hosts = {
            entry.get("host") for entry in entries
            if isinstance(entry.get("host"), str)
        }

        # `hosts` above, not anything the payload echoed back. The reading
        # this comparison rests on came from outside the sandbox, from the
        # broker's log on a host the sandbox has no route to, and that is
        # the whole reason this probe can say something a compromised
        # sandbox cannot contradict. Comparing that outside reading against
        # a list the sandbox chose would hand the crossing set straight
        # back to the system under test: a target answering with an empty
        # list would produce no findings at all, which is a clean
        # attribution result from a sandbox that logged nothing. The
        # harness supplied these hosts, so the harness compares against
        # them.
        findings = []
        for host in hosts:
            if host not in logged_hosts:
                findings.append(Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="crossing_unlogged", severity=Severity.HIGH,
                    title="A boundary crossing does not appear in the request log",
                    evidence=(
                        f"the sandbox attempted a crossing to {safe_text(host)} and "
                        "the request log has no entry for it"
                    ),
                ))
        # One finding per host rather than one per matching line: a broker
        # that logs the same undecided host repeatedly says nothing new each
        # time, and the host list is what the harness controls the size of.
        for host in hosts:
            if any(
                entry.get("host") == host and "decision" not in entry
                for entry in entries
            ):
                findings.append(Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="decision_missing", severity=Severity.MEDIUM,
                    title="A logged crossing records no decision",
                    evidence=(
                        f"the entry for {safe_text(host)} does not say whether "
                        "the request was allowed or denied"
                    ),
                ))

        return ProbeOutcome(findings=findings, control_ok=True)


register(AttributionProbe())
