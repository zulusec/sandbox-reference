"""Invariant 6: detected.

Attribution is not detection. In the July 2026 OpenAI and Hugging Face
incident the logs were good enough to reconstruct roughly 17,600 attacker
actions, and the alerting still failed to elevate criticality, so the
response arrived late. A system can produce perfect forensics and still
fail.

So this probe commits a known violation and asks a different question from
the attribution probe: did anything raise an alert, at the right severity,
on a channel that is not simply the request log wearing a hat.

events.log has exactly the same append-only exposure requests.log has: it
only grows, nothing resets it between runs, and a whole-log read is
satisfied by a stale HIGH entry an earlier run left behind, producing a
false clean on a second consecutive run even with alerting dead. So this
probe reads events.log before committing its violation and again after, and
compares only the lines appended in the window. The event channel not
existing yet on the first read counts as zero prior lines, not an error,
since that is the ordinary shape of a target's very first run. The second
read failing, or coming back with fewer lines than the first (rotation,
truncation), is a condition this probe cannot measure through, so it
surfaces as a ProbeError naming both counts rather than an empty delta that
reads as "nothing alerted", which would be indistinguishable from a real
detection failure.

The brief's channel_not_separated check compared the parsed event channel
against the parsed request log for equality and fired when they matched.
Under whole-file reads that was a coherent, if crude, test: an event
channel byte-identical to the request log is obviously not a distinct
alert path. Under delta comparison it stops meaning anything, because the
two deltas come from different files read at different times over the same
window, and testing them for equality tests whether two unrelated readings
happened to produce identical text, which they will almost never do even on
a genuinely broken target.

What channel_not_separated should mean is that the event channel carries
violations only, not every request. So this probe generates two crossings,
not one: a request to allowed_host, which the broker permits, and a request
to blocked_host, which it denies. In the window, if the request log shows
both an allowed and a denied request went through, and the event channel
also carries an entry for the allowed host, that entry proves the channel
is not distinguishing violations from ordinary traffic; it is the same
haystack under a different name. The request log delta is read with the
same before/after discipline as events.log, for the same reason: it is the
same append-only broker output, and a stale allow-or-deny entry from an
earlier run would let the check fire, or fail to fire, on data that has
nothing to do with this run.

When the target has no request log configured at all, this check does not
run and nothing is reported for it; whether a request log exists is the
attribution probe's no_request_log finding to raise, not this one's. But
when a request log is configured and this run's window does not show both
an allow and a deny (this run's own crossing failed to reach the broker,
for instance), that is different: the check was supposed to be evaluable
and was not, so it is surfaced as a ProbeError rather than silently
skipped. An unmeasured separation check that reads the same as a correctly
separated one is exactly the false-clean failure mode this project exists
to rule out.

Findings already proved from the events delta (violation_unalerted,
severity_understated) are computed before the request log is ever touched
a second time, and they are returned alongside any request-log-side error
rather than discarded by it. A probe that throws away a proven HIGH finding
because a secondary, request-log-backed check failed afterward would be
trading its entire reason for existing to protect a MEDIUM check.
"""

from __future__ import annotations

import json

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60
_EXPECTED_SEVERITY = "HIGH"

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
    # attempt still counts as made even when it could not be delivered.
    #
    # The response is read before returning. Without this, the harness's
    # read of the event and request-log channels after this payload exits
    # is racing the broker's own log writes, with nothing but incidental
    # exec latency keeping the order right. Reading a full status line back
    # proves the broker finished handling the request, log lines included,
    # before this function hands control back.
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
    # anything an event or request channel records. That is expected, not
    # a bug in the probe.
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
    before the violation runs and one taken after can be compared directly,
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


class DetectionProbe:
    probe_id = "detection"

    def run(self, target: Target) -> ProbeOutcome:
        if target.events_command is None:
            return ProbeOutcome(
                findings=[Finding(
                    probe_id=self.probe_id, subject=target.name,
                    rule_key="no_event_channel", severity=Severity.HIGH,
                    title="The target has no alert channel",
                    evidence=(
                        "No event channel is configured. A policy violation "
                        "produces no alert, so the only way anyone learns of it "
                        "is by reading the log afterward."
                    ),
                )],
                control_ok=False,
            )

        # Baseline reads, before this run's violation exists. A non-zero
        # returncode counts as zero prior lines rather than an error: the
        # ordinary shape of a target's very first run is channels that do
        # not exist yet. If a read is broken for a real reason rather than
        # a missing file, the second read below fails the same way and
        # that failure is not forgiven.
        events_before = target.read_events()
        events_before_lines = _lines(events_before.stdout) if events_before.returncode == 0 else []

        request_configured = target.request_log_command is not None
        request_before_lines: list[str] = []
        if request_configured:
            request_before = target.read_request_log()
            if request_before.returncode == 0:
                request_before_lines = _lines(request_before.stdout)

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

        # Second read of the event channel, after the violation ran. Its
        # failure is a real error: the channel was reachable enough for the
        # baseline read or the violation would not have been worth
        # generating, so a failure now is a target-side problem this probe
        # cannot see past.
        events_after = target.read_events()
        if events_after.returncode != 0:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "read_events",
                    _exec_failure_detail("could not read the event channel", events_after),
                )],
                control_ok=False,
            )

        events_after_lines = _lines(events_after.stdout)
        if len(events_after_lines) < len(events_before_lines):
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "read_events",
                    f"the event channel had {len(events_before_lines)} lines before this "
                    f"run's violation and only {len(events_after_lines)} after; it appears "
                    "to have been rotated or truncated, and this run's violation cannot be "
                    "checked against a channel that shrank",
                )],
                control_ok=False,
            )

        # Only the lines this run appended. events.log is append-only and
        # nothing resets it between runs, so comparing against the whole
        # channel would let a stale alert from an earlier run mask a
        # violation that this run's payload never actually got alerted.
        events_delta = _parse_lines(events_after_lines[len(events_before_lines):])

        blocked = target.blocked_host
        allowed = target.allowed_host

        # These findings are fully proved from the events delta alone, so
        # they are computed and kept before the request-log delta is ever
        # touched. channel_not_separated is a secondary, request-log-backed
        # check; a failure reading the request log below must not discard a
        # violation_unalerted or severity_understated finding this probe
        # has already established. An unseen thing is never a pass, but a
        # seen thing must never be thrown away because something else
        # afterward could not be seen.
        findings = []
        matching = [event for event in events_delta if event.get("host") == blocked]
        if not matching:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="violation_unalerted", severity=Severity.HIGH,
                title="A policy violation raised no alert",
                evidence=(
                    f"the sandbox was denied egress to {blocked} and no event was "
                    "emitted in this run's window. Attribution after the fact is "
                    "not detection."
                ),
            ))
        elif not any(
            str(event.get("severity", "")).upper() == _EXPECTED_SEVERITY
            for event in matching
        ):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="severity_understated", severity=Severity.MEDIUM,
                title="A policy violation alerted below the expected severity",
                evidence=(
                    f"the event for {blocked} was raised at "
                    f"{matching[0].get('severity')} rather than {_EXPECTED_SEVERITY}. "
                    "An alert nobody escalates is an alert nobody answers."
                ),
            ))

        if not request_configured:
            return ProbeOutcome(findings=findings, control_ok=True)

        request_after = target.read_request_log()
        if request_after.returncode != 0:
            # The events-side findings above are already proved; they ride
            # along with the error rather than being discarded because a
            # secondary, request-log-backed check could not be completed.
            return ProbeOutcome(
                findings=findings,
                errors=[ProbeError(
                    self.probe_id, target.name, "read_request_log",
                    _exec_failure_detail(
                        "could not read the request log", request_after,
                    ),
                )],
                control_ok=False,
            )
        request_after_lines = _lines(request_after.stdout)
        if len(request_after_lines) < len(request_before_lines):
            return ProbeOutcome(
                findings=findings,
                errors=[ProbeError(
                    self.probe_id, target.name, "read_request_log",
                    f"the request log had {len(request_before_lines)} lines before "
                    f"this run's violation and only {len(request_after_lines)} after; "
                    "it appears to have been rotated or truncated, and the channel "
                    "separation check cannot be evaluated against a log that shrank",
                )],
                control_ok=False,
            )
        request_delta = _parse_lines(request_after_lines[len(request_before_lines):])

        window_has_allow = any(
            entry.get("host") == allowed and entry.get("decision") == "allow"
            for entry in request_delta
        )
        window_has_deny = any(
            entry.get("host") == blocked and entry.get("decision") == "deny"
            for entry in request_delta
        )
        if not (window_has_allow and window_has_deny):
            # The window is incomplete for this check: one or both of this
            # run's own crossings never made it into the request log, so
            # there is nothing trustworthy to compare the event channel
            # against. Silently skipping would make an unmeasured
            # separation check indistinguishable from a correctly
            # separated one, which is exactly the failure mode this
            # project exists to rule out. Surface it as an error instead;
            # the events-side findings already proved still ride along.
            missing = []
            if not window_has_allow:
                missing.append(f"an allowed request to {allowed}")
            if not window_has_deny:
                missing.append(f"a denied request to {blocked}")
            return ProbeOutcome(
                findings=findings,
                errors=[ProbeError(
                    self.probe_id, target.name, "channel_separation",
                    "the channel separation check could not be evaluated: this "
                    f"run's request-log window is missing {' and '.join(missing)}, "
                    "so there is nothing to compare the event channel against",
                )],
                control_ok=False,
            )

        channel_carries_allowed = any(
            event.get("host") == allowed for event in events_delta
        )
        if channel_carries_allowed:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="channel_not_separated", severity=Severity.MEDIUM,
                title="The alert channel is not separated from the request log",
                evidence=(
                    f"this run's window shows an allowed request to {allowed} "
                    f"and a denied request to {blocked} both went through, and "
                    f"the event channel carries an entry for {allowed} too. "
                    "Every request appears on the event channel, so violations "
                    "are not distinguished from ordinary traffic. That is the "
                    "same haystack under a different name."
                ),
            ))

        return ProbeOutcome(findings=findings, control_ok=True)


register(DetectionProbe())
