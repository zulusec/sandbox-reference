"""Invariant 2: no ambient credentials.

The three places a credential is found in practice, in the order the July
2026 incident found them: the process environment, a mounted token file, and
the cloud metadata service.

Findings name the variable or path and never print the value. A posture tool
that copies secrets into its own report has moved them, not found them. That
also means no raw environment value ever crosses out of the sandbox: the
secret-shaped check runs inside the target process, on `_LOOKS_SECRET_SOURCE`
below, and only variable names come back on the wire.

This probe needs no positive control. Absence of a secret is directly
observable in a way that absence of egress is not. That is a design
decision rather than a control that passed, so it is reported as one: the
outcome carries control_ok=None and the run's JSON lists this probe under
controls_absent. What a reader must never be handed is a True standing in
for a confirmation nobody performed.
"""

from __future__ import annotations

import json

from sandbox_probe.evidence import (
    LIST,
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

# Every key PAYLOAD_BODY below fills in, and the shape each has to arrive
# in. All three are read with a falsy default further down, so a result
# missing one of them would read as "no secrets, no readable credential
# files, metadata service unreachable" from a payload that measured none of
# it.
_RESULT_SHAPE = {
    "env_secrets": LIST,
    "readable_paths": LIST,
    "imds": TEXT,
}

# The three states imds_state() can return. A fourth value, a misspelling,
# or a different case falls through both branches below in silence, and
# 'unreachable' is the good outcome, so an undefined state must never be
# allowed to stand in for it.
_IMDS_STATES = ("token_blocked", "token_obtained", "unreachable")

_CREDENTIAL_PATHS = (
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "~/.aws/credentials",
    "~/.config/gcloud/application_default_credentials.json",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.ssh/id_rsa",
)

# One definition, used on both sides of the sandbox boundary:
#
# - Prepended into the payload string below, so `looks_secret` is defined
#   inside the target process and the secret-shaped check runs there. Only
#   the names of variables that match ever come back in `result`; the actual
#   values never leave the sandbox.
# - exec'd once at import time (below) to bind the same function as this
#   module's `looks_secret`, for the module's own callers and its tests.
#
# Verbatim duplication of a logic block is itself a defect, so there is
# exactly one copy of this source, not two definitions that can drift apart.
_LOOKS_SECRET_SOURCE = """
import math

_MIN_SECRET_LENGTH = 16
_MIN_ENTROPY_BITS_PER_CHAR = 3.0

_KEY_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "github_pat_", "sk-", "xoxb-", "xoxp-")
_SUGGESTIVE = ("SECRET", "PASSWORD", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY",
               "CREDENTIAL", "PASSWD")


def _shannon_bits_per_char(value):
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_secret(name, value):
    \"\"\"A known key prefix, or a long high-entropy value under a suggestive name.

    Deliberately conservative. A posture tool that cries wolf about PATH gets
    turned off, and a turned-off tool finds nothing.
    \"\"\"
    if any(value.startswith(prefix) for prefix in _KEY_PREFIXES):
        return True
    if len(value) < _MIN_SECRET_LENGTH:
        return False
    upper = name.upper()
    if not any(word in upper for word in _SUGGESTIVE):
        return False
    return _shannon_bits_per_char(value) >= _MIN_ENTROPY_BITS_PER_CHAR
"""

_looks_secret_namespace: dict = {}
exec(_LOOKS_SECRET_SOURCE, _looks_secret_namespace)  # noqa: S102 -- binding the shared detection source, see comment above
looks_secret = _looks_secret_namespace["looks_secret"]


PAYLOAD_BODY = """
result['env_secrets'] = sorted(
    name for name, value in os.environ.items()
    if not name.startswith('PROBE_') and looks_secret(name, value)
)

paths = json.loads(os.environ['PROBE_CREDENTIAL_PATHS'])
readable = []
for path in paths:
    expanded = os.path.expanduser(path)
    try:
        with open(expanded, 'rb') as handle:
            handle.read(1)
        readable.append(path)
    except OSError:
        pass
result['readable_paths'] = sorted(readable)

def imds_state():
    # HttpPutResponseHopLimit caps the IP TTL of the token PUT *response*,
    # not the request. A hop limit of 1 (the secure default) means a
    # container one hop from the host never receives the response: the
    # connection opens, but the recv comes back empty or errors. A hop
    # limit of 2+ (insecure) means the response makes it back with a body.
    # So a body is the finding, not its absence.
    try:
        with socket.create_connection(('169.254.169.254', 80), timeout=2) as sock:
            sock.sendall(b'PUT /latest/api/token HTTP/1.0\\r\\n'
                         b'X-aws-ec2-metadata-token-ttl-seconds: 60\\r\\n\\r\\n')
            try:
                body = sock.recv(256)
            except OSError:
                body = b''
    except OSError:
        return 'unreachable'
    return 'token_obtained' if body else 'token_blocked'

result['imds'] = imds_state()
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


class CredentialsProbe:
    probe_id = "credentials"

    def run(self, target: Target) -> ProbeOutcome:
        # Direct assignment, not setdefault: the environment inside the sandbox
        # belongs to the system under test, and a preset PROBE_* name there
        # must never be allowed to choose what this probe measures instead of
        # what the target actually specifies.
        payload = emit(
            _LOOKS_SECRET_SOURCE + "\n"
            "os.environ['PROBE_CREDENTIAL_PATHS'] = "
            f"{json.dumps(list(_CREDENTIAL_PATHS))!r}\n" + PAYLOAD_BODY
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
                    f"inner result was not a JSON object: {safe_text(inner)}",
                )],
                control_ok=False,
            )

        # Before any measurement is read out of it. Nothing has been
        # computed yet at this point, so returning here throws no proved
        # finding away.
        problem = shape_problem_detail(inner, _RESULT_SHAPE)
        if problem is None and inner["imds"] not in _IMDS_STATES:
            problem = (
                "the payload reported a metadata-service state this probe does not "
                f"define: {safe_text(inner['imds'])}. The three it defines are "
                f"{', '.join(_IMDS_STATES)}, and a fourth cannot be read as any of "
                "them, least of all as the one that means the endpoint was not there"
            )
        if problem is not None:
            return ProbeOutcome(
                errors=[ProbeError(self.probe_id, target.name, "result", problem)],
                control_ok=False,
            )

        findings = []
        # Variable names are genuinely discovered inside the sandbox, so
        # there is no harness-side list to check them against. They are
        # cleaned and bounded instead: inner comes from the system under
        # test, and a report is written to an operator's terminal.
        names, dropped_names = bounded(inner["env_secrets"])
        for name in names:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="env_secret",
                severity=Severity.HIGH,
                title="A credential is present in the sandbox environment",
                evidence=(
                    f"environment variable {name} holds a secret-shaped value. "
                    "The value is deliberately not reproduced here."
                ),
            ))
        if dropped_names:
            findings.append(overflow_finding(
                probe_id=self.probe_id, subject=target.name, rule_key="env_secret",
                severity=Severity.HIGH, dropped=dropped_names,
                kind="secret-shaped environment variables",
            ))

        # The candidate paths went in from here, so a path that did not is
        # not an answer to anything this probe asked. Checking the reported
        # set against the list the harness sent keeps the report to paths
        # this harness named.
        reported = {
            item for item in inner["readable_paths"] if isinstance(item, str)
        }
        for path in _CREDENTIAL_PATHS:
            if path not in reported:
                continue
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="credential_file",
                severity=Severity.HIGH,
                title="A credential file is readable from inside the sandbox",
                evidence=f"{path} was open for reading",
            ))

        # imds state machine: 'unreachable' raises nothing (the good outcome,
        # and what both reference fixtures produce since neither runs on
        # EC2). 'token_obtained' means the token PUT response crossed the
        # container's network hop, so it raises both imds_reachable and
        # imds_hop_limit. 'token_blocked' means the endpoint is routable but
        # the hop limit stopped the token response, so it raises
        # imds_reachable only.
        imds = inner["imds"]
        if imds == "token_obtained":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="imds_reachable",
                severity=Severity.HIGH,
                title="The cloud metadata service is reachable from the sandbox",
                evidence=(
                    "169.254.169.254 accepted a connection and returned a "
                    "session token on request. Instance role credentials "
                    "are reachable from inside the sandbox."
                ),
            ))
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="imds_hop_limit",
                severity=Severity.HIGH,
                title="Metadata service hop limit is not enforced",
                evidence=(
                    "A token PUT request made from inside the sandbox "
                    "received a response body, meaning the response crossed "
                    "the container's network hop. A hop limit of 1 would "
                    "have dropped that response before it reached the "
                    "container, so the hop limit is not in effect here."
                ),
            ))
        elif imds == "token_blocked":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="imds_reachable",
                severity=Severity.HIGH,
                title="The cloud metadata service is reachable from the sandbox",
                evidence=(
                    "169.254.169.254 accepted a connection, though the "
                    "token request did not complete. The endpoint is "
                    "routable from inside the sandbox even though a "
                    "session token was not obtained."
                ),
            ))

        # None, not True. This probe has no positive control: absence of a
        # secret is directly observable in a way that absence of egress is
        # not, so there is no separate check to run. A hardcoded True would
        # be an affirmative claim that a control confirmed this probe was
        # measuring something, and none did. The report names the absence
        # instead, and a reader can tell "no control needed here" from "the
        # control ran and held".
        return ProbeOutcome(findings=findings, control_ok=None)


register(CredentialsProbe())
