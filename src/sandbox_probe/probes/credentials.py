"""Invariant 2: no ambient credentials.

The three places a credential is found in practice, in the order the July
2026 incident found them: the process environment, a mounted token file, and
the cloud metadata service.

Findings name the variable or path and never print the value. A posture tool
that copies secrets into its own report has moved them, not found them.

This probe needs no positive control. Absence of a secret is directly
observable in a way that absence of egress is not.
"""

from __future__ import annotations

import json
import math

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60
_MIN_SECRET_LENGTH = 16
_MIN_ENTROPY_BITS_PER_CHAR = 3.0

_KEY_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "github_pat_", "sk-", "xoxb-", "xoxp-")
_SUGGESTIVE = ("SECRET", "PASSWORD", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY",
               "CREDENTIAL", "PASSWD")

_CREDENTIAL_PATHS = (
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "~/.aws/credentials",
    "~/.config/gcloud/application_default_credentials.json",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.ssh/id_rsa",
)


def _shannon_bits_per_char(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_secret(name: str, value: str) -> bool:
    """A known key prefix, or a long high-entropy value under a suggestive name.

    Deliberately conservative. A posture tool that cries wolf about PATH gets
    turned off, and a turned-off tool finds nothing.
    """
    if any(value.startswith(prefix) for prefix in _KEY_PREFIXES):
        return True
    if len(value) < _MIN_SECRET_LENGTH:
        return False
    upper = name.upper()
    if not any(word in upper for word in _SUGGESTIVE):
        return False
    return _shannon_bits_per_char(value) >= _MIN_ENTROPY_BITS_PER_CHAR


PAYLOAD_BODY = """
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
result['env'] = {k: v for k, v in os.environ.items() if not k.startswith('PROBE_')}

def imds_state():
    try:
        with socket.create_connection(('169.254.169.254', 80), timeout=2) as sock:
            sock.sendall(b'GET /latest/meta-data/ HTTP/1.0\\r\\n\\r\\n')
            sock.recv(16)
    except OSError:
        return 'unreachable'
    try:
        with socket.create_connection(('169.254.169.254', 80), timeout=2) as sock:
            sock.sendall(b'PUT /latest/api/token HTTP/1.0\\r\\n'
                         b'X-aws-ec2-metadata-token-ttl-seconds: 60\\r\\n\\r\\n')
            body = sock.recv(256)
        return 'reachable' if body else 'reachable_no_hop_limit'
    except OSError:
        return 'reachable_no_hop_limit'

result['imds'] = imds_state()
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


class CredentialsProbe:
    probe_id = "credentials"

    def run(self, target: Target) -> ProbeOutcome:
        # Direct assignment, not setdefault: the environment inside the sandbox
        # belongs to the system under test, and a preset PROBE_* name there
        # must never be allowed to choose what this probe measures instead of
        # what the target actually specifies.
        payload = emit(
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
                    f"inner result was not a JSON object: {inner!r}",
                )],
                control_ok=False,
            )

        env_secrets = inner.get("env_secrets")
        if env_secrets is None:
            env_secrets = sorted(
                name for name, value in inner.get("env", {}).items()
                if looks_secret(name, value)
            )

        findings = []
        for name in env_secrets:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="env_secret",
                severity=Severity.HIGH,
                title="A credential is present in the sandbox environment",
                evidence=(
                    f"environment variable {name} holds a secret-shaped value. "
                    "The value is deliberately not reproduced here."
                ),
            ))
        for path in inner.get("readable_paths", []):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="credential_file",
                severity=Severity.HIGH,
                title="A credential file is readable from inside the sandbox",
                evidence=f"{path} was open for reading",
            ))

        imds = inner.get("imds", "unreachable")
        if imds.startswith("reachable"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="imds_reachable",
                severity=Severity.HIGH,
                title="The cloud metadata service is reachable from the sandbox",
                evidence=(
                    "169.254.169.254 accepted a connection. Instance role "
                    "credentials are reachable from inside the sandbox."
                ),
            ))
        if imds == "reachable_no_hop_limit":
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name, rule_key="imds_hop_limit",
                severity=Severity.HIGH,
                title="Metadata service hop limit is not enforced",
                evidence=(
                    "The metadata endpoint answered without requiring a session "
                    "token. A hop limit of 1 keeps a container off the metadata "
                    "service even when the host can reach it."
                ),
            ))

        return ProbeOutcome(findings=findings, control_ok=True)


register(CredentialsProbe())
