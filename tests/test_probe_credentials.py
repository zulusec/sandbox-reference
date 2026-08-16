import json

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.credentials import CredentialsProbe, looks_secret
from sandbox_probe.target import ExecResult, Target


def _target(inner: dict):
    target = Target(name="t", exec_command=["true"],
                    allowed_host="a.invalid", blocked_host="b.invalid")
    payload = f"{MARKER} {json.dumps(inner)}\n"
    object.__setattr__(target, "run_inside",
                       lambda argv, timeout: ExecResult(0, payload, ""))
    return target


_CLEAN = {"env_secrets": [], "readable_paths": [], "imds": "unreachable"}


def test_known_key_prefix_is_secret():
    assert looks_secret("SOME_VAR", "AKIAIOSFODNN7EXAMPLE")


def test_high_entropy_value_in_a_suggestive_name_is_secret():
    assert looks_secret("DATABASE_PASSWORD", "S8fj29dkQ1zLp0amXvTb")


def test_ordinary_config_is_not_secret():
    assert not looks_secret("LANG", "en_US.UTF-8")
    assert not looks_secret("PATH", "/usr/local/bin:/usr/bin:/bin")


def test_short_value_is_not_secret_even_in_a_suggestive_name():
    assert not looks_secret("API_TOKEN", "dev")


def test_clean_sandbox_produces_no_findings():
    assert CredentialsProbe().run(_target(_CLEAN)).findings == []


def test_env_secret_is_reported_by_name_not_by_value():
    outcome = CredentialsProbe().run(_target(
        dict(_CLEAN, env_secrets=["AWS_SECRET_ACCESS_KEY"])))
    finding = next(f for f in outcome.findings if f.rule_key == "env_secret")
    assert "AWS_SECRET_ACCESS_KEY" in finding.evidence


def test_readable_service_account_token_is_high():
    outcome = CredentialsProbe().run(_target(dict(
        _CLEAN, readable_paths=["/var/run/secrets/kubernetes.io/serviceaccount/token"])))
    finding = next(f for f in outcome.findings if f.rule_key == "credential_file")
    assert finding.severity.value == "HIGH"


def test_imds_token_blocked_is_reachable_only():
    """A hop limit of 1 lets the connection open but drops the token response.

    Renamed from the brief's 'reachable' fixture: the endpoint is routable
    but the token never came back, so only imds_reachable fires, not the
    hop-limit finding.
    """
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, imds="token_blocked")))
    keys = {f.rule_key for f in outcome.findings}
    assert keys == {"imds_reachable"}


def test_imds_token_obtained_adds_the_hop_limit_finding():
    """A token PUT response crossing the container's hop means the hop limit
    is not doing its job. Renamed from the brief's 'reachable_no_hop_limit'
    fixture, whose name described the opposite of this state: a body coming
    back is the insecure case, not its absence.
    """
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, imds="token_obtained")))
    keys = {f.rule_key for f in outcome.findings}
    assert keys == {"imds_reachable", "imds_hop_limit"}


def test_credential_probe_needs_no_positive_control():
    """Absence of secrets is directly observable, unlike absence of egress."""
    assert CredentialsProbe().run(_target(_CLEAN)).control_ok
