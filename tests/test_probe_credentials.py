import json

from sandbox_probe.evidence import LIST_LIMIT
from sandbox_probe.inner import MARKER
from sandbox_probe.probes.credentials import (
    _CREDENTIAL_PATHS,
    CredentialsProbe,
    looks_secret,
)
from sandbox_probe.result import merge_outcomes
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

    The endpoint is routable but the token never came back, so only
    imds_reachable fires, not the hop-limit finding.
    """
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, imds="token_blocked")))
    keys = {f.rule_key for f in outcome.findings}
    assert keys == {"imds_reachable"}


def test_imds_token_obtained_adds_the_hop_limit_finding():
    """A token PUT response crossing the container's hop means the hop limit
    is not doing its job. A body coming back is the insecure case, not its
    absence, which is the opposite of what the state name suggests at first
    reading.
    """
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, imds="token_obtained")))
    keys = {f.rule_key for f in outcome.findings}
    assert keys == {"imds_reachable", "imds_hop_limit"}


def test_credential_probe_reports_its_control_as_absent_not_as_passed():
    """Absence of secrets is directly observable, unlike absence of egress,
    so this probe has no positive control. It says so rather than reporting
    a control that passed: a hardcoded True is a claim that the probe
    confirmed it was measuring something, and nothing here confirmed that.
    A reader has to be able to tell "no control needed" from "the control
    ran and held"."""
    outcome = CredentialsProbe().run(_target(_CLEAN))
    assert outcome.control_ok is None
    assert outcome.errors == []


def test_a_probe_with_no_control_does_not_fail_the_run():
    """Absent is not failed. This probe measures what it claims to measure;
    what it does not have is a separate check confirming the measurement
    was possible."""
    outcome = CredentialsProbe().run(_target(_CLEAN))
    report = merge_outcomes({"credentials": outcome})
    assert report.controls_absent == ["credentials"]
    assert report.controls_failed == []
    assert report.complete
    assert report.exit_code == 0


# --- inner comes from the system under test, and evidence goes to a
# terminal. Variable names are genuinely discovered inside the sandbox, so
# there is no harness-side list to check them against; they are cleaned and
# bounded instead. Credential paths are different: this probe sent the
# candidate list in, so a path that was never sent is not an answer.

_FORGERY = "\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_a_forged_variable_name_cannot_repaint_the_report():
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, env_secrets=[_FORGERY])))
    finding = next(f for f in outcome.findings if f.rule_key == "env_secret")
    assert "\x1b" not in finding.evidence
    assert "unprintable characters removed" in finding.evidence


def test_an_enormous_variable_name_is_truncated():
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, env_secrets=["A" * 20000])))
    finding = next(f for f in outcome.findings if f.rule_key == "env_secret")
    assert len(finding.evidence) < 400
    assert "truncated from 20000 characters" in finding.evidence


def test_a_huge_env_secret_list_is_bounded_and_the_remainder_is_counted():
    outcome = CredentialsProbe().run(_target(dict(
        _CLEAN, env_secrets=[f"SECRET_{n:05d}" for n in range(20000)])))
    findings = [f for f in outcome.findings if f.rule_key == "env_secret"]
    assert len(findings) == LIST_LIMIT + 1
    assert str(20000 - LIST_LIMIT) in findings[-1].evidence


def test_a_credential_path_the_probe_never_asked_about_is_not_reported():
    outcome = CredentialsProbe().run(_target(dict(
        _CLEAN, readable_paths=["/invented/path", _FORGERY])))
    assert [f for f in outcome.findings if f.rule_key == "credential_file"] == []


# --- Errors render to the same terminal findings do, and everything an
# error quotes came from the system under test too. stderr is the widest of
# those channels: the target chooses every byte of it.

def test_a_forged_stderr_cannot_repaint_the_report_through_an_error():
    target = _target(_CLEAN)
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(1, "", _FORGERY + "padding" * 900),
    )
    outcome = CredentialsProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_an_enormous_non_dict_inner_result_is_bounded():
    """parse_inner returns whatever json.loads produced. A 300,000 character
    string is a valid JSON document and must not become a 300,000 character
    error detail."""
    target = _target(_CLEAN)
    payload = f"{MARKER} {json.dumps('a' * 300000)}\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = CredentialsProbe().run(target)
    assert outcome.errors
    assert len(outcome.errors[0].detail) < 500
    assert not outcome.control_ok


def test_credential_paths_are_reported_in_the_harnesss_own_order():
    outcome = CredentialsProbe().run(_target(dict(
        _CLEAN, readable_paths=list(reversed(_CREDENTIAL_PATHS)))))
    reported = [f.evidence.split()[0] for f in outcome.findings
                if f.rule_key == "credential_file"]
    assert reported == list(_CREDENTIAL_PATHS)


# --- The result's shape is checked before anything is read out of it. Once
# parse_inner succeeds, every measurement below is an inner.get with a falsy
# default, so a key that never came back reads exactly like a key that came
# back negative. Only a check of the shape tells them apart.

def test_an_empty_result_is_an_error_not_a_clean_verdict():
    """`{}` used to produce zero findings, zero errors, and a passing
    control: a clean credentials verdict from a payload that measured
    nothing at all."""
    outcome = CredentialsProbe().run(_target({}))
    assert outcome.findings == []
    assert outcome.errors
    assert outcome.control_ok is False
    assert "env_secrets is missing" in outcome.errors[0].detail


def test_a_missing_imds_key_does_not_default_to_the_good_outcome():
    inner = {"env_secrets": [], "readable_paths": []}
    outcome = CredentialsProbe().run(_target(inner))
    assert outcome.errors
    assert outcome.control_ok is False
    assert "imds is missing" in outcome.errors[0].detail


def test_an_imds_state_this_probe_does_not_define_is_an_error():
    """A misspelling, a wrong case, or an invented fourth state used to fall
    through both branches and report nothing."""
    for bogus in ("TOKEN_OBTAINED", "reachable", ""):
        outcome = CredentialsProbe().run(_target(dict(_CLEAN, imds=bogus)))
        assert outcome.errors, bogus
        assert outcome.control_ok is False, bogus
        assert outcome.findings == [], bogus


def test_a_wrong_typed_secret_list_is_an_error_not_an_absence():
    outcome = CredentialsProbe().run(_target(dict(_CLEAN, env_secrets="AWS_SECRET")))
    assert outcome.errors
    assert outcome.control_ok is False
    assert outcome.findings == []
