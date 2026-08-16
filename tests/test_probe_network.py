import json

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.network import NetworkProbe
from sandbox_probe.target import ExecResult, Target


def _target(inner: dict, returncode: int = 0, proxy: str | None = None, sent: list | None = None):
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        c2_hosts=["paste.invalid"], proxy=proxy,
    )
    payload = f"{MARKER} {json.dumps(inner)}\n"

    def run_inside(argv, timeout):
        if sent is not None:
            sent.append(argv)
        return ExecResult(returncode, payload, "")

    object.__setattr__(target, "run_inside", run_inside)
    return target


def _rule_keys(outcome):
    return {finding.rule_key for finding in outcome.findings}


def test_contained_sandbox_produces_no_findings():
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": True,
    }))
    assert outcome.findings == []
    assert outcome.control_ok


def test_reachable_blocked_host_is_a_high_finding():
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": True, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": True,
    }))
    assert "blocked_egress" in _rule_keys(outcome)
    assert outcome.findings[0].severity.value == "HIGH"


def test_dns_resolution_is_its_own_finding():
    """DNS is the exfiltration path an HTTP allowlist does not see."""
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": True,
        "c2_reachable": [], "control_reachable": True,
    }))
    assert "dns_canary" in _rule_keys(outcome)


def test_each_reachable_c2_class_is_reported_separately():
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": ["paste.invalid"], "control_reachable": True,
    }))
    findings = [f for f in outcome.findings if f.rule_key == "c2_channel"]
    assert len(findings) == 1
    assert "paste.invalid" in findings[0].evidence


def test_unreachable_control_fails_the_positive_control():
    """No egress at all looks identical to perfect containment. It is not."""
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": False,
    }))
    assert not outcome.control_ok


def test_unparseable_inner_output_is_an_error_not_a_pass():
    target = _target({})
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, "garbage", ""),
    )
    outcome = NetworkProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok


# --- Amendment: the positive control is proxy-aware, not direct-reachability-only.
#
# In a correctly contained sandbox (like the reference target) nothing is
# directly reachable, so the control has to go through the egress broker
# instead. These three tests cover each branch of that redefinition: a
# proxy configured and satisfied, a proxy configured and unreachable, and
# the no-proxy fallback used by targets (like the leaky fixture) that have
# no broker in front of them.

def test_proxy_configured_and_control_satisfied():
    sent: list = []
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": True,
    }, proxy="broker:3128", sent=sent))
    assert outcome.control_ok
    payload = sent[0][0]
    assert "PROBE_PROXY', 'broker:3128'" in payload


def test_proxy_configured_and_proxy_unreachable():
    sent: list = []
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": False,
    }, proxy="broker:3128", sent=sent))
    assert not outcome.control_ok
    payload = sent[0][0]
    assert "PROBE_PROXY', 'broker:3128'" in payload


def test_no_proxy_target_falls_back_to_direct_reachability():
    sent: list = []
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": True,
    }, proxy=None, sent=sent))
    assert outcome.control_ok
    payload = sent[0][0]
    # No proxy configured: the env var must not carry the string "None",
    # which would be truthy inside the sandbox and wrongly select the
    # proxy branch of the inner control logic.
    assert "PROBE_PROXY', ''" in payload
