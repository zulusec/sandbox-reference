import json
import socket
import threading

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.network import PAYLOAD_BODY, NetworkProbe
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


def test_exec_failure_detail_includes_returncode_and_stderr():
    """A dead container and a timeout must not both read as the same mystery.

    Finding 4: previously every unparseable-output cause collapsed into
    'inner payload produced no marked result line', discarding the
    returncode and stderr Target.run_inside already captured for exactly
    this situation (see target.py's timeout and exec-failure branches).
    """
    target = _target({})
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(124, "", "timed out after 60s"),
    )
    outcome = NetworkProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "124" in detail
    assert "timed out after 60s" in detail


def test_non_dict_inner_result_is_an_error_not_a_crash():
    """Finding 5: parse_inner returns whatever json.loads produced.

    A marked line carrying a JSON scalar must not raise AttributeError out
    of run(); it must become a ProbeError like any other protocol failure.
    """
    target = _target({})
    payload = f"{MARKER} 42\n"
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, payload, ""),
    )
    outcome = NetworkProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


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
    assert "PROBE_PROXY'] = 'broker:3128'" in payload


def test_proxy_configured_and_proxy_unreachable():
    sent: list = []
    outcome = NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": False,
    }, proxy="broker:3128", sent=sent))
    assert not outcome.control_ok
    payload = sent[0][0]
    assert "PROBE_PROXY'] = 'broker:3128'" in payload


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
    assert "PROBE_PROXY'] = ''" in payload


def test_probe_env_vars_use_direct_assignment_not_setdefault():
    """Finding 3: the sandbox's own environment must never choose what is measured.

    A preset PROBE_PROXY is the worst case: it would flip a no-proxy target
    onto the (trivially satisfiable) proxy control branch. setdefault lets
    that happen; direct assignment does not.
    """
    sent: list = []
    NetworkProbe().run(_target({
        "blocked_reachable": False, "dns_resolved": False,
        "c2_reachable": [], "control_reachable": True,
    }, proxy="broker:3128", sent=sent))
    payload = sent[0][0]
    assert "setdefault" not in payload
    for var in ("PROBE_BLOCKED_HOST", "PROBE_ALLOWED_HOST", "PROBE_C2_HOSTS", "PROBE_PROXY"):
        assert f"os.environ['{var}'] = " in payload


# --- Finding 1 and Finding 2: the inner proxy control logic itself.
#
# PAYLOAD_BODY is a module-level string by design, so its function
# definitions (everything above the environment-variable reads at the
# bottom) can be exec'd directly and exercised against a real loopback
# socket, stdlib only, no sandbox and no Docker required. This is the only
# way to prove proxy_allows and parse_proxy actually do what the amendment
# requires, rather than just checking that the right strings landed in an
# env var.

def _load_payload_functions():
    prefix, marker, _ = PAYLOAD_BODY.partition("\nblocked = os.environ")
    assert marker, "PAYLOAD_BODY layout changed; update the split point in this test"
    namespace: dict = {"socket": socket}
    exec(prefix, namespace)  # noqa: S102 -- exercising the payload's own source
    return namespace


def _serve_once(response: bytes):
    """Bind a loopback listener that replies once with `response`.

    Returns (port, received) where received[0] is filled in with whatever
    bytes the client sent, once the exchange completes.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received: list[bytes] = []

    def _accept():
        conn, _ = server.accept()
        with conn:
            conn.settimeout(3)
            try:
                received.append(conn.recv(4096))
            except OSError:
                received.append(b"")
            conn.sendall(response)
        server.close()

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    return port, received, thread


def test_proxy_allows_accepts_a_502_and_sends_absolute_uri_form():
    functions = _load_payload_functions()
    port, received, thread = _serve_once(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    result = functions["proxy_allows"](f"127.0.0.1:{port}", "allowed.invalid")
    thread.join(timeout=3)
    assert result is True
    # Pins the absolute-URI requirement: origin form ('GET / HTTP/1.0' with a
    # Host header) is the exact regression the amendment bans, because it
    # makes the reference broker log the path as the hostname.
    assert received[0].startswith(b"GET http://allowed.invalid/ HTTP/1.0")


def test_proxy_allows_rejects_a_403():
    functions = _load_payload_functions()
    port, _received, thread = _serve_once(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    result = functions["proxy_allows"](f"127.0.0.1:{port}", "blocked.invalid")
    thread.join(timeout=3)
    assert result is False


def test_proxy_allows_fails_closed_on_an_unreachable_port():
    functions = _load_payload_functions()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens here now: the connection is refused
    assert functions["proxy_allows"](f"127.0.0.1:{port}", "allowed.invalid") is False


def test_proxy_allows_fails_closed_on_a_malformed_proxy_value():
    """Reproduces the reviewer's finding exactly: a config typo must fail
    closed inside proxy_allows, not raise past it and discard every other
    measurement this payload took."""
    functions = _load_payload_functions()
    assert functions["proxy_allows"]("broker:abc", "allowed.invalid") is False
    assert functions["proxy_allows"]("broker", "allowed.invalid") is False


def test_parse_proxy_strips_ipv6_brackets_like_the_broker_does():
    functions = _load_payload_functions()
    assert functions["parse_proxy"]("[::1]:3128") == ("::1", 3128)
    assert functions["parse_proxy"]("broker:3128") == ("broker", 3128)
