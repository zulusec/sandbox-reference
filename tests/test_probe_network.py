import json
import socket
import threading

from sandbox_probe.evidence import LIST_LIMIT
from sandbox_probe.inner import MARKER
from sandbox_probe.probes.network import PAYLOAD_BODY, NetworkProbe
from sandbox_probe.target import ExecResult, Target

# What a contained sandbox reports: the address literal was attempted and
# the route was denied, no name resolved, nothing answered. Every case below
# overrides only the keys it is about, so a case cannot pass by accident
# because some unrelated key happened to be missing.
_CONTAINED = {
    "blocked_endpoint": "denied",
    "blocked_host": "unresolved",
    "dns_canary": "unresolved",
    "c2": {"paste.invalid": "unresolved"},
    "control_reachable": True,
}


def _inner(**overrides) -> dict:
    return dict(_CONTAINED, **overrides)


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
    outcome = NetworkProbe().run(_target(_inner()))
    assert outcome.findings == []
    assert outcome.errors == []
    assert outcome.control_ok


# --- The address literal is the check that carries invariant 1.
#
# It needs no DNS, so there is no state of the world in which it fails to
# run and looks like containment. The name-based checks below are additions
# to it, never substitutes for it.

def test_a_reachable_address_literal_is_a_high_finding():
    """The regression this whole module exists for: a sandbox with a route
    off its own network, and no name in the question to muddy the answer."""
    outcome = NetworkProbe().run(_target(_inner(blocked_endpoint="connected")))
    assert "blocked_egress" in _rule_keys(outcome)
    assert outcome.findings[0].severity.value == "HIGH"
    assert "1.1.1.1:443" in outcome.findings[0].evidence


def test_a_denied_address_literal_is_a_measurement_not_an_omission():
    outcome = NetworkProbe().run(_target(_inner(blocked_endpoint="denied")))
    assert outcome.findings == []
    assert outcome.errors == []


def test_an_unattempted_address_literal_is_an_error_not_a_pass():
    """If the one check with no vacuous failure mode did not run, the run is
    incomplete. Silence from it is not containment."""
    outcome = NetworkProbe().run(_target(_inner(blocked_endpoint="unattempted")))
    assert outcome.errors
    assert outcome.errors[0].operation == "blocked_endpoint"
    assert outcome.findings == []


def test_a_missing_address_literal_result_is_an_error_not_a_pass():
    inner = _inner()
    del inner["blocked_endpoint"]
    outcome = NetworkProbe().run(_target(inner))
    assert outcome.errors
    assert outcome.errors[0].operation == "blocked_endpoint"


def test_an_address_literal_that_needed_dns_is_an_error_not_a_pass():
    """'unresolved' from the literal check means something put a name in
    front of it. That is the defect this key closes, so it must never be
    read as a denied route."""
    outcome = NetworkProbe().run(_target(_inner(blocked_endpoint="unresolved")))
    assert outcome.errors
    assert outcome.findings == []


# --- Name-based checks report why they did not fire.

def test_a_reachable_blocked_host_is_a_high_finding():
    outcome = NetworkProbe().run(_target(_inner(blocked_host="connected")))
    assert "blocked_egress" in _rule_keys(outcome)
    assert "blocked.invalid" in outcome.findings[0].evidence


def test_an_unresolved_blocked_host_is_not_a_finding_and_not_an_error():
    """An unresolvable name measures nothing, so it produces no finding. It
    is also not an error, because the address-literal check above already
    answered the question this one would have asked, and it answered it
    without DNS. Remove that check and this branch becomes the hole again."""
    outcome = NetworkProbe().run(_target(_inner(blocked_host="unresolved")))
    assert outcome.findings == []
    assert outcome.errors == []


def test_a_denied_blocked_host_is_not_a_finding():
    outcome = NetworkProbe().run(_target(_inner(blocked_host="denied")))
    assert outcome.findings == []


def test_dns_resolution_is_its_own_finding():
    """DNS is the exfiltration path an HTTP allowlist does not see."""
    outcome = NetworkProbe().run(_target(_inner(dns_canary="resolved")))
    assert "dns_canary" in _rule_keys(outcome)
    assert "example.com" in outcome.findings[0].evidence


def test_an_unresolved_dns_canary_is_not_a_finding():
    outcome = NetworkProbe().run(_target(_inner(dns_canary="unresolved")))
    assert outcome.findings == []


def test_the_dns_canary_is_not_derived_from_the_blocked_host():
    """It used to be canary.<blocked_host>, which cannot resolve when the
    blocked host is a reserved name, so the check could never fire against
    the reference target no matter how open the sandbox was."""
    sent: list = []
    NetworkProbe().run(_target(_inner(), sent=sent))
    payload = sent[0][0]
    assert "canary." not in payload
    assert "PROBE_DNS_CANARY_HOST'] = 'example.com'" in payload


def test_each_reachable_c2_class_is_reported_separately():
    outcome = NetworkProbe().run(_target(_inner(c2={"paste.invalid": "connected"})))
    findings = [f for f in outcome.findings if f.rule_key == "c2_channel"]
    assert len(findings) == 1
    assert "paste.invalid" in findings[0].evidence


def test_an_unresolved_c2_host_is_not_a_finding():
    outcome = NetworkProbe().run(_target(_inner(c2={"paste.invalid": "unresolved"})))
    assert outcome.findings == []


def test_unreachable_control_fails_the_positive_control():
    """No egress at all looks identical to perfect containment. It is not."""
    outcome = NetworkProbe().run(_target(_inner(control_reachable=False)))
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

    Without the returncode and stderr folded in, every unparseable-output
    cause collapses into 'inner payload produced no marked result line',
    discarding what Target.run_inside already captured for exactly this
    situation (see target.py's timeout and exec-failure branches).
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
    """parse_inner returns whatever json.loads produced.

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


# --- The positive control is proxy-aware, not direct-reachability-only.
#
# In a correctly contained sandbox (like the reference target) nothing is
# directly reachable, so the control has to go through the egress broker
# instead. These three tests cover each branch of that redefinition: a
# proxy configured and satisfied, a proxy configured and unreachable, and
# the no-proxy fallback used by targets (like the leaky fixture) that have
# no broker in front of them.

def test_proxy_configured_and_control_satisfied():
    sent: list = []
    outcome = NetworkProbe().run(_target(_inner(), proxy="broker:3128", sent=sent))
    assert outcome.control_ok
    payload = sent[0][0]
    assert "PROBE_PROXY'] = 'broker:3128'" in payload


def test_proxy_configured_and_proxy_unreachable():
    sent: list = []
    outcome = NetworkProbe().run(
        _target(_inner(control_reachable=False), proxy="broker:3128", sent=sent)
    )
    assert not outcome.control_ok
    payload = sent[0][0]
    assert "PROBE_PROXY'] = 'broker:3128'" in payload


def test_no_proxy_target_falls_back_to_direct_reachability():
    sent: list = []
    outcome = NetworkProbe().run(_target(_inner(), proxy=None, sent=sent))
    assert outcome.control_ok
    payload = sent[0][0]
    # No proxy configured: the env var must not carry the string "None",
    # which would be truthy inside the sandbox and wrongly select the
    # proxy branch of the inner control logic.
    assert "PROBE_PROXY'] = ''" in payload


def test_probe_env_vars_use_direct_assignment_not_setdefault():
    """The sandbox's own environment must never choose what is measured.

    A preset PROBE_PROXY is the worst case: it would flip a no-proxy target
    onto the (trivially satisfiable) proxy control branch. setdefault lets
    that happen; direct assignment does not.
    """
    sent: list = []
    NetworkProbe().run(_target(_inner(), proxy="broker:3128", sent=sent))
    payload = sent[0][0]
    assert "setdefault" not in payload
    for var in (
        "PROBE_BLOCKED_HOST", "PROBE_BLOCKED_ENDPOINT", "PROBE_DNS_CANARY_HOST",
        "PROBE_ALLOWED_HOST", "PROBE_C2_HOSTS", "PROBE_PROXY",
    ):
        assert f"os.environ['{var}'] = " in payload


# --- The inner payload's own logic.
#
# PAYLOAD_BODY is a module-level string by design, so its function
# definitions (everything above the environment-variable reads at the
# bottom) can be exec'd directly and exercised against a real loopback
# socket, stdlib only, no sandbox and no Docker required. This is the only
# way to prove reachable, proxy_allows and parse_host_port actually do what
# the probe requires, rather than just checking that the right strings
# landed in an env var.

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


def _closed_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens here now: the connection is refused
    return port


def test_reachable_separates_a_denied_route_from_a_name_that_does_not_exist():
    """The defect, at the line where it lived. Catching OSError and
    returning False made 'the route was refused' and 'the name does not
    exist' the same answer, and the second one is not a measurement."""
    functions = _load_payload_functions()
    port, _received, thread = _serve_once(b"")
    assert functions["reachable"]("127.0.0.1", port) == "connected"
    thread.join(timeout=3)
    assert functions["reachable"]("127.0.0.1", _closed_port()) == "denied"
    assert functions["reachable"]("nothing-here.invalid", 80) == "unresolved"


def test_resolves_reports_resolved_or_unresolved():
    functions = _load_payload_functions()
    assert functions["resolves"]("localhost") == "resolved"
    assert functions["resolves"]("nothing-here.invalid") == "unresolved"


def test_the_literal_check_reports_unattempted_for_a_value_it_cannot_parse():
    """A malformed endpoint must not read as a denied route. The config
    validator refuses these, so reaching here means something else went
    wrong, and something else going wrong is not containment."""
    functions = _load_payload_functions()
    assert functions["endpoint_status"]("1.1.1.1") == "unattempted"
    assert functions["endpoint_status"]("") == "unattempted"


def test_the_literal_check_connects_without_resolving_a_name():
    functions = _load_payload_functions()
    port, _received, thread = _serve_once(b"")
    assert functions["endpoint_status"](f"127.0.0.1:{port}") == "connected"
    thread.join(timeout=3)
    assert functions["endpoint_status"](f"127.0.0.1:{_closed_port()}") == "denied"


def test_proxy_allows_accepts_a_502_and_sends_absolute_uri_form():
    functions = _load_payload_functions()
    port, received, thread = _serve_once(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    result = functions["proxy_allows"](f"127.0.0.1:{port}", "allowed.invalid")
    thread.join(timeout=3)
    assert result is True
    # Pins the absolute-URI requirement: origin form ('GET / HTTP/1.0' with a
    # Host header) is the exact regression this bans, because it makes the
    # reference broker log the path as the hostname.
    assert received[0].startswith(b"GET http://allowed.invalid/ HTTP/1.0")


def test_proxy_allows_rejects_a_403():
    functions = _load_payload_functions()
    port, _received, thread = _serve_once(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    result = functions["proxy_allows"](f"127.0.0.1:{port}", "blocked.invalid")
    thread.join(timeout=3)
    assert result is False


def test_proxy_allows_fails_closed_on_an_unreachable_port():
    functions = _load_payload_functions()
    assert functions["proxy_allows"](f"127.0.0.1:{_closed_port()}", "allowed.invalid") is False


def test_proxy_allows_fails_closed_on_a_malformed_proxy_value():
    """A config typo must fail closed inside proxy_allows, not raise past
    it and discard every other measurement this payload took."""
    functions = _load_payload_functions()
    assert functions["proxy_allows"]("broker:abc", "allowed.invalid") is False
    assert functions["proxy_allows"]("broker", "allowed.invalid") is False


def test_parse_host_port_strips_ipv6_brackets_like_the_broker_does():
    functions = _load_payload_functions()
    assert functions["parse_host_port"]("[::1]:3128") == ("::1", 3128)
    assert functions["parse_host_port"]("broker:3128") == ("broker", 3128)


# --- The target does not choose which hosts appear in the report.
#
# The harness put PROBE_C2_HOSTS into the payload, so the harness decides
# which of them count as answers. A host that was never asked about cannot
# be a measurement of anything, and rendering it would let the system under
# test write text of its own choosing straight to an operator's terminal.

_FORGERY = "\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_a_c2_host_nobody_asked_about_is_not_reported():
    outcome = NetworkProbe().run(_target(_inner(c2={
        "invented.invalid": "connected", "paste.invalid": "connected",
    })))
    findings = [f for f in outcome.findings if f.rule_key == "c2_channel"]
    assert len(findings) == 1
    assert "paste.invalid" in findings[0].evidence


def test_a_forged_c2_host_never_reaches_the_terminal():
    outcome = NetworkProbe().run(_target(_inner(c2={_FORGERY: "connected"})))
    assert outcome.findings == []


def test_a_non_mapping_c2_result_is_not_walked_character_by_character():
    """A string here would otherwise produce one finding per character."""
    outcome = NetworkProbe().run(_target(_inner(c2="paste.invalid")))
    assert outcome.findings == []


def test_c2_findings_follow_the_configs_order_not_the_targets():
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        c2_hosts=["a.invalid", "b.invalid", "c.invalid"],
    )
    payload = f"{MARKER} " + json.dumps(_inner(c2={
        "c.invalid": "connected", "a.invalid": "connected", "b.invalid": "connected",
    })) + "\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = NetworkProbe().run(target)
    evidence = [f.evidence for f in outcome.findings]
    assert len(evidence) == 3
    assert "a.invalid" in evidence[0]
    assert "b.invalid" in evidence[1]
    assert "c.invalid" in evidence[2]


def test_a_huge_c2_list_is_bounded_and_the_remainder_is_counted():
    """20000 findings from one JSON object is a denial of service against
    whoever is reading the report. The remainder is a count, not a drop."""
    hosts = [f"c2-{n:05d}.invalid" for n in range(200)]
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        c2_hosts=hosts,
    )
    payload = f"{MARKER} " + json.dumps(_inner(
        c2={host: "connected" for host in hosts},
    )) + "\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = NetworkProbe().run(target)
    assert len(outcome.findings) == LIST_LIMIT + 1
    assert str(200 - LIST_LIMIT) in outcome.findings[-1].evidence
