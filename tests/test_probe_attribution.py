import json
import socket
import threading

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.attribution import PAYLOAD_BODY, AttributionProbe
from sandbox_probe.target import ExecResult, Target


def _target(log_lines, configured=True, proxy="broker:3128", sent=None):
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        request_log_command=["true"] if configured else None,
        proxy=proxy,
    )
    inner = {"attempted": ["allowed.invalid", "blocked.invalid"]}

    def run_inside(argv, timeout):
        if sent is not None:
            sent.append(argv)
        return ExecResult(0, f"{MARKER} {json.dumps(inner)}\n", "")

    object.__setattr__(target, "run_inside", run_inside)
    body = "\n".join(json.dumps(line) for line in log_lines)
    object.__setattr__(
        target, "read_request_log",
        lambda timeout=30: ExecResult(0 if configured else 1, body,
                                      "" if configured else "not configured"),
    )
    return target


_BOTH_LOGGED = [
    {"host": "allowed.invalid", "method": "GET", "decision": "allow"},
    {"host": "blocked.invalid", "method": "GET", "decision": "deny"},
]


def _keys(outcome):
    return {f.rule_key for f in outcome.findings}


def test_fully_logged_run_is_clean():
    outcome = AttributionProbe().run(_target(_BOTH_LOGGED))
    assert outcome.findings == []
    assert outcome.control_ok


def test_missing_request_log_command_is_a_high_finding():
    outcome = AttributionProbe().run(_target([], configured=False))
    assert "no_request_log" in _keys(outcome)
    assert not outcome.control_ok


def test_an_unlogged_crossing_is_a_finding_naming_the_host():
    outcome = AttributionProbe().run(_target([_BOTH_LOGGED[0]]))
    finding = next(f for f in outcome.findings if f.rule_key == "crossing_unlogged")
    assert "blocked.invalid" in finding.evidence


def test_a_log_entry_without_a_decision_is_a_finding():
    outcome = AttributionProbe().run(_target([
        {"host": "allowed.invalid", "method": "GET"},
        _BOTH_LOGGED[1],
    ]))
    assert "decision_missing" in _keys(outcome)


def test_read_request_log_failure_is_an_error_not_a_pass():
    """A configured command that fails at run time (broker container down,
    permission error) must not read as a clean result just because the
    target declared a request_log_command at all."""
    target = _target(_BOTH_LOGGED)
    object.__setattr__(
        target, "read_request_log",
        lambda timeout=30: ExecResult(1, "", "no such container"),
    )
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert "no such container" in outcome.errors[0].detail


def test_unparseable_inner_output_is_an_error_not_a_pass():
    target = _target(_BOTH_LOGGED)
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, "garbage", ""),
    )
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


def test_exec_failure_detail_includes_returncode_and_stderr():
    target = _target(_BOTH_LOGGED)
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(124, "", "timed out after 60s"),
    )
    outcome = AttributionProbe().run(target)
    detail = outcome.errors[0].detail
    assert "124" in detail
    assert "timed out after 60s" in detail


def test_non_dict_inner_result_is_an_error_not_a_crash():
    target = _target(_BOTH_LOGGED)
    payload = f"{MARKER} 42\n"
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, payload, ""),
    )
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


# --- The crossings must actually traverse the broker.
#
# A raw TCP connect to allowed_host or blocked_host never reaches the
# broker in the reference sandbox (there is no route to anything else), so
# it produces no request-log entry even when containment is working
# correctly. The payload instead issues an HTTP request in absolute-URI
# form through target.proxy, the same shape network.py's positive control
# already uses, so there is genuinely something for the broker to log.

def test_probe_env_vars_use_direct_assignment_not_setdefault():
    sent = []
    AttributionProbe().run(_target(_BOTH_LOGGED, sent=sent))
    payload = sent[0][0]
    assert "setdefault" not in payload
    for var in ("PROBE_CROSSING_HOSTS", "PROBE_PROXY"):
        assert f"os.environ['{var}'] = " in payload


def test_crossing_hosts_and_proxy_reach_the_payload():
    sent = []
    AttributionProbe().run(_target(_BOTH_LOGGED, proxy="broker:3128", sent=sent))
    payload = sent[0][0]
    assert "PROBE_PROXY'] = 'broker:3128'" in payload
    assert "allowed.invalid" in payload
    assert "blocked.invalid" in payload


def test_no_proxy_target_does_not_carry_the_string_none():
    sent = []
    AttributionProbe().run(_target(_BOTH_LOGGED, proxy=None, sent=sent))
    payload = sent[0][0]
    assert "PROBE_PROXY'] = ''" in payload


def _load_payload_functions():
    prefix, marker, _ = PAYLOAD_BODY.partition("\nhosts = json.loads")
    assert marker, "PAYLOAD_BODY layout changed; update the split point in this test"
    namespace = {"socket": socket}
    exec(prefix, namespace)  # noqa: S102 -- exercising the payload's own source
    return namespace


def _serve_once():
    """Bind a loopback listener that accepts one connection and records what
    it received, without sending a reply (the payload does not read one)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = []

    def _accept():
        conn, _ = server.accept()
        with conn:
            conn.settimeout(3)
            try:
                received.append(conn.recv(4096))
            except OSError:
                received.append(b"")
        server.close()

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    return port, received, thread


def test_cross_via_proxy_sends_absolute_uri_form():
    functions = _load_payload_functions()
    port, received, thread = _serve_once()
    functions["cross_via_proxy"](f"127.0.0.1:{port}", "allowed.invalid")
    thread.join(timeout=3)
    assert received[0].startswith(b"GET http://allowed.invalid/ HTTP/1.0")


def test_cross_via_proxy_fails_closed_on_an_unreachable_proxy():
    functions = _load_payload_functions()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    functions["cross_via_proxy"](f"127.0.0.1:{port}", "allowed.invalid")  # must not raise


def test_cross_via_proxy_fails_closed_on_a_malformed_proxy_value():
    functions = _load_payload_functions()
    functions["cross_via_proxy"]("broker", "allowed.invalid")  # must not raise
