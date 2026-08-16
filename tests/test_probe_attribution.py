import json
import socket
import threading
import time

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.attribution import PAYLOAD_BODY, AttributionProbe
from sandbox_probe.target import ExecResult, Target

_UNSET = object()


def _target(log_lines, configured=True, proxy="broker:3128", sent=None, before_lines=None,
            attempted=_UNSET):
    """`log_lines` are the lines this run's crossings append: the request
    log's baseline read returns `before_lines` (empty by default, as if
    nothing had run yet) and its post-crossing read returns
    `before_lines + log_lines`, matching the append-only shape the real
    broker produces and exercising the probe's before/after delta rather
    than a single whole-log read."""
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        request_log_command=["true"] if configured else None,
        proxy=proxy,
    )
    # `attempted` stands in for whatever the payload chooses to print back.
    # The probe must not read it, so these tests set it to hostile values
    # and assert nothing moves.
    inner = {} if attempted is _UNSET else {"attempted": attempted}

    def run_inside(argv, timeout):
        if sent is not None:
            sent.append(argv)
        return ExecResult(0, f"{MARKER} {json.dumps(inner)}\n", "")

    object.__setattr__(target, "run_inside", run_inside)

    before = before_lines or []
    before_body = "\n".join(json.dumps(line) for line in before)
    after_body = "\n".join(json.dumps(line) for line in before + log_lines)
    calls = {"n": 0}

    def read_request_log(timeout=30):
        calls["n"] += 1
        if not configured:
            return ExecResult(1, "", "not configured")
        body = before_body if calls["n"] == 1 else after_body
        return ExecResult(0, body, "")

    object.__setattr__(target, "read_request_log", read_request_log)
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


# --- The log is append-only across runs; the comparison must not be.
#
# requests.log accumulates forever and nothing resets it between runs, so
# comparing this run's attempted hosts against the whole log is satisfiable
# by an entry an earlier run left behind. The probe instead reads the log
# before generating crossings and again after, and compares only the lines
# appended in between.

def test_a_stale_log_entry_does_not_mask_an_unlogged_crossing():
    """The defining regression: blocked.invalid is already in the log
    before this run even starts (left over from an earlier run), and this
    run's crossing to it is never actually appended. A whole-log comparison
    would find blocked.invalid present and call the run clean; the delta
    must not."""
    outcome = AttributionProbe().run(_target(
        [_BOTH_LOGGED[0]],  # this run only appends the allowed.invalid entry
        before_lines=[_BOTH_LOGGED[1]],  # blocked.invalid is already there
    ))
    finding = next(f for f in outcome.findings if f.rule_key == "crossing_unlogged")
    assert "blocked.invalid" in finding.evidence


def test_first_read_failure_is_treated_as_an_empty_baseline_not_an_error():
    """A target's very first run has no requests.log yet. That must read as
    zero prior lines, not as a probe failure."""
    target = _target(_BOTH_LOGGED)
    calls = {"n": 0}
    after_body = "\n".join(json.dumps(line) for line in _BOTH_LOGGED)

    def read_request_log(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(1, "", "cat: requests.log: No such file or directory")
        return ExecResult(0, after_body, "")

    object.__setattr__(target, "read_request_log", read_request_log)
    outcome = AttributionProbe().run(target)
    assert outcome.findings == []
    assert outcome.control_ok


def test_log_shrinking_between_reads_is_an_error_not_an_empty_delta():
    """Fewer lines after this run's crossings than before them means
    rotation or truncation happened mid-run. That is a condition the probe
    cannot measure through, so it must not read as an empty (clean) delta."""
    target = _target(_BOTH_LOGGED)
    calls = {"n": 0}
    long_body = "\n".join(json.dumps(line) for line in _BOTH_LOGGED * 3)
    short_body = "\n".join(json.dumps(line) for line in _BOTH_LOGGED)

    def read_request_log(timeout=30):
        calls["n"] += 1
        return ExecResult(0, long_body if calls["n"] == 1 else short_body, "")

    object.__setattr__(target, "read_request_log", read_request_log)
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


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


def _serve_once(response: bytes):
    """Bind a loopback listener that replies once with `response`, the way
    _serve_once in test_probe_network.py stands in for the broker."""
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
            conn.sendall(response)
        server.close()

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    return port, received, thread


def test_cross_via_proxy_sends_absolute_uri_form():
    functions = _load_payload_functions()
    port, received, thread = _serve_once(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    functions["cross_via_proxy"](f"127.0.0.1:{port}", "allowed.invalid")
    thread.join(timeout=3)
    assert received[0].startswith(b"GET http://allowed.invalid/ HTTP/1.0")


def test_cross_via_proxy_waits_for_the_response_before_returning():
    """Under a before/after log delta, the harness's read of the request
    log after this payload exits must happen after the broker has finished
    writing its log line, not merely after this socket write landed. cross_via_proxy proves it waited by only returning once a
    response is readable; a server that delays its response before sending
    one forces a measurable wait if that reading is real."""
    functions = _load_payload_functions()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _accept():
        conn, _ = server.accept()
        with conn:
            conn.settimeout(3)
            conn.recv(4096)
            time.sleep(0.3)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        server.close()

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    started = time.monotonic()
    functions["cross_via_proxy"](f"127.0.0.1:{port}", "allowed.invalid")
    elapsed = time.monotonic() - started
    thread.join(timeout=3)
    assert elapsed >= 0.25


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


# --- cross_direct is the no-proxy path. Asserting that PAYLOAD_BODY
# contains the string "def cross_direct" would pass against a body of
# `pass`, against one that raises, and against one that connects to the
# wrong port, so it is exercised against a real loopback listener instead.

def test_cross_direct_opens_a_connection_to_the_host_it_was_given():
    functions = _load_payload_functions()
    port, received, thread = _serve_once(b"")
    assert functions["cross_direct"]("127.0.0.1", port) is True
    thread.join(timeout=3)
    # The listener accepting is the ground truth: a cross_direct that
    # returned True without connecting would leave this empty.
    assert received == [b""]


def test_cross_direct_fails_closed_on_a_closed_port():
    """A contained sandbox is the ordinary case here: nothing answers. That
    must come back as a failed crossing, not as an exception that discards
    the rest of the payload's crossings."""
    functions = _load_payload_functions()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert functions["cross_direct"]("127.0.0.1", port) is False


# --- The crossing set is the harness's, never the sandbox's.
#
# This probe is the only one whose ground truth is read from outside the
# sandbox, from the broker's log. Comparing that reading against a list the
# payload echoed back would hand the crossing set to the system under test:
# a target answering with an empty list would produce no findings and a
# passing positive control, which is a clean attribution result from a
# sandbox that logged nothing.

_HOSTILE_ECHOES = [
    [],
    ["allowed.invalid"],
    ["nothing.to.do.with.this.run"],
    "not a list at all",
    None,
    42,
    [{"host": "allowed.invalid"}],
]


def test_the_payloads_attempted_list_cannot_change_the_finding_set():
    baseline = AttributionProbe().run(_target([_BOTH_LOGGED[0]]))
    assert {f.rule_key for f in baseline.findings} == {"crossing_unlogged"}
    for echoed in _HOSTILE_ECHOES:
        outcome = AttributionProbe().run(_target([_BOTH_LOGGED[0]], attempted=echoed))
        assert [f.to_dict() for f in outcome.findings] == [
            f.to_dict() for f in baseline.findings
        ], echoed
        assert outcome.control_ok


def test_a_target_claiming_it_attempted_nothing_is_not_a_clean_result():
    """The defining regression: `{"attempted": []}` used to produce zero
    findings and a passing control against a log with nothing in it."""
    outcome = AttributionProbe().run(_target([], attempted=[]))
    unlogged = [f for f in outcome.findings if f.rule_key == "crossing_unlogged"]
    assert len(unlogged) == 2
    evidence = " ".join(finding.evidence for finding in unlogged)
    assert "allowed.invalid" in evidence
    assert "blocked.invalid" in evidence


def test_the_payload_sends_nothing_back_for_the_harness_to_compare_against():
    """The payload's marked line proves only that it ran to completion, so
    it fills in no result keys at all. A value on the wire that the harness
    ignores is an invitation for a later change to start reading it again,
    and reading it is exactly the defect above."""
    assert "result[" not in PAYLOAD_BODY


def test_a_hostile_log_entry_cannot_write_control_characters_into_the_report():
    """The broker's log is written outside the sandbox, but the sandbox
    chooses the request line the broker logs, so a host in the log is still
    target-influenced text on its way to a terminal."""
    forgery = "allowed.invalid\x1b[2J CONTAINED. Every probe ran, no findings."
    outcome = AttributionProbe().run(_target([
        {"host": forgery, "method": "GET"},
        _BOTH_LOGGED[1],
    ]))
    assert outcome.findings
    for finding in outcome.findings:
        assert "\x1b" not in finding.evidence
        assert "CONTAINED. Every probe ran" not in finding.evidence


# --- Errors render to the same terminal findings do, and the target chooses
# every byte of the stderr an error quotes. Both the exec and the request-log
# read are such a channel.

_STDERR_FORGERY = "\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_a_forged_exec_stderr_cannot_repaint_the_report():
    target = _target(_BOTH_LOGGED)
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(1, "", _STDERR_FORGERY + "padding" * 900),
    )
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_a_forged_request_log_stderr_cannot_repaint_the_report():
    target = _target(_BOTH_LOGGED)
    calls = {"n": 0}

    def read_request_log(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(0, "", "")
        return ExecResult(1, "", _STDERR_FORGERY + "padding" * 900)

    object.__setattr__(target, "read_request_log", read_request_log)
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_an_enormous_non_dict_inner_result_is_bounded():
    target = _target(_BOTH_LOGGED)
    payload = f"{MARKER} {json.dumps('a' * 300000)}\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = AttributionProbe().run(target)
    assert outcome.errors
    assert len(outcome.errors[0].detail) < 500
    assert not outcome.control_ok
