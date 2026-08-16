import json

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.detection import PAYLOAD_BODY, DetectionProbe
from sandbox_probe.target import ExecResult, Target

_ALLOW_ENTRY = {"host": "allowed.invalid", "method": "GET", "decision": "allow"}
_DENY_ENTRY = {"host": "blocked.invalid", "method": "GET", "decision": "deny"}
_ALERT = {"severity": "HIGH", "event": "egress_denied", "host": "blocked.invalid"}

_BOTH_LOGGED = [_ALLOW_ENTRY, _DENY_ENTRY]


def _target(
    events_delta,
    configured=True,
    request_delta=None,
    before_events=None,
    before_request=None,
    request_configured=True,
    proxy="broker:3128",
    sent=None,
):
    """`events_delta`/`request_delta` are the lines this run's crossings
    append to each channel. `before_events`/`before_request` are lines
    already present before this run starts, standing in for whatever an
    earlier run left behind. The event channel's baseline read returns
    `before_events` and its post-violation read returns
    `before_events + events_delta`; the request log works the same way.
    This mirrors requests.log's append-only shape and exercises the
    probe's before/after delta rather than a whole-file read."""
    target = Target(
        name="t", exec_command=["true"],
        allowed_host="allowed.invalid", blocked_host="blocked.invalid",
        events_command=["true"] if configured else None,
        request_log_command=["true"] if request_configured else None,
        proxy=proxy,
    )
    # The real payload's result dict carries no fields; its marked line
    # existing at all is what proves the crossing loop ran to completion.
    inner = {}

    def run_inside(argv, timeout):
        if sent is not None:
            sent.append(argv)
        return ExecResult(0, f"{MARKER} {json.dumps(inner)}\n", "")

    object.__setattr__(target, "run_inside", run_inside)

    before_events = before_events or []
    events_body_before = "\n".join(json.dumps(e) for e in before_events)
    events_body_after = "\n".join(json.dumps(e) for e in before_events + events_delta)
    events_calls = {"n": 0}

    def read_events(timeout=30):
        events_calls["n"] += 1
        if not configured:
            return ExecResult(1, "", "not configured")
        body = events_body_before if events_calls["n"] == 1 else events_body_after
        return ExecResult(0, body, "")

    object.__setattr__(target, "read_events", read_events)

    request_delta = request_delta if request_delta is not None else list(_BOTH_LOGGED)
    before_request = before_request or []
    request_body_before = "\n".join(json.dumps(e) for e in before_request)
    request_body_after = "\n".join(json.dumps(e) for e in before_request + request_delta)
    request_calls = {"n": 0}

    def read_request_log(timeout=30):
        request_calls["n"] += 1
        if not request_configured:
            return ExecResult(1, "", "not configured")
        body = request_body_before if request_calls["n"] == 1 else request_body_after
        return ExecResult(0, body, "")

    object.__setattr__(target, "read_request_log", read_request_log)
    return target


def _keys(outcome):
    return {f.rule_key for f in outcome.findings}


# --- Core behavior


def test_alerted_violation_is_clean():
    outcome = DetectionProbe().run(_target([_ALERT]))
    assert outcome.findings == []
    assert outcome.control_ok


def test_no_event_channel_is_a_high_finding():
    outcome = DetectionProbe().run(_target([], configured=False))
    assert "no_event_channel" in _keys(outcome)
    assert not outcome.control_ok


def test_violation_with_no_matching_event_is_a_finding():
    """Logging succeeded and alerting failed. This is the July 2026 gap."""
    outcome = DetectionProbe().run(_target([]))
    assert "violation_unalerted" in _keys(outcome)


def test_understated_severity_is_a_finding():
    outcome = DetectionProbe().run(_target([dict(_ALERT, severity="LOW")]))
    assert "severity_understated" in _keys(outcome)


# --- channel_not_separated, reformulated for delta comparison (Amendment 2)
#
# The event channel should carry violations only. This run generates both
# an allowed and a denied crossing; if the request log shows both went
# through and the event channel also carries an entry for the allowed one,
# the channel is not distinguishing violations from ordinary traffic.

def test_event_channel_carrying_the_allowed_request_is_a_finding():
    entries = [_ALERT, {"host": "allowed.invalid", "decision": "allow"}]
    outcome = DetectionProbe().run(_target(entries, request_delta=_BOTH_LOGGED))
    assert "channel_not_separated" in _keys(outcome)


def test_event_channel_with_only_the_denial_is_not_flagged():
    outcome = DetectionProbe().run(_target([_ALERT], request_delta=_BOTH_LOGGED))
    assert "channel_not_separated" not in _keys(outcome)


def test_incomplete_window_surfaces_as_an_error_not_a_silent_pass():
    """The request log did not show an allowed request went through in this
    window (only the denial), so there is nothing to compare the event
    channel's extra entry against. The check must not fire, but it also
    must not simply say nothing: an unmeasured separation check that reads
    the same as a correctly separated one is the false-clean failure mode
    this project exists to rule out, so it must surface as a ProbeError."""
    entries = [_ALERT, {"host": "allowed.invalid", "decision": "allow"}]
    outcome = DetectionProbe().run(_target(entries, request_delta=[_DENY_ENTRY]))
    assert "channel_not_separated" not in _keys(outcome)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.errors[0].operation == "channel_separation"
    assert "allowed.invalid" in outcome.errors[0].detail


def test_incomplete_window_still_carries_an_events_side_finding_already_proved():
    """The request-log window is incomplete for channel_not_separated, but
    the events delta already proved severity_understated independently.
    That finding must ride along with the channel_separation error rather
    than being discarded by it."""
    entries = [dict(_ALERT, severity="LOW"), {"host": "allowed.invalid", "decision": "allow"}]
    outcome = DetectionProbe().run(_target(entries, request_delta=[_DENY_ENTRY]))
    assert "severity_understated" in _keys(outcome)
    assert outcome.errors
    assert outcome.errors[0].operation == "channel_separation"


def test_channel_not_separated_is_not_checked_when_request_log_is_unconfigured():
    """Whether the request log is even configured is the attribution
    probe's concern (no_request_log). This probe simply has nothing to
    compare against and must not raise an error or a finding for it."""
    entries = [_ALERT, {"host": "allowed.invalid", "decision": "allow"}]
    outcome = DetectionProbe().run(_target(entries, request_configured=False))
    assert "channel_not_separated" not in _keys(outcome)
    assert outcome.errors == []


# --- A request-log failure must not discard a finding the events delta
# already proved. Findings are computed from the events delta before the
# request log is read a second time, and a secondary, request-log-backed
# check failing afterward must not throw away a HIGH finding to protect a
# MEDIUM one.

def test_request_log_failure_preserves_an_already_proved_violation_finding():
    target = _target([])  # no alert for the violation: violation_unalerted
    calls = {"n": 0}

    def read_request_log(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(0, "", "")
        return ExecResult(1, "", "no such container")

    object.__setattr__(target, "read_request_log", read_request_log)
    outcome = DetectionProbe().run(target)
    assert "violation_unalerted" in _keys(outcome)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.errors[0].operation == "read_request_log"
    assert "no such container" in outcome.errors[0].detail


def test_request_log_shrinking_preserves_an_already_proved_severity_finding():
    target = _target([dict(_ALERT, severity="LOW")])
    calls = {"n": 0}
    long_body = "\n".join(json.dumps(e) for e in _BOTH_LOGGED * 3)
    short_body = "\n".join(json.dumps(e) for e in _BOTH_LOGGED)

    def read_request_log(timeout=30):
        calls["n"] += 1
        return ExecResult(0, long_body if calls["n"] == 1 else short_body, "")

    object.__setattr__(target, "read_request_log", read_request_log)
    outcome = DetectionProbe().run(target)
    assert "severity_understated" in _keys(outcome)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.errors[0].operation == "read_request_log"


# --- The event channel is append-only; the comparison must not be.

def test_a_stale_event_does_not_mask_an_unalerted_violation():
    """The defining regression: an alert for blocked.invalid is already in
    events.log before this run starts (left over from an earlier run), and
    this run's violation never actually gets alerted. A whole-log
    comparison would find blocked.invalid present and call this clean; the
    delta must not."""
    outcome = DetectionProbe().run(_target([], before_events=[_ALERT]))
    assert "violation_unalerted" in _keys(outcome)


def test_first_events_read_failure_is_treated_as_an_empty_baseline_not_an_error():
    """A target's very first run has no events.log yet. That must read as
    zero prior lines, not as a probe failure."""
    target = _target([_ALERT])
    calls = {"n": 0}
    after_body = "\n".join(json.dumps(e) for e in [_ALERT])

    def read_events(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(1, "", "cat: events.log: No such file or directory")
        return ExecResult(0, after_body, "")

    object.__setattr__(target, "read_events", read_events)
    outcome = DetectionProbe().run(target)
    assert outcome.findings == []
    assert outcome.control_ok


def test_second_events_read_failure_is_an_error_not_a_pass():
    target = _target([_ALERT])
    calls = {"n": 0}

    def read_events(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(0, "", "")
        return ExecResult(1, "", "no such container")

    object.__setattr__(target, "read_events", read_events)
    outcome = DetectionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []
    assert "no such container" in outcome.errors[0].detail


def test_event_channel_shrinking_between_reads_is_an_error_naming_both_counts():
    """Fewer lines after this run's violation than before it means rotation
    or truncation happened mid-run. That must not read as an empty (clean)
    delta."""
    target = _target([_ALERT])
    calls = {"n": 0}
    long_body = "\n".join(json.dumps(e) for e in [_ALERT] * 3)
    short_body = "\n".join(json.dumps(e) for e in [_ALERT])

    def read_events(timeout=30):
        calls["n"] += 1
        return ExecResult(0, long_body if calls["n"] == 1 else short_body, "")

    object.__setattr__(target, "read_events", read_events)
    outcome = DetectionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []
    detail = outcome.errors[0].detail
    assert "3" in detail
    assert "1" in detail


# --- Exec and protocol failures


def test_read_events_failure_after_a_clean_baseline_includes_stderr():
    target = _target([_ALERT])
    calls = {"n": 0}

    def read_events(timeout=30):
        calls["n"] += 1
        if calls["n"] == 1:
            return ExecResult(0, "", "")
        return ExecResult(1, "", "permission denied")

    object.__setattr__(target, "read_events", read_events)
    outcome = DetectionProbe().run(target)
    assert "permission denied" in outcome.errors[0].detail


def test_unparseable_inner_output_is_an_error_not_a_pass():
    target = _target([_ALERT])
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, "garbage", ""),
    )
    outcome = DetectionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


def test_exec_failure_detail_includes_returncode_and_stderr():
    target = _target([_ALERT])
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(124, "", "timed out after 60s"),
    )
    outcome = DetectionProbe().run(target)
    detail = outcome.errors[0].detail
    assert "124" in detail
    assert "timed out after 60s" in detail


def test_non_dict_inner_result_is_an_error_not_a_crash():
    target = _target([_ALERT])
    payload = f"{MARKER} 42\n"
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(0, payload, ""),
    )
    outcome = DetectionProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


# --- The crossings must generate both an allowed and a denied request
# (Amendment 2), and must use direct env assignment (Pattern 1).

def test_probe_env_vars_use_direct_assignment_not_setdefault():
    sent = []
    DetectionProbe().run(_target([_ALERT], sent=sent))
    payload = sent[0][0]
    assert "setdefault" not in payload
    for var in ("PROBE_CROSSING_HOSTS", "PROBE_PROXY"):
        assert f"os.environ['{var}'] = " in payload


def test_crossing_hosts_include_both_allowed_and_blocked():
    sent = []
    DetectionProbe().run(_target([_ALERT], sent=sent))
    payload = sent[0][0]
    assert "allowed.invalid" in payload
    assert "blocked.invalid" in payload


def test_no_proxy_target_does_not_carry_the_string_none():
    sent = []
    DetectionProbe().run(_target([_ALERT], proxy=None, sent=sent))
    payload = sent[0][0]
    assert "PROBE_PROXY'] = ''" in payload


def test_payload_body_defines_both_crossing_paths():
    assert "def cross_via_proxy" in PAYLOAD_BODY
    assert "def cross_direct" in PAYLOAD_BODY
