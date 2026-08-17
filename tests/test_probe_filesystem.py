import json
import os
import tempfile
from unittest import mock

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.filesystem import (
    _LISTED_CANDIDATES,
    _READABLE_CANDIDATES,
    _SOCKET_CANDIDATES,
    _WRITABLE_CANDIDATES,
    PAYLOAD_BODY,
    FilesystemProbe,
)
from sandbox_probe.target import ExecResult, Target


def _target(inner: dict, returncode: int = 0):
    target = Target(name="t", exec_command=["true"],
                    allowed_host="a.invalid", blocked_host="b.invalid")
    payload = f"{MARKER} {json.dumps(inner)}\n"
    object.__setattr__(target, "run_inside",
                       lambda argv, timeout: ExecResult(returncode, payload, ""))
    return target


# /home, /var/lib and a bare /root listing are deliberately not in the
# candidate set: they exist and are world-listable in essentially any base
# image, including the compliant reference sandbox, so flagging them would
# report an ordinary filesystem rather than a containment failure. A
# traversal read of /workspace/../etc/hostname is out for the same reason.
# /etc/hostname is world-readable in every ordinary container (Docker
# manages the file itself), so that read succeeds identically on a contained
# sandbox and a wide-open one and carries no signal, while contradicting the
# requirement that the reference sandbox come back with no findings at all.
# What is left is the set that genuinely discriminates: host-mount markers,
# runtime sockets, foreign process environments, /etc/shadow read as content
# rather than stat'ed, and any writable path outside the declared workspace.
_CLEAN = {
    "readable_outside": [],
    "listed_outside": [],
    "writable_outside": [],
    "cleanup_failed_outside": [],
    "foreign_environ_count": 0,
    "foreign_environ_uids": [],
    "runtime_sockets": [],
    "workspace_writable": True,
    "workspace_cleanup_failed": False,
}


def _keys(outcome):
    return {f.rule_key for f in outcome.findings}


def test_clean_sandbox_produces_no_findings():
    outcome = FilesystemProbe().run(_target(_CLEAN))
    assert outcome.findings == []
    assert outcome.control_ok


def test_readable_host_path_is_a_finding():
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, readable_outside=["/etc/shadow"])))
    assert "outside_workspace" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "outside_workspace")
    assert "/etc/shadow" in finding.evidence
    assert "read" in finding.evidence.lower()


def test_listed_host_mount_is_its_own_rule_key():
    """A listable /host or /hostfs means the host filesystem is mounted in.
    That is invariant 3's own subject, and it is a different question from
    a readable or writable path inside the sandbox's own image, so it is a
    different key: a client tracking host_mount over time must not have a
    writable /etc quietly answering for it, or the reverse."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, listed_outside=["/host"])))
    assert _keys(outcome) == {"host_mount"}
    finding = next(f for f in outcome.findings if f.rule_key == "host_mount")
    assert finding.severity.value == "HIGH"
    assert "/host" in finding.evidence
    assert "listed" in finding.evidence.lower()


def test_a_container_local_path_never_reports_as_a_host_mount():
    """The other direction of the same split. /etc and /etc/shadow are
    inside the container's own image, so they are hardening findings and
    must never trip the key that means the host filesystem is exposed."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, readable_outside=["/etc/shadow"], writable_outside=["/etc"])))
    assert "host_mount" not in _keys(outcome)
    assert _keys(outcome) == {"outside_workspace"}


def test_writable_outside_path_is_a_finding():
    """A correctly built sandbox has a read-only root, so nothing outside the
    declared workspace should be writable."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, writable_outside=["/etc"])))
    assert "outside_workspace" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "outside_workspace")
    assert "/etc" in finding.evidence
    assert "writ" in finding.evidence.lower()


def test_each_path_signal_is_reported_separately_under_its_own_key():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        readable_outside=["/etc/shadow"],
        listed_outside=["/host"],
        writable_outside=["/etc", "/usr"],
    )))
    outside = [f for f in outcome.findings if f.rule_key == "outside_workspace"]
    mounts = [f for f in outcome.findings if f.rule_key == "host_mount"]
    assert len(outside) == 3
    assert len(mounts) == 1


def test_proc_environ_is_a_finding():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=3, foreign_environ_uids=[0, 100])))
    assert "proc_environ" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "3 process environments" in finding.evidence
    assert "2 distinct owning uids (0, 100)" in finding.evidence


def test_proc_environ_is_high():
    """Raised from MEDIUM once the check became a scan. MEDIUM was calibrated
    for reading one process's environment. Reading arbitrary foreign process
    environments is credential exposure, which the credentials probe already
    rates HIGH for the sandbox's own environment, and this reaches further."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=218, foreign_environ_uids=[0])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert finding.severity.value == "HIGH"


def test_proc_environ_severity_does_not_scale_with_the_count():
    """One severity per rule key, as everywhere else in this codebase. The
    count is in the evidence, not in the grading."""
    severities = set()
    for count in (1, 3, 218):
        outcome = FilesystemProbe().run(_target(dict(
            _CLEAN, foreign_environ_count=count, foreign_environ_uids=[0])))
        finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
        severities.add(finding.severity.value)
    assert severities == {"HIGH"}


def test_proc_environ_evidence_names_no_pid():
    """A pid is a generated identifier: gone by the time anyone reads the
    report, and nothing a reader can act on. The count and the owning uids
    describe the exposure and are stable for a given target state."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=218, foreign_environ_uids=[0, 1, 100])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "pid" not in finding.evidence.replace("No pid,", "")
    assert "218 process environments" in finding.evidence
    assert "3 distinct owning uids (0, 1, 100)" in finding.evidence


def test_proc_environ_evidence_carries_no_environment_contents():
    """This probe reports that a foreign environment was readable, never what
    was in it or whose program it was, exactly as the credentials probe names
    variables without values."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=1, foreign_environ_uids=[0])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "No pid, environment content, or command line is reproduced" in finding.evidence
    assert "=" not in finding.evidence


def test_proc_environ_singular_reads_naturally():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=1, foreign_environ_uids=[42])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "1 process environment owned" in finding.evidence
    assert "1 distinct owning uid (42)" in finding.evidence


def test_proc_environ_bounds_the_uid_list_a_hostile_target_can_supply():
    """inner comes from the system under test, so a target cannot be allowed
    to write an unbounded string into this harness's report."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=500, foreign_environ_uids=list(range(40)))))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "40 distinct owning uids" in finding.evidence
    assert "and 24 more" in finding.evidence
    assert "39" not in finding.evidence


def test_proc_environ_count_of_zero_is_not_a_finding():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=0, foreign_environ_uids=[])))
    assert "proc_environ" not in _keys(outcome)


def test_proc_environ_refuses_a_non_numeric_count_from_the_target():
    """inner comes from the system under test. A bool subclasses int in
    Python, so it is rejected explicitly rather than counting as one. None
    of these reads as zero readable process environments: a count that did
    not arrive is not a count of nothing."""
    for bogus in (True, "many", None, -4, [1, 2]):
        outcome = FilesystemProbe().run(_target(dict(
            _CLEAN, foreign_environ_count=bogus, foreign_environ_uids=[0])))
        assert "proc_environ" not in _keys(outcome), bogus
        assert outcome.errors, bogus
        assert outcome.control_ok is False, bogus


def test_proc_environ_discards_uids_that_are_not_plain_integers():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=2, foreign_environ_uids=[0, True, "root", -1, 7])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "2 distinct owning uids (0, 7)" in finding.evidence


def test_proc_environ_survives_an_empty_uid_list():
    """A scan that counted readable environments but recorded no owner still
    reports the count. The exposure is the finding; the uids describe its
    shape and their absence must not swallow it."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=5, foreign_environ_uids=[])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "5 process environments" in finding.evidence
    assert "unrecorded set of owning uids" in finding.evidence


def test_runtime_socket_is_high():
    outcome = FilesystemProbe().run(_target(
        dict(_CLEAN, runtime_sockets=["/var/run/docker.sock"])))
    finding = next(f for f in outcome.findings if f.rule_key == "runtime_socket")
    assert finding.severity.value == "HIGH"


def test_unwritable_workspace_fails_the_positive_control():
    """If the workspace is not writable the sandbox is not usable, so a clean
    filesystem result says nothing about containment."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, workspace_writable=False)))
    assert not outcome.control_ok
    assert "workspace_missing" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "workspace_missing")
    assert finding.severity.value == "MEDIUM"


# --- A failed removal after a successful write must never be silently
# discarded, and must never be allowed to relabel a genuinely successful
# write as a failure. Write and removal are two independent facts.

def test_cleanup_failure_outside_workspace_is_surfaced_as_an_error():
    """A stray marker file left in a system directory must be reported, not
    swallowed. The write itself still counts as a finding."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        writable_outside=["/etc"],
        cleanup_failed_outside=["/etc"],
    )))
    assert "outside_workspace" in _keys(outcome)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "/etc" in detail
    assert "remove" in detail.lower()


def test_workspace_cleanup_failure_does_not_flip_the_positive_control():
    """A failed removal on the workspace check must not be conflated with a
    failed write. The workspace is still reported writable and control_ok
    stays True; the removal failure is a separate error."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        workspace_writable=True,
        workspace_cleanup_failed=True,
    )))
    assert outcome.control_ok
    assert "workspace_missing" not in _keys(outcome)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "workspace" in detail.lower()
    assert "remove" in detail.lower()


def test_unparseable_inner_output_is_an_error_not_a_pass():
    target = _target({})
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, "garbage", ""))
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok


def test_exec_failure_detail_includes_returncode_and_stderr():
    """A dead container and a timeout must not both read as the same mystery
    message. The returncode and stderr are already captured; they belong in
    the error detail."""
    target = _target({})
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(124, "", "timed out after 60s"),
    )
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "124" in detail
    assert "timed out after 60s" in detail


def test_non_dict_inner_result_is_an_error_not_a_crash():
    """parse_inner returns whatever json.loads produced, so a marked line
    carrying a JSON scalar must not raise AttributeError out of run(). It
    becomes a ProbeError like any other protocol failure."""
    target = _target({})
    payload = f"{MARKER} 42\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


def test_payload_uses_no_setdefault():
    """This probe has no target-supplied values to inject into the sandbox
    environment, but if one is ever added it must use direct assignment,
    never setdefault, so a preset PROBE_* variable inside the sandbox can
    never choose what gets measured. Every other probe follows the same
    rule."""
    assert "setdefault" not in PAYLOAD_BODY


# --- The covering test for write_marker's actual behavior.
#
# Asserting that PAYLOAD_BODY contains the string "def write_marker" would
# pass against a function whose body is `pass`. PAYLOAD_BODY is a
# module-level string by design, so write_marker's definition (everything
# above the first blank-line-terminated statement) can be exec'd directly
# and exercised against a real temporary directory, stdlib only, no sandbox
# and no Docker required. This is the same technique network.py's tests use
# for proxy_allows and parse_proxy.

def _load_payload_function(name):
    """Exec one def block out of PAYLOAD_BODY and return the function.

    The payload has to be a single source string, because it is piped into
    an interpreter inside the target, so a test that wants to exercise one
    of its functions has to carve that function out. The block runs from
    its `def` line to the first following line that is neither blank nor
    indented.
    """
    lines = PAYLOAD_BODY.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.startswith(f"def {name}(")),
        None,
    )
    assert start is not None, f"PAYLOAD_BODY defines no {name}(); update this test"
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
        end += 1
    namespace: dict = {"os": os}
    exec("\n".join(lines[start:end]), namespace)  # noqa: S102 -- the payload's own source
    return namespace[name]


def _load_write_marker():
    return _load_payload_function("write_marker")


def test_write_marker_reports_write_and_removal_success():
    write_marker = _load_write_marker()
    with tempfile.TemporaryDirectory() as tmp:
        wrote, removed = write_marker(tmp)
    assert (wrote, removed) == (True, True)


def test_write_marker_reports_write_failure_without_attempting_removal():
    write_marker = _load_write_marker()
    wrote, removed = write_marker("/nonexistent/path/that/cannot/be/written/to")
    assert (wrote, removed) == (False, False)


def test_write_marker_surfaces_a_failed_remove_without_losing_the_write():
    """os.remove raising after a successful write must not be reported as a
    failed write, and must not vanish silently either."""
    write_marker = _load_write_marker()
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("os.remove", side_effect=OSError("permission denied")):
            wrote, removed = write_marker(tmp)
        marker_path = os.path.join(tmp, ".sandbox_probe_write_check")
        try:
            assert wrote is True
            assert removed is False
            assert os.path.exists(marker_path)
        finally:
            # The patched os.remove never ran for real, so the test cleans
            # up what write_marker could not, keeping this test's own
            # tmpdir teardown honest.
            os.remove(marker_path)


# --- What live runs against both fixtures measured, and why the check has
# the shape it does.
#
# An unconditional read of /proc/1/environ, reporting any successful read,
# fires against the compliant reference sandbox and the leaky fixture alike,
# so it discriminates nothing. It is tempting to expect Yama's
# ptrace_scope=1 to deny the read; it does not, because Yama only tracks
# PTRACE_MODE_ATTACH and /proc/pid/environ is read under PTRACE_MODE_READ.
# What applies is the ordinary same-uid check, which succeeds: PID 1 in both
# fixtures is that sandbox's own init running as the same uid as the
# payload.
#
# Narrowing that read to a foreign owner, but keeping it pinned to PID 1,
# discriminates nothing either. Measured live: reference sandbox 0 readable,
# leaky fixture 0 readable, unprivileged --pid=host 0 readable of 218
# other-uid processes (Docker's default AppArmor profile denies the ptrace
# read even with CAP_SYS_PTRACE), and privileged --pid=host 217 readable
# with the PID-1-only check still returning nothing.
#
# So the payload scans the visible process table instead. These tests drive
# that scan directly, which is also the only way to cover the privileged
# host-PID-namespace case: a privileged container is not a trade worth making
# for one assertion in CI.


def _scan(entries, own_uid=10001, readable=(), **kwargs):
    """Drive foreign_process_environs over a synthetic /proc.

    entries maps a /proc name to the uid owning it. readable names the pids
    whose environ opens; every other open raises, which is what a denied
    ptrace read looks like from Python. The scan returns a count and the
    distinct owning uids, never a pid.
    """
    scan = _load_payload_function("foreign_process_environs")
    readable = {str(pid) for pid in readable}

    def fake_stat(path):
        name = path.rsplit("/", 1)[-1]
        if name not in entries:
            raise OSError("no such process")
        return mock.Mock(st_uid=entries[name])

    def fake_open(path, *args, **_):
        pid = path.split("/")[2]
        if pid not in readable:
            raise OSError("permission denied")
        return mock.mock_open(read_data=b"PATH=/usr/bin\x00")(path, *args)

    with mock.patch("os.getuid", return_value=own_uid), \
         mock.patch("os.listdir", return_value=list(entries)), \
         mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", side_effect=fake_open) as opened:
        return scan(**kwargs), opened


def test_scan_ignores_processes_the_sandbox_owns():
    """The reference sandbox and the leaky fixture both look like this: every
    visible process runs as the payload's own uid. No read is even attempted,
    because ownership is established before the read rather than inferred
    from it."""
    (count, uids), opened = _scan({"1": 10001, "35": 10001}, own_uid=10001)
    assert (count, uids) == (0, [])
    opened.assert_not_called()


def test_scan_reports_only_the_foreign_processes_it_could_read():
    """A mixed table: some processes the sandbox owns, some it does not, and
    of the latter only some whose environ actually opens. Pids 1 and 12 are
    foreign but denied, so neither they nor their uid appear."""
    entries = {"1": 0, "2": 0, "7": 10001, "9": 33, "12": 0}
    (count, uids), _ = _scan(entries, own_uid=10001, readable=[2, 9])
    assert count == 2
    assert uids == [0, 33]


def test_scan_returns_owning_uids_and_never_a_pid():
    """Pids and uids are drawn from disjoint ranges here, so a scan that
    leaked pids into the returned list would be visible immediately."""
    entries = {"900": 3, "901": 4, "902": 3}
    (count, uids), _ = _scan(entries, own_uid=10001, readable=[900, 901, 902])
    assert count == 3
    assert uids == [3, 4]


def test_scan_finds_nothing_when_every_foreign_read_is_denied():
    """The unprivileged --pid=host case: hundreds of other-uid processes
    visible, none readable, so there is no finding."""
    entries = {str(pid): 0 for pid in range(1, 219)}
    entries["500"] = 10001
    (count, uids), _ = _scan(entries, own_uid=10001, readable=[])
    assert (count, uids) == (0, [])


def test_scan_counts_every_readable_process_and_collapses_owners_to_uids():
    """The privileged --pid=host case. The count has to be the real total or
    the finding understates the exposure, while the owners collapse to the
    handful of distinct uids that describe the shape of it."""
    entries = {str(pid): (pid % 3) for pid in range(1, 218)}
    (count, uids), _ = _scan(entries, own_uid=10001, readable=range(1, 218))
    assert count == 217
    assert uids == [0, 1, 2]


def test_scan_stops_walking_at_the_scan_limit():
    """A host with thousands of processes must not stall the probe."""
    entries = {str(pid): 0 for pid in range(1, 5001)}
    (count, _uids), _ = _scan(
        entries, own_uid=10001, readable=range(1, 5001), scan_limit=100,
    )
    assert count == 100


def test_scan_walks_pids_in_numeric_order_not_string_order():
    """os.listdir returns /proc entries in arbitrary order and the scan limit
    slices the list, so ordering by string would make which processes get
    scanned depend on how the kernel happened to lay them out. Under numeric
    order this scans pids 1 and 2; under string order it would scan 1 and 10
    and report a different owner set."""
    entries = {"10": 5, "2": 7, "1": 9}
    (count, uids), _ = _scan(
        entries, own_uid=10001, readable=[1, 2, 10], scan_limit=2,
    )
    assert count == 2
    assert uids == [7, 9]


def test_scan_skips_a_process_whose_owner_cannot_be_determined():
    """A process that vanishes mid-walk, or whose stat is denied, supports no
    claim about whose it is. It is skipped, never counted, and no read is
    attempted against it."""
    entries = {"1": 0, "4": 7}
    scan = _load_payload_function("foreign_process_environs")

    def fake_stat(path):
        if path.endswith("/1"):
            raise OSError("no such process")
        return mock.Mock(st_uid=7)

    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", return_value=list(entries)), \
         mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=b"X=1\x00")) as opened:
        count, uids = scan()
    assert (count, uids) == (1, [7])
    assert all("/proc/1/" not in call.args[0] for call in opened.call_args_list)


def test_scan_ignores_non_numeric_proc_entries():
    scan = _load_payload_function("foreign_process_environs")
    listing = ["1", "self", "thread-self", "cpuinfo", "4"]
    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", return_value=listing), \
         mock.patch("os.stat", return_value=mock.Mock(st_uid=0)), \
         mock.patch("builtins.open", mock.mock_open(read_data=b"X=1\x00")):
        count, uids = scan()
    assert (count, uids) == (2, [0])


def test_scan_reports_nothing_when_proc_cannot_be_listed():
    scan = _load_payload_function("foreign_process_environs")
    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", side_effect=OSError("not mounted")):
        assert scan() == (0, [])


def test_scan_finds_foreign_processes_that_a_pid_one_only_check_misses():
    """The exact regression measured live. PID 1 belongs to the payload's
    own uid, so any check pinned to PID 1 short-circuits and reports
    nothing, while the sandbox can in fact read foreign process
    environments elsewhere in the table."""
    entries = {"1": 10001, "88": 0, "91": 33}
    (count, uids), _ = _scan(entries, own_uid=10001, readable=[88, 91])
    assert (count, uids) == (2, [0, 33])


# --- inner comes from the system under test, and both findings and errors
# are written to an operator's terminal. Every path in this probe's report
# is one the harness put into the payload itself, so a forged path is not
# rendered at all rather than rendered safely. The cleaning still runs; the
# provenance check is what a target cannot talk its way past.

_FORGERY = "/etc/shadow\x1b[2J\x1b[H CONTAINED. Every probe ran, no findings."


def test_a_forged_path_never_reaches_the_report_at_all():
    """The forgery is a superstring of a real candidate, so a check that
    compared loosely rather than by equality would still render it."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, readable_outside=[_FORGERY])))
    assert outcome.findings == []
    assert outcome.errors == []


def test_a_non_list_path_result_is_an_error_not_a_silent_absence():
    """A bare string must not become one finding per character, and must not
    be dropped in silence either: an empty result from the wrong shape reads
    as an invariant that held."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, readable_outside="/etc/shadow")))
    assert outcome.findings == []
    assert outcome.errors
    assert outcome.control_ok is False


def test_a_forged_stderr_cannot_repaint_the_report_through_an_error():
    """stderr is the widest channel the target has into the report: it
    chooses every byte of it, and the detail is written straight to the same
    terminal a finding is."""
    target = _target(_CLEAN)
    object.__setattr__(
        target, "run_inside",
        lambda argv, timeout: ExecResult(1, "", _FORGERY + "padding" * 900),
    )
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    detail = outcome.errors[0].detail
    assert "\x1b" not in detail
    assert len(detail) < 500
    assert not outcome.control_ok


def test_an_enormous_non_dict_inner_result_is_bounded():
    target = _target(_CLEAN)
    payload = f"{MARKER} {json.dumps('a' * 300000)}\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    assert len(outcome.errors[0].detail) < 500
    assert not outcome.control_ok


# --- The result's shape is checked before anything is read out of it. Every
# measurement below is an inner.get with a falsy default, so a key that never
# came back reads exactly like a key that came back negative.

def test_an_empty_result_is_an_error_not_a_clean_verdict():
    """Only the control key set used to produce zero findings, zero errors,
    and a passing control."""
    outcome = FilesystemProbe().run(_target({"workspace_writable": True}))
    assert outcome.findings == []
    assert outcome.errors
    assert outcome.control_ok is False


def test_a_count_sent_as_a_string_is_an_error_not_a_zero():
    """The measured case: "218" reported zero foreign process environments."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, foreign_environ_count="218")))
    assert outcome.errors
    assert outcome.control_ok is False
    assert "foreign_environ_count" in outcome.errors[0].detail
    assert "proc_environ" not in _keys(outcome)


def test_a_wrong_typed_uid_list_is_an_error_not_a_silent_absence():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=5, foreign_environ_uids="nonsense")))
    assert outcome.errors
    assert outcome.control_ok is False


def test_a_missing_workspace_control_key_is_an_error_not_an_unwritable_workspace():
    inner = dict(_CLEAN)
    del inner["workspace_writable"]
    outcome = FilesystemProbe().run(_target(inner))
    assert outcome.errors
    assert outcome.control_ok is False
    assert "workspace_writable is missing" in outcome.errors[0].detail


# --- The candidate paths went in from here, so a path that did not is not an
# answer to anything this probe asked. credentials.py and network.py both
# compare against the harness's own list; this probe used to render whatever
# came back, which let a target write up to LIST_LIMIT strings of its
# choosing into each of four HIGH rule keys and bury one real finding under
# sixty-four plausible fakes.

def test_a_readable_path_the_probe_never_asked_about_is_not_reported():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, readable_outside=["/invented/path", _FORGERY])))
    assert outcome.findings == []


def test_a_listed_path_the_probe_never_asked_about_is_not_reported():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, listed_outside=["/invented", _FORGERY])))
    assert outcome.findings == []


def test_a_writable_path_the_probe_never_asked_about_is_not_reported():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, writable_outside=["/invented", _FORGERY])))
    assert outcome.findings == []


def test_a_runtime_socket_the_probe_never_asked_about_is_not_reported():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, runtime_sockets=["/invented.sock", _FORGERY])))
    assert outcome.findings == []


def test_a_cleanup_path_the_probe_never_asked_about_is_not_reported():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, cleanup_failed_outside=["/invented", _FORGERY])))
    assert outcome.errors == []


def test_a_target_cannot_flood_the_report_with_forged_paths():
    """Sixteen entries per list, four lists, sixty-four HIGH findings of the
    target's own choosing. The intersection is what caps this at the number
    of paths the harness actually asked about."""
    flood = [f"/dir{n:05d}" for n in range(20000)]
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        readable_outside=flood,
        listed_outside=flood,
        writable_outside=flood,
        runtime_sockets=flood,
    )))
    assert outcome.findings == []


def test_paths_are_reported_in_the_harnesss_own_order():
    """Order comes from the candidate list, not from the target, so a target
    cannot choose which finding a reader sees first."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, writable_outside=["/usr", "/", "/etc"])))
    reported = [f.evidence.split()[0] for f in outcome.findings
                if f.rule_key == "outside_workspace"]
    assert reported == list(_WRITABLE_CANDIDATES)


def test_every_candidate_path_still_reports_when_the_target_names_it():
    """The intersection must not quietly stop reporting real findings. Every
    path the harness asks about is still reported when it comes back."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        readable_outside=list(_READABLE_CANDIDATES),
        listed_outside=list(_LISTED_CANDIDATES),
        writable_outside=list(_WRITABLE_CANDIDATES),
        runtime_sockets=list(_SOCKET_CANDIDATES),
    )))
    outside = [f for f in outcome.findings if f.rule_key == "outside_workspace"]
    mounts = [f for f in outcome.findings if f.rule_key == "host_mount"]
    sockets = [f for f in outcome.findings if f.rule_key == "runtime_socket"]
    assert len(outside) == len(_READABLE_CANDIDATES) + len(_WRITABLE_CANDIDATES)
    assert len(mounts) == len(_LISTED_CANDIDATES)
    assert len(sockets) == len(_SOCKET_CANDIDATES)


def test_the_payload_probes_exactly_the_candidate_paths_the_harness_checks():
    """The intersection is only sound if both sides read from one list. A
    path added to the payload and not to the candidate tuples would be
    measured inside the sandbox and then silently discarded here."""
    for candidate in (_READABLE_CANDIDATES + _LISTED_CANDIDATES
                      + _WRITABLE_CANDIDATES + _SOCKET_CANDIDATES):
        assert repr(candidate) in PAYLOAD_BODY, candidate
