import json
import os
import tempfile
from unittest import mock

from sandbox_probe.inner import MARKER
from sandbox_probe.probes.filesystem import PAYLOAD_BODY, FilesystemProbe
from sandbox_probe.target import ExecResult, Target


def _target(inner: dict, returncode: int = 0):
    target = Target(name="t", exec_command=["true"],
                    allowed_host="a.invalid", blocked_host="b.invalid")
    payload = f"{MARKER} {json.dumps(inner)}\n"
    object.__setattr__(target, "run_inside",
                       lambda argv, timeout: ExecResult(returncode, payload, ""))
    return target


# Amendment: /home, /var/lib and a bare /root listing are dropped from the
# candidate set because they exist and are world-listable in essentially any
# base image, including the compliant reference sandbox. The traversal check
# against /workspace/../etc/hostname is dropped too: /etc/hostname is
# world-readable in every ordinary container (Docker manages it itself), so
# keeping it as a bare content-read finding would false-positive against the
# compliant reference sandbox exactly as readily as against the leaky
# fixture, contradicting the requirement that the reference sandbox come
# back with no findings at all. This mirrors Ruling R5 in the project's SDD
# progress log, which lists the genuine signals as host-mount markers,
# runtime sockets, /proc/1/environ, /etc/shadow as a content read, and any
# writable path outside the declared workspace, with no traversal check.
_CLEAN = {
    "readable_outside": [],
    "listed_outside": [],
    "writable_outside": [],
    "cleanup_failed_outside": [],
    "foreign_environ_count": 0,
    "foreign_environ_pids": [],
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


def test_listed_host_mount_is_a_finding():
    """A listable /host or /hostfs means the host filesystem is mounted in,
    which is a distinct signal from an ordinary writable or readable path."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, listed_outside=["/host"])))
    assert "outside_workspace" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "outside_workspace")
    assert "/host" in finding.evidence
    assert "listed" in finding.evidence.lower()


def test_writable_outside_path_is_a_finding():
    """A correctly built sandbox has a read-only root, so nothing outside the
    declared workspace should be writable."""
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, writable_outside=["/etc"])))
    assert "outside_workspace" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "outside_workspace")
    assert "/etc" in finding.evidence
    assert "writ" in finding.evidence.lower()


def test_each_outside_workspace_signal_is_reported_separately():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN,
        readable_outside=["/etc/shadow"],
        listed_outside=["/host"],
        writable_outside=["/etc", "/usr"],
    )))
    findings = [f for f in outcome.findings if f.rule_key == "outside_workspace"]
    assert len(findings) == 4


def test_proc_environ_is_a_finding():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=3, foreign_environ_pids=[1, 214, 907])))
    assert "proc_environ" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert finding.severity.value == "MEDIUM"
    assert "3 process environments" in finding.evidence
    for pid in ("1", "214", "907"):
        assert pid in finding.evidence


def test_proc_environ_evidence_names_the_overflow_rather_than_dumping_it():
    """A privileged host-PID-namespace container can read hundreds. The
    finding says how many and shows a bounded sample."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=217, foreign_environ_pids=[1, 2, 3])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "217 process environments" in finding.evidence
    assert "and 214 more" in finding.evidence


def test_proc_environ_evidence_carries_no_environment_contents():
    """This probe reports that a foreign environment was readable, never
    what was in it, exactly as the credentials probe names variables
    without values."""
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=1, foreign_environ_pids=[1])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "not reproduced" in finding.evidence
    assert "=" not in finding.evidence


def test_proc_environ_singular_reads_naturally():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=1, foreign_environ_pids=[9])))
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert "1 process environment owned" in finding.evidence


def test_proc_environ_count_of_zero_is_not_a_finding():
    outcome = FilesystemProbe().run(_target(dict(
        _CLEAN, foreign_environ_count=0, foreign_environ_pids=[])))
    assert "proc_environ" not in _keys(outcome)


def test_proc_environ_ignores_a_non_numeric_count_from_the_target():
    """inner comes from the system under test. A bool subclasses int in
    Python, so it is rejected explicitly rather than counting as one."""
    for bogus in (True, "many", None, -4, [1, 2]):
        outcome = FilesystemProbe().run(_target(dict(
            _CLEAN, foreign_environ_count=bogus, foreign_environ_pids=[1])))
        assert "proc_environ" not in _keys(outcome), bogus


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


# --- Fix round: a failed removal after a successful write must never be
# silently discarded (Finding 1) and must never be allowed to relabel a
# genuinely successful write as a failure (Finding 2).

def test_cleanup_failure_outside_workspace_is_surfaced_as_an_error():
    """Finding 1: a stray marker file left in a system directory must be
    reported, not swallowed. The write itself still counts as a finding."""
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
    """Finding 2: a failed removal on the workspace check must not be
    conflated with a failed write. The workspace is still reported writable
    and control_ok stays True; the removal failure is a separate error."""
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
    """Pattern 3, copied from network.py: a dead container and a timeout must
    not both read as the same mystery message."""
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
    """Pattern 4, copied from network.py: parse_inner returns whatever
    json.loads produced, and a marked line carrying a JSON scalar must not
    raise AttributeError out of run()."""
    target = _target({})
    payload = f"{MARKER} 42\n"
    object.__setattr__(target, "run_inside", lambda argv, timeout: ExecResult(0, payload, ""))
    outcome = FilesystemProbe().run(target)
    assert outcome.errors
    assert not outcome.control_ok
    assert outcome.findings == []


def test_payload_uses_no_setdefault():
    """Pattern 1, copied from network.py: this probe has no target-supplied
    values to inject into the sandbox environment, but if one is ever added
    it must use direct assignment, never setdefault, so a preset PROBE_*
    variable inside the sandbox can never choose what gets measured."""
    assert "setdefault" not in PAYLOAD_BODY


# --- Finding 3: the covering test for write_marker's actual behavior.
#
# PAYLOAD_BODY is a module-level string by design, so write_marker's
# definition (everything above the first blank-line-terminated statement)
# can be exec'd directly and exercised against a real temporary directory,
# stdlib only, no sandbox and no Docker required. This is the same
# technique network.py's tests use for proxy_allows and parse_proxy.

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
    """The exact regression both findings describe: os.remove raising after
    a successful write must not be reported as a failed write, and must not
    vanish silently either."""
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


# --- Task 15, live runs against both fixtures, and the review that followed.
#
# The original payload read /proc/1/environ unconditionally and reported any
# successful read. That fired against the compliant reference sandbox and
# against the leaky fixture alike, so it discriminated nothing. The project
# ledger expected Yama's ptrace_scope=1 to deny the read; it does not, because
# Yama only tracks PTRACE_MODE_ATTACH and /proc/pid/environ is read under
# PTRACE_MODE_READ. What applies is the ordinary same-uid check, which
# succeeds: PID 1 in both fixtures is that sandbox's own init running as the
# same uid as the payload.
#
# Narrowing that read to a foreign owner, but keeping it pinned to PID 1,
# discriminated nothing either. Measured live: reference sandbox 0 readable,
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
    ptrace read looks like from Python.
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
    (count, sample), opened = _scan({"1": 10001, "35": 10001}, own_uid=10001)
    assert (count, sample) == (0, [])
    opened.assert_not_called()


def test_scan_reports_only_the_foreign_processes_it_could_read():
    """A mixed table: some processes the sandbox owns, some it does not, and
    of the latter only some whose environ actually opens."""
    entries = {"1": 0, "2": 0, "7": 10001, "9": 33, "12": 0}
    (count, sample), _ = _scan(entries, own_uid=10001, readable=[2, 9])
    assert count == 2
    assert sample == [2, 9]


def test_scan_finds_nothing_when_every_foreign_read_is_denied():
    """The unprivileged --pid=host case: hundreds of other-uid processes
    visible, none readable, so there is no finding."""
    entries = {str(pid): 0 for pid in range(1, 219)}
    entries["500"] = 10001
    (count, sample), _ = _scan(entries, own_uid=10001, readable=[])
    assert (count, sample) == (0, [])


def test_scan_counts_every_readable_process_but_samples_a_bounded_few():
    """The privileged --pid=host case. The count has to be the real total or
    the finding understates the exposure; the sample has to stay bounded or
    the evidence string becomes a process dump."""
    entries = {str(pid): 0 for pid in range(1, 218)}
    (count, sample), _ = _scan(
        entries, own_uid=10001, readable=range(1, 218), sample_limit=8,
    )
    assert count == 217
    assert len(sample) == 8
    assert sample == [1, 2, 3, 4, 5, 6, 7, 8]


def test_scan_stops_walking_at_the_scan_limit():
    """A host with thousands of processes must not stall the probe."""
    entries = {str(pid): 0 for pid in range(1, 5001)}
    (count, _sample), _ = _scan(
        entries, own_uid=10001, readable=range(1, 5001), scan_limit=100,
    )
    assert count == 100


def test_scan_walks_pids_in_numeric_order_not_string_order():
    """os.listdir returns /proc entries in arbitrary order, and the scan
    limit slices the list, so ordering by string would make which processes
    get scanned depend on how the kernel happened to lay them out."""
    entries = {"10": 0, "2": 0, "1": 0}
    (_count, sample), _ = _scan(entries, own_uid=10001, readable=[1, 2, 10])
    assert sample == [1, 2, 10]


def test_scan_skips_a_process_whose_owner_cannot_be_determined():
    """A process that vanishes mid-walk, or whose stat is denied, supports no
    claim about whose it is. It is skipped, never counted, and no read is
    attempted against it."""
    entries = {"1": 0, "4": 0}
    scan = _load_payload_function("foreign_process_environs")

    def fake_stat(path):
        if path.endswith("/1"):
            raise OSError("no such process")
        return mock.Mock(st_uid=0)

    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", return_value=list(entries)), \
         mock.patch("os.stat", side_effect=fake_stat), \
         mock.patch("builtins.open", mock.mock_open(read_data=b"X=1\x00")) as opened:
        count, sample = scan()
    assert (count, sample) == (1, [4])
    assert all("/proc/1/" not in call.args[0] for call in opened.call_args_list)


def test_scan_ignores_non_numeric_proc_entries():
    scan = _load_payload_function("foreign_process_environs")
    listing = ["1", "self", "thread-self", "cpuinfo", "4"]
    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", return_value=listing), \
         mock.patch("os.stat", return_value=mock.Mock(st_uid=0)), \
         mock.patch("builtins.open", mock.mock_open(read_data=b"X=1\x00")):
        count, sample = scan()
    assert (count, sample) == (2, [1, 4])


def test_scan_reports_nothing_when_proc_cannot_be_listed():
    scan = _load_payload_function("foreign_process_environs")
    with mock.patch("os.getuid", return_value=10001), \
         mock.patch("os.listdir", side_effect=OSError("not mounted")):
        assert scan() == (0, [])


def test_scan_finds_foreign_processes_that_a_pid_one_only_check_misses():
    """The exact regression the review measured. PID 1 belongs to the
    payload's own uid, so any check pinned to PID 1 short-circuits and
    reports nothing, while the sandbox can in fact read foreign process
    environments elsewhere in the table."""
    entries = {"1": 10001, "88": 0, "91": 0}
    (count, sample), _ = _scan(entries, own_uid=10001, readable=[88, 91])
    assert (count, sample) == (2, [88, 91])
