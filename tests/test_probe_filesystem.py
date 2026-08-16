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
    "proc_environ": False,
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
    outcome = FilesystemProbe().run(_target(dict(_CLEAN, proc_environ=True)))
    assert "proc_environ" in _keys(outcome)
    finding = next(f for f in outcome.findings if f.rule_key == "proc_environ")
    assert finding.severity.value == "MEDIUM"


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

def _load_write_marker():
    prefix, marker, _ = PAYLOAD_BODY.partition("\nreadable = []")
    assert marker, "PAYLOAD_BODY layout changed; update the split point in this test"
    namespace: dict = {"os": os}
    exec(prefix, namespace)  # noqa: S102 -- exercising the payload's own source
    return namespace["write_marker"]


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
