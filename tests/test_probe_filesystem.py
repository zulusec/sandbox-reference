import json

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
    "proc_environ": False,
    "runtime_sockets": [],
    "workspace_writable": True,
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


def test_payload_writability_checks_clean_up_after_themselves():
    """The payload must remove any marker file it creates: once for the
    system-directory writability checks, once for the workspace positive
    control."""
    assert PAYLOAD_BODY.count("os.remove(marker)") >= 2
