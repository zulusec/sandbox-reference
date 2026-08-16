"""Invariant 3: no ambient filesystem.

An explicitly mounted workspace and nothing else. The positive control here
is that the workspace is actually writable, because a sandbox with no usable
workspace passes every negative test by being useless.

Candidate paths (each a genuine containment-failure signal, not an artifact
of an ordinary Linux filesystem):

- /host, /hostfs: host-mount markers. These do not exist in a normal base
  image; their presence, checked by directory listing, means someone
  mounted the host filesystem in.
- /etc/shadow: checked as a content read (open and read a byte), not a stat
  or an existence check. The file exists in every image; being able to read
  it is the finding.
- /etc, /usr, /: checked for writability, not mere readability. In a
  correctly built sandbox the root filesystem is read-only, so nothing
  outside the declared workspace is writable. Anything written here to test
  writability is removed immediately. Write and removal are tracked
  separately: if the write succeeds but the removal fails, that is
  surfaced as its own error rather than silently discarded or allowed to
  overwrite the write result (see write_marker below and Finding 1/2 of
  the review that added this).
- /proc/1/environ: another process's environment.
- container runtime sockets: docker.sock, containerd.sock, crio.sock.

/home, /var/lib, and a bare /root listing are deliberately not probed: they
exist and are world-listable in essentially every base image, including the
compliant reference sandbox, so flagging them would be a false positive
against an ordinary filesystem rather than a containment failure. A
traversal read of /workspace/../etc/hostname was considered and dropped for
the same reason: /etc/hostname is world-readable in any ordinary container
(Docker manages the file itself), so a bare successful read of it is
guaranteed on the compliant reference sandbox too and carries no signal.
"""

from __future__ import annotations

from sandbox_probe.finding import Finding, Severity
from sandbox_probe.inner import InnerProtocolError, emit, parse_inner
from sandbox_probe.probes import register
from sandbox_probe.result import ProbeError, ProbeOutcome
from sandbox_probe.target import ExecResult, Target

_TIMEOUT = 60

PAYLOAD_BODY = """
def write_marker(base):
    # Shared by the outside-writability loop and the workspace positive
    # control below, so both report write and removal as two independent
    # facts instead of drifting into two different shapes of the same
    # check. Returns (wrote, removed): wrote is True the moment the file is
    # written, before removal is attempted, so a removal failure can never
    # retroactively make a successful write look like a failed one.
    marker = os.path.join(base, '.sandbox_probe_write_check')
    try:
        with open(marker, 'w') as handle:
            handle.write('ok')
    except OSError:
        return False, False
    try:
        os.remove(marker)
    except OSError:
        return True, False
    return True, True

readable = []
try:
    with open('/etc/shadow', 'rb') as handle:
        handle.read(1)
    readable.append('/etc/shadow')
except OSError:
    pass
result['readable_outside'] = sorted(readable)

listed = []
for path in ('/host', '/hostfs'):
    try:
        os.listdir(path)
        listed.append(path)
    except OSError:
        pass
result['listed_outside'] = sorted(listed)

try:
    with open('/proc/1/environ', 'rb') as handle:
        handle.read(1)
    result['proc_environ'] = True
except OSError:
    result['proc_environ'] = False

sockets = []
for path in ('/var/run/docker.sock', '/run/docker.sock',
             '/run/containerd/containerd.sock', '/var/run/crio/crio.sock'):
    if os.path.exists(path):
        sockets.append(path)
result['runtime_sockets'] = sorted(sockets)

writable = []
cleanup_failed = []
for base in ('/etc', '/usr', '/'):
    wrote, removed = write_marker(base)
    if wrote:
        writable.append(base)
        if not removed:
            cleanup_failed.append(base)
result['writable_outside'] = sorted(writable)
result['cleanup_failed_outside'] = sorted(cleanup_failed)

workspace_wrote, workspace_removed = write_marker(os.getcwd())
result['workspace_writable'] = workspace_wrote
result['workspace_cleanup_failed'] = workspace_wrote and not workspace_removed
"""


def _exec_failure_detail(base: str, executed: ExecResult) -> str:
    """Fold the exec result's returncode and stderr into an error detail.

    Without this, a dead container, a timeout, and a genuine protocol
    violation all collapse into the same message, "inner payload produced
    no marked result line", and an operator cannot tell a target-side
    problem from a probe-side one.
    """
    detail = base
    if executed.returncode != 0:
        detail += f" (exit code {executed.returncode})"
    if executed.stderr.strip():
        detail += f"; stderr: {executed.stderr.strip()}"
    return detail


class FilesystemProbe:
    probe_id = "filesystem"

    def run(self, target: Target) -> ProbeOutcome:
        executed = target.run_inside([emit(PAYLOAD_BODY)], timeout=_TIMEOUT)
        try:
            inner = parse_inner(executed.stdout)
        except InnerProtocolError as error:
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    _exec_failure_detail(str(error), executed),
                )],
                control_ok=False,
            )

        if not isinstance(inner, dict):
            return ProbeOutcome(
                errors=[ProbeError(
                    self.probe_id, target.name, "exec",
                    f"inner result was not a JSON object: {inner!r}",
                )],
                control_ok=False,
            )

        findings = []
        errors = []
        for path in inner.get("readable_outside", []):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                title="A path outside the workspace is readable",
                evidence=f"{path} was read from inside the sandbox",
            ))
        for path in inner.get("listed_outside", []):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                title="A host mount is exposed inside the sandbox",
                evidence=(
                    f"{path} was listed from inside the sandbox. A host-mount "
                    "marker directory should not exist at all in a contained sandbox."
                ),
            ))
        for path in inner.get("writable_outside", []):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                title="A path outside the workspace is writable",
                evidence=(
                    f"{path} was written to from inside the sandbox. A correctly "
                    "built sandbox has a read-only root, so nothing outside the "
                    "declared workspace should be writable."
                ),
            ))
        for path in inner.get("cleanup_failed_outside", []):
            errors.append(ProbeError(
                self.probe_id, target.name, "cleanup",
                f"wrote a marker file into {path} to test writability but could "
                "not remove it afterward; .sandbox_probe_write_check may remain "
                "there. The write itself is still reported above.",
            ))
        if inner.get("proc_environ"):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="proc_environ", severity=Severity.MEDIUM,
                title="Another process environment is readable",
                evidence=(
                    "/proc/1/environ was readable, which exposes the environment "
                    "of a process the sandbox does not own."
                ),
            ))
        for path in inner.get("runtime_sockets", []):
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="runtime_socket", severity=Severity.HIGH,
                title="A container runtime socket is present in the sandbox",
                evidence=(
                    f"{path} exists. Access to the runtime socket is equivalent "
                    "to control of the host."
                ),
            ))

        writable = bool(inner.get("workspace_writable"))
        if not writable:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="workspace_missing", severity=Severity.MEDIUM,
                title="The workspace is not writable",
                evidence=(
                    "The working directory could not be written. A clean "
                    "filesystem result from an unusable sandbox measures nothing."
                ),
            ))
        if inner.get("workspace_cleanup_failed"):
            errors.append(ProbeError(
                self.probe_id, target.name, "cleanup",
                "wrote a marker file into the workspace to exercise the "
                "writable positive control but could not remove it afterward; "
                ".sandbox_probe_write_check may remain there. The workspace "
                "is still reported as writable above.",
            ))

        return ProbeOutcome(findings=findings, errors=errors, control_ok=writable)


register(FilesystemProbe())
