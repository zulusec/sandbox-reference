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
  writability is removed immediately.
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
for base in ('/etc', '/usr', '/'):
    marker = os.path.join(base, '.sandbox_probe_write_check')
    try:
        with open(marker, 'w') as handle:
            handle.write('ok')
    except OSError:
        continue
    writable.append(base)
    try:
        os.remove(marker)
    except OSError:
        pass
result['writable_outside'] = sorted(writable)

try:
    marker = os.path.join(os.getcwd(), '.sandbox_probe_write_check')
    with open(marker, 'w') as handle:
        handle.write('ok')
    os.remove(marker)
    result['workspace_writable'] = True
except OSError:
    result['workspace_writable'] = False
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

        return ProbeOutcome(findings=findings, control_ok=writable)


register(FilesystemProbe())
