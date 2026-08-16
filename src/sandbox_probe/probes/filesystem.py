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
  overwrite the write result (see write_marker below). A stray marker left
  in a system directory must be reported, and a removal that failed must
  never make a successful write read as a failed one.
- /proc/<pid>/environ across every visible process: the environment of any
  process the sandbox does not own, established by comparing that process's
  owning uid against the payload's own before the read is attempted.

  An unconditional read of /proc/1/environ is not a signal. Reading the
  environ of a same-uid process is ordinary procfs behavior and succeeds in
  every container that runs its workload under one uid, the compliant
  reference sandbox included, where PID 1 is the sandbox's own init holding
  the environment the payload already has. Yama does not change that:
  ptrace_scope only tracks PTRACE_MODE_ATTACH, while /proc/pid/environ is
  read under PTRACE_MODE_READ, so the ordinary same-uid check is what
  applies.

  Narrowing that read to a foreign owner but keeping it pinned to PID 1 is
  not a signal either, for the same reason from the other direction: PID 1
  is the sandbox's own init on both a compliant sandbox and a wide-open
  one, so the check short-circuits on both. The configuration that actually
  loses this invariant is a sandbox sharing the host's PID namespace with
  enough privilege to read across it, and the processes it can read then
  have unpredictable pids. Measured on a privileged --pid=host container,
  a PID-1-only check reports nothing while 218 foreign process
  environments are in fact readable. So the whole visible process table is
  scanned, bounded, and the finding reports how many environments were
  readable and the distinct uids owning them.

  It reports no pid, because a pid is a generated identifier that is gone
  by the time anyone reads the report and tells the reader nothing they
  can act on, and reports no environment content or command line at all.
  Rated HIGH: this is arbitrary credential exposure, the same class the
  credentials probe rates HIGH for the sandbox's own environment, and
  strictly worse in reach.
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

from sandbox_probe.evidence import LIST_LIMIT, bounded, overflow_finding
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

def foreign_process_environs(scan_limit=2048):
    # The invariant is that the sandbox cannot read the environment of a
    # process it does not own, so this measures exactly that and nothing
    # else: walk the numeric entries under /proc, and for every one whose
    # owning uid differs from this payload's own, try to open its environ.
    #
    # Reading the environ of a same-uid process is ordinary procfs
    # behavior, not a containment failure, so those are skipped. Looking
    # only at PID 1 was not enough: PID 1 is the sandbox's own init in any
    # ordinary container, running as the same uid as the payload, so a
    # PID-1-only check short-circuits on a correctly built sandbox and on
    # an all-root one alike and measures nothing either way. The case that
    # matters is a sandbox sharing the host's PID namespace with enough
    # privilege to read across it, and there the readable environments
    # belong to processes whose pids nobody can predict in advance. Only a
    # scan finds them.
    #
    # This needs no namespace detection and no fingerprinting, which is
    # the point: it tests the invariant directly rather than testing for
    # a configuration that would imply it.
    #
    # Ownership is established before the read, never inferred from it. A
    # process whose owner cannot be determined supports no claim about
    # whose it is, so it is skipped rather than counted.
    #
    # scan_limit bounds the walk so a host with thousands of processes
    # cannot stall the probe. Walking in numeric order matters because of
    # that slice: ordering by string would make which processes get
    # scanned depend on how the kernel happened to lay out the directory.
    #
    # What comes back is a count and the distinct uids owning those
    # processes. No pid. A pid is a generated identifier: it is gone by
    # the time anyone reads the report and there is nothing a reader can
    # do with it. The count and the owning uids describe the shape of the
    # exposure and are stable for a given target state. Environment
    # contents and command lines never leave the sandbox at all, the same
    # rule the credentials probe follows for variable values: this
    # reports that a foreign environment was readable, never what was in
    # it or whose program it was.
    own = os.getuid()
    try:
        pids = sorted(int(name) for name in os.listdir('/proc') if name.isdigit())
    except OSError:
        return 0, []
    count = 0
    owners = set()
    for pid in pids[:scan_limit]:
        try:
            owner = os.stat('/proc/' + str(pid)).st_uid
        except OSError:
            continue
        if owner == own:
            continue
        try:
            with open('/proc/' + str(pid) + '/environ', 'rb') as handle:
                handle.read(1)
        except OSError:
            continue
        count += 1
        owners.add(owner)
    return count, sorted(owners)

foreign_count, foreign_uids = foreign_process_environs()
result['foreign_environ_count'] = foreign_count
result['foreign_environ_uids'] = foreign_uids

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


def _foreign_count(value) -> int:
    """The scan's count, or zero for anything that is not a real count.

    inner comes from the system under test, so a bool (which subclasses int
    in Python) or a string must not be allowed to stand in for a number of
    readable processes.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _foreign_uids(value) -> list:
    """The distinct owning uids, from a value the system under test supplied.

    Anything that is not a plain non-negative integer is discarded, bools
    included since they subclass int.
    """
    if not isinstance(value, list):
        return []
    return sorted({
        item for item in value
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0
    })


def _foreign_environ_evidence(count: int, uids: list) -> str:
    """Name how many foreign environments opened and which uids own them.

    No pid: a pid is a generated identifier, gone by the time anyone reads
    the report and carrying nothing a reader can act on. No environment
    contents and no command line either. The credentials probe names
    variables without their values for the same reason: a posture tool that
    copies a secret into its own report has moved it, not found it.

    The uid list is bounded here rather than in the payload because inner
    comes from the system under test, and a hostile target must not be able
    to write an unbounded string into this harness's report. The bound is
    the shared one every probe uses on a target-supplied list, so there is
    one number to reason about rather than one per probe.
    """
    shown = ", ".join(str(uid) for uid in uids[:LIST_LIMIT])
    if len(uids) > LIST_LIMIT:
        shown = f"{shown} and {len(uids) - LIST_LIMIT} more"
    owner_noun = "uid" if len(uids) == 1 else "uids"
    owners = f"{len(uids)} distinct owning {owner_noun} ({shown})" if uids else (
        "an unrecorded set of owning uids"
    )
    noun = "environment" if count == 1 else "environments"
    return (
        f"{count} process {noun} owned by a different user could be opened from "
        f"inside the sandbox, across {owners}. Reading a process the sandbox does "
        "not own needs root or CAP_SYS_PTRACE, and a process environment is where "
        "credentials sit. No pid, environment content, or command line is "
        "reproduced here."
    )


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

        # Every path below arrived from inside the sandbox, so every one of
        # them is cleaned and bounded before it reaches a finding or an
        # error. Both of those get written to an operator's terminal.
        findings = []
        errors = []
        readable, dropped_readable = bounded(inner.get("readable_outside"))
        for path in readable:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                title="A path outside the workspace is readable",
                evidence=f"{path} was read from inside the sandbox",
            ))
        listed, dropped_listed = bounded(inner.get("listed_outside"))
        for path in listed:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                title="A host mount is exposed inside the sandbox",
                evidence=(
                    f"{path} was listed from inside the sandbox. A host-mount "
                    "marker directory should not exist at all in a contained sandbox."
                ),
            ))
        writable_paths, dropped_writable = bounded(inner.get("writable_outside"))
        for path in writable_paths:
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
        dropped_outside = dropped_readable + dropped_listed + dropped_writable
        if dropped_outside:
            findings.append(overflow_finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="outside_workspace", severity=Severity.HIGH,
                dropped=dropped_outside, kind="paths outside the workspace",
            ))
        stray, dropped_stray = bounded(inner.get("cleanup_failed_outside"))
        for path in stray:
            errors.append(ProbeError(
                self.probe_id, target.name, "cleanup",
                f"wrote a marker file into {path} to test writability but could "
                "not remove it afterward; .sandbox_probe_write_check may remain "
                "there. The write itself is still reported above.",
            ))
        if dropped_stray:
            errors.append(ProbeError(
                self.probe_id, target.name, "cleanup",
                f"{dropped_stray} further paths were reported as holding a marker "
                "file that could not be removed. They are counted rather than "
                "listed: the list comes from the system under test and is bounded "
                f"at {LIST_LIMIT} entries.",
            ))
        foreign_count = _foreign_count(inner.get("foreign_environ_count"))
        if foreign_count:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="proc_environ", severity=Severity.HIGH,
                title="Process environments the sandbox does not own are readable",
                evidence=_foreign_environ_evidence(
                    foreign_count, _foreign_uids(inner.get("foreign_environ_uids")),
                ),
            ))
        sockets, dropped_sockets = bounded(inner.get("runtime_sockets"))
        for path in sockets:
            findings.append(Finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="runtime_socket", severity=Severity.HIGH,
                title="A container runtime socket is present in the sandbox",
                evidence=(
                    f"{path} exists. Access to the runtime socket is equivalent "
                    "to control of the host."
                ),
            ))
        if dropped_sockets:
            findings.append(overflow_finding(
                probe_id=self.probe_id, subject=target.name,
                rule_key="runtime_socket", severity=Severity.HIGH,
                dropped=dropped_sockets, kind="runtime sockets",
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
