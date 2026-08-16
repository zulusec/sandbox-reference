# sandbox-reference

Containment probes for agent sandboxes.

A harness that asks whether a sandbox you run an AI agent in actually enforces
six containment invariants: no ambient network, no ambient credentials, no
ambient filesystem, bounded and disposable, attributable, and detected. It
ships six probes, a minimal reference sandbox that passes them, and a
deliberately leaky fixture that fails them. The probes are vendor neutral: a
target is anything the harness can run a command inside, described by a small
JSON config, so the same six probes work against Compose on a laptop, a
virtual machine over SSH, or anything else that can exec.

Its sibling repository is
[`posture-reference`](https://github.com/zulusec/posture-reference), which
applies the same discipline to cloud posture: findings that are reproducible,
and a run that never reports clean for anything it did not measure.

## What it is not

- **Not a product, and not maintained as one.** It is a reference
  implementation, published as evidence of how the work is built.
- **Not a kernel isolation boundary.** Containers do not stop a determined
  kernel exploit. These invariants contain consequences (reach, credentials,
  data, blast radius), not escapes. Saying otherwise under a security brand
  would be a lie.
- **Not a prompt-injection detector.** The honest control there is a process
  gate on the agent's output, not a runtime check inside the sandbox.
- **Not a general escape toolkit.** The probes assert configuration properties
  of a sandbox the operator owns. They are not exploit code.
- **Not complete coverage.** It cannot detect confused-deputy attacks. See
  [Limitations](#limitations), which are stated in full rather than buried.

## Run it in one command

No cloud account and no credentials are required. Everything runs locally
against containers, and every hostname the reference uses ends in `.invalid`,
which RFC 2606 reserves so it can never resolve for anyone. You need Python
3.11 or newer and Docker with Compose v2.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
docker compose -f reference/docker-compose.yml up -d --build
sandbox-probe
```

Real output from that last command, in a clean checkout:

```console
$ sandbox-probe
CONTAINED. Every probe ran, no findings.
$ echo $?
0
```

`CONTAINED` appears only when every registered probe ran and none of them
found anything. An incomplete run, or a run that covered only a subset of the
probes, can never print it.

Bring the stack down when you are finished:

```bash
docker compose -f reference/docker-compose.yml down -v
```

The reference sandbox is described in [`reference/README.md`](reference/README.md).
One thing there is worth repeating here: the broker forwards nothing. It
answers `403` for a denied host and `502` for an allowed one, and never opens
a connection outward. Giving the reference sandbox real internet egress in
order to demonstrate containment would defeat the exercise. What the reference
shows is the decision boundary, not a working egress path.

## See it fail

A harness you have never seen fail is a harness you have no reason to trust.
So the repository also ships a sandbox that is wrong in every way a real
deployment is wrong by default: no network boundary, the host filesystem
mounted in, the container runtime socket handed over, credentials in
environment variables, no resource limits, running as root.

Take that literally before you start it. While this fixture is up, a container
on your machine holds your host filesystem read-only and your Docker socket
read-write, which is what makes the findings real. Bring it down as soon as
you have seen the output, and never use it as a starting point for anything.

```bash
docker compose -f fixtures/leaky/docker-compose.yml up -d
sandbox-probe --target fixtures/leaky/target.json
```

Real output from that last command:

```console
$ sandbox-probe --target fixtures/leaky/target.json
POSITIVE CONTROL FAILED: attribution, bounds, detection
These probes could not confirm they were testing a reachable target.
An empty result from them means nothing was measured, not that
nothing was found.

HIGH    attribution  no_request_log
        The target has no request log
        No request log is configured for this target. Boundary crossings cannot be reconstructed afterward, which is the difference between an incident and a mystery.

HIGH    bounds  no_reset_configured
        The sandbox has no reset path
        No reset command is configured for this target, so disposability cannot be demonstrated and state carries from one task to the next.

HIGH    credentials  env_secret
        A credential is present in the sandbox environment
        environment variable AWS_SECRET_ACCESS_KEY holds a secret-shaped value. The value is deliberately not reproduced here.

HIGH    credentials  env_secret
        A credential is present in the sandbox environment
        environment variable DATABASE_PASSWORD holds a secret-shaped value. The value is deliberately not reproduced here.

HIGH    detection  no_event_channel
        The target has no alert channel
        No event channel is configured. A policy violation produces no alert, so the only way anyone learns of it is by reading the log afterward.

HIGH    filesystem  outside_workspace
        A path outside the workspace is readable
        /etc/shadow was read from inside the sandbox

HIGH    filesystem  outside_workspace
        A host mount is exposed inside the sandbox
        /host was listed from inside the sandbox. A host-mount marker directory should not exist at all in a contained sandbox.

HIGH    filesystem  outside_workspace
        A path outside the workspace is writable
        / was written to from inside the sandbox. A correctly built sandbox has a read-only root, so nothing outside the declared workspace should be writable.

HIGH    filesystem  outside_workspace
        A path outside the workspace is writable
        /etc was written to from inside the sandbox. A correctly built sandbox has a read-only root, so nothing outside the declared workspace should be writable.

HIGH    filesystem  outside_workspace
        A path outside the workspace is writable
        /usr was written to from inside the sandbox. A correctly built sandbox has a read-only root, so nothing outside the declared workspace should be writable.

HIGH    filesystem  runtime_socket
        A container runtime socket is present in the sandbox
        /run/docker.sock exists. Access to the runtime socket is equivalent to control of the host.

HIGH    filesystem  runtime_socket
        A container runtime socket is present in the sandbox
        /var/run/docker.sock exists. Access to the runtime socket is equivalent to control of the host.

HIGH    network  blocked_egress
        The sandbox reached a host that is not on the allowlist
        opened a TCP connection to unauthorized:80

MEDIUM  bounds  memory_uncapped
        No memory limit is configured
        The sandbox cgroup reports no memory ceiling, so one task can exhaust the host.

MEDIUM  bounds  wallclock_uncapped
        No wall-clock limit is configured
        The target declares no wall-clock bound. A wall-clock cap is enforced by whatever invokes the task (an agent framework's task timeout, a scheduler deadline, a CI job timeout), not by the sandbox itself, and nothing here declares one.
$ echo $?
2
```

The exit code is worth dwelling on, because it is not 3. This target has no
broker, so it has no request log, no event channel, and no reset path, which
means three probes could not confirm they were testing anything at all. Their
positive controls failed. That makes the run incomplete, and incomplete
outranks findings-present: the harness reports the strongest true statement it
can, which here is that some of these checks were not measured, not that this
is the complete list of what is wrong with this sandbox. A leaky target is
usually also an unmeasurable one, and that is the honest result.

Bring it down when you are finished:

```bash
docker compose -f fixtures/leaky/docker-compose.yml down -v
```

Full detail is in [`fixtures/leaky/README.md`](fixtures/leaky/README.md).

## The six invariants

Each invariant gets one probe. Every finding carries a `rule_key` and a fixed
severity, so a result can be diffed between runs and tracked over time.

### 1. No ambient network, and the broker is not a trusted zone

Probe id `network`. The sandbox has no route to anything by default, and all
egress passes a broker applying an allowlist. Three questions, not one: can
the sandbox reach a host it should not, can it resolve names (the exfiltration
path an HTTP allowlist never sees), and can it reach the classes of host that
serve as staging and command-and-control. An allowlisted destination is not a
trusted destination: package registries, pastebins, request-capture services,
and file-drop hosts are exfiltration channels whether or not the hostname is on
the list.

| Rule key | Severity |
| --- | --- |
| `blocked_egress` | HIGH |
| `dns_canary` | HIGH |
| `c2_channel` | HIGH |

Positive control: the broker answers a request for the allowed host with
something other than a denial. In a correctly contained sandbox nothing is
directly reachable, so the control cannot be direct reachability of the
allowed host. A target with no `proxy` configured falls back to direct
reachability of `allowed_host`.

### 2. No ambient credentials

Probe id `credentials`. Secrets never enter the sandbox. The three places a
credential turns up in practice, in the order the July 2026 OpenAI and Hugging
Face incident found them: the process environment, a mounted token file, and
the cloud metadata service. That incident is cited here as a dated example of
why these invariants are drawn where they are, not as the subject of the
repository.

| Rule key | Severity |
| --- | --- |
| `env_secret` | HIGH |
| `credential_file` | HIGH |
| `imds_reachable` | HIGH |
| `imds_hop_limit` | HIGH |

Findings name the variable or the path and never print the value. The
secret-shaped check runs inside the target process, so no environment value
ever crosses out of the sandbox. A posture tool that copies secrets into its
own report has moved them, not found them. This probe needs no positive
control: absence of a secret is directly observable in a way that absence of
egress is not.

### 3. No ambient filesystem

Probe id `filesystem`. An explicitly mounted workspace and nothing else. No
host filesystem, no other tenants, no container runtime socket.

| Rule key | Severity |
| --- | --- |
| `outside_workspace` | HIGH |
| `runtime_socket` | HIGH |
| `proc_environ` | HIGH |
| `workspace_missing` | MEDIUM |

Candidate paths are chosen to be genuine containment-failure signals rather
than artifacts of an ordinary Linux filesystem: host-mount marker directories,
runtime sockets, `/etc/shadow` as a content read rather than a stat, writability
outside the declared workspace, and the environment of any process owned by a
different uid. Positive control: the workspace is actually writable, because a
sandbox with no usable workspace passes every negative test by being useless.

### 4. Bounded and disposable

Probe id `bounds`. Memory, process, and wall-clock ceilings, and a sandbox
that is reset between tasks such that persistence across runs is not
achievable. Persistence is what turns one bad task into a foothold.

| Rule key | Severity |
| --- | --- |
| `persists_across_runs` | HIGH |
| `no_reset_configured` | HIGH |
| `memory_uncapped` | MEDIUM |
| `pids_uncapped` | MEDIUM |
| `wallclock_uncapped` | MEDIUM |

Caps are read from the sandbox's own cgroup view rather than tested by
exhaustion. Allocating memory until the kernel intervenes would be a denial of
service against the machine running the harness, and the question the invariant
asks is whether a limit is configured. Two of these keys are weaker than the
rest and both are disclosed under [Limitations](#limitations).

### 5. Attributable

Probe id `attribution`. Every boundary crossing is recorded well enough to
reconstruct afterward what the agent reached, when, and on whose authority. In
the July 2026 incident roughly 17,600 attacker actions were reconstructed from
logs like these, and that reconstruction is the only reason anyone knows what
happened.

| Rule key | Severity |
| --- | --- |
| `no_request_log` | HIGH |
| `crossing_unlogged` | HIGH |
| `decision_missing` | MEDIUM |

The probe generates a known set of crossings and compares only the log lines
appended during that window. A whole-log comparison would be satisfied by a
stale entry from an earlier run, so a second consecutive run would report clean
with the broker dead. That is a false clean, the worst failure mode a
containment harness has.

### 6. Detected

Probe id `detection`. Attribution is not detection. A crossing that violates
policy raises an alert, at the correct severity, when it happens. In July 2026
the logs were good enough to reconstruct the whole intrusion and the alerting
still failed to elevate criticality, so the response arrived late. A system can
produce perfect forensics and still fail.

| Rule key | Severity |
| --- | --- |
| `no_event_channel` | HIGH |
| `violation_unalerted` | HIGH |
| `severity_understated` | MEDIUM |
| `channel_not_separated` | MEDIUM |

`channel_not_separated` asks whether the event channel carries violations only
rather than every request. It needs a window containing both an allowed and a
denied crossing; when it does not get one, the probe records that it could not
evaluate rather than clearing silently, because a check nobody evaluated must
never be indistinguishable from a check that passed.

### The seventh invariant, which is not a probe

The agent's output is untrusted input. Anything leaving the sandbox (code, a
pull request, a message) crosses a review or policy gate. A sandbox that
contains perfectly and then merges automatically contains nothing. That is a
process gate rather than a runtime property, so this harness does not test it
and does not pretend to.

## Limitations

Four of them, stated here rather than buried, because a harness implying
coverage it does not have would be worse than no harness.

**1. Confused-deputy attacks are out of reach.** The harness tests what the
sandbox itself can reach. It cannot detect an attack where the agent supplies
data that causes a privileged component to read or execute on its behalf. The
sandbox never touches the resource; something trusted touches it on the
sandbox's behalf, and from inside the sandbox that is invisible. Both initial
data-theft vectors in the July 2026 OpenAI and Hugging Face incident were of
this class. Six clean probes do not mean a sandbox is safe from this, and
nothing in this repository should be read as saying otherwise.

**2. The wall-clock bound is declared, not measured.** `wallclock_uncapped`
fires when the target config declares no `wallclock_limit_seconds`. It does not
fire because a limit was tested and found missing. The harness cannot verify a
declared limit is actually enforced without deliberately hanging a task for its
full duration, which would be an unacceptable thing to put in a test suite and
would hang forever against a target with no limit at all. A wall-clock bound
genuinely lives in whatever invokes the task (an agent framework's timeout, a
Kubernetes `activeDeadlineSeconds`, a CI job limit) rather than in the
sandbox's own configuration, which is why it is modeled as a declaration. A
target can satisfy this check by declaring a limit nothing enforces.

**3. `pids_uncapped` reports the effective cgroup limit, which may come from a
daemon default.** A container can read a large `pids.max` it was never
configured with, so this check can read as capped on a sandbox whose operator
set no process limit at all. This is measured, not theoretical: the leaky
fixture in this repository sets no `pids_limit`, and on the machine where this
was written its container reads back `pids.max=34592` from the Docker daemon
default, so the key does not trip on the one target built to fail everything.
That is why it is deliberately excluded from the end-to-end assertions. A threshold for "implausibly high"
would be arbitrary and wrong on some other host, so the probe reports the
effective value truthfully and this section says what that value means.

**4. Containers are not a kernel boundary.** These invariants contain
consequences, not escapes, and a determined kernel exploit is outside what any
of them measure. It is listed under
[What it is not](#what-it-is-not) as well, because it is the same discipline
seen from the other side.

## Probing your own sandbox

A target is any sandbox the harness can run a command inside. Everything
vendor-specific lives in one JSON file, which is why the same six probes work
against Docker Compose, a virtual machine, or a runtime that has not been
written yet.

The inner payload is delivered on the command's standard input rather than as
an argument, so the harness never has to quote code through someone else's exec
wrapper. `exec_command` must therefore end in something that reads a program
from stdin, such as `python3 -`.

### Required keys

| Key | Type | What it is |
| --- | --- | --- |
| `name` | string | The target's name. It appears as the `subject` on every finding. |
| `exec_command` | list of strings | Runs a command inside the sandbox, reading the payload from stdin. |
| `allowed_host` | string | A host the sandbox is legitimately permitted to reach. Used as the network probe's positive control. |
| `blocked_host` | string | A host the sandbox must not reach. It has to genuinely resolve and answer, or the check cannot tell a contained sandbox from an unreachable name. |

### Optional keys

| Key | Type | What it is, and what its absence means |
| --- | --- | --- |
| `c2_hosts` | list of strings | Staging and command-and-control class hosts (pastebins, request-capture services, file drops). Absent means `c2_channel` is not exercised. |
| `proxy` | string, `host:port` | The egress broker. When set, the network positive control and the attribution and detection crossings go through it in absolute-URI form. When absent, those probes fall back to direct reachability, which is honest about proving less. |
| `request_log_command` | list of strings | Run outside the sandbox; prints the broker's request log on stdout. Absent produces `no_request_log`. |
| `events_command` | list of strings | Run outside the sandbox; prints the alert channel on stdout. Absent produces `no_event_channel`. |
| `reset_command` | list of strings | Resets the sandbox to a clean state. Absent produces `no_reset_configured`, because a sandbox nobody can reset carries state from one task to the next by definition. |
| `wallclock_limit_seconds` | integer | Declares that something outside the sandbox bounds task duration. Absent produces `wallclock_uncapped`. Read limitation 2 before relying on this key. |

Malformed configs are rejected with one line a reader can act on rather than a
traceback: the four required keys must be present, the four command keys must
be lists of strings, `proxy` must be a string, and `wallclock_limit_seconds`
must be an integer (`true` is not an integer here, even though Python's `bool`
is a subclass of `int`).

### A worked example that is not Compose

A long-lived virtual machine reached over SSH, with a separate broker host and
a hypervisor that can revert it to a clean snapshot. Nothing about the probes
changes; only this file does. The hosts below are documentation names under
RFC 2606's reserved `.example` domain, so this config is a shape to copy
rather than something you can run here.

```json
{
  "name": "agent-vm",
  "exec_command": ["ssh", "agent-vm.example", "python3", "-"],
  "allowed_host": "packages.internal.example",
  "blocked_host": "unauthorized.internal.example",
  "c2_hosts": ["paste.example", "requestcapture.example", "filedrop.example"],
  "proxy": "broker.internal.example:3128",
  "request_log_command": ["ssh", "broker.example", "cat", "/var/log/broker/requests.log"],
  "events_command": ["ssh", "broker.example", "cat", "/var/log/broker/events.log"],
  "reset_command": ["ssh", "hypervisor.example", "virsh", "snapshot-revert", "agent-vm", "clean"],
  "wallclock_limit_seconds": 900
}
```

Save that file wherever you keep it, and point the harness at it:

```bash
sandbox-probe --target targets/agent-vm.json
sandbox-probe --target targets/agent-vm.json --json
```

`--json` emits findings alongside a metadata block carrying `complete`, the
errors, the failed positive controls, and both the probes that ran and the
full registered set. Findings carry no timestamp, no duration, and no
generated identifier, so the same target state produces the same findings byte
for byte, and a test asserts it.

### Running a subset

```bash
sandbox-probe --list-probes
sandbox-probe --probe network
```

A `--probe` subset run always exits 2, even when it finds nothing, because a
subset is not a complete assessment. It exists for iteration and debugging.
Anything gating on containment must run the full set. Real output of the
second command against the reference sandbox:

```console
$ sandbox-probe --probe network
PARTIAL RUN: 1 of 6 probes selected (network).
This is not a full assessment. A pipeline must not read this run's
exit code as containment.

No findings in what could be measured.
$ echo $?
2
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every registered probe ran, and none of them found anything. The sandbox held. |
| 1 | The run could not start. A bad target config, or a target the harness could not reach. |
| 2 | The run was incomplete. A probe could not run, a positive control failed, or the run covered only a subset of the probes. |
| 3 | Containment findings are present. |

Code 2 outranks code 3. A run with both gaps and findings reports 2, because
the findings alone are not the full picture and a shorter list of findings is
otherwise indistinguishable from a cleaner sandbox.

Code 0 is the only code that means the sandbox was assessed and held, so a
pipeline treating it that way cannot be handed that claim by a partial run.

## Authorization

Run this only against sandboxes you own or are authorized to assess.

The probes assert configuration properties of a sandbox the operator controls.
They are not exploit code and they do not attempt to break out of anything.
They do open network connections, read files, write and remove a marker
outside the workspace to test writability, and request a reset if one is
configured, all of which is intrusive enough that pointing it at someone
else's infrastructure is not yours to do.

## Getting this built

Designing and building containment like this is the
[Zero-Trust Architecture](https://zulusec.com/services/zero-trust) service
line. Teams who want the tooling itself built, tested, and wired into a
pipeline are the
[Automation Engineering](https://zulusec.com/services/automation) line.

## License

MIT. See [`LICENSE`](LICENSE).

---

Built by [ZuluSec](https://zulusec.com).
