# sandbox-reference

Containment probes for agent sandboxes.

A harness that asks whether a sandbox you run an AI agent in actually enforces
six containment invariants: no ambient network, no ambient credentials, no
ambient filesystem, bounded and disposable, attributable, and detected. It
ships six probes, a minimal reference sandbox that passes them, and a
deliberately leaky fixture that fails them. The probes are built to be vendor
neutral: a target is anything the harness can run a command inside, described
by a small JSON config, so the same six probes are meant to work against
Compose on a laptop, a virtual machine over SSH, or anything else that can
exec. Compose is the only shape demonstrated in this repository.

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
against containers. The named hosts the reference target uses end in
`.invalid`, which RFC 2606 reserves so they can never resolve for anyone, and
the two things it points at the outside world are chosen to be inert: a TCP
connection attempt to `1.1.1.1:443`, and a DNS lookup of `example.com`. Both
are checks that fire only on a sandbox that should not have reached them.
Neither is required for the suite to pass. You need Python 3.11 or newer and
Docker with Compose v2.

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
        The sandbox has a route to the public internet
        opened a TCP connection to 1.1.1.1:443, an address literal that needs no name resolution. Ambient egress, whatever the allowlist says.

HIGH    network  blocked_egress
        The sandbox reached a host that is not on the allowlist
        opened a TCP connection to unauthorized:80

HIGH    network  dns_canary
        The sandbox resolved a public name
        resolved example.com. Name resolution is an exfiltration channel that an HTTP allowlist does not cover.

MEDIUM  bounds  memory_uncapped
        No memory limit is configured
        The sandbox cgroup reports no memory ceiling, so one task can exhaust the host.

MEDIUM  bounds  wallclock_uncapped
        No wall-clock limit is configured
        The target declares no wall-clock bound. A wall-clock cap is enforced by whatever invokes the task (an agent framework's task timeout, a scheduler deadline, a CI job timeout), not by the sandbox itself, and nothing here declares one.
$ echo $?
2
```

Two of those lines depend on the machine you run this on having internet
access: the route to `1.1.1.1:443` and the resolution of `example.com`. On a
machine with no internet they are absent, and the third network line, the one
that reaches a container inside the fixture, is still there. That asymmetry is
deliberate. A check that needs the outside world can add a finding but must
never be what a clean result rests on.

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

These tables are the full reference of all 23 rule keys, not a list of what
the demo above exercises. The leaky fixture trips nine of them end to end, and
they are exactly the nine in its output: `blocked_egress`, `env_secret`,
`outside_workspace`, `runtime_socket`, `no_request_log`, `no_event_channel`,
`no_reset_configured`, `memory_uncapped`, `wallclock_uncapped`. A tenth,
`dns_canary`, trips as well when the machine running the fixture has internet
access, and the end-to-end suite does not assert it for exactly that reason.
The other fourteen (`c2_channel`, `credential_file`, `imds_reachable`,
`imds_hop_limit`, `proc_environ`, `workspace_missing`, `pids_uncapped`,
`persists_across_runs`, `crossing_unlogged`, `decision_missing`,
`violation_unalerted`, `severity_understated`, `channel_not_separated`) are
covered by unit tests only, because no fixture here reproduces the condition
each one detects. `proc_environ` is the clearest case: the leaky container
runs as uid 0 and its PID 1 is uid 0, so the scan finds no foreign-uid process
to read.

### 1. No ambient network, and the broker is not a trusted zone

Probe id `network`. The sandbox has no route to anything by default, and all
egress passes a broker applying an allowlist. Four questions, not one. Can the
sandbox open a TCP connection to `blocked_endpoint`, a bare `IP:port` literal.
Can it reach a host it should not by name. Can it resolve `dns_canary_host`,
name resolution being the exfiltration path an HTTP allowlist never sees. And
can it reach the classes of host that serve as staging and command-and-control.
An allowlisted destination is not a trusted destination: package registries,
pastebins, request-capture services, and file-drop hosts are exfiltration
channels whether or not the hostname is on the list.

The first question is the one that carries the invariant, and it is the only
one with no name in it. Every name-based check has a failure mode that looks
exactly like containment: a name that does not resolve is unreachable from a
locked-down sandbox and from a wide open one alike, so a config full of
unresolvable names produces a clean network result on a sandbox with a default
route to the internet. That is not hypothetical. It is what this harness did
until the address-literal check was added, and the fix is the reason each
check now reports *why* it did not fire:

| Inner status | What it means | How the probe reads it |
| --- | --- | --- |
| `connected` / `resolved` | The sandbox reached it. | Finding. |
| `denied` | The attempt was made and refused. | A measurement. Clean. |
| `unresolved` | The name did not resolve, so nothing was attempted. | Not a finding and not a pass. Nothing was measured. |
| `unattempted` | The literal could not be used at all. | `ProbeError`. The run is incomplete and cannot print `CONTAINED`. |

So a clean `network` result rests on `blocked_endpoint` having been attempted
and denied. An `unresolved` name never contributes to it.

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

**Without internet access**, `blocked_endpoint` still measures: no route is no
route, whether the address is unroutable from this sandbox or from this whole
machine. The DNS canary and the name-based reach checks are the ones that lose
their teeth offline, and they lose them in the safe direction. They can only
add findings, never subtract them, so an offline run detects less and claims
no more. The suite is built to that rule: every case that asserts a network
leak asserts it from something reachable inside the fixtures, and the one that
proves a route out of the reference sandbox is a finding points at a
neighbouring container rather than at a public address.

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

Five of them, stated here rather than buried, because a harness implying
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

**5. Four of the six probes take the sandbox at its word.** `network`,
`credentials`, `filesystem` and `bounds` measure by running a payload inside
the sandbox and reading the line it prints back. A sandbox already under an
adversary's control can print whatever it likes, so a clean result from those
four means the sandbox said it was clean. `attribution` and `detection` are
the exceptions: they generate boundary crossings from inside, but their
evidence is the broker's request log and event channel, read from outside on a
host the sandbox has no route to, and a sandbox that skips the crossings makes
those probes report a finding rather than a pass. Where the harness supplied a
value it compares against its own copy rather than the sandbox's echo of it,
and everything that does come back is stripped of control characters and
bounded in length and count before it reaches the report, so a hostile target
cannot forge the report's rendering: it cannot repaint your terminal, flood it,
or write text of its choosing into a finding. What it can still forge is the
measurement itself in those four probes, by honestly performing the crossings
the harness can corroborate and lying about the rest. Sanitizing what a liar
says is not the same as catching the lie. This harness answers whether a sandbox is configured to contain,
not whether an already-compromised one is telling the truth.

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
| `blocked_host` | string | A host the sandbox must not reach, by name. When it resolves and answers, reaching it is a finding; when it does not resolve, the check reports `unresolved` and measures nothing, which is why it is not the check this invariant rests on. |

### Optional keys

| Key | Type | What it is, and what its absence means |
| --- | --- | --- |
| `blocked_endpoint` | string, `IP:port` | The address literal the sandbox must not reach. Defaults to `1.1.1.1:443`. Needs no DNS, so it measures raw routability in every environment, and it is what a clean `network` result rests on. A hostname here is rejected, because a hostname would put name resolution back in front of the one check that survives without it. |
| `dns_canary_host` | string | A name that genuinely resolves wherever DNS egress exists. Defaults to `example.com`. Resolving it is a `dns_canary` finding. Failing to resolve it is not a pass, because an environment with no DNS at all fails the same way. |
| `c2_hosts` | list of strings | Staging and command-and-control class hosts (pastebins, request-capture services, file drops). Absent means `c2_channel` is not exercised. |
| `proxy` | string, `host:port` | The egress broker. When set, the network positive control and the attribution and detection crossings go through it in absolute-URI form. When absent, those probes fall back to direct reachability, which is honest about proving less. |
| `request_log_command` | list of strings | Run outside the sandbox; prints the broker's request log on stdout. Absent produces `no_request_log`. |
| `events_command` | list of strings | Run outside the sandbox; prints the alert channel on stdout. Absent produces `no_event_channel`. |
| `reset_command` | list of strings | Resets the sandbox to a clean state. Absent produces `no_reset_configured`, because a sandbox nobody can reset carries state from one task to the next by definition. |
| `wallclock_limit_seconds` | integer | Declares that something outside the sandbox bounds task duration. Absent produces `wallclock_uncapped`. Read limitation 2 before relying on this key. |

Malformed configs are rejected with one line a reader can act on rather than a
traceback: the four required keys must be present, `name`, `allowed_host`,
`blocked_host`, `dns_canary_host` and `proxy` must be strings, the four command
keys and `c2_hosts` must be lists of strings, `blocked_endpoint` must be an
address literal and a port in range, and `wallclock_limit_seconds` must be an
integer (`true` is not an integer here, even though Python's `bool` is a
subclass of `int`).

A bare string where a list belongs is the case worth naming, because accepting
it would measure nothing and say nothing. `"c2_hosts": "paste.example"` reads
as thirteen single-character hostnames, none of which exists, so `c2_channel`
would report clean having never probed the host the operator meant. It is
rejected instead.

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

## How this repository was built

[zulusec/posture-reference](https://github.com/zulusec/posture-reference) was
built through a pull request loop and documents that loop in its own README.
This repository was not. Its history is commits pushed directly to `main`, with
no pull requests, and CI recorded only on the pushes that reached GitHub rather
than on every change.

The work was reviewed, and what the review produced is visible in the code
rather than in the history: the positive controls, the address-literal check
described under Limitations, and the CI gate that fails a skipped end-to-end
test all came out of it. But the record here is weaker than the record there.
Anyone checking how ZuluSec builds things should read posture-reference for
that, and read this repository for what it measures.

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
