# The leaky sandbox fixture

This fixture exists to fail. It is the deliberately broken counterpart to
`reference/`, and every probe in this project is expected to assert against
both: clean on the reference, tripped on this one. A test suite whose tests
always pass proves nothing; this is what makes the harness falsifiable.

**Do not copy this file as a starting point for a real sandbox.** Every
setting in `docker-compose.yml` is the wrong answer, and each one is what
some real deployment ships by default anyway.

## What each setting violates

- No `networks` key on `sandbox`: it lands on the default bridge network
  with unrestricted egress. Invariant 1 (network containment) fails.
- `/:/host:ro` mounts the entire host filesystem read-only into the
  container. Invariant 3 (no host filesystem access) fails.
- `/var/run/docker.sock:/var/run/docker.sock` hands the container the
  runtime socket, which is a straightforward path to controlling the host's
  Docker daemon (and from there, the host). Invariant 3 fails again.
- `AWS_SECRET_ACCESS_KEY` and `DATABASE_PASSWORD` are set directly as plain
  environment variables, visible to anything running inside the container
  or inspecting it from outside. Invariant 2 (no exposed credentials)
  fails. Both values are obviously fake: the AWS key uses the AWS
  documentation example prefix (`AKIAIOSFODNN7EXAMPLE`), and the password
  is a well-known non-secret.
- No `mem_limit`, no `pids_limit`. Invariant 4 (bounded resource
  consumption) fails: nothing stops the sandbox from exhausting host memory
  or forking until the process table is full.
- No `user`, no `cap_drop`, no `read_only`. The container runs as root with
  its full default capability set on a writable filesystem. Invariants 2
  and 3 fail together: an escape from this container is an escape as root.

## The `unauthorized` service (amendment to the original brief)

The brief that shaped this fixture set `blocked_host` to a `.invalid` name,
matching the reference target. That cannot demonstrate a leak: RFC 2606
reserves `.invalid` so it never resolves, for anyone, including a sandbox
with completely open networking. A network probe that tries to connect to
a `.invalid` host fails the same way whether the sandbox is contained or
wide open, which means the leaky fixture would report no network finding
and the suite's own assertion that this fixture trips `blocked_egress`
would be false.

`unauthorized` is the fix: a second service on the same default network as
`sandbox`, running a stdlib `python3 -m http.server` on port 80. It stands
in for a real external host that a contained sandbox has no business
reaching. Because it is a Compose service name on a private network, not a
public hostname, it is exempt from the `.invalid` convention that applies
everywhere else in this repository; `target.json` points `blocked_host` at
`unauthorized` for exactly this reason. `allowed_host` and `c2_hosts` stay
as `.invalid` names, because those are supposed to stay unreachable, and a
`.invalid` name reliably delivers that regardless of what the sandbox
allows.

## No broker, so no logs

Unlike `reference/target.json`, `fixtures/leaky/target.json` declares no
`request_log_command`, no `events_command`, and no `reset_command`. This is
not an oversight: there is no broker in this stack, and nothing straddles
a network boundary to log or reset from. That absence is itself a finding
that the attribution and detection probes are expected to report, not
silently skip.

## Running it

```
docker compose -f fixtures/leaky/docker-compose.yml up -d
docker compose -f fixtures/leaky/docker-compose.yml exec -T sandbox \
  sh -c 'ls /host/etc/hostname && echo $AWS_SECRET_ACCESS_KEY'
```

Expected: the host file path prints, followed by the fake key, confirming
the fixture leaks host filesystem access and credentials in one shot.

Bring it down when done:

```
docker compose -f fixtures/leaky/docker-compose.yml down -v
```
