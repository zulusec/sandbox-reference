# The reference sandbox

This is the sandbox that the probes are supposed to find clean. It exists so
a reader can see what compliant containment looks like before pointing the
harness at something that has not earned that verdict.

## Architecture

Two Compose networks:

- `contained`, marked `internal: true`. The `sandbox` service lives here
  only. Docker will not route this network anywhere outside itself, so
  nothing on it can reach the internet, the host, or any other container by
  address alone.
- `egress`, a normal routable network. Only the `broker` service is attached
  to it, in addition to `contained`.

That is the whole containment story: the sandbox shares no network with
anything routable, and the only component that straddles both is the broker.
Any traffic the sandbox wants to send outward has to pass through it, because
there is no other path out.

The sandbox is further restricted with `read_only: true`, a dropped
capability set, `no-new-privileges`, a memory limit, a process limit, and a
CPU quota, and it runs as an unprivileged user (`10001:10001`). The CPU
setting is `cpus`, which writes a quota into the cgroup, rather than a share
weight, which bounds nothing on an idle host. The broker runs under the
same non-root user and the same read-only, no-new-privileges, capability-drop
posture.

## The broker forwards nothing

This is deliberate and worth stating plainly: **the broker does not proxy
traffic anywhere.** It answers every request with one of two things:

- `403` if the requested host is not on the allowlist
- `502` if the requested host is on the allowlist

It never opens a connection to the outside world, on either verdict. Giving
the reference sandbox real internet egress in order to demonstrate
containment would defeat the purpose of the exercise. The `502` is not a
bug or an unfinished feature; it is what "allowed, but this reference
implementation has nothing to hand you" looks like. A real deployment
replaces the broker with an actual proxy that forwards allowed traffic; what
this reference shows is the decision boundary, not a working egress path.

## Two logs, not one

The broker writes to two separate files, and it does so on purpose:

- `requests.log` records every decision the broker makes, allow or deny. It
  is what makes a run reconstructable after the fact.
- `events.log` records only policy violations (denied requests). It is what
  something is supposed to alert on.

A system that produces the first without the second can tell you what
happened only if someone thinks to go looking. It cannot tell you while it
matters. Do not merge these two files or treat one as a subset view of the
other; they serve different consumers.

## Allowlist matching

`example.invalid` matches only that exact host. `*.pypi.invalid` matches
exactly one additional label, so `files.pypi.invalid` is allowed but
`pypi.invalid` (the bare domain) and `evilpypi.invalid` (a suffix impostor)
are both denied. Suffix matching on a bare string is the classic way an
allowlist quietly becomes an open door; this broker matches on labels
instead.

## Hostnames

Every hostname this reference sandbox uses, in `allowlist.json` and in
`reference/target.json`, ends in `.invalid`. RFC 2606 reserves that suffix
so it cannot resolve for anyone running this. No real vendor or service is
named.

The leaky fixture under `fixtures/leaky/` is the deliberate exception. It
has to demonstrate a leak, which needs a host that genuinely answers, so
its `allowed_host` and `blocked_host` are the Compose service names
`authorized` and `unauthorized` on a private network. Its own README
explains why. Its `c2_hosts` stay `.invalid`, because those are supposed to
stay unreachable.

## Running it

```
docker compose -f reference/docker-compose.yml up -d --build
docker compose -f reference/docker-compose.yml ps
```

Logs are readable from outside the sandbox network by execing into the
broker container, which is how `reference/target.json` wires up
`request_log_command` and `events_command`:

```
docker compose -f reference/docker-compose.yml exec -T broker cat /var/log/broker/requests.log
docker compose -f reference/docker-compose.yml exec -T broker cat /var/log/broker/events.log
```

Bring it down (and drop the log volume) with:

```
docker compose -f reference/docker-compose.yml down -v
```
