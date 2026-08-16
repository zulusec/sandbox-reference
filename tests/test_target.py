import json

import pytest

from sandbox_probe.target import TargetConfigError, load_target

_MINIMAL = {
    "name": "reference",
    "exec_command": ["sh", "-c", "cat"],
    "allowed_host": "example.invalid",
    "blocked_host": "blocked.invalid",
    "c2_hosts": ["paste.invalid"],
}


def _write(tmp_path, data):
    path = tmp_path / "target.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_loads_a_minimal_target(tmp_path):
    target = load_target(_write(tmp_path, _MINIMAL))
    assert target.name == "reference"
    assert target.exec_command == ["sh", "-c", "cat"]
    assert target.request_log_command is None
    assert target.proxy is None


def test_missing_required_key_is_a_config_error(tmp_path):
    data = dict(_MINIMAL)
    del data["exec_command"]
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, data))
    assert "exec_command" in str(excinfo.value)


def test_exec_command_must_be_a_list_of_strings(tmp_path):
    with pytest.raises(TargetConfigError):
        load_target(_write(tmp_path, dict(_MINIMAL, exec_command="sh -c cat")))


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(TargetConfigError):
        load_target(tmp_path / "absent.json")


def test_run_inside_pipes_the_payload_and_returns_output(tmp_path):
    target = load_target(_write(tmp_path, dict(
        _MINIMAL, exec_command=["python3", "-c", "import sys; print(sys.stdin.read().strip())"]
    )))
    result = target.run_inside(["hello"], timeout=10)
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_inside_reports_timeout_as_a_nonzero_result(tmp_path):
    target = load_target(_write(tmp_path, dict(
        _MINIMAL, exec_command=["python3", "-c", "import time; time.sleep(5)"]
    )))
    result = target.run_inside(["x"], timeout=1)
    assert result.returncode != 0
    assert "timed out" in result.stderr


# --- A reset that returns before the sandbox is usable is not a reset.
#
# `docker compose restart` returns in tens of milliseconds on Compose v5 and
# leaves the service still stopping, so the next probe execs into a container
# that is about to be killed and gets SIGKILLed partway through its payload.
# Observed live against the reference stack: two runs in three lost the
# network probe that way, reporting exit 137, an empty result and a failed
# positive control. The harness was honest about not having measured, and
# the reason it had not measured was its own reset.

def _counting_target(tmp_path, failures: int):
    """A target whose exec fails `failures` times before it succeeds, the
    way a container that is still restarting does."""
    counter = tmp_path / "attempts"
    counter.write_text("", encoding="utf-8")
    script = tmp_path / "flaky-exec.sh"
    script.write_text(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        f'printf x >> "{counter}"\n'
        f'attempts=$(wc -c < "{counter}")\n'
        f"if [ \"$attempts\" -le {failures} ]; then\n"
        '  echo "service \\"sandbox\\" is not running" >&2\n'
        "  exit 1\n"
        "fi\n"
        "echo ready\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return load_target(_write(tmp_path, dict(
        _MINIMAL, exec_command=[str(script)], reset_command=["true"],
    ))), counter


def test_reset_waits_until_the_sandbox_can_run_a_command_again(tmp_path):
    target, counter = _counting_target(tmp_path, failures=3)
    result = target.reset(timeout=30)
    assert result.returncode == 0
    # The reset command itself succeeded immediately; what took the time was
    # waiting for the sandbox to answer. Four attempts: three refusals and
    # the one that worked.
    assert len(counter.read_text(encoding="utf-8")) == 4
    # And the sandbox really is usable when reset returns, which is the
    # whole contract.
    assert target.run_inside(["print('x')"], timeout=10).returncode == 0


def test_reset_reports_a_sandbox_that_never_comes_back(tmp_path):
    """A sandbox that never answers must not be reported as reset. The
    reset command's own success is not evidence that anything came back."""
    target, _counter = _counting_target(tmp_path, failures=1000)
    result = target.reset(timeout=5)
    assert result.returncode != 0
    assert "did not accept an exec" in result.stderr


def test_readiness_requires_an_exec_that_survives_a_moment(tmp_path):
    """One exec that returns is not proof the sandbox is back.

    `docker compose restart` returns before the container has stopped, so a
    readiness check that only asks "does an exec succeed right now" gets its
    answer from the container that is about to be killed. The next probe
    then starts a long payload and loses it partway through. Readiness has
    to ask the sandbox to still be there in a moment, not merely to answer.
    """
    target, _counter = _counting_target(tmp_path, failures=0)
    recorded = tmp_path / "stdin"
    script = tmp_path / "recording-exec.sh"
    script.write_text(f'#!/bin/sh\ncat > "{recorded}"\nexit 0\n', encoding="utf-8")
    script.chmod(0o755)
    object.__setattr__(target, "exec_command", [str(script)])
    assert target.reset(timeout=30).returncode == 0
    assert "sleep" in recorded.read_text(encoding="utf-8")


def test_a_failed_reset_command_is_not_followed_by_a_wait(tmp_path):
    """No point waiting for a sandbox nobody asked to restart."""
    target, counter = _counting_target(tmp_path, failures=0)
    object.__setattr__(target, "reset_command", ["false"])
    result = target.reset(timeout=5)
    assert result.returncode != 0
    assert counter.read_text(encoding="utf-8") == ""


def test_reset_without_a_reset_command_is_unchanged(tmp_path):
    target = load_target(_write(tmp_path, _MINIMAL))
    result = target.reset()
    assert result.returncode == 1
    assert "not configured" in result.stderr


def test_loads_a_target_with_a_proxy(tmp_path):
    target = load_target(_write(tmp_path, dict(_MINIMAL, proxy="broker:3128")))
    assert target.proxy == "broker:3128"


def test_proxy_must_be_a_string(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, proxy=3128)))
    assert "proxy" in str(excinfo.value)


def test_loads_a_target_with_a_wallclock_limit(tmp_path):
    target = load_target(_write(tmp_path, dict(_MINIMAL, wallclock_limit_seconds=300)))
    assert target.wallclock_limit_seconds == 300


def test_wallclock_limit_defaults_to_none(tmp_path):
    target = load_target(_write(tmp_path, _MINIMAL))
    assert target.wallclock_limit_seconds is None


def test_wallclock_limit_must_be_an_integer(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, wallclock_limit_seconds="300")))
    assert "wallclock_limit_seconds" in str(excinfo.value)


def test_wallclock_limit_rejects_a_bool(tmp_path):
    """bool is a subclass of int in Python; True/False must not silently pass
    as valid second counts."""
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, wallclock_limit_seconds=True)))
    assert "wallclock_limit_seconds" in str(excinfo.value)


def test_non_object_config_is_a_config_error(tmp_path):
    """A config whose top-level JSON value is not an object must raise
    TargetConfigError, not escape as a raw AttributeError or TypeError."""
    path = tmp_path / "target.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(path)
    assert str(path) in str(excinfo.value)
    assert "object" in str(excinfo.value)


# --- A malformed config must fail loudly rather than measure nothing.
#
# The command keys have been validated from the start. These four never
# were, and the failure they produce is this project's central one arriving
# through the config door: a check that runs, finds nothing, and reports
# clean, having never looked at the thing the operator meant.

def test_c2_hosts_as_a_bare_string_is_rejected(tmp_path):
    """The dangerous case. list("paste.example") is thirteen one-character
    hostnames, none of which exists, so c2_channel would report clean
    having never probed the host named in the config."""
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, c2_hosts="paste.example")))
    assert "c2_hosts" in str(excinfo.value)


def test_c2_hosts_must_hold_only_strings(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, c2_hosts=[1, 2])))
    assert "c2_hosts" in str(excinfo.value)


def test_c2_hosts_may_be_absent(tmp_path):
    target = load_target(_write(tmp_path, {
        key: value for key, value in _MINIMAL.items() if key != "c2_hosts"
    }))
    assert target.c2_hosts == []


def test_name_must_be_a_string(tmp_path):
    """name is the subject on every finding, so a dict here would end up
    rendered into the report as one."""
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, name={"a": 1})))
    assert "name" in str(excinfo.value)


def test_allowed_host_must_be_a_string(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, allowed_host=5)))
    assert "allowed_host" in str(excinfo.value)


def test_blocked_host_must_be_a_string(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_host=["a", "b"])))
    assert "blocked_host" in str(excinfo.value)


# --- The address literal the network probe cannot fail to measure.
#
# Every name-based check has a vacuous failure mode: a name that does not
# exist is unreachable for a contained sandbox and for a wide open one
# alike. blocked_endpoint has no such mode, because there is no name in it.
# That is only true if the config guarantees it holds an address literal and
# a port, so the guarantee is enforced here rather than assumed.

def test_blocked_endpoint_defaults_to_a_public_address_literal(tmp_path):
    target = load_target(_write(tmp_path, _MINIMAL))
    assert target.blocked_endpoint == "1.1.1.1:443"


def test_blocked_endpoint_may_be_overridden(tmp_path):
    target = load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="192.0.2.9:80")))
    assert target.blocked_endpoint == "192.0.2.9:80"


def test_blocked_endpoint_accepts_a_bracketed_ipv6_literal(tmp_path):
    target = load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="[2001:db8::1]:443")))
    assert target.blocked_endpoint == "[2001:db8::1]:443"


def test_blocked_endpoint_rejects_a_hostname(tmp_path):
    """A hostname here would reintroduce the defect this key exists to close:
    the check would need DNS, and an unresolvable name would read as a denied
    route."""
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="blocked.invalid:443")))
    assert "blocked_endpoint" in str(excinfo.value)


def test_blocked_endpoint_rejects_a_missing_port(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="1.1.1.1")))
    assert "blocked_endpoint" in str(excinfo.value)


def test_blocked_endpoint_rejects_a_port_out_of_range(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="1.1.1.1:70000")))
    assert "blocked_endpoint" in str(excinfo.value)


def test_blocked_endpoint_rejects_an_empty_string(tmp_path):
    """An empty value must not silently disable the one check that has no
    vacuous failure mode."""
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint="")))
    assert "blocked_endpoint" in str(excinfo.value)


def test_blocked_endpoint_must_be_a_string(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, blocked_endpoint=443)))
    assert "blocked_endpoint" in str(excinfo.value)


# --- The DNS canary needs a name that genuinely resolves somewhere.

def test_dns_canary_host_defaults_to_a_name_that_resolves_on_the_open_internet(tmp_path):
    target = load_target(_write(tmp_path, _MINIMAL))
    assert target.dns_canary_host == "example.com"


def test_dns_canary_host_may_be_overridden(tmp_path):
    target = load_target(_write(tmp_path, dict(_MINIMAL, dns_canary_host="example.net")))
    assert target.dns_canary_host == "example.net"


def test_dns_canary_host_must_be_a_non_empty_string(tmp_path):
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, dns_canary_host="")))
    assert "dns_canary_host" in str(excinfo.value)
    with pytest.raises(TargetConfigError) as excinfo:
        load_target(_write(tmp_path, dict(_MINIMAL, dns_canary_host=["example.com"])))
    assert "dns_canary_host" in str(excinfo.value)
