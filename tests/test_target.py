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
