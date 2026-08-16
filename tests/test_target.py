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
