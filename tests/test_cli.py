import json

import pytest

from sandbox_probe import cli


def test_missing_target_exits_cannot_start(capsys):
    assert cli.main(["--target", "does/not/exist.json"]) == 1
    assert "no target config" in capsys.readouterr().err


def test_malformed_target_exits_cannot_start(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert cli.main(["--target", str(path)]) == 1
    assert "sandbox-probe:" in capsys.readouterr().err


def test_help_names_the_authorization_rule(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "authorized" in capsys.readouterr().out


def test_list_probes_names_all_six(capsys):
    assert cli.main(["--list-probes"]) == 0
    out = capsys.readouterr().out
    for probe_id in ("network", "credentials", "filesystem",
                      "bounds", "attribution", "detection"):
        assert probe_id in out


def test_json_output_is_valid_json(tmp_path, capsys):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "name": "stub",
        "exec_command": ["python3", "-c", "pass"],
        "allowed_host": "a.invalid",
        "blocked_host": "b.invalid",
    }), encoding="utf-8")
    cli.main(["--target", str(path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert "metadata" in payload
    assert "findings" in payload


def test_probe_selection_runs_only_the_named_probe(tmp_path, capsys):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "name": "stub",
        "exec_command": ["python3", "-c", "pass"],
        "allowed_host": "a.invalid",
        "blocked_host": "b.invalid",
    }), encoding="utf-8")
    cli.main(["--target", str(path), "--probe", "filesystem", "--json"])
    payload = json.loads(capsys.readouterr().out)
    reported = {error["probe_id"] for error in payload["metadata"]["errors"]}
    assert reported <= {"filesystem"}


def test_unknown_probe_name_exits_cannot_start(tmp_path, capsys):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "name": "stub", "exec_command": ["true"],
        "allowed_host": "a.invalid", "blocked_host": "b.invalid",
    }), encoding="utf-8")
    assert cli.main(["--target", str(path), "--probe", "nope"]) == 1
    assert "unknown probe" in capsys.readouterr().err
