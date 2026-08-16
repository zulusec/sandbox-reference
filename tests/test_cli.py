import json

import pytest

from sandbox_probe import cli
from sandbox_probe.result import ProbeOutcome


class _FakeProbe:
    """A probe stand-in that always reports clean, for isolating the
    partial-selection contract from real probe/exec behavior."""

    def __init__(self, probe_id):
        self.probe_id = probe_id

    def run(self, target):
        return ProbeOutcome()


def _write_stub_target(tmp_path):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "name": "stub",
        "exec_command": ["true"],
        "allowed_host": "a.invalid",
        "blocked_host": "b.invalid",
    }), encoding="utf-8")
    return path


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


def test_subset_run_with_no_findings_exits_incomplete_not_ok(tmp_path, capsys, monkeypatch):
    """A --probe subset that ran clean must not be indistinguishable from a
    full clean assessment: it exits 2, not 0, and the table must name the
    subset rather than claim CONTAINED."""
    path = _write_stub_target(tmp_path)
    fakes = [_FakeProbe("alpha"), _FakeProbe("beta")]
    monkeypatch.setattr(cli, "all_probes", lambda: fakes)

    exit_code = cli.main(["--target", str(path), "--probe", "alpha"])
    out = capsys.readouterr().out

    assert exit_code == 2
    assert "CONTAINED" not in out
    assert "PARTIAL RUN" in out
    assert "alpha" in out


def test_full_run_with_no_findings_still_exits_ok_and_says_contained(
    tmp_path, capsys, monkeypatch
):
    path = _write_stub_target(tmp_path)
    fakes = [_FakeProbe("alpha"), _FakeProbe("beta")]
    monkeypatch.setattr(cli, "all_probes", lambda: fakes)

    exit_code = cli.main(["--target", str(path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "CONTAINED" in out
    assert "PARTIAL RUN" not in out


def test_json_metadata_distinguishes_selected_from_registered(tmp_path, capsys, monkeypatch):
    path = _write_stub_target(tmp_path)
    fakes = [_FakeProbe("alpha"), _FakeProbe("beta")]
    monkeypatch.setattr(cli, "all_probes", lambda: fakes)

    exit_code = cli.main(["--target", str(path), "--probe", "alpha", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["metadata"]["probes_selected"] == ["alpha"]
    assert payload["metadata"]["probes_registered"] == ["alpha", "beta"]


def test_json_metadata_lists_match_when_selection_is_full(tmp_path, capsys, monkeypatch):
    path = _write_stub_target(tmp_path)
    fakes = [_FakeProbe("alpha"), _FakeProbe("beta")]
    monkeypatch.setattr(cli, "all_probes", lambda: fakes)

    cli.main(["--target", str(path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["metadata"]["probes_selected"] == ["alpha", "beta"]
    assert payload["metadata"]["probes_registered"] == ["alpha", "beta"]
