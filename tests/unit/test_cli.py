from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from xir_lab.cli import COMMANDS, run
from xir_lab.live import LIVE_DISABLE_ENV, LIVE_FEATURE_ENV, LIVE_FEATURE_VERSION


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_has_a_zero_write_machine_readable_boundary(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run([command]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == "xir-lab-command-status-v1"
    assert result["command"] == command
    assert result["outcome"] == "not_executed"
    assert result["mode"] == "offline_zero_write"
    assert set(result["effects"].values()) == {0}


@pytest.mark.parametrize("command", COMMANDS)
def test_live_flag_fails_closed(
    command: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(LIVE_DISABLE_ENV, raising=False)
    monkeypatch.delenv(LIVE_FEATURE_ENV, raising=False)
    assert run([command, "--live"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "blocked"
    assert result["reason_code"] == "live_feature_not_enabled"
    assert set(result["effects"].values()) == {0}


@pytest.mark.parametrize(
    "injected",
    (
        {LIVE_DISABLE_ENV: "1"},
        {LIVE_DISABLE_ENV: "true", LIVE_FEATURE_ENV: LIVE_FEATURE_VERSION},
    ),
)
def test_hard_disable_precedes_even_config_loading(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    injected: Mapping[str, str],
) -> None:
    config = tmp_path / "would-be-invalid.json"
    config.write_text("not json")
    for key in (LIVE_DISABLE_ENV, LIVE_FEATURE_ENV):
        monkeypatch.delenv(key, raising=False)
    for key, value in injected.items():
        monkeypatch.setenv(key, value)

    assert run(["deploy", "--live", "--config", str(config)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["reason_code"] == "live_writes_hard_disabled"
    assert result["inputs"]["config_sha256"] is None
    assert set(result["effects"].values()) == {0}


def test_enabled_feature_requires_all_guarded_live_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.json"
    config.write_text('{"schema_version":"fixture"}\n')
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.delenv(LIVE_DISABLE_ENV, raising=False)
    monkeypatch.setenv(LIVE_FEATURE_ENV, LIVE_FEATURE_VERSION)

    assert (
        run(
            [
                "deploy",
                "--live",
                "--config",
                str(config),
                "--run-dir",
                str(run_dir),
            ]
        )
        == 2
    )
    result = json.loads(capsys.readouterr().out)
    assert result["reason_code"] == "live command requires --profile"
    assert set(result["effects"].values()) == {0}


def test_config_must_be_a_json_object(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "config.json"
    config.write_text("[]\n")
    assert run(["plan", "--config", str(config)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "invalid_input"
    assert result["reason_code"] == "config root must be a JSON object"


def test_existing_inputs_are_identified_without_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "config.json"
    config.write_text('{"schema_version":"fixture"}\n')
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    assert run(["reconcile", "--config", str(config), "--run-dir", str(run_dir)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["inputs"]["config_path"] == str(config.resolve())
    assert len(result["inputs"]["config_sha256"]) == 64
    assert result["inputs"]["run_dir"] == str(run_dir.resolve())
    assert list(run_dir.iterdir()) == []
