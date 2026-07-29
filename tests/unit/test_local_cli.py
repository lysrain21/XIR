from __future__ import annotations

import json
from pathlib import Path

import pytest

from xir_lab.cli import run

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "configs" / "local" / "topology-v1.json"
PROFILE = ROOT / "configs" / "profiles" / "local-scale-v1.json"


def test_local_init_render_and_current_host_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = tmp_path / "runtime"
    assert run(
        [
            "local-init",
            "--topology",
            str(TOPOLOGY),
            "--runtime-root",
            str(runtime),
        ]
    ) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert initialized["outcome"] == "initialized"
    assert initialized["effects"]["public_network_calls"] == 0
    assert initialized["effects"]["local_private_keys_created"] == 14

    assert run(
        [
            "local-render",
            "--topology",
            str(TOPOLOGY),
            "--identity-manifest",
            str(runtime / "identity-manifest.json"),
        ]
    ) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["outcome"] == "rendered"
    assert rendered["details"]["compose_yaml"].count("image:") == 12

    exit_code = run(
        [
            "local-preflight",
            "--topology",
            str(TOPOLOGY),
            "--identity-manifest",
            str(runtime / "identity-manifest.json"),
            "--mode",
            "scale",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert result["outcome"] == "blocked"
    assert result["effects"]["containers_started"] == 0


def test_local_plan_rejects_bad_digest_and_accepts_progression(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run(
        [
            "local-plan",
            "--topology",
            str(TOPOLOGY),
            "--profile",
            str(PROFILE),
            "--smoke-freeze-sha256",
            "invalid",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().out)["outcome"] == "blocked"

    digest = "ab" * 32
    assert run(
        [
            "local-plan",
            "--topology",
            str(TOPOLOGY),
            "--profile",
            str(PROFILE),
            "--smoke-freeze-sha256",
            digest,
            "--rehearsal-freeze-sha256",
            digest,
            "--measured-limits-sha256",
            digest,
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "eligible"
    assert result["details"]["plan"]["counts"]["physical_transactions"] == 30000
