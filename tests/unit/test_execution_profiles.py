from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.config.profiles import (
    LiveLimits,
    ProfileError,
    freeze_execution_profile,
    load_execution_profile,
    materialize_live_pilot,
)
from xir_lab.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "configs" / "profiles" / "pilot-template-v1.json"
PRIMARY = ROOT / "configs" / "profiles" / "primary-template-v1.json"
SCALE = ROOT / "configs" / "profiles" / "scale-template-v1.json"


def _document(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _make_live(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result["profile_mode"] = "live"
    limits = result["live_limits"]
    limits["max_retries_per_lineage"] = 1
    limits["max_batch_attempts"] = 4
    limits["max_duration_seconds"] = 3600
    limits["max_in_flight_attempts"] = 2
    limits["chain_budget_wei"] = {
        "11155420": 100,
        "421614": 100,
        "84532": 100,
    }
    limits["stop_policy"] = {
        "consecutive_failures": 2,
        "rolling_window": 10,
        "rolling_failure_rate": 0.3,
        "timeout_count": 2,
        "collector_backlog": 100,
        "collector_heartbeat_seconds": 30,
        "disk_floor_bytes": 1000000,
    }
    limits["allow_partial_conditions"] = False
    return result


def test_pilot_template_has_exact_non_executable_counts() -> None:
    profile = load_execution_profile(PILOT)
    assert profile.executable is False
    assert profile.counts.planned_pair_slots == 20
    assert profile.counts.planned_designated_attempts == 40


def test_pilot_template_materializes_and_freezes_exact_bounded_live_profile(
    tmp_path: Path,
) -> None:
    template = load_execution_profile(PILOT)
    profile = materialize_live_pilot(
        template,
        profile_id="pilot-live-fixture",
        limits=LiveLimits(
            max_retries_per_lineage=1,
            max_batch_attempts=4,
            max_duration_seconds=3600,
            max_in_flight_attempts=2,
            chain_budget_wei={
                "11155420": 100,
                "421614": 200,
                "84532": 300,
            },
            stop_policy={
                "consecutive_failures": 2,
                "rolling_window": 10,
                "rolling_failure_rate": 0.3,
                "timeout_count": 2,
                "collector_backlog": 100,
                "collector_heartbeat_seconds": 30,
                "disk_floor_bytes": 1_000_000,
            },
            allow_partial_conditions=False,
        ),
    )
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    document, digest = freeze_execution_profile(profile, store=store)
    assert document["counts"]["planned_pair_slots"] == 20
    assert document["counts"]["planned_designated_attempts"] == 40
    assert document["counts"]["planned_warmup_attempts"] == 0
    assert document["live_limits"]["allow_partial_conditions"] is False
    assert store.read_raw(digest)


def test_primary_template_has_exact_counts_and_warmups() -> None:
    profile = load_execution_profile(PRIMARY)
    assert profile.executable is False
    assert profile.counts.planned_pair_slots == 120
    assert profile.counts.planned_designated_attempts == 240
    assert profile.counts.planned_warmup_attempts == 8


def test_template_rejects_concrete_live_value(tmp_path: Path) -> None:
    document = _document(PILOT)
    document["live_limits"]["max_batch_attempts"] = 1
    with pytest.raises(ProfileError, match="null live-limit"):
        load_execution_profile(_write(tmp_path, document))


def test_live_profile_rejects_remaining_placeholder(tmp_path: Path) -> None:
    document = _make_live(_document(PILOT))
    document["live_limits"]["max_duration_seconds"] = None
    with pytest.raises(ProfileError, match="unresolved limit"):
        load_execution_profile(_write(tmp_path, document))


def test_primary_live_requires_reconciled_pilot_freeze(tmp_path: Path) -> None:
    document = _make_live(_document(PRIMARY))
    with pytest.raises(ProfileError, match="reconciled pilot freeze"):
        load_execution_profile(_write(tmp_path, document))
    document["derived_from"] = {
        "kind": "pilot",
        "run_id": "run_pilot_fixture",
        "freeze_sha256": "ab" * 32,
        "reconciled": True,
    }
    assert load_execution_profile(_write(tmp_path, document)).executable


def test_primary_count_cannot_be_renamed_attempt_total(tmp_path: Path) -> None:
    document = _document(PRIMARY)
    document["counts"]["planned_designated_attempts"] = 248
    with pytest.raises(ProfileError, match="count identity"):
        load_execution_profile(_write(tmp_path, document))


def test_primary_pair_count_cannot_be_reinterpreted(tmp_path: Path) -> None:
    document = _document(PRIMARY)
    document["counts"]["planned_pair_slots"] = 240
    with pytest.raises(ProfileError, match="count identity"):
        load_execution_profile(_write(tmp_path, document))


def test_scale_template_has_exact_separate_attempt_counts() -> None:
    profile = load_execution_profile(SCALE)
    assert profile.executable is False
    assert profile.counts.planned_pair_slots == 5000
    assert profile.counts.planned_designated_attempts == 10000
    assert profile.counts.retry_attempts_in_designated_count is False
    assert profile.approval_operation_type == "scale"


def test_live_scale_requires_reconciled_primary_freeze(tmp_path: Path) -> None:
    document = _make_live(_document(SCALE))
    with pytest.raises(ProfileError, match="reconciled primary freeze"):
        load_execution_profile(_write(tmp_path, document))
    document["derived_from"] = {
        "kind": "primary",
        "run_id": "run_primary_fixture",
        "freeze_sha256": "cd" * 32,
        "reconciled": True,
    }
    assert load_execution_profile(_write(tmp_path, document)).executable


def test_scale_cannot_reuse_primary_approval_type(tmp_path: Path) -> None:
    document = _document(SCALE)
    document["approval_operation_type"] = "primary"
    with pytest.raises(ProfileError, match="own operation-typed approval"):
        load_execution_profile(_write(tmp_path, document))
