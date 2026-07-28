from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.evidence.records import RecordError, load_evidence_record_bundle, stable_id


def _ids() -> dict[str, str]:
    run = stable_id("run", "fixture")
    condition = stable_id("condition", run, "HH")
    arm = stable_id("arm", condition, "baseline")
    pair = stable_id("pair", condition, 0)
    repetition = stable_id("repetition", pair, 0)
    attempt = stable_id("attempt", repetition, arm, "primary", 0)
    retry = stable_id("attempt", repetition, arm, "retry", 1)
    stage = stable_id("stage", attempt, 0)
    intent = stable_id("intent", stage, 0)
    transaction = stable_id("transaction", intent, 0)
    return {
        "run": run,
        "condition": condition,
        "arm": arm,
        "pair": pair,
        "repetition": repetition,
        "attempt": attempt,
        "retry": retry,
        "stage": stage,
        "intent": intent,
        "transaction": transaction,
    }


def _bundle() -> dict[str, Any]:
    ids = _ids()
    return {
        "schema_version": "xir-lab-evidence-record-bundle-v1",
        "runs": [
            {
                "run_id": ids["run"],
                "profile_id": "primary-template-v1",
                "plan_sha256": "11" * 32,
            }
        ],
        "conditions": [
            {
                "condition_id": ids["condition"],
                "run_id": ids["run"],
                "carrier_sequence": "HH",
            }
        ],
        "arms": [
            {
                "arm_id": ids["arm"],
                "condition_id": ids["condition"],
                "arm": "baseline",
            }
        ],
        "pair_slots": [
            {
                "pair_slot_id": ids["pair"],
                "condition_id": ids["condition"],
                "slot_index": 0,
            }
        ],
        "repetitions": [
            {
                "repetition_id": ids["repetition"],
                "pair_slot_id": ids["pair"],
                "repetition_index": 0,
            }
        ],
        "attempts": [
            {
                "attempt_id": ids["attempt"],
                "condition_id": ids["condition"],
                "arm_id": ids["arm"],
                "pair_slot_id": ids["pair"],
                "repetition_id": ids["repetition"],
                "attempt_kind": "primary",
                "prior_attempt_id": None,
                "original_attempt_kind": None,
                "state": "planned",
            },
            {
                "attempt_id": ids["retry"],
                "condition_id": ids["condition"],
                "arm_id": ids["arm"],
                "pair_slot_id": ids["pair"],
                "repetition_id": ids["repetition"],
                "attempt_kind": "retry",
                "prior_attempt_id": ids["attempt"],
                "original_attempt_kind": "primary",
                "state": "planned",
            },
        ],
        "stages": [
            {
                "stage_id": ids["stage"],
                "attempt_id": ids["attempt"],
                "stage_name": "source_dispatch",
                "ordinal": 0,
            }
        ],
        "messages": [],
        "transaction_intents": [
            {
                "intent_id": ids["intent"],
                "stage_id": ids["stage"],
                "chain_id": 11155420,
                "operation_id": "fixture-op-0",
            }
        ],
        "transactions": [
            {
                "transaction_id": ids["transaction"],
                "intent_id": ids["intent"],
                "chain_id": 11155420,
                "nonce": 1,
                "transaction_hash": None,
                "replaces_transaction_id": None,
            }
        ],
        "observations": [],
        "freeze_scopes": [
            {
                "freeze_scope_id": stable_id("freeze", ids["run"], "primary"),
                "run_id": ids["run"],
                "attempt_ids": [ids["attempt"], ids["retry"]],
                "prior_freeze_sha256": None,
                "scope_sha256": "22" * 32,
            }
        ],
    }


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "records.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_stable_id_is_deterministic_and_namespaced() -> None:
    first = stable_id("attempt", "run-a", "HH", "baseline", 0)
    assert first == stable_id("attempt", "run-a", "HH", "baseline", 0)
    assert first != stable_id("stage", "run-a", "HH", "baseline", 0)


def test_loads_linked_records(tmp_path: Path) -> None:
    bundle = load_evidence_record_bundle(_write(tmp_path, _bundle()))
    assert bundle.attempts[0].attempt_kind == "primary"
    assert bundle.attempts[1].original_attempt_kind == "primary"


def test_retry_cannot_change_arm(tmp_path: Path) -> None:
    document = _bundle()
    other_arm = stable_id("arm", _ids()["condition"], "xir")
    document["arms"].append(
        {
            "arm_id": other_arm,
            "condition_id": _ids()["condition"],
            "arm": "xir",
        }
    )
    document["attempts"][1]["arm_id"] = other_arm
    with pytest.raises(RecordError, match="matching coordinates"):
        load_evidence_record_bundle(_write(tmp_path, document))


def test_retry_cannot_claim_a_new_original_kind(tmp_path: Path) -> None:
    document = _bundle()
    document["attempts"][1]["original_attempt_kind"] = "pilot"
    with pytest.raises(RecordError, match="original attempt kind"):
        load_evidence_record_bundle(_write(tmp_path, document))


def test_retry_lineage_must_be_acyclic(tmp_path: Path) -> None:
    document = _bundle()
    ids = _ids()
    document["attempts"][0]["attempt_kind"] = "retry"
    document["attempts"][0]["prior_attempt_id"] = ids["retry"]
    document["attempts"][0]["original_attempt_kind"] = "primary"
    with pytest.raises(RecordError, match="cyclic retry lineage"):
        load_evidence_record_bundle(_write(tmp_path, document))


def test_transaction_replacement_preserves_nonce(tmp_path: Path) -> None:
    document = _bundle()
    ids = _ids()
    replacement = copy.deepcopy(document["transactions"][0])
    replacement["transaction_id"] = stable_id("transaction", ids["intent"], 1)
    replacement["nonce"] = 2
    replacement["replaces_transaction_id"] = ids["transaction"]
    document["transactions"].append(replacement)
    with pytest.raises(RecordError, match="replacement changed"):
        load_evidence_record_bundle(_write(tmp_path, document))


def test_freeze_cannot_include_an_unknown_attempt(tmp_path: Path) -> None:
    document = _bundle()
    document["freeze_scopes"][0]["attempt_ids"].append(
        stable_id("attempt", "unknown")
    )
    with pytest.raises(RecordError, match="unknown attempt"):
        load_evidence_record_bundle(_write(tmp_path, document))
