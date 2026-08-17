from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
import rfc8785
from eth_account import Account
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_runner import (
    MULTIHOP_EFFECT_TOPIC,
    MultihopRunnerState,
    NativeMultihopRunner,
    _canonical_transaction_hash,
    _write_private_raw_durably,
)
from xir_lab.native.multihop_scalability import build_multihop_attempts

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "native" / "native-multihop-switching-v1.json"


def test_effect_topic_matches_the_nine_parameter_contract_event() -> None:
    signature = (
        "NativeMultihopEffectApplied(bytes32,bytes32,uint64,bytes,bytes32,"
        "bytes32,bytes32,bytes32,uint256)"
    )
    assert MULTIHOP_EFFECT_TOPIC == "0x" + keccak(text=signature).hex()


def test_runner_state_records_dual_clock_boot_and_process_identity(tmp_path: Path) -> None:
    state = MultihopRunnerState(tmp_path / "runner.sqlite")
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    assert state.begin(attempt)  # type: ignore[arg-type]
    state.record_stage(
        attempt.attempt_id,
        "root_create",
        "intended",
        {"role": "a", "hop_index": 0},
    )
    row = state.connection.execute("SELECT * FROM events").fetchone()
    assert row is not None
    assert int(row["utc_ns"]) > 0
    assert int(row["monotonic_ns"]) > 0
    assert str(row["boot_id"])
    assert int(row["process_id"]) > 0
    assert json.loads(row["detail_json"])["role"] == "a"


def test_runner_state_persists_exact_phase_authority_and_rejects_drift(
    tmp_path: Path,
) -> None:
    state = MultihopRunnerState(tmp_path / "runner.sqlite")
    authority = {
        "schema_version": "xir-lab-native-multihop-phase-authority-v1",
        "phase": "smoke",
        "prior_phase_handoffs": {},
    }
    authority["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(authority)
    ).hexdigest()
    state.bind_phase_authority(authority)
    state.bind_phase_authority(authority)
    drifted = dict(authority)
    drifted["phase"] = "scale"
    drifted["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps({key: value for key, value in drifted.items() if key != "semantic_sha256"})
    ).hexdigest()
    with pytest.raises(LocalTopologyError, match="differs from durable"):
        state.bind_phase_authority(drifted)


def test_runner_state_resume_keeps_succeeded_attempt_closed(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    first = MultihopRunnerState(path)
    assert first.begin(attempt)  # type: ignore[arg-type]
    first.finish(attempt.attempt_id)
    first.connection.close()
    second = MultihopRunnerState(path)
    assert not second.begin(attempt)  # type: ignore[arg-type]
    assert second.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    second.connection.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 1


def test_runner_state_reserves_root_nonce_from_multihop_stage(tmp_path: Path) -> None:
    state = MultihopRunnerState(tmp_path / "runner.sqlite")
    attempts = build_multihop_attempts(config_path=CONFIG, phase="smoke")[:2]
    for nonce, attempt in enumerate(attempts, start=41):
        assert state.begin(attempt)  # type: ignore[arg-type]
        state.record_stage(
            attempt.attempt_id,
            "root_create",
            "intended",
            {"role": "a", "hop_index": 0, "record_nonce": nonce},
        )
    assert state.next_reserved_root_nonce() == 43


def test_runner_state_atomically_records_intent_and_signed_boundary(tmp_path: Path) -> None:
    state = MultihopRunnerState(tmp_path / "runner.sqlite")
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    assert state.begin(attempt)  # type: ignore[arg-type]
    intended = {
        "role": "a",
        "hop_index": 0,
        "nonce": 7,
        "target": "0x" + "22" * 20,
        "calldata_sha256": "33" * 32,
    }
    signed = {**intended, "raw_sha256": "44" * 32}
    transaction_hash = "0x" + "55" * 32
    state.record_durable_signed_stage(
        attempt_id=attempt.attempt_id,
        stage="root_create",
        intended_detail=intended,
        signed_detail=signed,
        transaction_hash=transaction_hash,
        raw_transaction=b"signed transaction bytes",
    )
    current = state.stage(attempt.attempt_id, "root_create")
    assert current is not None
    assert current["state"] == "signed"
    assert current["transaction_hash"] == transaction_hash
    history = state.connection.execute(
        "SELECT state FROM stage_history ORDER BY history_id"
    ).fetchall()
    assert [row["state"] for row in history] == ["intended", "signed"]
    events = state.connection.execute(
        "SELECT event FROM events ORDER BY event_id"
    ).fetchall()
    assert [row["event"] for row in events] == ["intended", "signed"]
    durable = state.durable_signed_transaction(attempt.attempt_id, "root_create")
    assert durable is not None
    assert bytes(durable["raw_transaction"]) == b"signed transaction bytes"


def test_signed_raw_db_commit_recovers_missing_materialized_file(tmp_path: Path) -> None:
    state_path = tmp_path / "runner.sqlite"
    state = MultihopRunnerState(state_path)
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    assert state.begin(attempt)  # type: ignore[arg-type]
    raw = b"immutable signed transaction"
    transaction_hash = "0x" + "66" * 32
    detail = {
        "role": "a",
        "nonce": 9,
        "target": "0x" + "22" * 20,
        "calldata_sha256": "33" * 32,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    state.record_durable_signed_stage(
        attempt_id=attempt.attempt_id,
        stage="root_create",
        intended_detail={key: value for key, value in detail.items() if key != "raw_sha256"},
        signed_detail=detail,
        transaction_hash=transaction_hash,
        raw_transaction=raw,
    )
    state.connection.close()

    # This is the crash window after SQLite commit but before file materialization.
    raw_path = tmp_path / "private-signed-transactions" / f"{transaction_hash}.raw"
    assert not raw_path.exists()
    raw_path.parent.mkdir()
    reopened = MultihopRunnerState(state_path)
    pending = reopened.pending_signed_transactions()
    assert len(pending) == 1
    recovered = bytes(pending[0]["raw_transaction"])
    _write_private_raw_durably(raw_path, recovered)
    assert raw_path.read_bytes() == raw


def test_runner_state_rejects_plan_coordinate_drift(tmp_path: Path) -> None:
    state = MultihopRunnerState(tmp_path / "runner.sqlite")
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    assert state.begin(attempt)  # type: ignore[arg-type]
    with pytest.raises(LocalTopologyError, match="coordinates differ"):
        state.begin(replace(attempt, route="L"))  # type: ignore[arg-type]


def test_multihop_raw_identity_is_fail_closed_and_fsynced(tmp_path: Path) -> None:
    account = Account.from_key("0x" + "11" * 32)
    transaction = {
        "chainId": 31_337,
        "nonce": 9,
        "to": "0x" + "22" * 20,
        "data": b"multihop",
        "value": 0,
        "gas": 100_000,
        "maxFeePerGas": 1,
        "maxPriorityFeePerGas": 0,
        "type": 2,
    }
    signed = account.sign_transaction(transaction)
    raw = bytes(signed.raw_transaction)
    transaction_hash = _canonical_transaction_hash(signed.hash.hex())
    path = tmp_path / f"{transaction_hash}.raw"
    _write_private_raw_durably(path, raw)
    assert path.read_bytes() == raw
    assert path.stat().st_mode & 0o777 == 0o600

    runner = NativeMultihopRunner.__new__(NativeMultihopRunner)
    runner.account = account
    runner.chain_by_role = {"a": {"chain_id": 31_337}}
    detail = {
        "role": "a",
        "nonce": 9,
        "target": transaction["to"],
        "calldata_sha256": hashlib.sha256(b"multihop").hexdigest(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    runner._validate_durable_raw(
        raw=raw,
        transaction_hash=transaction_hash,
        detail=detail,
        role="a",
    )
    with pytest.raises(LocalTopologyError, match="identity drift"):
        runner._validate_durable_raw(
            raw=raw,
            transaction_hash=transaction_hash,
            detail={**detail, "calldata_sha256": "00" * 32},
            role="a",
        )
