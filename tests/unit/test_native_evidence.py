from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xir_lab.evidence.native import (
    NativeActionIntent,
    NativeActionObservation,
    NativeEvidenceStore,
    NativeProcessSample,
    native_evidence_id,
)
from xir_lab.evidence.store import EvidenceStore, StoreError

DIGEST = "ab" * 32


def _native_store(tmp_path: Path) -> tuple[EvidenceStore, NativeEvidenceStore]:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-native', 'native-v1', ?, 'running', 'now')
            """,
            (DIGEST,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hl', 'run-native', 'HL', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, arm, attempt_kind, state, created_at
            ) VALUES ('attempt-hl-0', 'condition-hl', 'xir', 'primary', 'planned', 'now')
            """
        )
    return store, NativeEvidenceStore(store)


def _intent(action_id: str, **updates: object) -> NativeActionIntent:
    values: dict[str, object] = {
        "action_id": action_id,
        "run_id": "run-native",
        "attempt_id": "attempt-hl-0",
        "protocol": "layerzero-v2",
        "action_kind": "endpoint-send",
        "chain_id": 3133701,
        "actor_public_id": "runner-1",
        "nonce": 1,
        "target": "0x1111111111111111111111111111111111111111",
        "calldata_sha256": DIGEST,
        "calldata_bytes": 96,
        "protocol_identifier": "guid-1",
    }
    values.update(updates)
    return NativeActionIntent(**values)  # type: ignore[arg-type]


def test_migration_two_is_applied_and_native_tables_are_strict(tmp_path: Path) -> None:
    store, _ = _native_store(tmp_path)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT max(version) FROM schema_migrations"
        ).fetchone()[0] == 2
        assert connection.execute(
            """
            SELECT count(*) FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'native_%'
            """
        ).fetchone()[0] >= 10


def test_action_intent_precedes_append_only_observations(tmp_path: Path) -> None:
    store, native = _native_store(tmp_path)
    with pytest.raises(StoreError, match="lacks prior intent"):
        native.append_action_observation(
            NativeActionObservation(
                observation_id="orphan",
                action_id="missing",
                state="submitted",
                transaction_id=None,
                raw_sha256=None,
                error_class=None,
                details={},
            )
        )

    native.record_action_intent(_intent("action-1"))
    native.append_action_observation(
        NativeActionObservation(
            observation_id=native_evidence_id("action_observation", "action-1", 1),
            action_id="action-1",
            state="submitted",
            transaction_id=None,
            raw_sha256=None,
            error_class=None,
            details={"rpc": "local-source"},
        )
    )
    native.append_action_observation(
        NativeActionObservation(
            observation_id=native_evidence_id("action_observation", "action-1", 2),
            action_id="action-1",
            state="succeeded",
            transaction_id=None,
            raw_sha256=None,
            error_class=None,
            details={},
        )
    )
    with pytest.raises(StoreError, match="terminal native action"):
        native.append_action_observation(
            NativeActionObservation(
                observation_id="too-late",
                action_id="action-1",
                state="finalized",
                transaction_id=None,
                raw_sha256=None,
                error_class=None,
                details={},
            )
        )
    with store.write() as connection, pytest.raises(
        sqlite3.IntegrityError, match="append-only"
    ):
        connection.execute(
            """
            UPDATE native_action_observations SET state = 'failed'
            WHERE action_id = 'action-1'
            """
        )


def test_retry_preserves_semantic_coordinates_and_is_consecutive(tmp_path: Path) -> None:
    _, native = _native_store(tmp_path)
    native.record_action_intent(_intent("action-1"))
    native.record_action_intent(
        _intent(
            "action-2",
            nonce=2,
            retry_of_action_id="action-1",
            retry_index=1,
        )
    )
    with pytest.raises(StoreError, match="changed semantic coordinates"):
        native.record_action_intent(
            _intent(
                "action-3",
                nonce=3,
                protocol_identifier="another-guid",
                retry_of_action_id="action-2",
                retry_index=2,
            )
        )


def test_empty_resource_sample_must_be_an_explicit_gap(tmp_path: Path) -> None:
    _, native = _native_store(tmp_path)
    empty = NativeProcessSample(
        sample_id="sample-1",
        run_id="run-native",
        phase="smoke",
        process_kind="hyperlane-relayer",
        process_id="relayer-1",
        pid=None,
        cpu_percent=None,
        rss_bytes=None,
        read_bytes=None,
        write_bytes=None,
        network_rx_bytes=None,
        network_tx_bytes=None,
        queue_depth=None,
        healthy=None,
        gap_error=None,
    )
    with pytest.raises(StoreError, match="requires a gap error"):
        native.record_process_sample(empty)
    native.record_process_sample(
        NativeProcessSample(**{**empty.__dict__, "gap_error": "process-not-readable"})
    )
