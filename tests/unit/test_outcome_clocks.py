from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xir_lab.collect.outcomes import OutcomeClockError, OutcomeClockRecorder
from xir_lab.evidence.store import EvidenceStore

CHAIN = 84_532
APPROVAL_SHA = "11" * 32
BLOCK_HASH = "0x" + "22" * 32
TX_HASH = "0x" + "33" * 32


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("44" * 32,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-1', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-1', 'condition-1', 0)
            """
        )
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, pair_id, arm, attempt_kind,
                state, created_at
            ) VALUES (
                'attempt-1', 'condition-1', 'pair-1', 'xir',
                'primary', 'in_flight', '2026-07-26T00:00:00Z'
            )
            """
        )
        for ordinal, stage_name in enumerate(("source", "destination")):
            connection.execute(
                """
                INSERT INTO stages(
                    stage_id, attempt_id, ordinal, stage_name, chain_id, state
                ) VALUES (?, 'attempt-1', ?, ?, ?, 'collecting')
                """,
                (f"stage-{ordinal}", ordinal, stage_name, CHAIN),
            )
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES (
                'intent-1', 'stage-1', 'signop-1', ?, 1, 'submitted', ?,
                '2026-07-26T00:00:00Z'
            )
            """,
            (CHAIN, "55" * 32),
        )
        connection.execute(
            """
            INSERT INTO transactions(
                transaction_id, intent_id, chain_id, nonce,
                transaction_hash, state
            ) VALUES ('transaction-1', 'intent-1', ?, 1, ?, 'submitted')
            """,
            (CHAIN, TX_HASH),
        )
        connection.execute(
            """
            INSERT INTO approval_consumptions(
                approval_id, issuer_id, approval_key_id, issuer_sequence,
                operation_type, operation_id, payload_sha256,
                valid_from, valid_until, consumed_at
            ) VALUES (
                'approval-1', 'issuer-1', 'key-1', 1, 'primary', 'run-1', ?,
                '2026-07-25T00:00:00Z', '2026-07-27T00:00:00Z',
                '2026-07-26T00:00:00Z'
            )
            """,
            (APPROVAL_SHA,),
        )
    return store


def _recorder(tmp_path: Path) -> tuple[EvidenceStore, OutcomeClockRecorder]:
    store = _store(tmp_path)
    recorder = OutcomeClockRecorder(store=store)
    recorder.register_window(
        attempt_id="attempt-1",
        approval_id="approval-1",
        approval_payload_sha256=APPROVAL_SHA,
        observer_session_id="boot-a",
        started_utc="2026-07-26T00:00:00Z",
        started_monotonic_ns=1_000_000_000,
        deadline_utc="2026-07-26T00:01:00Z",
    )
    return store, recorder


def _finality_proof(store: EvidenceStore) -> str:
    proof_id = "finality-destination-1"
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO transaction_finality_observations(
                finality_observation_id, transaction_id, chain_id,
                block_number, block_hash, observation_state, canonical,
                policy_kind, policy_head_block, observed_at
            ) VALUES (
                ?, 'transaction-1', ?, 100, ?, 'finalized', 1,
                'l2-finalized', 100, '2026-07-26T00:02:00Z'
            )
            """,
            (proof_id, CHAIN, BLOCK_HASH),
        )
    return proof_id


def test_timeout_is_immutable_when_eventual_delivery_arrives(
    tmp_path: Path,
) -> None:
    store, recorder = _recorder(tmp_path)
    deadline = recorder.mark_deadline_timeout(
        attempt_id="attempt-1",
        observed_utc="2026-07-26T00:01:05Z",
        observer_session_id="boot-a",
        observed_monotonic_ns=66_000_000_000,
    )
    proof_id = _finality_proof(store)
    eventual = recorder.record_eventual_outcome(
        attempt_id="attempt-1",
        outcome="delivered_after_timeout",
        observed_utc="2026-07-26T00:02:00Z",
        observer_session_id="boot-a",
        observed_monotonic_ns=121_000_000_000,
        proof_finality_observation_id=proof_id,
    )
    assert deadline.outcome == "timed_out"
    assert eventual.outcome == "delivered_after_timeout"
    with store.connect(read_only=True) as connection:
        rows = connection.execute(
            """
            SELECT outcome_kind, outcome FROM attempt_outcome_observations
            ORDER BY rowid
            """
        ).fetchall()
        assert [tuple(row) for row in rows] == [
            ("deadline", "timed_out"),
            ("eventual", "delivered_after_timeout"),
        ]
        assert connection.execute(
            "SELECT state FROM attempts WHERE attempt_id = 'attempt-1'"
        ).fetchone()[0] == "timed_out"
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            """
            UPDATE attempt_outcome_observations
            SET outcome = 'delivered'
            WHERE outcome_kind = 'deadline'
            """
        )
    with pytest.raises(OutcomeClockError, match="already recorded"):
        recorder.mark_deadline_timeout(
            attempt_id="attempt-1",
            observed_utc="2026-07-26T00:03:00Z",
            observer_session_id="boot-a",
            observed_monotonic_ns=181_000_000_000,
        )


def test_eventual_delivery_requires_current_finalized_destination_proof(
    tmp_path: Path,
) -> None:
    store, recorder = _recorder(tmp_path)
    recorder.mark_deadline_timeout(
        attempt_id="attempt-1",
        observed_utc="2026-07-26T00:01:00Z",
        observer_session_id="boot-a",
        observed_monotonic_ns=61_000_000_000,
    )
    with pytest.raises(OutcomeClockError, match="requires finalized"):
        recorder.record_eventual_outcome(
            attempt_id="attempt-1",
            outcome="delivered_after_timeout",
            observed_utc="2026-07-26T00:02:00Z",
            observer_session_id="boot-a",
            observed_monotonic_ns=121_000_000_000,
        )
    proof_id = _finality_proof(store)
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO transaction_finality_observations(
                finality_observation_id, transaction_id, chain_id,
                block_number, block_hash, observation_state, canonical,
                policy_kind, supersedes_observation_id, observed_at
            ) VALUES (
                'orphan-1', 'transaction-1', ?, 100, ?, 'orphaned', 0,
                'l2-finalized', ?, '2026-07-26T00:02:01Z'
            )
            """,
            (CHAIN, BLOCK_HASH, proof_id),
        )
    with pytest.raises(OutcomeClockError, match="canonical finalized"):
        recorder.record_eventual_outcome(
            attempt_id="attempt-1",
            outcome="delivered_after_timeout",
            observed_utc="2026-07-26T00:02:00Z",
            observer_session_id="boot-a",
            observed_monotonic_ns=121_000_000_000,
            proof_finality_observation_id=proof_id,
        )


def test_observer_failure_stays_distinct_from_execution_and_submission(
    tmp_path: Path,
) -> None:
    store, recorder = _recorder(tmp_path)
    failure = recorder.record_failure(
        attempt_id="attempt-1",
        outcome="observer_failed",
        source="observer",
        failure_code="receipt_rpc_unavailable",
        observed_utc="2026-07-26T00:00:30Z",
        observer_session_id="boot-a",
        observed_monotonic_ns=31_000_000_000,
    )
    assert failure.outcome == "observer_failed"
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM attempts WHERE attempt_id = 'attempt-1'"
        ).fetchone()[0] == "observer_failed"
        assert connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-1'
            """
        ).fetchone()[0] == "submitted"
    with pytest.raises(OutcomeClockError, match="does not match"):
        recorder.record_failure(
            attempt_id="attempt-1",
            outcome="carrier_failed",
            source="observer",
            failure_code="rpc_timeout",
            observed_utc="2026-07-26T00:00:31Z",
            observer_session_id="boot-a",
            observed_monotonic_ns=32_000_000_000,
        )


def test_observer_elapsed_uses_monotonic_when_wall_clock_jumps(
    tmp_path: Path,
) -> None:
    _, recorder = _recorder(tmp_path)
    start = recorder.record_phase(
        attempt_id="attempt-1",
        phase="submitted",
        observer_session_id="boot-a",
        wall_utc="2026-07-26T00:00:10Z",
        monotonic_ns=11_000_000_000,
    )
    end = recorder.record_phase(
        attempt_id="attempt-1",
        phase="included",
        observer_session_id="boot-a",
        wall_utc="2026-07-26T00:00:05Z",
        monotonic_ns=13_000_000_000,
    )
    measurement = recorder.observer_duration(
        start_observation_id=start.observation_id,
        end_observation_id=end.observation_id,
    )
    assert end.wall_clock_discontinuity is True
    assert measurement.elapsed_ms == 2_000
    assert measurement.unavailable_reason == "wall_clock_discontinuity_recorded"
    assert "monotonic" in measurement.clock_statement


def test_independent_chain_clock_anomaly_is_unavailable_not_zero(
    tmp_path: Path,
) -> None:
    _, recorder = _recorder(tmp_path)
    source = recorder.record_chain_clock(
        attempt_id="attempt-1",
        role="source",
        chain_id=11_155_420,
        block_number=10,
        block_hash="0x" + "66" * 32,
        block_timestamp=1_000,
    )
    destination = recorder.record_chain_clock(
        attempt_id="attempt-1",
        role="destination",
        chain_id=84_532,
        block_number=20,
        block_hash="0x" + "77" * 32,
        block_timestamp=990,
    )
    measurement = recorder.cross_chain_interval(
        source_observation_id=source.observation_id,
        terminal_observation_id=destination.observation_id,
        maximum_plausible_seconds=300,
    )
    assert measurement.elapsed_ms is None
    assert measurement.unavailable_reason == "independent_chain_clocks_out_of_order"
    assert "not a precise common clock" in measurement.clock_statement


def test_window_is_approval_bound_and_utc_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    recorder = OutcomeClockRecorder(store=store)
    with pytest.raises(OutcomeClockError, match="consumed approval"):
        recorder.register_window(
            attempt_id="attempt-1",
            approval_id="approval-1",
            approval_payload_sha256="ff" * 32,
            observer_session_id="boot-a",
            started_utc="2026-07-26T00:00:00Z",
            started_monotonic_ns=1,
            deadline_utc="2026-07-26T00:01:00Z",
        )
    with pytest.raises(OutcomeClockError, match="must use UTC"):
        recorder.register_window(
            attempt_id="attempt-1",
            approval_id="approval-1",
            approval_payload_sha256=APPROVAL_SHA,
            observer_session_id="boot-a",
            started_utc="2026-07-26T08:00:00+08:00",
            started_monotonic_ns=1,
            deadline_utc="2026-07-26T08:01:00+08:00",
        )
