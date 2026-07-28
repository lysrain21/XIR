from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import (
    ControlDecision,
    ControlError,
    RunControlManager,
)
from xir_lab.execute.leases import (
    BudgetLimit,
    LeaseBudgetManager,
    PlannedStageBudget,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)
CHAIN = 11_155_420


def _decision(index: int, *, approval: bool = False) -> ControlDecision:
    return ControlDecision(
        decision_id=f"decision-{index}",
        decision_sha256=f"{index:02x}" * 32,
        reason_code=f"fixture-{index}",
        approval_payload_sha256=("ab" * 32 if approval else None),
    )


def _setup(tmp_path: Path) -> tuple[EvidenceStore, RunControlManager]:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', ?)
            """,
            ("11" * 32, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hh', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-0', 'condition-hh', 0)
            """
        )
    store.insert_attempt(
        attempt_id="attempt-0",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="primary",
    )
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO stages(stage_id, attempt_id, ordinal, stage_name, state)
            VALUES ('stage-0', 'attempt-0', 0, 'source_dispatch', 'planned')
            """
        )
    budgets = LeaseBudgetManager(store)
    budgets.configure_limits(
        run_id="run-1",
        limits=(BudgetLimit(CHAIN, 100, 100, 100, 0, 1_000),),
        observed_at=NOW,
    )
    budgets.reserve_complete_route(
        reservation_id="reservation-0",
        attempt_id="attempt-0",
        batch_id="batch-0",
        stages=(PlannedStageBudget("source", CHAIN, 80),),
        now=NOW,
    )
    budgets.mark_source_in_flight(reservation_id="reservation-0", now=NOW)
    manager = RunControlManager(store)
    manager.initialize(run_id="run-1", decision=_decision(1), now=NOW)
    return store, manager


def _seed_pending_transaction(store: EvidenceStore) -> None:
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES (
                'intent-0', 'stage-0', 'signop-0', ?, 7,
                'submitted', ?, ?
            )
            """,
            (CHAIN, "22" * 32, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO transactions(
                transaction_id, intent_id, chain_id, nonce, transaction_hash, state
            ) VALUES (
                'transaction-0', 'intent-0', ?, 7, ?, 'submitted'
            )
            """,
            (CHAIN, "0x" + "33" * 32),
        )


def test_drain_persists_across_restart_and_allows_only_inflight_continuation(
    tmp_path: Path,
) -> None:
    store, manager = _setup(tmp_path)
    state = manager.drain(run_id="run-1", decision=_decision(2), now=NOW)
    assert state.mode == "drain"
    restarted = RunControlManager(store)
    assert restarted.state("run-1").mode == "drain"

    with pytest.raises(ControlError, match="source"):
        restarted.assert_signature_allowed(
            run_id="run-1",
            attempt_id="attempt-0",
            is_source_stage=True,
        )
    restarted.assert_signature_allowed(
        run_id="run-1",
        attempt_id="attempt-0",
        is_source_stage=False,
    )


def test_halt_blocks_signatures_and_retained_signed_byte_submission(
    tmp_path: Path,
) -> None:
    _, manager = _setup(tmp_path)
    manager.halt(run_id="run-1", decision=_decision(2))
    with pytest.raises(ControlError, match="every new signature"):
        manager.assert_signature_allowed(
            run_id="run-1",
            attempt_id="attempt-0",
            is_source_stage=False,
        )
    with pytest.raises(ControlError, match="retained-byte"):
        manager.assert_signature_allowed(
            run_id="run-1",
            attempt_id="attempt-0",
            is_source_stage=False,
            retained_signed_bytes=True,
        )


def test_resume_is_explicit_and_changed_bound_state_requires_new_approval(
    tmp_path: Path,
) -> None:
    _, manager = _setup(tmp_path)
    manager.halt(run_id="run-1", decision=_decision(2))
    with pytest.raises(ControlError, match="new approval"):
        manager.resume(
            run_id="run-1",
            decision=_decision(3),
            approval_state_changed=True,
        )
    state = manager.resume(
        run_id="run-1",
        decision=_decision(3, approval=True),
        approval_state_changed=True,
    )
    assert state.mode == "running"
    assert state.sequence == 3


def test_revocation_is_not_locally_resumable_but_observation_continues(
    tmp_path: Path,
) -> None:
    store, manager = _setup(tmp_path)
    _seed_pending_transaction(store)
    manager.revoke(run_id="run-1", decision=_decision(2))
    with pytest.raises(ControlError, match="cannot transition"):
        manager.resume(
            run_id="run-1",
            decision=_decision(3, approval=True),
            approval_state_changed=True,
        )
    work = RunControlManager(store).pending_observation_work(run_id="run-1")
    assert work.transaction_ids == ("transaction-0",)
    assert work.attempt_ids == ("attempt-0",)


def test_control_decisions_are_append_only_and_replay_safe(tmp_path: Path) -> None:
    store, manager = _setup(tmp_path)
    manager.drain(run_id="run-1", decision=_decision(2))
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            "UPDATE control_events SET reason_code = 'forged' WHERE sequence = 1"
        )
    with pytest.raises(ControlError, match="cannot transition"):
        manager.drain(run_id="run-1", decision=_decision(2))
    with store.connect(read_only=True) as connection:
        events = connection.execute(
            """
            SELECT from_mode, to_mode, decision_id
            FROM control_events ORDER BY sequence
            """
        ).fetchall()
    assert [tuple(row) for row in events] == [
        (None, "running", "decision-1"),
        ("running", "drain", "decision-2"),
    ]
