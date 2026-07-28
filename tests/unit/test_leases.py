from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.leases import (
    BudgetError,
    BudgetLimit,
    LeaseBudgetManager,
    LeaseError,
    PlannedStageBudget,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)
CHAIN = 11_155_420


def _seed(
    tmp_path: Path,
    *,
    attempts: int = 3,
    limit: BudgetLimit | None = None,
) -> tuple[EvidenceStore, LeaseBudgetManager]:
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
        for index in range(attempts):
            connection.execute(
                """
                INSERT INTO pairs(pair_id, condition_id, slot_index)
                VALUES (?, 'condition-hh', ?)
                """,
                (f"pair-{index}", index),
            )
    for index in range(attempts):
        store.insert_attempt(
            attempt_id=f"attempt-{index}",
            condition_id="condition-hh",
            pair_id=f"pair-{index}",
            arm="baseline" if index % 2 == 0 else "xir",
            attempt_kind="primary",
        )
    manager = LeaseBudgetManager(store)
    manager.configure_limits(
        run_id="run-1",
        limits=(
            limit
            or BudgetLimit(
                CHAIN,
                max_transaction_wei=100,
                max_batch_wei=180,
                max_run_wei=200,
                minimum_runner_balance_wei=50,
                observed_runner_balance_wei=250,
            ),
        ),
        observed_at=NOW,
    )
    return store, manager


def _reserve(
    manager: LeaseBudgetManager,
    *,
    attempt: int,
    amount: int,
    batch_id: str = "batch-1",
) -> str:
    reservation_id = f"reservation-{attempt}"
    manager.reserve_complete_route(
        reservation_id=reservation_id,
        attempt_id=f"attempt-{attempt}",
        batch_id=batch_id,
        stages=(
            PlannedStageBudget(
                stage_key="source",
                chain_id=CHAIN,
                gas_wei=amount,
            ),
        ),
        now=NOW,
    )
    return reservation_id


def _start_lineage(
    manager: LeaseBudgetManager,
    *,
    attempt: int,
    amount: int,
    nonce: int,
) -> str:
    reservation_id = _reserve(manager, attempt=attempt, amount=amount)
    manager.mark_source_in_flight(reservation_id=reservation_id, now=NOW)
    lineage_id = f"lineage-{attempt}"
    manager.acquire_nonce_subreservation(
        lease_id=f"nonce-lease-{attempt}",
        lineage_id=lineage_id,
        reservation_id=reservation_id,
        stage_key="source",
        signer_id="runner",
        holder_id="worker",
        nonce=nonce,
        requested_wei=amount,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    return lineage_id


def test_complete_route_reservation_is_atomic_across_concurrent_workers(
    tmp_path: Path,
) -> None:
    store, manager = _seed(tmp_path, attempts=2)
    errors: list[BaseException] = []

    def reserve(attempt: int) -> None:
        try:
            _reserve(manager, attempt=attempt, amount=100)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    workers = [threading.Thread(target=reserve, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert len(errors) == 1
    assert isinstance(errors[0], BudgetError)
    snapshot = manager.snapshots(run_id="run-1")[0]
    assert snapshot.active_reserved_wei == 100
    with store.connect(read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM budgets").fetchone()[0] == 1


def test_reservation_checks_transaction_run_batch_and_balance_floor(
    tmp_path: Path,
) -> None:
    _, manager = _seed(
        tmp_path,
        limit=BudgetLimit(CHAIN, 100, 180, 200, 170, 250),
    )
    with pytest.raises(BudgetError, match="per-transaction"):
        _reserve(manager, attempt=0, amount=101)

    _reserve(manager, attempt=0, amount=70)
    with pytest.raises(BudgetError, match="balance floor"):
        _reserve(manager, attempt=1, amount=20)


def test_in_flight_reservation_cannot_grow_and_replacements_share_nonce(
    tmp_path: Path,
) -> None:
    store, manager = _seed(tmp_path)
    reservation = _reserve(manager, attempt=0, amount=80)
    manager.mark_source_in_flight(reservation_id=reservation, now=NOW)
    manager.acquire_nonce_subreservation(
        lease_id="nonce-lease",
        lineage_id="lineage",
        reservation_id=reservation,
        stage_key="source",
        signer_id="runner",
        holder_id="worker-a",
        nonce=7,
        requested_wei=60,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    manager.acquire_nonce_subreservation(
        lease_id="ignored-replacement-lease",
        lineage_id="lineage",
        reservation_id=reservation,
        stage_key="source",
        signer_id="runner",
        holder_id="worker-b",
        nonce=7,
        requested_wei=80,
        ttl=timedelta(minutes=5),
        now=NOW + timedelta(minutes=1),
    )
    with pytest.raises(BudgetError, match="pre-existing reservation"):
        manager.acquire_nonce_subreservation(
            lease_id="too-large",
            lineage_id="lineage",
            reservation_id=reservation,
            stage_key="source",
            signer_id="runner",
            holder_id="worker-b",
            nonce=7,
            requested_wei=81,
            ttl=timedelta(minutes=5),
            now=NOW,
        )
    with store.connect(read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM nonce_leases").fetchone()[0] == 1
        row = connection.execute(
            "SELECT allocated_wei FROM transaction_subreservations"
        ).fetchone()
        assert row[0] == 80
    assert manager.snapshots(run_id="run-1")[0].active_reserved_wei == 80


def test_unknown_and_included_lineages_stay_locked_until_finality(
    tmp_path: Path,
) -> None:
    store, manager = _seed(tmp_path)
    lineage = _start_lineage(manager, attempt=0, amount=80, nonce=7)
    manager.mark_lineage_pending(lineage_id=lineage, state="broadcast_unknown", now=NOW)
    snapshot = manager.snapshots(run_id="run-1")[0]
    assert (snapshot.active_reserved_wei, snapshot.provisional_wei) == (80, 0)

    manager.record_included(lineage_id=lineage, actual_spent_wei=55, now=NOW)
    snapshot = manager.snapshots(run_id="run-1")[0]
    assert (snapshot.active_reserved_wei, snapshot.provisional_wei) == (80, 55)
    with pytest.raises(BudgetError, match="canonically resolved"):
        manager.release_dead_lineage(
            lineage_id=lineage,
            proof_sha256="ab" * 32,
            signed_bytes_destroyed=True,
        )

    manager.finalize_lineage(lineage_id=lineage, actual_spent_wei=55, now=NOW)
    snapshot = manager.snapshots(run_id="run-1")[0]
    assert (
        snapshot.active_reserved_wei,
        snapshot.provisional_wei,
        snapshot.finalized_wei,
    ) == (0, 0, 55)
    with store.connect(read_only=True) as connection:
        nonce = connection.execute(
            "SELECT state, locked FROM nonce_leases WHERE lineage_id = ?",
            (lineage,),
        ).fetchone()
        assert tuple(nonce) == ("finalized", 0)


def test_release_requires_proof_and_destroyed_bytes_or_manual_authorization(
    tmp_path: Path,
) -> None:
    _, manager = _seed(tmp_path)
    lineage = _start_lineage(manager, attempt=0, amount=60, nonce=7)
    manager.mark_lineage_pending(lineage_id=lineage, state="broadcast_unknown")
    with pytest.raises(BudgetError, match="requires either"):
        manager.release_dead_lineage(lineage_id=lineage, proof_sha256="ab" * 32)
    with pytest.raises(BudgetError, match="requires either"):
        manager.release_dead_lineage(
            lineage_id=lineage,
            proof_sha256="ab" * 32,
            signed_bytes_destroyed=True,
            manual_release_decision_sha256="cd" * 32,
        )
    manager.release_dead_lineage(
        lineage_id=lineage,
        proof_sha256="ab" * 32,
        signed_bytes_destroyed=True,
    )
    assert manager.snapshots(run_id="run-1")[0].active_reserved_wei == 0

    second = _start_lineage(manager, attempt=1, amount=50, nonce=8)
    manager.release_dead_lineage(
        lineage_id=second,
        manual_release_decision_sha256="cd" * 32,
    )
    assert manager.snapshots(run_id="run-1")[0].active_reserved_wei == 0


def test_reorganization_reopens_or_durably_halts_if_capacity_was_reused(
    tmp_path: Path,
) -> None:
    store, manager = _seed(
        tmp_path,
        limit=BudgetLimit(CHAIN, 100, 120, 120, 0, 250),
    )
    lineage = _start_lineage(manager, attempt=0, amount=80, nonce=7)
    manager.record_included(lineage_id=lineage, actual_spent_wei=40)
    manager.finalize_lineage(lineage_id=lineage, actual_spent_wei=40)
    _reserve(manager, attempt=1, amount=50, batch_id="batch-2")

    with pytest.raises(BudgetError, match="run halted"):
        manager.reopen_after_reorganization(
            lineage_id=lineage,
            violation_id="violation-reorg",
        )
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM runs WHERE run_id = 'run-1'"
        ).fetchone()[0] == "halted"
        assert connection.execute(
            """
            SELECT invariant_code FROM invariant_violations
            WHERE violation_id = 'violation-reorg'
            """
        ).fetchone()[0] == "budget_reorg_restore_failed"


def test_included_reorganization_reopens_without_releasing_reservation(
    tmp_path: Path,
) -> None:
    _, manager = _seed(tmp_path)
    lineage = _start_lineage(manager, attempt=0, amount=80, nonce=7)
    manager.record_included(lineage_id=lineage, actual_spent_wei=40)
    manager.reopen_after_reorganization(
        lineage_id=lineage,
        violation_id="unused-violation-id",
    )
    snapshot = manager.snapshots(run_id="run-1")[0]
    assert (
        snapshot.active_reserved_wei,
        snapshot.provisional_wei,
        snapshot.finalized_wei,
    ) == (80, 0, 0)


def test_drain_blocks_source_start_but_existing_in_flight_route_can_continue(
    tmp_path: Path,
) -> None:
    store, manager = _seed(tmp_path, attempts=2)
    first = _reserve(manager, attempt=0, amount=60)
    manager.mark_source_in_flight(reservation_id=first)
    second = _reserve(manager, attempt=1, amount=50)
    with store.write() as connection:
        connection.execute("UPDATE runs SET state = 'drain' WHERE run_id = 'run-1'")

    manager.acquire_nonce_subreservation(
        lease_id="nonce-live",
        lineage_id="lineage-live",
        reservation_id=first,
        stage_key="source",
        signer_id="runner",
        holder_id="worker",
        nonce=7,
        requested_wei=60,
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(BudgetError, match="drain"):
        manager.mark_source_in_flight(reservation_id=second)
    with pytest.raises(BudgetError, match="blocks new source"):
        manager.reserve_complete_route(
            reservation_id="reservation-new",
            attempt_id="attempt-1",
            batch_id="batch-2",
            stages=(PlannedStageBudget("replacement", CHAIN, 1),),
        )
    manager.release_unstarted_route(reservation_id=second)
    assert manager.snapshots(run_id="run-1")[0].active_reserved_wei == 60


def test_expired_work_lease_reclaim_requires_resolved_nonce_state(
    tmp_path: Path,
) -> None:
    _, manager = _seed(tmp_path)
    manager.acquire_work(
        lease_id="work-1",
        attempt_id="attempt-0",
        holder_id="worker-a",
        ttl=timedelta(seconds=10),
        now=NOW,
    )
    lineage = _start_lineage(manager, attempt=0, amount=60, nonce=7)
    with pytest.raises(LeaseError, match="unresolved"):
        manager.acquire_work(
            lease_id="work-2",
            attempt_id="attempt-0",
            holder_id="worker-b",
            ttl=timedelta(seconds=10),
            now=NOW + timedelta(seconds=11),
        )
    manager.release_dead_lineage(
        lineage_id=lineage,
        proof_sha256="ab" * 32,
        signed_bytes_destroyed=True,
    )
    lease = manager.acquire_work(
        lease_id="work-2",
        attempt_id="attempt-0",
        holder_id="worker-b",
        ttl=timedelta(seconds=10),
        now=NOW + timedelta(seconds=11),
    )
    assert lease.holder_id == "worker-b"


def test_cumulative_totals_survive_manager_restart(tmp_path: Path) -> None:
    store, manager = _seed(tmp_path)
    lineage = _start_lineage(manager, attempt=0, amount=80, nonce=7)
    manager.record_included(lineage_id=lineage, actual_spent_wei=45)
    restarted = LeaseBudgetManager(store)
    assert restarted.snapshots(run_id="run-1")[0] == manager.snapshots(run_id="run-1")[0]
