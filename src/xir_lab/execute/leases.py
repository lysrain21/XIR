"""Durable work, nonce, and complete-route budget reservations."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from xir_lab.evidence.store import EvidenceStore


class LeaseError(RuntimeError):
    """Raised when exclusive work or nonce ownership cannot be proved."""


class BudgetError(RuntimeError):
    """Raised when a complete-route reservation or settlement is unsafe."""


@dataclass(frozen=True)
class WorkLease:
    lease_id: str
    attempt_id: str
    holder_id: str
    expires_at: datetime


@dataclass(frozen=True)
class BudgetLimit:
    chain_id: int
    max_transaction_wei: int
    max_batch_wei: int
    max_run_wei: int
    minimum_runner_balance_wei: int
    observed_runner_balance_wei: int


@dataclass(frozen=True)
class PlannedStageBudget:
    stage_key: str
    chain_id: int
    gas_wei: int
    carrier_payment_wei: int = 0
    transaction_value_wei: int = 0
    other_runner_funded_wei: int = 0
    replacement_allowance_wei: int = 0

    @property
    def worst_case_wei(self) -> int:
        values = (
            self.gas_wei,
            self.carrier_payment_wei,
            self.transaction_value_wei,
            self.other_runner_funded_wei,
            self.replacement_allowance_wei,
        )
        if any(value < 0 for value in values):
            raise BudgetError("planned stage budget values cannot be negative")
        return sum(values)


@dataclass(frozen=True)
class BudgetSnapshot:
    run_id: str
    chain_id: int
    active_reserved_wei: int
    provisional_wei: int
    finalized_wei: int
    observed_runner_balance_wei: int
    minimum_runner_balance_wei: int


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("lease timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _time(value: datetime | None = None) -> str:
    return _utc(value).isoformat()


def _details(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


class LeaseBudgetManager:
    """Serialize leases and budget changes through the evidence-store writer."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def configure_limits(
        self,
        *,
        run_id: str,
        limits: Iterable[BudgetLimit],
        observed_at: datetime | None = None,
    ) -> None:
        rows = tuple(limits)
        if not rows:
            raise BudgetError("at least one chain budget limit is required")
        if len({row.chain_id for row in rows}) != len(rows):
            raise BudgetError("chain budget limits must be unique")
        now = _time(observed_at)
        with self.store.write() as connection:
            if connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone() is None:
                raise BudgetError(f"unknown run: {run_id}")
            for limit in rows:
                values = (
                    limit.max_transaction_wei,
                    limit.max_batch_wei,
                    limit.max_run_wei,
                    limit.minimum_runner_balance_wei,
                    limit.observed_runner_balance_wei,
                )
                if any(value < 0 for value in values):
                    raise BudgetError("budget limits and balances cannot be negative")
                if not (
                    limit.max_transaction_wei
                    <= limit.max_batch_wei
                    <= limit.max_run_wei
                ):
                    raise BudgetError(
                        "budget limits must satisfy transaction <= batch <= run"
                    )
                present = connection.execute(
                    """
                    SELECT max_transaction_wei, max_batch_wei, max_run_wei,
                           minimum_runner_balance_wei
                    FROM budget_limits WHERE run_id = ? AND chain_id = ?
                    """,
                    (run_id, limit.chain_id),
                ).fetchone()
                immutable = (
                    limit.max_transaction_wei,
                    limit.max_batch_wei,
                    limit.max_run_wei,
                    limit.minimum_runner_balance_wei,
                )
                if present is not None and tuple(present) != immutable:
                    raise BudgetError("configured cumulative budget limits are immutable")
                connection.execute(
                    """
                    INSERT INTO budget_limits(
                        run_id, chain_id, max_transaction_wei, max_batch_wei,
                        max_run_wei, minimum_runner_balance_wei,
                        observed_runner_balance_wei, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id, chain_id) DO UPDATE SET
                        observed_runner_balance_wei = excluded.observed_runner_balance_wei,
                        updated_at = excluded.updated_at
                    """,
                    (run_id, limit.chain_id, *immutable, limit.observed_runner_balance_wei, now),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO budget_totals(
                        run_id, chain_id, active_reserved_wei, provisional_wei,
                        finalized_wei, updated_at
                    ) VALUES (?, ?, 0, 0, 0, ?)
                    """,
                    (run_id, limit.chain_id, now),
                )

    def acquire_work(
        self,
        *,
        lease_id: str,
        attempt_id: str,
        holder_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> WorkLease:
        acquired = _utc(now)
        if ttl <= timedelta(0):
            raise LeaseError("work lease TTL must be positive")
        expires = acquired + ttl
        with self.store.write() as connection:
            if connection.execute(
                "SELECT 1 FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone() is None:
                raise LeaseError(f"unknown attempt: {attempt_id}")
            active = connection.execute(
                """
                SELECT lease_id, holder_id, expires_at FROM work_leases
                WHERE attempt_id = ? AND state = 'active'
                """,
                (attempt_id,),
            ).fetchone()
            if active is not None:
                active_expiry = datetime.fromisoformat(str(active["expires_at"]))
                if active_expiry > acquired:
                    raise LeaseError(
                        f"attempt already leased by holder {active['holder_id']}"
                    )
                if self._attempt_has_unresolved_submission(connection, attempt_id):
                    raise LeaseError(
                        "expired work lease has unresolved transaction or nonce state"
                    )
                connection.execute(
                    """
                    UPDATE work_leases SET state = 'expired', released_at = ?
                    WHERE lease_id = ?
                    """,
                    (_time(acquired), active["lease_id"]),
                )
            connection.execute(
                """
                INSERT INTO work_leases(
                    lease_id, attempt_id, holder_id, acquired_at, heartbeat_at,
                    expires_at, state, released_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL)
                """,
                (
                    lease_id,
                    attempt_id,
                    holder_id,
                    _time(acquired),
                    _time(acquired),
                    _time(expires),
                ),
            )
            self.store.append_transition(
                connection,
                entity_kind="work_lease",
                entity_id=lease_id,
                from_state=None,
                to_state="active",
                payload={"attempt_id": attempt_id, "holder_id": holder_id},
            )
        return WorkLease(lease_id, attempt_id, holder_id, expires)

    def heartbeat_work(
        self,
        *,
        lease_id: str,
        holder_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> WorkLease:
        heartbeat = _utc(now)
        if ttl <= timedelta(0):
            raise LeaseError("work lease TTL must be positive")
        expires = heartbeat + ttl
        with self.store.write() as connection:
            row = connection.execute(
                """
                SELECT attempt_id, holder_id, expires_at, state FROM work_leases
                WHERE lease_id = ?
                """,
                (lease_id,),
            ).fetchone()
            if row is None or row["state"] != "active":
                raise LeaseError("work lease is not active")
            if row["holder_id"] != holder_id:
                raise LeaseError("work lease holder mismatch")
            if datetime.fromisoformat(str(row["expires_at"])) <= heartbeat:
                raise LeaseError("work lease has expired")
            connection.execute(
                """
                UPDATE work_leases SET heartbeat_at = ?, expires_at = ?
                WHERE lease_id = ?
                """,
                (_time(heartbeat), _time(expires), lease_id),
            )
        return WorkLease(lease_id, str(row["attempt_id"]), holder_id, expires)

    def release_work(self, *, lease_id: str, holder_id: str) -> None:
        with self.store.write() as connection:
            row = connection.execute(
                "SELECT holder_id, state FROM work_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None or row["state"] != "active":
                raise LeaseError("work lease is not active")
            if row["holder_id"] != holder_id:
                raise LeaseError("work lease holder mismatch")
            connection.execute(
                """
                UPDATE work_leases SET state = 'released', released_at = ?
                WHERE lease_id = ?
                """,
                (_time(), lease_id),
            )

    def reserve_complete_route(
        self,
        *,
        reservation_id: str,
        attempt_id: str,
        batch_id: str,
        stages: Iterable[PlannedStageBudget],
        now: datetime | None = None,
    ) -> None:
        planned = tuple(stages)
        if not planned:
            raise BudgetError("complete-route reservation requires planned stages")
        if len({stage.stage_key for stage in planned}) != len(planned):
            raise BudgetError("planned stage keys must be unique within an attempt")
        by_chain: dict[int, int] = defaultdict(int)
        stage_totals: list[tuple[PlannedStageBudget, int]] = []
        for stage in planned:
            total = stage.worst_case_wei
            by_chain[stage.chain_id] += total
            stage_totals.append((stage, total))
        occurred_at = _time(now)
        with self.store.write() as connection:
            attempt = connection.execute(
                """
                SELECT attempt.state, condition.run_id, run.state AS run_state
                FROM attempts AS attempt
                JOIN conditions AS condition
                    ON condition.condition_id = attempt.condition_id
                JOIN runs AS run ON run.run_id = condition.run_id
                WHERE attempt.attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                raise BudgetError(f"unknown attempt: {attempt_id}")
            if attempt["state"] != "planned":
                raise BudgetError("complete-route reservation requires a planned attempt")
            if attempt["run_state"] in {"drain", "halted", "revoked"}:
                raise BudgetError(
                    f"run state blocks new source attempts: {attempt['run_state']}"
                )
            run_id = str(attempt["run_id"])
            if connection.execute(
                "SELECT 1 FROM budgets WHERE attempt_id = ?", (attempt_id,)
            ).fetchone() is not None:
                raise BudgetError("attempt already has a complete-route reservation")
            for stage, total in stage_totals:
                limit = self._limit(connection, run_id, stage.chain_id)
                if total > int(limit["max_transaction_wei"]):
                    raise BudgetError(
                        f"stage {stage.stage_key} exceeds per-transaction limit"
                    )
            for chain_id, requested in by_chain.items():
                self._assert_capacity(
                    connection,
                    run_id=run_id,
                    batch_id=batch_id,
                    chain_id=chain_id,
                    requested_wei=requested,
                )
            for chain_id, requested in by_chain.items():
                connection.execute(
                    """
                    INSERT INTO budgets(
                        reservation_id, attempt_id, run_id, batch_id, chain_id,
                        reserved_wei, provisional_wei, finalized_wei,
                        source_in_flight, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 'reserved', ?)
                    """,
                    (
                        reservation_id,
                        attempt_id,
                        run_id,
                        batch_id,
                        chain_id,
                        requested,
                        occurred_at,
                    ),
                )
                self._change_totals(
                    connection,
                    run_id=run_id,
                    batch_id=batch_id,
                    chain_id=chain_id,
                    reserved_delta=requested,
                    provisional_delta=0,
                    finalized_delta=0,
                    occurred_at=occurred_at,
                )
                self._event(
                    connection,
                    run_id=run_id,
                    batch_id=batch_id,
                    chain_id=chain_id,
                    reservation_id=reservation_id,
                    subreservation_id=None,
                    event_type="route_reserved",
                    reserved_delta=requested,
                    provisional_delta=0,
                    finalized_delta=0,
                    details={"attempt_id": attempt_id},
                    occurred_at=occurred_at,
                )
            for index, (stage, total) in enumerate(stage_totals):
                connection.execute(
                    """
                    INSERT INTO transaction_subreservations(
                        subreservation_id, reservation_id, attempt_id, stage_key,
                        chain_id, reserved_wei, state
                    ) VALUES (?, ?, ?, ?, ?, ?, 'reserved')
                    """,
                    (
                        f"{reservation_id}:stage:{index}",
                        reservation_id,
                        attempt_id,
                        stage.stage_key,
                        stage.chain_id,
                        total,
                    ),
                )
            self.store.append_transition(
                connection,
                entity_kind="budget_reservation",
                entity_id=reservation_id,
                from_state=None,
                to_state="reserved",
                payload={
                    "attempt_id": attempt_id,
                    "batch_id": batch_id,
                    "chains": {
                        str(chain_id): amount
                        for chain_id, amount in sorted(by_chain.items())
                    },
                },
            )

    def mark_source_in_flight(
        self, *, reservation_id: str, now: datetime | None = None
    ) -> None:
        with self.store.write() as connection:
            rows = connection.execute(
                """
                SELECT budget.attempt_id, budget.run_id, run.state AS run_state,
                       budget.source_in_flight
                FROM budgets AS budget
                JOIN runs AS run ON run.run_id = budget.run_id
                WHERE budget.reservation_id = ?
                """,
                (reservation_id,),
            ).fetchall()
            if not rows:
                raise BudgetError(f"unknown reservation: {reservation_id}")
            if any(row["source_in_flight"] for row in rows):
                return
            if rows[0]["run_state"] in {"drain", "halted", "revoked"}:
                raise BudgetError("drain or hard stop blocks source-attempt start")
            attempt_id = str(rows[0]["attempt_id"])
            attempt = connection.execute(
                "SELECT state FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None or attempt["state"] != "planned":
                raise BudgetError("source start requires a planned attempt")
            connection.execute(
                """
                UPDATE budgets SET source_in_flight = 1, state = 'in_flight'
                WHERE reservation_id = ?
                """,
                (reservation_id,),
            )
            connection.execute(
                "UPDATE attempts SET state = 'in_flight' WHERE attempt_id = ?",
                (attempt_id,),
            )
            self.store.append_transition(
                connection,
                entity_kind="attempt",
                entity_id=attempt_id,
                from_state="planned",
                to_state="in_flight",
                payload={"reservation_id": reservation_id, "at": _time(now)},
            )

    def acquire_nonce_subreservation(
        self,
        *,
        lease_id: str,
        lineage_id: str,
        reservation_id: str,
        stage_key: str,
        signer_id: str,
        holder_id: str,
        nonce: int,
        requested_wei: int,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> None:
        acquired = _utc(now)
        if nonce < 0 or requested_wei < 0 or ttl <= timedelta(0):
            raise LeaseError("nonce, requested amount, and TTL must be non-negative")
        with self.store.write() as connection:
            sub = connection.execute(
                """
                SELECT sub.*, budget.source_in_flight, budget.run_id
                FROM transaction_subreservations AS sub
                JOIN budgets AS budget
                  ON budget.reservation_id = sub.reservation_id
                 AND budget.chain_id = sub.chain_id
                WHERE sub.reservation_id = ? AND sub.stage_key = ?
                """,
                (reservation_id, stage_key),
            ).fetchone()
            if sub is None:
                raise LeaseError("unknown transaction sub-reservation")
            if not sub["source_in_flight"]:
                raise LeaseError("source attempt is not in flight")
            if requested_wei > int(sub["reserved_wei"]):
                raise BudgetError("transaction does not fit its pre-existing reservation")
            limit = self._limit(connection, str(sub["run_id"]), int(sub["chain_id"]))
            if requested_wei > int(limit["max_transaction_wei"]):
                raise BudgetError("transaction exceeds the approved per-transaction limit")
            existing = connection.execute(
                """
                SELECT * FROM nonce_leases
                WHERE chain_id = ? AND signer_id = ? AND nonce = ?
                """,
                (sub["chain_id"], signer_id, nonce),
            ).fetchone()
            if existing is not None:
                coordinates = (
                    existing["lineage_id"],
                    existing["reservation_id"],
                    existing["stage_key"],
                )
                if coordinates != (lineage_id, reservation_id, stage_key):
                    raise LeaseError("nonce is already bound to another lineage")
                connection.execute(
                    """
                    UPDATE transaction_subreservations
                    SET allocated_wei = max(allocated_wei, ?)
                    WHERE subreservation_id = ?
                    """,
                    (requested_wei, sub["subreservation_id"]),
                )
                return
            if sub["lineage_id"] is not None:
                raise LeaseError("stage is already bound to another nonce lineage")
            connection.execute(
                """
                INSERT INTO nonce_leases(
                    lease_id, lineage_id, chain_id, signer_id, holder_id, nonce,
                    attempt_id, stage_key, reservation_id, acquired_at, expires_at,
                    state, locked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1)
                """,
                (
                    lease_id,
                    lineage_id,
                    sub["chain_id"],
                    signer_id,
                    holder_id,
                    nonce,
                    sub["attempt_id"],
                    stage_key,
                    reservation_id,
                    _time(acquired),
                    _time(acquired + ttl),
                ),
            )
            connection.execute(
                """
                UPDATE transaction_subreservations
                SET lineage_id = ?, allocated_wei = ?, state = 'active'
                WHERE subreservation_id = ?
                """,
                (lineage_id, requested_wei, sub["subreservation_id"]),
            )

    def mark_lineage_pending(
        self, *, lineage_id: str, state: str, now: datetime | None = None
    ) -> None:
        if state not in {"broadcast_unknown", "submitted"}:
            raise LeaseError("pending lineage state must be broadcast_unknown or submitted")
        with self.store.write() as connection:
            row = self._lineage(connection, lineage_id)
            if row["state"] in {"finalized", "released"}:
                raise LeaseError("settled nonce lineage cannot become pending")
            connection.execute(
                "UPDATE nonce_leases SET state = ?, locked = 1 WHERE lineage_id = ?",
                (state, lineage_id),
            )
            connection.execute(
                """
                UPDATE transaction_subreservations SET state = ?
                WHERE lineage_id = ?
                """,
                (state, lineage_id),
            )
            self._lineage_event(
                connection, row, f"lineage_{state}", 0, 0, 0, {}, _time(now)
            )

    def record_included(
        self,
        *,
        lineage_id: str,
        actual_spent_wei: int,
        now: datetime | None = None,
    ) -> None:
        if actual_spent_wei < 0:
            raise BudgetError("actual spending cannot be negative")
        occurred_at = _time(now)
        with self.store.write() as connection:
            row = self._lineage(connection, lineage_id)
            if row["state"] in {"finalized", "released"}:
                raise LeaseError("settled nonce lineage cannot become included")
            if actual_spent_wei > int(row["reserved_wei"]):
                raise BudgetError("receipt spending exceeds the locked reservation")
            difference = actual_spent_wei - int(row["provisional_wei"])
            connection.execute(
                """
                UPDATE nonce_leases SET state = 'included', locked = 1
                WHERE lineage_id = ?
                """,
                (lineage_id,),
            )
            connection.execute(
                """
                UPDATE transaction_subreservations
                SET provisional_wei = ?, state = 'included'
                WHERE lineage_id = ?
                """,
                (actual_spent_wei, lineage_id),
            )
            connection.execute(
                """
                UPDATE budgets SET provisional_wei = provisional_wei + ?
                WHERE reservation_id = ? AND chain_id = ?
                """,
                (difference, row["reservation_id"], row["chain_id"]),
            )
            self._change_totals(
                connection,
                run_id=str(row["run_id"]),
                batch_id=str(row["batch_id"]),
                chain_id=int(row["chain_id"]),
                reserved_delta=0,
                provisional_delta=difference,
                finalized_delta=0,
                occurred_at=occurred_at,
            )
            self._lineage_event(
                connection,
                row,
                "receipt_included",
                0,
                difference,
                0,
                {"actual_spent_wei": actual_spent_wei},
                occurred_at,
            )

    def finalize_lineage(
        self,
        *,
        lineage_id: str,
        actual_spent_wei: int,
        now: datetime | None = None,
    ) -> None:
        if actual_spent_wei < 0:
            raise BudgetError("actual spending cannot be negative")
        occurred_at = _time(now)
        with self.store.write() as connection:
            row = self._lineage(connection, lineage_id)
            if row["state"] == "finalized":
                if int(row["finalized_wei"]) != actual_spent_wei:
                    raise BudgetError("finalized spending is immutable")
                return
            if row["state"] == "released":
                raise LeaseError("released lineage cannot be finalized")
            reserved = int(row["reserved_wei"])
            if actual_spent_wei > reserved:
                raise BudgetError("final spending exceeds the locked reservation")
            provisional = int(row["provisional_wei"])
            connection.execute(
                """
                UPDATE transaction_subreservations
                SET provisional_wei = 0, finalized_wei = ?, state = 'finalized'
                WHERE lineage_id = ?
                """,
                (actual_spent_wei, lineage_id),
            )
            connection.execute(
                """
                UPDATE nonce_leases
                SET state = 'finalized', locked = 0, released_at = ?
                WHERE lineage_id = ?
                """,
                (occurred_at, lineage_id),
            )
            connection.execute(
                """
                UPDATE budgets
                SET provisional_wei = provisional_wei - ?,
                    finalized_wei = finalized_wei + ?
                WHERE reservation_id = ? AND chain_id = ?
                """,
                (
                    provisional,
                    actual_spent_wei,
                    row["reservation_id"],
                    row["chain_id"],
                ),
            )
            self._change_totals(
                connection,
                run_id=str(row["run_id"]),
                batch_id=str(row["batch_id"]),
                chain_id=int(row["chain_id"]),
                reserved_delta=-reserved,
                provisional_delta=-provisional,
                finalized_delta=actual_spent_wei,
                occurred_at=occurred_at,
            )
            self._lineage_event(
                connection,
                row,
                "lineage_finalized",
                -reserved,
                -provisional,
                actual_spent_wei,
                {"actual_spent_wei": actual_spent_wei},
                occurred_at,
            )
            self._settle_completed_budget_rows(connection, str(row["reservation_id"]))

    def release_dead_lineage(
        self,
        *,
        lineage_id: str,
        proof_sha256: str | None = None,
        signed_bytes_destroyed: bool = False,
        manual_release_decision_sha256: str | None = None,
        now: datetime | None = None,
    ) -> None:
        proof_release = proof_sha256 is not None and signed_bytes_destroyed
        manual_release = manual_release_decision_sha256 is not None
        if proof_release == manual_release:
            raise BudgetError(
                "release requires either proof plus destroyed bytes or one manual decision"
            )
        for digest in (proof_sha256, manual_release_decision_sha256):
            if digest is not None and (
                len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise BudgetError("release digests must be lowercase SHA-256 values")
        occurred_at = _time(now)
        with self.store.write() as connection:
            row = self._lineage(connection, lineage_id)
            if row["state"] in {"included", "finalized"}:
                raise BudgetError(
                    "included or finalized lineage must be canonically resolved first"
                )
            if row["state"] == "released":
                return
            reserved = int(row["reserved_wei"])
            connection.execute(
                """
                UPDATE transaction_subreservations
                SET state = 'released', release_proof_sha256 = ?,
                    manual_release_decision_sha256 = ?,
                    signed_bytes_destroyed = ?
                WHERE lineage_id = ?
                """,
                (
                    proof_sha256,
                    manual_release_decision_sha256,
                    int(signed_bytes_destroyed),
                    lineage_id,
                ),
            )
            connection.execute(
                """
                UPDATE nonce_leases
                SET state = 'released', locked = 0, released_at = ?
                WHERE lineage_id = ?
                """,
                (occurred_at, lineage_id),
            )
            self._change_totals(
                connection,
                run_id=str(row["run_id"]),
                batch_id=str(row["batch_id"]),
                chain_id=int(row["chain_id"]),
                reserved_delta=-reserved,
                provisional_delta=0,
                finalized_delta=0,
                occurred_at=occurred_at,
            )
            self._lineage_event(
                connection,
                row,
                "lineage_proof_released" if proof_release else "lineage_manual_released",
                -reserved,
                0,
                0,
                {
                    "proof_sha256": proof_sha256,
                    "manual_release_decision_sha256": manual_release_decision_sha256,
                    "signed_bytes_destroyed": signed_bytes_destroyed,
                },
                occurred_at,
            )
            self._settle_completed_budget_rows(connection, str(row["reservation_id"]))

    def reopen_after_reorganization(
        self,
        *,
        lineage_id: str,
        violation_id: str,
        now: datetime | None = None,
    ) -> None:
        occurred_at = _time(now)
        capacity_failure: str | None = None
        with self.store.write() as connection:
            row = self._lineage(connection, lineage_id)
            if row["state"] == "included":
                provisional = int(row["provisional_wei"])
                connection.execute(
                    """
                    UPDATE transaction_subreservations
                    SET provisional_wei = 0, state = 'reopened'
                    WHERE lineage_id = ?
                    """,
                    (lineage_id,),
                )
                connection.execute(
                    """
                    UPDATE nonce_leases
                    SET state = 'active', locked = 1, released_at = NULL
                    WHERE lineage_id = ?
                    """,
                    (lineage_id,),
                )
                connection.execute(
                    """
                    UPDATE budgets SET provisional_wei = provisional_wei - ?
                    WHERE reservation_id = ? AND chain_id = ?
                    """,
                    (provisional, row["reservation_id"], row["chain_id"]),
                )
                self._change_totals(
                    connection,
                    run_id=str(row["run_id"]),
                    batch_id=str(row["batch_id"]),
                    chain_id=int(row["chain_id"]),
                    reserved_delta=0,
                    provisional_delta=-provisional,
                    finalized_delta=0,
                    occurred_at=occurred_at,
                )
                self._lineage_event(
                    connection,
                    row,
                    "included_receipt_reopened",
                    0,
                    -provisional,
                    0,
                    {},
                    occurred_at,
                )
                return
            if row["state"] != "finalized":
                raise LeaseError("only included or finalized lineages can be reorganized")
            reserved = int(row["reserved_wei"])
            finalized = int(row["finalized_wei"])
            try:
                self._assert_capacity(
                    connection,
                    run_id=str(row["run_id"]),
                    batch_id=str(row["batch_id"]),
                    chain_id=int(row["chain_id"]),
                    requested_wei=reserved,
                    finalized_credit_wei=finalized,
                )
            except BudgetError as exc:
                capacity_failure = str(exc)
                connection.execute(
                    "UPDATE runs SET state = 'halted' WHERE run_id = ?",
                    (row["run_id"],),
                )
                connection.execute(
                    """
                    INSERT INTO invariant_violations(
                        violation_id, run_id, invariant_code, details_json, resolved_at
                    ) VALUES (?, ?, 'budget_reorg_restore_failed', ?, NULL)
                    """,
                    (
                        violation_id,
                        row["run_id"],
                        _details(
                            {
                                "lineage_id": lineage_id,
                                "reason": capacity_failure,
                            }
                        ),
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE transaction_subreservations
                    SET finalized_wei = 0, state = 'reopened'
                    WHERE lineage_id = ?
                    """,
                    (lineage_id,),
                )
                connection.execute(
                    """
                    UPDATE nonce_leases
                    SET state = 'active', locked = 1, released_at = NULL
                    WHERE lineage_id = ?
                    """,
                    (lineage_id,),
                )
                connection.execute(
                    """
                    UPDATE budgets
                    SET finalized_wei = finalized_wei - ?, state = 'in_flight'
                    WHERE reservation_id = ? AND chain_id = ?
                    """,
                    (finalized, row["reservation_id"], row["chain_id"]),
                )
                self._change_totals(
                    connection,
                    run_id=str(row["run_id"]),
                    batch_id=str(row["batch_id"]),
                    chain_id=int(row["chain_id"]),
                    reserved_delta=reserved,
                    provisional_delta=0,
                    finalized_delta=-finalized,
                    occurred_at=occurred_at,
                )
                self._lineage_event(
                    connection,
                    row,
                    "finalized_receipt_reopened",
                    reserved,
                    0,
                    -finalized,
                    {},
                    occurred_at,
                )
        if capacity_failure is not None:
            raise BudgetError(
                "reorganization reservation could not be restored; run halted"
            )

    def release_unstarted_route(
        self, *, reservation_id: str, now: datetime | None = None
    ) -> None:
        occurred_at = _time(now)
        with self.store.write() as connection:
            budgets = connection.execute(
                "SELECT * FROM budgets WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchall()
            if not budgets:
                raise BudgetError(f"unknown reservation: {reservation_id}")
            if any(row["source_in_flight"] for row in budgets):
                raise BudgetError("in-flight route reservation cannot be cancelled")
            for row in budgets:
                self._change_totals(
                    connection,
                    run_id=str(row["run_id"]),
                    batch_id=str(row["batch_id"]),
                    chain_id=int(row["chain_id"]),
                    reserved_delta=-int(row["reserved_wei"]),
                    provisional_delta=0,
                    finalized_delta=0,
                    occurred_at=occurred_at,
                )
                self._event(
                    connection,
                    run_id=str(row["run_id"]),
                    batch_id=str(row["batch_id"]),
                    chain_id=int(row["chain_id"]),
                    reservation_id=reservation_id,
                    subreservation_id=None,
                    event_type="unstarted_route_released",
                    reserved_delta=-int(row["reserved_wei"]),
                    provisional_delta=0,
                    finalized_delta=0,
                    details={},
                    occurred_at=occurred_at,
                )
            connection.execute(
                """
                UPDATE transaction_subreservations SET state = 'released'
                WHERE reservation_id = ?
                """,
                (reservation_id,),
            )
            connection.execute(
                """
                UPDATE budgets SET state = 'released'
                WHERE reservation_id = ?
                """,
                (reservation_id,),
            )

    def snapshots(self, *, run_id: str) -> tuple[BudgetSnapshot, ...]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT total.run_id, total.chain_id, total.active_reserved_wei,
                       total.provisional_wei, total.finalized_wei,
                       limits.observed_runner_balance_wei,
                       limits.minimum_runner_balance_wei
                FROM budget_totals AS total
                JOIN budget_limits AS limits
                  ON limits.run_id = total.run_id
                 AND limits.chain_id = total.chain_id
                WHERE total.run_id = ? ORDER BY total.chain_id
                """,
                (run_id,),
            ).fetchall()
        return tuple(
            BudgetSnapshot(
                run_id=str(row["run_id"]),
                chain_id=int(row["chain_id"]),
                active_reserved_wei=int(row["active_reserved_wei"]),
                provisional_wei=int(row["provisional_wei"]),
                finalized_wei=int(row["finalized_wei"]),
                observed_runner_balance_wei=int(row["observed_runner_balance_wei"]),
                minimum_runner_balance_wei=int(row["minimum_runner_balance_wei"]),
            )
            for row in rows
        )

    @staticmethod
    def _attempt_has_unresolved_submission(
        connection: sqlite3.Connection, attempt_id: str
    ) -> bool:
        transaction = connection.execute(
            """
            SELECT 1
            FROM transactions AS transaction_record
            JOIN intents AS intent ON intent.intent_id = transaction_record.intent_id
            JOIN stages AS stage ON stage.stage_id = intent.stage_id
            WHERE stage.attempt_id = ?
              AND transaction_record.state NOT IN ('finalized','released','dropped')
            LIMIT 1
            """,
            (attempt_id,),
        ).fetchone()
        nonce = connection.execute(
            """
            SELECT 1 FROM nonce_leases
            WHERE attempt_id = ? AND locked = 1
            LIMIT 1
            """,
            (attempt_id,),
        ).fetchone()
        return transaction is not None or nonce is not None

    @staticmethod
    def _limit(
        connection: sqlite3.Connection, run_id: str, chain_id: int
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM budget_limits WHERE run_id = ? AND chain_id = ?
            """,
            (run_id, chain_id),
        ).fetchone()
        if row is None:
            raise BudgetError(f"missing budget limit for chain {chain_id}")
        return cast(sqlite3.Row, row)

    def _assert_capacity(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        batch_id: str,
        chain_id: int,
        requested_wei: int,
        finalized_credit_wei: int = 0,
    ) -> None:
        limit = self._limit(connection, run_id, chain_id)
        total = connection.execute(
            """
            SELECT active_reserved_wei, finalized_wei FROM budget_totals
            WHERE run_id = ? AND chain_id = ?
            """,
            (run_id, chain_id),
        ).fetchone()
        if total is None:
            raise BudgetError("budget totals were not initialized")
        batch = connection.execute(
            """
            SELECT active_reserved_wei, finalized_wei FROM batch_budget_totals
            WHERE run_id = ? AND batch_id = ? AND chain_id = ?
            """,
            (run_id, batch_id, chain_id),
        ).fetchone()
        batch_active = 0 if batch is None else int(batch["active_reserved_wei"])
        batch_finalized = 0 if batch is None else int(batch["finalized_wei"])
        run_use = (
            int(total["active_reserved_wei"])
            + int(total["finalized_wei"])
            - finalized_credit_wei
            + requested_wei
        )
        batch_use = (
            batch_active + batch_finalized - finalized_credit_wei + requested_wei
        )
        if run_use > int(limit["max_run_wei"]):
            raise BudgetError(f"run budget exhausted on chain {chain_id}")
        if batch_use > int(limit["max_batch_wei"]):
            raise BudgetError(f"batch budget exhausted on chain {chain_id}")
        balance_after_reservations = (
            int(limit["observed_runner_balance_wei"])
            - int(total["active_reserved_wei"])
            - requested_wei
        )
        if balance_after_reservations < int(limit["minimum_runner_balance_wei"]):
            raise BudgetError(f"runner balance floor would be violated on chain {chain_id}")

    @staticmethod
    def _change_totals(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        batch_id: str,
        chain_id: int,
        reserved_delta: int,
        provisional_delta: int,
        finalized_delta: int,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            UPDATE budget_totals
            SET active_reserved_wei = active_reserved_wei + ?,
                provisional_wei = provisional_wei + ?,
                finalized_wei = finalized_wei + ?,
                updated_at = ?
            WHERE run_id = ? AND chain_id = ?
            """,
            (
                reserved_delta,
                provisional_delta,
                finalized_delta,
                occurred_at,
                run_id,
                chain_id,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE batch_budget_totals
            SET active_reserved_wei = active_reserved_wei + ?,
                provisional_wei = provisional_wei + ?,
                finalized_wei = finalized_wei + ?,
                updated_at = ?
            WHERE run_id = ? AND batch_id = ? AND chain_id = ?
            """,
            (
                reserved_delta,
                provisional_delta,
                finalized_delta,
                occurred_at,
                run_id,
                batch_id,
                chain_id,
            ),
        )
        if cursor.rowcount == 0:
            if min(reserved_delta, provisional_delta, finalized_delta) < 0:
                raise BudgetError("cannot subtract from missing batch budget totals")
            connection.execute(
                """
                INSERT INTO batch_budget_totals(
                    run_id, batch_id, chain_id, active_reserved_wei,
                    provisional_wei, finalized_wei, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    batch_id,
                    chain_id,
                    reserved_delta,
                    provisional_delta,
                    finalized_delta,
                    occurred_at,
                ),
            )

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        batch_id: str,
        chain_id: int,
        reservation_id: str,
        subreservation_id: str | None,
        event_type: str,
        reserved_delta: int,
        provisional_delta: int,
        finalized_delta: int,
        details: Mapping[str, Any],
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO budget_events(
                run_id, batch_id, chain_id, reservation_id, subreservation_id,
                event_type, reserved_delta_wei, provisional_delta_wei,
                finalized_delta_wei, details_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                batch_id,
                chain_id,
                reservation_id,
                subreservation_id,
                event_type,
                reserved_delta,
                provisional_delta,
                finalized_delta,
                _details(details),
                occurred_at,
            ),
        )

    def _lineage(
        self, connection: sqlite3.Connection, lineage_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT sub.*, nonce.state AS nonce_state, budget.run_id, budget.batch_id
            FROM transaction_subreservations AS sub
            JOIN nonce_leases AS nonce ON nonce.lineage_id = sub.lineage_id
            JOIN budgets AS budget
              ON budget.reservation_id = sub.reservation_id
             AND budget.chain_id = sub.chain_id
            WHERE sub.lineage_id = ?
            """,
            (lineage_id,),
        ).fetchone()
        if row is None:
            raise LeaseError(f"unknown nonce lineage: {lineage_id}")
        return cast(sqlite3.Row, row)

    def _lineage_event(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        event_type: str,
        reserved_delta: int,
        provisional_delta: int,
        finalized_delta: int,
        details: Mapping[str, Any],
        occurred_at: str,
    ) -> None:
        self._event(
            connection,
            run_id=str(row["run_id"]),
            batch_id=str(row["batch_id"]),
            chain_id=int(row["chain_id"]),
            reservation_id=str(row["reservation_id"]),
            subreservation_id=str(row["subreservation_id"]),
            event_type=event_type,
            reserved_delta=reserved_delta,
            provisional_delta=provisional_delta,
            finalized_delta=finalized_delta,
            details=details,
            occurred_at=occurred_at,
        )

    @staticmethod
    def _settle_completed_budget_rows(
        connection: sqlite3.Connection, reservation_id: str
    ) -> None:
        connection.execute(
            """
            UPDATE budgets
            SET state = 'settled'
            WHERE reservation_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM transaction_subreservations AS sub
                  WHERE sub.reservation_id = budgets.reservation_id
                    AND sub.chain_id = budgets.chain_id
                    AND sub.state NOT IN ('finalized','released')
              )
            """,
            (reservation_id,),
        )
