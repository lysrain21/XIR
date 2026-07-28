"""Persistent drain, halt, resume, and revocation control plane."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from xir_lab.evidence.store import EvidenceStore

ControlMode = Literal["running", "drain", "halted", "revoked"]


class ControlError(RuntimeError):
    """Raised when a stop-state transition or signing action is forbidden."""


@dataclass(frozen=True)
class ControlDecision:
    decision_id: str
    decision_sha256: str
    reason_code: str
    approval_payload_sha256: str | None = None


@dataclass(frozen=True)
class ControlState:
    run_id: str
    mode: ControlMode
    reason_code: str
    decision_id: str
    decision_sha256: str
    approval_payload_sha256: str | None
    sequence: int
    updated_at: datetime


@dataclass(frozen=True)
class ObservationWork:
    transaction_ids: tuple[str, ...]
    attempt_ids: tuple[str, ...]


def _digest(value: str | None, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if value is None or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ControlError(f"{label} must be a lowercase SHA-256 value")


def _time(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ControlError("control timestamps must be timezone-aware")
    return current.astimezone(UTC).isoformat()


class RunControlManager:
    """Persist control transitions and fail closed across process restarts."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def initialize(
        self,
        *,
        run_id: str,
        decision: ControlDecision,
        now: datetime | None = None,
    ) -> ControlState:
        self._validate_decision(decision)
        occurred_at = _time(now)
        with self.store.write() as connection:
            run = connection.execute(
                "SELECT state FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise ControlError(f"unknown run: {run_id}")
            present = connection.execute(
                "SELECT 1 FROM run_controls WHERE run_id = ?", (run_id,)
            ).fetchone()
            if present is not None:
                raise ControlError("run control state is already initialized")
            if run["state"] in {"halted", "revoked", "drain"}:
                raise ControlError("cannot initialize running over an existing stop state")
            connection.execute(
                """
                INSERT INTO run_controls(
                    run_id, mode, reason_code, decision_id, decision_sha256,
                    approval_payload_sha256, sequence, updated_at
                ) VALUES (?, 'running', ?, ?, ?, ?, 1, ?)
                """,
                (
                    run_id,
                    decision.reason_code,
                    decision.decision_id,
                    decision.decision_sha256,
                    decision.approval_payload_sha256,
                    occurred_at,
                ),
            )
            self._event(
                connection,
                run_id=run_id,
                from_mode=None,
                to_mode="running",
                decision=decision,
                occurred_at=occurred_at,
            )
        return self.state(run_id)

    def drain(
        self,
        *,
        run_id: str,
        decision: ControlDecision,
        now: datetime | None = None,
    ) -> ControlState:
        return self._transition(
            run_id=run_id,
            allowed_from={"running"},
            to_mode="drain",
            decision=decision,
            now=now,
        )

    def halt(
        self,
        *,
        run_id: str,
        decision: ControlDecision,
        now: datetime | None = None,
    ) -> ControlState:
        return self._transition(
            run_id=run_id,
            allowed_from={"running", "drain"},
            to_mode="halted",
            decision=decision,
            now=now,
        )

    def revoke(
        self,
        *,
        run_id: str,
        decision: ControlDecision,
        now: datetime | None = None,
    ) -> ControlState:
        return self._transition(
            run_id=run_id,
            allowed_from={"running", "drain", "halted"},
            to_mode="revoked",
            decision=decision,
            now=now,
        )

    def resume(
        self,
        *,
        run_id: str,
        decision: ControlDecision,
        approval_state_changed: bool,
        now: datetime | None = None,
    ) -> ControlState:
        if approval_state_changed and decision.approval_payload_sha256 is None:
            raise ControlError("changed approval-bound state requires a new approval digest")
        return self._transition(
            run_id=run_id,
            allowed_from={"drain", "halted"},
            to_mode="running",
            decision=decision,
            now=now,
        )

    def state(self, run_id: str) -> ControlState:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM run_controls WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise ControlError("run control state is not initialized")
        return self._state(row)

    def assert_signature_allowed(
        self,
        *,
        run_id: str,
        attempt_id: str,
        is_source_stage: bool,
        retained_signed_bytes: bool = False,
    ) -> None:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT control.mode, attempt.state AS attempt_state,
                       count(budget.chain_id) AS reservation_chains,
                       min(budget.source_in_flight) AS all_source_in_flight
                FROM run_controls AS control
                JOIN attempts AS attempt ON attempt.attempt_id = ?
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                 AND condition.run_id = control.run_id
                LEFT JOIN budgets AS budget ON budget.attempt_id = attempt.attempt_id
                WHERE control.run_id = ?
                GROUP BY control.mode, attempt.state
                """,
                (attempt_id, run_id),
            ).fetchone()
        if row is None:
            raise ControlError("cannot prove control, attempt, and run binding")
        mode = cast(ControlMode, row["mode"])
        if mode in {"halted", "revoked"}:
            kind = "retained-byte submission" if retained_signed_bytes else "signature"
            raise ControlError(f"{mode} blocks every new {kind}")
        if row["attempt_state"] != "in_flight":
            raise ControlError("attempt is not durably in flight")
        if int(row["reservation_chains"]) == 0 or not row["all_source_in_flight"]:
            raise ControlError("attempt lacks a complete in-flight route reservation")
        if mode == "drain" and is_source_stage:
            raise ControlError("drain blocks every new source attempt")

    def pending_observation_work(self, *, run_id: str) -> ObservationWork:
        with self.store.connect(read_only=True) as connection:
            transaction_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT transaction_record.transaction_id
                    FROM transactions AS transaction_record
                    JOIN intents AS intent
                      ON intent.intent_id = transaction_record.intent_id
                    JOIN stages AS stage ON stage.stage_id = intent.stage_id
                    JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                      AND transaction_record.state IN (
                          'broadcast_unknown','submitted','included'
                      )
                    ORDER BY transaction_record.transaction_id
                    """,
                    (run_id,),
                )
            )
            attempt_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT DISTINCT attempt.attempt_id
                    FROM attempts AS attempt
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    LEFT JOIN carrier_messages AS message
                      ON message.attempt_id = attempt.attempt_id
                    WHERE condition.run_id = ?
                      AND (
                          attempt.state = 'in_flight'
                          OR message.carrier_message_id IS NOT NULL
                      )
                    ORDER BY attempt.attempt_id
                    """,
                    (run_id,),
                )
            )
        return ObservationWork(transaction_ids, attempt_ids)

    def _transition(
        self,
        *,
        run_id: str,
        allowed_from: set[ControlMode],
        to_mode: ControlMode,
        decision: ControlDecision,
        now: datetime | None,
    ) -> ControlState:
        self._validate_decision(decision)
        occurred_at = _time(now)
        with self.store.write() as connection:
            row = connection.execute(
                "SELECT * FROM run_controls WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise ControlError("run control state is not initialized")
            current = cast(ControlMode, row["mode"])
            if current not in allowed_from:
                raise ControlError(f"cannot transition run control from {current} to {to_mode}")
            sequence = int(row["sequence"]) + 1
            connection.execute(
                """
                UPDATE run_controls
                SET mode = ?, reason_code = ?, decision_id = ?,
                    decision_sha256 = ?, approval_payload_sha256 = ?,
                    sequence = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    to_mode,
                    decision.reason_code,
                    decision.decision_id,
                    decision.decision_sha256,
                    decision.approval_payload_sha256,
                    sequence,
                    occurred_at,
                    run_id,
                ),
            )
            connection.execute(
                "UPDATE runs SET state = ? WHERE run_id = ?",
                (to_mode, run_id),
            )
            self._event(
                connection,
                run_id=run_id,
                from_mode=current,
                to_mode=to_mode,
                decision=decision,
                occurred_at=occurred_at,
            )
            self.store.append_transition(
                connection,
                entity_kind="run_control",
                entity_id=run_id,
                from_state=current,
                to_state=to_mode,
                payload={
                    "decision_id": decision.decision_id,
                    "reason_code": decision.reason_code,
                },
            )
        return self.state(run_id)

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        from_mode: ControlMode | None,
        to_mode: ControlMode,
        decision: ControlDecision,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO control_events(
                run_id, from_mode, to_mode, reason_code, decision_id,
                decision_sha256, approval_payload_sha256, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                from_mode,
                to_mode,
                decision.reason_code,
                decision.decision_id,
                decision.decision_sha256,
                decision.approval_payload_sha256,
                occurred_at,
            ),
        )

    @staticmethod
    def _validate_decision(decision: ControlDecision) -> None:
        if decision.decision_id == "" or decision.reason_code == "":
            raise ControlError("control decision ID and reason must be non-empty")
        _digest(decision.decision_sha256, "decision digest")
        _digest(
            decision.approval_payload_sha256,
            "approval payload digest",
            optional=True,
        )

    @staticmethod
    def _state(row: sqlite3.Row) -> ControlState:
        return ControlState(
            run_id=str(row["run_id"]),
            mode=cast(ControlMode, row["mode"]),
            reason_code=str(row["reason_code"]),
            decision_id=str(row["decision_id"]),
            decision_sha256=str(row["decision_sha256"]),
            approval_payload_sha256=(
                None
                if row["approval_payload_sha256"] is None
                else str(row["approval_payload_sha256"])
            ),
            sequence=int(row["sequence"]),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
        )
