"""Restartable bounded-batch execution over a frozen durable plan."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import rfc8785

from xir_lab.config.stages import StageTemplate, StageTemplateSet
from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import TERMINAL_ATTEMPT_STATES, EvidenceStore
from xir_lab.execute.controls import RunControlManager
from xir_lab.execute.leases import LeaseBudgetManager, LeaseError
from xir_lab.execute.scheduler import ExecutionPlan, ScheduledAttempt


class ExecutorError(RuntimeError):
    """Raised when durable execution would diverge from its frozen plan."""


@dataclass(frozen=True)
class ClaimedAttempt:
    attempt: ScheduledAttempt
    work_lease_id: str
    holder_id: str
    expires_at: datetime


@dataclass(frozen=True)
class ExecutorSnapshot:
    planned: int
    leased: int
    in_flight: int
    terminal: int
    current_batch: int | None


def _time(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ExecutorError("executor timestamps must be timezone-aware")
    return current.astimezone(UTC).isoformat()


def _lease_id(run_id: str, attempt_id: str, holder_id: str, now: datetime) -> str:
    material = rfc8785.dumps(
        {
            "domain": "xir-lab-work-lease-v1",
            "run_id": run_id,
            "attempt_id": attempt_id,
            "holder_id": holder_id,
            "acquired_at": _time(now),
        }
    )
    return "lease_" + hashlib.sha256(material).hexdigest()[:24]


class DurableBatchExecutor:
    """Persist a frozen plan and coordinate restart-safe work claims."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        plan: ExecutionPlan,
        templates: StageTemplateSet,
    ) -> None:
        self.store = store
        self.plan = plan
        self.templates: dict[tuple[str, str], StageTemplate] = {
            (template.condition, template.arm): template
            for template in templates.templates
        }
        self.leases = LeaseBudgetManager(store)
        self.controls = RunControlManager(store)

    def register_plan(self, *, now: datetime | None = None) -> None:
        if not self.plan.executable:
            raise ExecutorError("only a concrete live plan can enter execution storage")
        if len(self.templates) != 8:
            raise ExecutorError("all eight preregistered stage templates are required")
        created_at = _time(now)
        condition_ids = {
            condition: stable_id("condition", self.plan.run_id, condition)
            for condition in ("HH", "HL", "LH", "LL")
        }
        with self.store.write() as connection:
            run = connection.execute(
                "SELECT profile_id, plan_sha256 FROM runs WHERE run_id = ?",
                (self.plan.run_id,),
            ).fetchone()
            if run is None:
                connection.execute(
                    """
                    INSERT INTO runs(
                        run_id, profile_id, plan_sha256, state, created_at
                    ) VALUES (?, ?, ?, 'running', ?)
                    """,
                    (
                        self.plan.run_id,
                        self.plan.profile_id,
                        self.plan.plan_sha256,
                        created_at,
                    ),
                )
            elif (
                run["profile_id"],
                run["plan_sha256"],
            ) != (self.plan.profile_id, self.plan.plan_sha256):
                raise ExecutorError("run ID is already bound to another frozen plan")
            for condition, condition_id in condition_ids.items():
                connection.execute(
                    """
                    INSERT OR IGNORE INTO conditions(
                        condition_id, run_id, carrier_sequence, state
                    ) VALUES (?, ?, ?, 'planned')
                    """,
                    (condition_id, self.plan.run_id, condition),
                )
            for item in self.plan.attempts:
                condition_id = condition_ids[item.condition]
                if item.pair_id is not None:
                    if item.pair_slot_index is None:
                        raise ExecutorError("planned pair lost its slot index")
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO pairs(
                            pair_id, condition_id, slot_index
                        ) VALUES (?, ?, ?)
                        """,
                        (item.pair_id, condition_id, item.pair_slot_index),
                    )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO attempts(
                        attempt_id, condition_id, pair_id, arm, attempt_kind,
                        original_attempt_kind, retry_of, schedule_index,
                        batch_index, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, 'planned', ?)
                    """,
                    (
                        item.attempt_id,
                        condition_id,
                        item.pair_id,
                        item.arm,
                        item.attempt_kind,
                        item.sequence_index,
                        item.batch_index,
                        created_at,
                    ),
                )
                template = self.templates[(item.condition, item.arm)]
                for transaction in template.physical_transaction_templates:
                    stage_id = stable_id(
                        "stage",
                        item.attempt_id,
                        template.template_id,
                        transaction.ordinal,
                    )
                    labels_json = rfc8785.dumps(
                        list(transaction.logical_labels)
                    ).decode()
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO stages(
                            stage_id, attempt_id, ordinal, stage_name,
                            stage_template_id, chain_id, accounting_bucket,
                            logical_labels_json, state
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'planned')
                        """,
                        (
                            stage_id,
                            item.attempt_id,
                            transaction.ordinal,
                            transaction.transaction_template_id,
                            template.template_id,
                            transaction.chain_id,
                            transaction.accounting_bucket,
                            labels_json,
                        ),
                    )
            counts = connection.execute(
                """
                SELECT count(*) AS attempts,
                       count(DISTINCT schedule_index) AS schedule_indices
                FROM attempts
                JOIN conditions USING(condition_id)
                WHERE conditions.run_id = ? AND retry_of IS NULL
                """,
                (self.plan.run_id,),
            ).fetchone()
            if (
                int(counts["attempts"]) != len(self.plan.attempts)
                or int(counts["schedule_indices"]) != len(self.plan.attempts)
            ):
                raise ExecutorError("durable plan count does not match frozen expansion")

    def claim_next(
        self,
        *,
        holder_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> ClaimedAttempt | None:
        acquired = now or datetime.now(UTC)
        if acquired.tzinfo is None:
            raise ExecutorError("executor timestamps must be timezone-aware")
        control = self.controls.state(self.plan.run_id)
        if control.mode != "running":
            return None
        state_by_id, active_ids, current_batch = self._claim_state(acquired)
        if current_batch is None:
            return None
        maximum = self.plan.max_in_flight_attempts
        if maximum is None:
            raise ExecutorError("live plan lacks maximum in-flight limit")
        if len(active_ids) >= maximum:
            return None
        active_pairs = {
            item.pair_id
            for item in self.plan.attempts
            if item.attempt_id in active_ids and item.pair_id is not None
        }
        for item in self.plan.attempts:
            if item.batch_index != current_batch:
                continue
            state = state_by_id[item.attempt_id]
            if state != "planned" or item.attempt_id in active_ids:
                continue
            if item.pair_id is not None and item.pair_id in active_pairs:
                return None
            lease_id = _lease_id(
                self.plan.run_id,
                item.attempt_id,
                holder_id,
                acquired,
            )
            try:
                lease = self.leases.acquire_work(
                    lease_id=lease_id,
                    attempt_id=item.attempt_id,
                    holder_id=holder_id,
                    ttl=ttl,
                    now=acquired,
                )
            except LeaseError as exc:
                raise ExecutorError("durable work claim lost a concurrent race") from exc
            return ClaimedAttempt(
                attempt=item,
                work_lease_id=lease.lease_id,
                holder_id=holder_id,
                expires_at=lease.expires_at,
            )
        return None

    def transition_stage(
        self,
        *,
        stage_id: str,
        to_state: str,
    ) -> None:
        transitions = {
            "planned": {"prepared"},
            "prepared": {"in_flight"},
            "in_flight": {"completed", "failed"},
        }
        with self.store.write() as connection:
            row = connection.execute(
                """
                SELECT stage.*, attempt.state AS attempt_state
                FROM stages AS stage
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                WHERE stage.stage_id = ?
                """,
                (stage_id,),
            ).fetchone()
            if row is None:
                raise ExecutorError(f"unknown stage: {stage_id}")
            current = str(row["state"])
            if current == to_state:
                return
            if to_state not in transitions.get(current, set()):
                raise ExecutorError(f"invalid stage transition: {current} -> {to_state}")
            if to_state == "prepared":
                prior_incomplete = connection.execute(
                    """
                    SELECT 1 FROM stages
                    WHERE attempt_id = ? AND ordinal < ? AND state != 'completed'
                    LIMIT 1
                    """,
                    (row["attempt_id"], row["ordinal"]),
                ).fetchone()
                if prior_incomplete is not None:
                    raise ExecutorError("prior preregistered stage is not complete")
            if to_state == "in_flight":
                intent = connection.execute(
                    "SELECT 1 FROM intents WHERE stage_id = ? LIMIT 1",
                    (stage_id,),
                ).fetchone()
                if intent is None:
                    raise ExecutorError("stage cannot enter flight before durable intent")
            connection.execute(
                "UPDATE stages SET state = ? WHERE stage_id = ?",
                (to_state, stage_id),
            )
            self.store.append_transition(
                connection,
                entity_kind="stage",
                entity_id=stage_id,
                from_state=current,
                to_state=to_state,
                payload={},
            )

    def complete_attempt(
        self,
        *,
        attempt_id: str,
        work_lease_id: str,
        holder_id: str,
    ) -> None:
        with self.store.write() as connection:
            row = connection.execute(
                """
                SELECT attempt.state,
                       sum(stage.state != 'completed') AS incomplete
                FROM attempts AS attempt
                JOIN stages AS stage ON stage.attempt_id = attempt.attempt_id
                WHERE attempt.attempt_id = ?
                GROUP BY attempt.state
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise ExecutorError(f"unknown attempt: {attempt_id}")
            if int(row["incomplete"]) != 0:
                raise ExecutorError("attempt cannot complete with unfinished stages")
            if row["state"] == "delivered":
                return
            connection.execute(
                "UPDATE attempts SET state = 'delivered' WHERE attempt_id = ?",
                (attempt_id,),
            )
            self.store.append_transition(
                connection,
                entity_kind="attempt",
                entity_id=attempt_id,
                from_state=str(row["state"]),
                to_state="delivered",
                payload={},
            )
        self.leases.release_work(
            lease_id=work_lease_id,
            holder_id=holder_id,
        )

    def assert_intent_before_broadcast(self) -> None:
        with self.store.connect(read_only=True) as connection:
            unregistered = connection.execute(
                """
                SELECT transaction_record.transaction_id
                FROM transactions AS transaction_record
                LEFT JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                WHERE transaction_record.state IN (
                    'broadcast_unknown','submitted','included','finalized'
                )
                  AND (
                    intent.intent_id IS NULL
                    OR intent.state = 'prepared'
                  )
                LIMIT 1
                """
            ).fetchone()
        if unregistered is not None:
            raise ExecutorError(
                f"broadcast lacks durable signed intent: {unregistered[0]}"
            )

    def snapshot(self, *, now: datetime | None = None) -> ExecutorSnapshot:
        current = now or datetime.now(UTC)
        state_by_id, active_ids, batch = self._claim_state(current)
        terminal = sum(
            state in TERMINAL_ATTEMPT_STATES for state in state_by_id.values()
        )
        in_flight = sum(state == "in_flight" for state in state_by_id.values())
        leased = len(active_ids) - in_flight
        planned = sum(state == "planned" for state in state_by_id.values())
        return ExecutorSnapshot(planned, max(0, leased), in_flight, terminal, batch)

    def _claim_state(
        self, now: datetime
    ) -> tuple[dict[str, str], set[str], int | None]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT attempt.attempt_id, attempt.state, attempt.batch_index,
                       lease.expires_at
                FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                LEFT JOIN work_leases AS lease
                  ON lease.attempt_id = attempt.attempt_id
                 AND lease.state = 'active'
                WHERE condition.run_id = ? AND attempt.retry_of IS NULL
                ORDER BY attempt.schedule_index
                """,
                (self.plan.run_id,),
            ).fetchall()
        if len(rows) != len(self.plan.attempts):
            raise ExecutorError("durable attempts no longer match frozen plan")
        states = {str(row["attempt_id"]): str(row["state"]) for row in rows}
        active = {
            str(row["attempt_id"])
            for row in rows
            if row["state"] == "in_flight"
            or (
                row["expires_at"] is not None
                and datetime.fromisoformat(str(row["expires_at"]))
                > now.astimezone(UTC)
            )
        }
        unfinished_batches = [
            int(row["batch_index"])
            for row in rows
            if row["state"] not in TERMINAL_ATTEMPT_STATES
        ]
        return states, active, min(unfinished_batches, default=None)
