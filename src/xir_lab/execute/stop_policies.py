"""Persistent stop-policy evaluation for financial and operational safety."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import (
    ControlDecision,
    ControlError,
    RunControlManager,
)

PolicyCategory = Literal["financial", "execution", "evidence_operations"]
TriggeredMode = Literal["drain", "halted"]


class StopPolicyError(RuntimeError):
    """Raised when a stop policy cannot be evaluated from durable state."""


@dataclass(frozen=True)
class FinancialStopPolicy:
    max_quote_age_seconds: int
    max_quote_movement_bps: int


@dataclass(frozen=True)
class ExecutionStopPolicy:
    consecutive_failures: int
    rolling_window: int
    rolling_failure_rate: float
    timeout_count: int
    nonce_gap_action: str = "halt"
    rpc_disagreement_action: str = "halt"
    reorganization_action: str = "halt"


@dataclass(frozen=True)
class EvidenceOperationsStopPolicy:
    collector_backlog: int
    collector_heartbeat_seconds: int
    disk_floor_bytes: int


@dataclass(frozen=True)
class QuoteObservation:
    quote_id: str
    quoted_at: datetime
    amount_wei: int
    reference_amount_wei: int


@dataclass(frozen=True)
class PolicyResult:
    event_id: str
    policy_code: str
    triggered: bool


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise StopPolicyError("policy timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _canonical(value: dict[str, Any]) -> str:
    return rfc8785.dumps(_jcs_safe(value)).decode()


def _jcs_safe(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            return str(value)
        return value
    if isinstance(value, dict):
        return {str(key): _jcs_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jcs_safe(item) for item in value]
    return value


class StopPolicyEngine:
    """Record every evaluated threshold and durably halt on a trigger."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        controls: RunControlManager,
        financial: FinancialStopPolicy,
        execution: ExecutionStopPolicy | None = None,
        evidence_operations: EvidenceOperationsStopPolicy | None = None,
    ) -> None:
        if financial.max_quote_age_seconds < 0:
            raise StopPolicyError("maximum quote age cannot be negative")
        if financial.max_quote_movement_bps < 0:
            raise StopPolicyError("maximum quote movement cannot be negative")
        self.store = store
        self.controls = controls
        self.financial = financial
        self.execution = execution
        self.evidence_operations = evidence_operations
        if execution is not None:
            if min(
                execution.consecutive_failures,
                execution.rolling_window,
                execution.timeout_count,
            ) < 1:
                raise StopPolicyError("execution count thresholds must be positive")
            if not 0 <= execution.rolling_failure_rate <= 1:
                raise StopPolicyError("rolling failure rate must be within [0, 1]")
            if {
                execution.nonce_gap_action,
                execution.rpc_disagreement_action,
                execution.reorganization_action,
            } != {"halt"}:
                raise StopPolicyError("execution integrity actions must be halt")
        if evidence_operations is not None and min(
            evidence_operations.collector_backlog,
            evidence_operations.collector_heartbeat_seconds,
            evidence_operations.disk_floor_bytes,
        ) < 0:
            raise StopPolicyError("evidence/operations thresholds cannot be negative")
        if (
            evidence_operations is not None
            and evidence_operations.collector_heartbeat_seconds == 0
        ):
            raise StopPolicyError("collector heartbeat threshold must be positive")

    def check_budget(
        self,
        *,
        run_id: str,
        batch_id: str,
        chain_id: int,
        requested_wei: int,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        if requested_wei < 0:
            raise StopPolicyError("requested budget cannot be negative")
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT limits.max_transaction_wei, limits.max_batch_wei,
                       limits.max_run_wei, limits.minimum_runner_balance_wei,
                       limits.observed_runner_balance_wei,
                       totals.active_reserved_wei AS run_reserved,
                       totals.finalized_wei AS run_finalized,
                       coalesce(batch.active_reserved_wei, 0) AS batch_reserved,
                       coalesce(batch.finalized_wei, 0) AS batch_finalized
                FROM budget_limits AS limits
                JOIN budget_totals AS totals
                  ON totals.run_id = limits.run_id
                 AND totals.chain_id = limits.chain_id
                LEFT JOIN batch_budget_totals AS batch
                  ON batch.run_id = limits.run_id
                 AND batch.chain_id = limits.chain_id
                 AND batch.batch_id = ?
                WHERE limits.run_id = ? AND limits.chain_id = ?
                """,
                (batch_id, run_id, chain_id),
            ).fetchone()
        if row is None:
            raise StopPolicyError("budget policy lacks configured limits and totals")
        run_use = int(row["run_reserved"]) + int(row["run_finalized"]) + requested_wei
        batch_use = (
            int(row["batch_reserved"]) + int(row["batch_finalized"]) + requested_wei
        )
        remaining_balance = (
            int(row["observed_runner_balance_wei"])
            - int(row["run_reserved"])
            - requested_wei
        )
        thresholds = {
            "max_transaction_wei": int(row["max_transaction_wei"]),
            "max_batch_wei": int(row["max_batch_wei"]),
            "max_run_wei": int(row["max_run_wei"]),
            "minimum_runner_balance_wei": int(row["minimum_runner_balance_wei"]),
        }
        observed = {
            "chain_id": chain_id,
            "batch_id": batch_id,
            "requested_wei": requested_wei,
            "batch_use_wei": batch_use,
            "run_use_wei": run_use,
            "remaining_balance_wei": remaining_balance,
        }
        if requested_wei > thresholds["max_transaction_wei"]:
            code = "transaction_budget_exhausted"
        elif batch_use > thresholds["max_batch_wei"]:
            code = "batch_budget_exhausted"
        elif run_use > thresholds["max_run_wei"]:
            code = "run_budget_exhausted"
        elif remaining_balance < thresholds["minimum_runner_balance_wei"]:
            code = "runner_balance_floor"
        else:
            code = "financial_budget_pass"
        return self._record_and_stop(
            run_id=run_id,
            category="financial",
            policy_code=code,
            triggered=code != "financial_budget_pass",
            threshold=thresholds,
            observed=observed,
            checked_at=checked_at,
        )

    def check_quote(
        self,
        *,
        run_id: str,
        quote: QuoteObservation,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        checked = _utc(checked_at)
        quoted = _utc(quote.quoted_at)
        if quote.amount_wei < 0 or quote.reference_amount_wei < 0:
            raise StopPolicyError("quote amounts cannot be negative")
        age_seconds = max(0, int((checked - quoted).total_seconds()))
        movement_numerator = (
            abs(quote.amount_wei - quote.reference_amount_wei) * 10_000
        )
        movement_denominator = quote.reference_amount_wei
        movement_exceeded = (
            quote.amount_wei != 0
            if movement_denominator == 0
            else movement_numerator
            > movement_denominator * self.financial.max_quote_movement_bps
        )
        thresholds = {
            "max_quote_age_seconds": self.financial.max_quote_age_seconds,
            "max_quote_movement_bps": self.financial.max_quote_movement_bps,
        }
        observed = {
            "quote_id": quote.quote_id,
            "quoted_at": quoted.isoformat(),
            "checked_at": checked.isoformat(),
            "age_seconds": age_seconds,
            "amount_wei": quote.amount_wei,
            "reference_amount_wei": quote.reference_amount_wei,
            "movement_numerator": movement_numerator,
            "movement_denominator": movement_denominator,
        }
        if age_seconds > self.financial.max_quote_age_seconds:
            code = "quote_age_exceeded"
        elif movement_exceeded:
            code = "quote_movement_exceeded"
        else:
            code = "financial_quote_pass"
        return self._record_and_stop(
            run_id=run_id,
            category="financial",
            policy_code=code,
            triggered=code != "financial_quote_pass",
            threshold=thresholds,
            observed=observed,
            checked_at=checked,
        )

    def record_execution_outcome(
        self,
        *,
        run_id: str,
        outcome_id: str,
        failed: bool,
        timed_out: bool,
        occurred_at: datetime | None = None,
    ) -> PolicyResult:
        policy = self._execution_policy()
        if outcome_id == "":
            raise StopPolicyError("execution outcome ID must be non-empty")
        occurred = _utc(occurred_at)
        with self.store.write() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO execution_outcomes(
                        outcome_id, run_id, failed, timed_out, occurred_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        outcome_id,
                        run_id,
                        int(failed),
                        int(timed_out),
                        occurred.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StopPolicyError("execution outcome is duplicate or invalid") from exc
            recent = connection.execute(
                """
                SELECT failed, timed_out FROM execution_outcomes
                WHERE run_id = ? ORDER BY sequence DESC LIMIT ?
                """,
                (run_id, policy.rolling_window),
            ).fetchall()
            timeout_total = int(
                connection.execute(
                    """
                    SELECT count(*) FROM execution_outcomes
                    WHERE run_id = ? AND timed_out = 1
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
        consecutive = 0
        for row in recent:
            if not row["failed"]:
                break
            consecutive += 1
        failure_count = sum(int(row["failed"]) for row in recent)
        rolling_full = len(recent) == policy.rolling_window
        rolling_exceeded = (
            rolling_full
            and failure_count > 0
            and failure_count
            >= policy.rolling_failure_rate * policy.rolling_window
        )
        thresholds: dict[str, Any] = {
            "consecutive_failures": policy.consecutive_failures,
            "rolling_window": policy.rolling_window,
            "rolling_failure_rate": policy.rolling_failure_rate,
            "timeout_count": policy.timeout_count,
        }
        observed: dict[str, Any] = {
            "outcome_id": outcome_id,
            "failed": failed,
            "timed_out": timed_out,
            "consecutive_failures": consecutive,
            "rolling_observations": len(recent),
            "rolling_failures": failure_count,
            "timeout_total": timeout_total,
        }
        if consecutive >= policy.consecutive_failures:
            code = "consecutive_failures"
        elif rolling_exceeded:
            code = "rolling_failure_rate"
        elif timeout_total >= policy.timeout_count:
            code = "timeout_count"
        else:
            code = "execution_outcome_pass"
        return self._record_and_stop(
            run_id=run_id,
            category="execution",
            policy_code=code,
            triggered=code != "execution_outcome_pass",
            threshold=thresholds,
            observed=observed,
            checked_at=occurred,
        )

    def check_nonce_gap(
        self,
        *,
        run_id: str,
        chain_id: int,
        expected_nonce: int,
        observed_nonce: int,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        policy = self._execution_policy()
        if min(expected_nonce, observed_nonce) < 0:
            raise StopPolicyError("nonces cannot be negative")
        triggered = expected_nonce != observed_nonce
        return self._record_and_stop(
            run_id=run_id,
            category="execution",
            policy_code="nonce_gap" if triggered else "nonce_contiguous",
            triggered=triggered,
            threshold={"action": policy.nonce_gap_action},
            observed={
                "chain_id": chain_id,
                "expected_nonce": expected_nonce,
                "observed_nonce": observed_nonce,
            },
            checked_at=checked_at,
        )

    def check_rpc_agreement(
        self,
        *,
        run_id: str,
        subject_id: str,
        provider_digests: dict[str, str],
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        policy = self._execution_policy()
        if len(provider_digests) < 2:
            raise StopPolicyError("RPC agreement requires at least two providers")
        triggered = len(set(provider_digests.values())) != 1
        return self._record_and_stop(
            run_id=run_id,
            category="execution",
            policy_code="rpc_disagreement" if triggered else "rpc_agreement",
            triggered=triggered,
            threshold={"action": policy.rpc_disagreement_action},
            observed={
                "subject_id": subject_id,
                "provider_digests": dict(sorted(provider_digests.items())),
            },
            checked_at=checked_at,
        )

    def check_reorganization(
        self,
        *,
        run_id: str,
        chain_id: int,
        block_number: int,
        prior_block_hash: str,
        current_block_hash: str,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        policy = self._execution_policy()
        if block_number < 0:
            raise StopPolicyError("block number cannot be negative")
        triggered = prior_block_hash != current_block_hash
        return self._record_and_stop(
            run_id=run_id,
            category="execution",
            policy_code="chain_reorganization" if triggered else "canonical_block_match",
            triggered=triggered,
            threshold={"action": policy.reorganization_action},
            observed={
                "chain_id": chain_id,
                "block_number": block_number,
                "prior_block_hash": prior_block_hash,
                "current_block_hash": current_block_hash,
            },
            checked_at=checked_at,
        )

    def check_evidence_operations(
        self,
        *,
        run_id: str,
        collector_backlog: int,
        collector_heartbeat_at: datetime,
        disk_available_bytes: int,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        policy = self._evidence_operations_policy()
        checked = _utc(checked_at)
        heartbeat = _utc(collector_heartbeat_at)
        if collector_backlog < 0 or disk_available_bytes < 0:
            raise StopPolicyError("backlog and disk availability cannot be negative")
        heartbeat_age = max(0, int((checked - heartbeat).total_seconds()))
        thresholds = {
            "collector_backlog": policy.collector_backlog,
            "collector_heartbeat_seconds": policy.collector_heartbeat_seconds,
            "disk_floor_bytes": policy.disk_floor_bytes,
        }
        observed = {
            "collector_backlog": collector_backlog,
            "collector_heartbeat_at": heartbeat.isoformat(),
            "collector_heartbeat_age_seconds": heartbeat_age,
            "disk_available_bytes": disk_available_bytes,
        }
        if disk_available_bytes < policy.disk_floor_bytes:
            code = "disk_floor"
            mode: TriggeredMode = "halted"
        elif heartbeat_age > policy.collector_heartbeat_seconds:
            code = "collector_heartbeat_loss"
            mode = "drain"
        elif collector_backlog > policy.collector_backlog:
            code = "collector_backlog"
            mode = "drain"
        else:
            code = "evidence_operations_pass"
            mode = "drain"
        return self._record_and_stop(
            run_id=run_id,
            category="evidence_operations",
            policy_code=code,
            triggered=code != "evidence_operations_pass",
            threshold=thresholds,
            observed=observed,
            checked_at=checked,
            triggered_mode=mode,
        )

    def manual_stop(
        self,
        *,
        run_id: str,
        mode: Literal["drain", "halted"],
        decision: ControlDecision,
        checked_at: datetime | None = None,
    ) -> PolicyResult:
        occurred = _utc(checked_at)
        if mode == "drain":
            self.controls.drain(run_id=run_id, decision=decision, now=occurred)
            code = "manual_drain"
        else:
            self.controls.halt(run_id=run_id, decision=decision, now=occurred)
            code = "manual_halt"
        return self._record_event(
            run_id=run_id,
            category="evidence_operations",
            policy_code=code,
            triggered=True,
            threshold={"mode": mode},
            observed={
                "decision_id": decision.decision_id,
                "reason_code": decision.reason_code,
            },
            occurred=occurred,
        )

    def _record_and_stop(
        self,
        *,
        run_id: str,
        category: PolicyCategory,
        policy_code: str,
        triggered: bool,
        threshold: dict[str, Any],
        observed: dict[str, Any],
        checked_at: datetime | None,
        triggered_mode: TriggeredMode = "halted",
    ) -> PolicyResult:
        occurred = _utc(checked_at)
        result = self._record_event(
            run_id=run_id,
            category=category,
            policy_code=policy_code,
            triggered=triggered,
            threshold=threshold,
            observed=observed,
            occurred=occurred,
        )
        if triggered:
            full_digest = hashlib.sha256(
                rfc8785.dumps(
                    {
                        "event_id": result.event_id,
                        "run_id": run_id,
                        "policy_code": policy_code,
                    }
                )
            ).hexdigest()
            decision = ControlDecision(
                decision_id=result.event_id,
                decision_sha256=full_digest,
                reason_code=policy_code,
            )
            try:
                state = self.controls.state(run_id)
                if triggered_mode == "halted" and state.mode in {"running", "drain"}:
                    self.controls.halt(
                        run_id=run_id,
                        decision=decision,
                        now=occurred,
                    )
                elif triggered_mode == "drain" and state.mode == "running":
                    self.controls.drain(
                        run_id=run_id,
                        decision=decision,
                        now=occurred,
                    )
            except ControlError as exc:
                raise StopPolicyError(
                    "triggered policy could not establish persistent stop"
                ) from exc
        return result

    def _record_event(
        self,
        *,
        run_id: str,
        category: PolicyCategory,
        policy_code: str,
        triggered: bool,
        threshold: dict[str, Any],
        observed: dict[str, Any],
        occurred: datetime,
    ) -> PolicyResult:
        material: dict[str, Any] = {
            "run_id": run_id,
            "category": category,
            "policy_code": policy_code,
            "threshold": threshold,
            "observed": observed,
            "occurred_at": occurred.isoformat(),
        }
        digest = hashlib.sha256(rfc8785.dumps(_jcs_safe(material))).hexdigest()
        event_id = f"stop_{digest[:24]}"
        with self.store.write() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO stop_policy_events(
                        event_id, run_id, category, policy_code, outcome,
                        threshold_json, observed_json, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        run_id,
                        category,
                        policy_code,
                        "triggered" if triggered else "pass",
                        _canonical(threshold),
                        _canonical(observed),
                        occurred.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                existing = connection.execute(
                    """
                    SELECT run_id, category, policy_code, outcome
                    FROM stop_policy_events WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchone()
                expected = (
                    run_id,
                    category,
                    policy_code,
                    "triggered" if triggered else "pass",
                )
                if existing is None or tuple(existing) != expected:
                    raise StopPolicyError("stop-policy event identity collision") from exc
        return PolicyResult(event_id, policy_code, triggered)

    def _execution_policy(self) -> ExecutionStopPolicy:
        if self.execution is None:
            raise StopPolicyError("execution stop policy is not configured")
        return self.execution

    def _evidence_operations_policy(self) -> EvidenceOperationsStopPolicy:
        if self.evidence_operations is None:
            raise StopPolicyError("evidence/operations stop policy is not configured")
        return self.evidence_operations


def decode_policy_event(row: sqlite3.Row) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode stored policy values for reconciliation without altering them."""
    return json.loads(str(row["threshold_json"])), json.loads(str(row["observed_json"]))
