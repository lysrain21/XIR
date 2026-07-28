"""Fail-closed count, pair-lineage, and freeze-scope reconciliation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import rfc8785

from xir_lab.evidence.store import EvidenceStore


class ReconciliationError(RuntimeError):
    """Raised when a run cannot be reconciled for formal analysis."""


@dataclass(frozen=True)
class CountExpectation:
    condition: str
    arm: str
    attempt_kind: str
    count: int


@dataclass(frozen=True)
class ReconciliationIssue:
    code: str
    subject_id: str
    detail: str


@dataclass(frozen=True)
class ReconciliationReport:
    run_id: str
    planned: int
    submitted: int
    not_submitted: int
    terminal_at_deadline: int
    pending_backfill: int
    issues: tuple[ReconciliationIssue, ...]

    @property
    def valid(self) -> bool:
        return not self.issues


class RunReconciler:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def declare_freeze_scope(
        self,
        *,
        scope_id: str,
        run_id: str,
        version: int,
        attempt_ids: tuple[str, ...],
        prior_freeze_id: str | None = None,
        prior_freeze_sha256: str | None = None,
    ) -> str:
        if version < 1 or len(attempt_ids) != len(set(attempt_ids)):
            raise ReconciliationError("freeze scope version and attempt IDs are invalid")
        ordered = tuple(sorted(attempt_ids))
        document = {
            "run_id": run_id,
            "version": version,
            "attempt_ids": ordered,
            "prior_freeze_id": prior_freeze_id,
            "prior_freeze_sha256": prior_freeze_sha256,
        }
        digest = hashlib.sha256(rfc8785.dumps(cast(Any, document))).hexdigest()
        with self.store.write() as connection:
            existing_attempts = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT attempt.attempt_id
                    FROM attempts AS attempt
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    """,
                    (run_id,),
                )
            }
            unknown = set(ordered) - existing_attempts
            if unknown:
                raise ReconciliationError(
                    "freeze scope has unknown attempts: " + ",".join(sorted(unknown))
                )
            if prior_freeze_id is not None:
                prior = connection.execute(
                    """
                    SELECT database_sha256 FROM freezes WHERE freeze_id = ?
                    """,
                    (prior_freeze_id,),
                ).fetchone()
                if (
                    prior is None
                    or prior_freeze_sha256 is None
                    or prior["database_sha256"] != prior_freeze_sha256
                ):
                    raise ReconciliationError("prior freeze digest reference is invalid")
            connection.execute(
                """
                INSERT INTO declared_freeze_scopes(
                    scope_id, run_id, version, attempt_ids_json, scope_sha256,
                    prior_freeze_id, prior_freeze_sha256, declared_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope_id,
                    run_id,
                    version,
                    json.dumps(ordered, separators=(",", ":")),
                    digest,
                    prior_freeze_id,
                    prior_freeze_sha256,
                    datetime.now(UTC).isoformat(),
                ),
            )
        return digest

    def set_backfill_status(
        self,
        *,
        attempt_id: str,
        state: str,
        reason_code: str,
    ) -> None:
        if state not in {"pending", "resolved"} or not reason_code:
            raise ReconciliationError("backfill state and reason are required")
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT INTO attempt_backfill_status(
                    attempt_id, state, reason_code, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(attempt_id) DO UPDATE SET
                    state = excluded.state,
                    reason_code = excluded.reason_code,
                    updated_at = excluded.updated_at
                """,
                (
                    attempt_id,
                    state,
                    reason_code,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def reconcile(
        self,
        *,
        run_id: str,
        expectations: tuple[CountExpectation, ...],
        freeze_scope_id: str,
        record_violations: bool = True,
    ) -> ReconciliationReport:
        issues: list[ReconciliationIssue] = []
        with self.store.connect(read_only=True) as connection:
            attempts = connection.execute(
                """
                SELECT attempt.*, condition.carrier_sequence,
                       EXISTS(
                           SELECT 1 FROM transactions AS transaction_record
                           JOIN intents AS intent
                             ON intent.intent_id = transaction_record.intent_id
                           JOIN stages AS stage
                             ON stage.stage_id = intent.stage_id
                           WHERE stage.attempt_id = attempt.attempt_id
                             AND transaction_record.state IN (
                                 'broadcast_unknown','submitted','included',
                                 'finalized','orphaned'
                             )
                       ) AS submitted,
                       EXISTS(
                           SELECT 1 FROM attempt_outcome_observations AS outcome
                           WHERE outcome.attempt_id = attempt.attempt_id
                             AND outcome.outcome_kind = 'deadline'
                       ) AS terminal_at_deadline,
                       coalesce(backfill.state, 'resolved') AS backfill_state
                FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                LEFT JOIN attempt_backfill_status AS backfill
                  ON backfill.attempt_id = attempt.attempt_id
                WHERE condition.run_id = ?
                ORDER BY attempt.attempt_id
                """,
                (run_id,),
            ).fetchall()
            scope_row = connection.execute(
                """
                SELECT attempt_ids_json FROM declared_freeze_scopes
                WHERE scope_id = ? AND run_id = ?
                """,
                (freeze_scope_id, run_id),
            ).fetchone()
        if scope_row is None:
            raise ReconciliationError("formal reconciliation requires a declared scope")
        scope_ids = set(json.loads(str(scope_row["attempt_ids_json"])))
        by_id = {str(row["attempt_id"]): row for row in attempts}
        expected_map = {
            (item.condition, item.arm, item.attempt_kind): item.count
            for item in expectations
        }
        if len(expected_map) != len(expectations) or any(
            count < 0 for count in expected_map.values()
        ):
            raise ReconciliationError("count expectations are invalid or duplicated")
        actual_map: dict[tuple[str, str, str], int] = {}
        for row in attempts:
            key = (
                str(row["carrier_sequence"]),
                str(row["arm"]),
                str(row["attempt_kind"]),
            )
            actual_map[key] = actual_map.get(key, 0) + 1
        for key in sorted(set(expected_map) | set(actual_map)):
            if expected_map.get(key, 0) != actual_map.get(key, 0):
                issues.append(
                    ReconciliationIssue(
                        "condition_arm_kind_count",
                        "/".join(key),
                        f"expected={expected_map.get(key, 0)} actual={actual_map.get(key, 0)}",
                    )
                )

        planned = len(attempts)
        submitted = sum(int(row["submitted"]) for row in attempts)
        not_submitted = sum(row["state"] == "not_submitted" for row in attempts)
        terminal = sum(int(row["terminal_at_deadline"]) for row in attempts)
        pending = sum(row["backfill_state"] == "pending" for row in attempts)
        if planned != submitted + not_submitted:
            issues.append(
                ReconciliationIssue(
                    "planned_submission_identity",
                    run_id,
                    f"{planned} != {submitted} + {not_submitted}",
                )
            )
        if submitted != terminal + pending:
            issues.append(
                ReconciliationIssue(
                    "submitted_terminal_identity",
                    run_id,
                    f"{submitted} != {terminal} + {pending}",
                )
            )

        pair_groups: dict[str, list[object]] = {}
        for row in attempts:
            if row["pair_id"] is not None and row["attempt_kind"] == "primary":
                pair_groups.setdefault(str(row["pair_id"]), []).append(row)
        for pair_id, rows in pair_groups.items():
            arms = sorted(str(row["arm"]) for row in rows)  # type: ignore[index]
            if arms != ["baseline", "xir"]:
                issues.append(
                    ReconciliationIssue(
                        "primary_pair_arms",
                        pair_id,
                        f"arms={arms}",
                    )
                )

        for row in attempts:
            attempt_id = str(row["attempt_id"])
            if row["attempt_kind"] == "retry":
                prior = by_id.get(str(row["retry_of"]))
                if prior is None or (
                    prior["condition_id"],
                    prior["pair_id"],
                    prior["arm"],
                ) != (
                    row["condition_id"],
                    row["pair_id"],
                    row["arm"],
                ):
                    issues.append(
                        ReconciliationIssue(
                            "retry_lineage",
                            attempt_id,
                            "retry predecessor changed matching coordinates",
                        )
                    )
            if attempt_id in scope_ids and (
                not row["terminal_at_deadline"]
                or row["backfill_state"] == "pending"
            ):
                issues.append(
                    ReconciliationIssue(
                        "freeze_scope_pending",
                        attempt_id,
                        "scope attempt lacks reconciled deadline or has pending backfill",
                    )
                )
        missing_scope = scope_ids - set(by_id)
        for attempt_id in sorted(missing_scope):
            issues.append(
                ReconciliationIssue(
                    "freeze_scope_missing",
                    attempt_id,
                    "declared scope attempt is absent",
                )
            )
        report = ReconciliationReport(
            run_id,
            planned,
            submitted,
            not_submitted,
            terminal,
            pending,
            tuple(issues),
        )
        if issues and record_violations:
            self._record_issues(run_id, issues)
        return report

    def require_valid(self, report: ReconciliationReport) -> None:
        if not report.valid:
            raise ReconciliationError(
                f"run reconciliation failed with {len(report.issues)} issue(s)"
            )

    def _record_issues(
        self,
        run_id: str,
        issues: list[ReconciliationIssue],
    ) -> None:
        with self.store.write() as connection:
            for issue in issues:
                detail = {
                    "subject_id": issue.subject_id,
                    "detail": issue.detail,
                }
                digest = hashlib.sha256(
                    rfc8785.dumps(
                        {
                            "run_id": run_id,
                            "code": issue.code,
                            **detail,
                        }
                    )
                ).hexdigest()
                connection.execute(
                    """
                    INSERT OR IGNORE INTO invariant_violations(
                        violation_id, run_id, invariant_code,
                        details_json, resolved_at
                    ) VALUES (?, ?, ?, ?, NULL)
                    """,
                    (
                        "violation_" + digest[:24],
                        run_id,
                        issue.code,
                        rfc8785.dumps(detail).decode(),
                    ),
                )
