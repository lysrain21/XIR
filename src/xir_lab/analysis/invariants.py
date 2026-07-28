"""Cross-table evidence invariants required before formal aggregation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import rfc8785

from xir_lab.evidence.store import EvidenceStore


@dataclass(frozen=True)
class InvariantIssue:
    code: str
    subject_id: str
    detail: str


@dataclass(frozen=True)
class InvariantReport:
    run_id: str
    checked_attempts: int
    issues: tuple[InvariantIssue, ...]

    @property
    def valid(self) -> bool:
        return not self.issues


class EvidenceInvariantValidator:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def validate(
        self,
        *,
        run_id: str,
        freeze_scope_id: str,
        record_violations: bool = True,
    ) -> InvariantReport:
        issues: list[InvariantIssue] = []
        with self.store.connect(read_only=True) as connection:
            scope = connection.execute(
                """
                SELECT attempt_ids_json FROM declared_freeze_scopes
                WHERE scope_id = ? AND run_id = ?
                """,
                (freeze_scope_id, run_id),
            ).fetchone()
            if scope is None:
                raise ValueError("invariant validation requires a declared freeze scope")
            attempt_ids = tuple(json.loads(str(scope["attempt_ids_json"])))
            unresolved = connection.execute(
                """
                SELECT violation_id, invariant_code
                FROM invariant_violations
                WHERE run_id = ? AND resolved_at IS NULL
                """,
                (run_id,),
            ).fetchall()
            for row in unresolved:
                issues.append(
                    InvariantIssue(
                        "unresolved_invariant",
                        str(row["violation_id"]),
                        str(row["invariant_code"]),
                    )
                )
            for attempt_id in attempt_ids:
                self._validate_attempt(connection, str(attempt_id), issues)
            self._validate_nonce_and_transactions(connection, run_id, issues)
            self._validate_budgets(connection, run_id, issues)
            self._validate_resources(connection, run_id, issues)
        raw = self.store.repair_raw()
        for kind in ("missing", "corrupt", "orphans"):
            for digest in raw[kind]:
                issues.append(
                    InvariantIssue(
                        f"raw_{kind}",
                        digest,
                        "raw evidence store is not closed and exact",
                    )
                )
        report = InvariantReport(run_id, len(attempt_ids), tuple(issues))
        if issues and record_violations:
            self._record(run_id, issues)
        return report

    @staticmethod
    def _validate_attempt(
        connection: object,
        attempt_id: str,
        issues: list[InvariantIssue],
    ) -> None:
        # sqlite3.Connection is kept structural here to make the query-only helper
        # straightforward to exercise against read-only connections.
        execute = connection.execute  # type: ignore[attr-defined]
        attempt = execute(
            "SELECT arm FROM attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if attempt is None:
            issues.append(
                InvariantIssue("scope_attempt_missing", attempt_id, "attempt absent")
            )
            return
        stages = execute(
            """
            SELECT * FROM stages WHERE attempt_id = ? ORDER BY ordinal
            """,
            (attempt_id,),
        ).fetchall()
        if not stages:
            issues.append(
                InvariantIssue(
                    "stage_template",
                    attempt_id,
                    "formal attempt has no preregistered stages",
                )
            )
        ordinals = [int(row["ordinal"]) for row in stages]
        if ordinals != list(range(len(stages))):
            issues.append(
                InvariantIssue(
                    "stage_ordinals",
                    attempt_id,
                    f"ordinals={ordinals}",
                )
            )
        for row in stages:
            if (
                row["stage_template_id"] is None
                or row["chain_id"] is None
                or row["accounting_bucket"] is None
                or row["logical_labels_json"] is None
            ):
                issues.append(
                    InvariantIssue(
                        "stage_template",
                        str(row["stage_id"]),
                        "formal stage lacks frozen template metadata",
                    )
                )
        messages = execute(
            """
            SELECT * FROM carrier_messages
            WHERE attempt_id = ? ORDER BY leg_index
            """,
            (attempt_id,),
        ).fetchall()
        if messages:
            if [int(row["leg_index"]) for row in messages] != [0, 1]:
                issues.append(
                    InvariantIssue(
                        "carrier_leg_continuity",
                        attempt_id,
                        "carrier path is not exactly legs 0 and 1",
                    )
                )
            for row in messages:
                if (
                    row["source_transaction_id"] is None
                    or row["destination_transaction_id"] is None
                    or row["payload_sha256"] is None
                ):
                    issues.append(
                        InvariantIssue(
                            "carrier_transaction_link",
                            str(row["carrier_message_id"]),
                            "carrier record lacks transaction or payload link",
                        )
                    )
        xir = execute(
            "SELECT * FROM xir_attempt_records WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if attempt["arm"] == "xir":
            if xir is None:
                issues.append(
                    InvariantIssue(
                        "xir_trace_missing",
                        attempt_id,
                        "XIR arm lacks RID/MID trace",
                    )
                )
            elif not (
                xir["intermediate_verified"]
                and xir["destination_verified"]
                and xir["effect_succeeded"]
            ):
                issues.append(
                    InvariantIssue(
                        "xir_destination_effect",
                        attempt_id,
                        "XIR verification/effect is not successful",
                    )
                )
        elif xir is not None:
            issues.append(
                InvariantIssue(
                    "baseline_xir_contamination",
                    attempt_id,
                    "baseline arm contains an XIR trace",
                )
            )
        transactions = execute(
            """
            SELECT transaction_record.transaction_id, transaction_record.state
            FROM transactions AS transaction_record
            JOIN intents AS intent
              ON intent.intent_id = transaction_record.intent_id
            JOIN stages AS stage ON stage.stage_id = intent.stage_id
            WHERE stage.attempt_id = ?
            """,
            (attempt_id,),
        ).fetchall()
        for transaction in transactions:
            if transaction["state"] != "finalized":
                continue
            latest = execute(
                """
                SELECT current.observation_state, current.canonical
                FROM transaction_finality_observations AS current
                WHERE current.transaction_id = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM transaction_finality_observations AS later
                    WHERE later.supersedes_observation_id =
                          current.finality_observation_id
                  )
                """,
                (transaction["transaction_id"],),
            ).fetchone()
            if (
                latest is None
                or latest["observation_state"] != "finalized"
                or latest["canonical"] != 1
            ):
                issues.append(
                    InvariantIssue(
                        "finality",
                        str(transaction["transaction_id"]),
                        "finalized transaction lacks current canonical finality",
                    )
                )

    @staticmethod
    def _validate_nonce_and_transactions(
        connection: object,
        run_id: str,
        issues: list[InvariantIssue],
    ) -> None:
        execute = connection.execute  # type: ignore[attr-defined]
        duplicates = execute(
            """
            SELECT transaction_record.chain_id, intent.signer_id,
                   transaction_record.nonce, count(*) AS count_rows
            FROM transactions AS transaction_record
            JOIN intents AS intent
              ON intent.intent_id = transaction_record.intent_id
            JOIN stages AS stage ON stage.stage_id = intent.stage_id
            JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
            JOIN conditions AS condition
              ON condition.condition_id = attempt.condition_id
            WHERE condition.run_id = ?
              AND transaction_record.replaces_transaction_id IS NULL
            GROUP BY transaction_record.chain_id, intent.signer_id,
                     transaction_record.nonce
            HAVING count(*) > 1
            """,
            (run_id,),
        ).fetchall()
        for row in duplicates:
            issues.append(
                InvariantIssue(
                    "nonce_uniqueness",
                    f"{row['chain_id']}:{row['signer_id']}:{row['nonce']}",
                    f"lineages={row['count_rows']}",
                )
            )
        replacements = execute(
            """
            SELECT child.transaction_id
            FROM transactions AS child
            JOIN transactions AS parent
              ON parent.transaction_id = child.replaces_transaction_id
            WHERE child.intent_id != parent.intent_id
               OR child.chain_id != parent.chain_id
               OR child.nonce != parent.nonce
            """
        ).fetchall()
        for row in replacements:
            issues.append(
                InvariantIssue(
                    "replacement_lineage",
                    str(row["transaction_id"]),
                    "replacement changed intent, chain, or nonce",
                )
            )

    @staticmethod
    def _validate_budgets(
        connection: object,
        run_id: str,
        issues: list[InvariantIssue],
    ) -> None:
        execute = connection.execute  # type: ignore[attr-defined]
        rows = execute(
            """
            SELECT budget.reservation_id, budget.chain_id,
                   budget.provisional_wei, budget.finalized_wei,
                   coalesce(sum(sub.provisional_wei), 0) AS sub_provisional,
                   coalesce(sum(sub.finalized_wei), 0) AS sub_finalized
            FROM budgets AS budget
            LEFT JOIN transaction_subreservations AS sub
              ON sub.reservation_id = budget.reservation_id
             AND sub.chain_id = budget.chain_id
            WHERE budget.run_id = ?
            GROUP BY budget.reservation_id, budget.chain_id
            """,
            (run_id,),
        ).fetchall()
        for row in rows:
            if (
                row["provisional_wei"] != row["sub_provisional"]
                or row["finalized_wei"] != row["sub_finalized"]
            ):
                issues.append(
                    InvariantIssue(
                        "budget_arithmetic",
                        f"{row['reservation_id']}:{row['chain_id']}",
                        "budget and subreservation totals differ",
                    )
                )

    @staticmethod
    def _validate_resources(
        connection: object,
        run_id: str,
        issues: list[InvariantIssue],
    ) -> None:
        execute = connection.execute  # type: ignore[attr-defined]
        rows = execute(
            """
            SELECT resource.*
            FROM transaction_resources AS resource
            JOIN transactions AS transaction_record
              ON transaction_record.transaction_id = resource.transaction_id
            JOIN intents AS intent
              ON intent.intent_id = transaction_record.intent_id
            JOIN stages AS stage ON stage.stage_id = intent.stage_id
            JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
            JOIN conditions AS condition
              ON condition.condition_id = attempt.condition_id
            WHERE condition.run_id = ?
            """,
            (run_id,),
        ).fetchall()
        for row in rows:
            expected = int(row["gas_used"]) * int(row["effective_gas_price_wei"])
            if int(row["execution_fee_wei"]) != expected:
                issues.append(
                    InvariantIssue(
                        "resource_arithmetic",
                        str(row["transaction_id"]),
                        f"execution_fee_wei != {expected}",
                    )
                )
            if (row["l1_data_fee_wei"] is None) == (
                row["l1_data_fee_unavailable_reason"] is None
            ):
                issues.append(
                    InvariantIssue(
                        "null_reason",
                        str(row["transaction_id"]),
                        "L1 data fee needs exactly one value or unavailable reason",
                    )
                )

    def _record(self, run_id: str, issues: list[InvariantIssue]) -> None:
        with self.store.write() as connection:
            for issue in issues:
                material = {
                    "run_id": run_id,
                    "code": issue.code,
                    "subject_id": issue.subject_id,
                    "detail": issue.detail,
                }
                digest = hashlib.sha256(rfc8785.dumps(material)).hexdigest()
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
                        rfc8785.dumps(material).decode(),
                    ),
                )
