"""Deterministic primary-condition and separate scale-run report builders."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

import rfc8785

from xir_lab.analysis.overhead import PairDecision, PairFirstAnalyzer
from xir_lab.analysis.resources import ResourceReporter
from xir_lab.evidence.store import EvidenceStore

CONDITIONS = ("HH", "HL", "LH", "LL")
ARMS = ("baseline", "xir")


class ReportError(RuntimeError):
    """Raised when a formal report cannot reconcile its declared run."""


@dataclass(frozen=True)
class ConditionSummary:
    condition: str
    execution_state: str
    planned_pairs: int
    eligible_pairs: int
    delivered_attempts: int
    failed_attempts: int
    timed_out_attempts: int


@dataclass(frozen=True)
class ScaleSummary:
    run_id: str
    planned_primary: int
    submitted_primary: int
    not_submitted_primary: int
    deadline_terminal_primary: int
    pending_backfill_primary: int
    retry_attempts: int
    physical_transactions: int
    input_bytes: int
    duration_measurements: int
    claim_label: str


class PrimaryReportBuilder:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store
        self.analyzer = PairFirstAnalyzer(store=store)
        self.resources = ResourceReporter(store=store)

    def build(
        self,
        *,
        run_id: str,
        freeze_id: str,
        destination: Path,
    ) -> str:
        freeze_digest = self._freeze_digest(run_id, freeze_id)
        destination.mkdir(parents=True, exist_ok=False)
        decisions = self.analyzer.decide_pairs(run_id=run_id)
        values = self.analyzer.pair_values(
            run_id=run_id,
            metrics=(
                "gas_used",
                "input_bytes",
                "execution_fee_wei",
                "l1_data_fee_wei",
                "carrier_payment_wei",
                "transaction_count",
            ),
        )
        aggregates = self.analyzer.aggregate(values)
        summaries = tuple(
            self._condition_summary(run_id, condition, decisions)
            for condition in CONDITIONS
        )
        with self.store.connect(read_only=True) as connection:
            stage_map = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT condition.carrier_sequence AS condition, attempt.arm,
                           stage.accounting_bucket, stage.stage_name,
                           count(*) AS stage_count
                    FROM stages AS stage
                    JOIN attempts AS attempt
                      ON attempt.attempt_id = stage.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    GROUP BY condition.carrier_sequence, attempt.arm,
                             stage.accounting_bucket, stage.stage_name
                    ORDER BY condition.carrier_sequence, attempt.arm,
                             stage.accounting_bucket, stage.stage_name
                    """,
                    (run_id,),
                )
            ]
            latency = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT measurement.attempt_id, measurement.measurement_kind,
                           measurement.elapsed_ms,
                           measurement.unavailable_reason,
                           measurement.clock_statement
                    FROM clock_measurements AS measurement
                    JOIN attempts AS attempt
                      ON attempt.attempt_id = measurement.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY measurement.attempt_id,
                             measurement.measurement_kind
                    """,
                    (run_id,),
                )
            ]
        table = {
            "schema_version": "xir-lab-primary-condition-report-v1",
            "run_id": run_id,
            "freeze_id": freeze_id,
            "freeze_database_sha256": freeze_digest,
            "conditions": [asdict(item) for item in summaries],
            "pair_values": [asdict(item) for item in values],
            "aggregates": [asdict(item) for item in aggregates],
            "stage_map": stage_map,
            "per_chain_resources": [
                asdict(item)
                for item in self.resources.transaction_rows(run_id=run_id)
            ],
            "latency": latency,
            "units": {
                "gas_used": "gas",
                "input_bytes": "bytes",
                "execution_fee_wei": "chain_native_wei",
                "l1_data_fee_wei": "chain_native_wei",
                "carrier_payment_wei": "chain_native_wei",
                "transaction_count": "transactions",
            },
            "unit_limitation": (
                "chain-specific native-token amounts are not summed or priced"
            ),
        }
        table_bytes = rfc8785.dumps(table)  # type: ignore[arg-type]
        table_path = destination / "primary-conditions.json"
        table_path.write_bytes(table_bytes + b"\n")
        figure_bytes = _condition_svg(summaries).encode()
        figure_path = destination / "condition-eligibility.svg"
        figure_path.write_bytes(figure_bytes)
        artifacts = {
            table_path.name: hashlib.sha256(table_bytes).hexdigest(),
            figure_path.name: hashlib.sha256(figure_bytes).hexdigest(),
        }
        manifest = {
            "schema_version": "xir-lab-primary-report-manifest-v1",
            "run_id": run_id,
            "freeze_id": freeze_id,
            "freeze_database_sha256": freeze_digest,
            "artifacts": artifacts,
        }
        manifest_bytes = rfc8785.dumps(manifest)  # type: ignore[arg-type]
        (destination / "manifest.json").write_bytes(manifest_bytes + b"\n")
        return hashlib.sha256(manifest_bytes).hexdigest()

    def _condition_summary(
        self,
        run_id: str,
        condition: str,
        decisions: tuple[PairDecision, ...],
    ) -> ConditionSummary:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT count(DISTINCT pair_record.pair_id) AS planned_pairs,
                       sum(attempt.state = 'delivered') AS delivered,
                       sum(attempt.state IN (
                           'submission_failed','carrier_failed','xir_rejected',
                           'destination_failed','observer_failed',
                           'incomplete_evidence'
                       )) AS failed,
                       sum(attempt.state = 'timed_out') AS timed_out
                FROM conditions AS condition
                LEFT JOIN pairs AS pair_record
                  ON pair_record.condition_id = condition.condition_id
                LEFT JOIN attempts AS attempt
                  ON attempt.condition_id = condition.condition_id
                 AND attempt.attempt_kind = 'primary'
                WHERE condition.run_id = ?
                  AND condition.carrier_sequence = ?
                """,
                (run_id, condition),
            ).fetchone()
        planned = int(row["planned_pairs"] or 0)
        eligible = sum(
            decision.eligible
            and self._pair_condition(decision.pair_id) == condition
            for decision in decisions
        )
        return ConditionSummary(
            condition,
            "executed" if planned else "not_executed",
            planned,
            eligible,
            int(row["delivered"] or 0),
            int(row["failed"] or 0),
            int(row["timed_out"] or 0),
        )

    def _pair_condition(self, pair_id: str) -> str:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT condition.carrier_sequence
                FROM pairs AS pair_record
                JOIN conditions AS condition
                  ON condition.condition_id = pair_record.condition_id
                WHERE pair_record.pair_id = ?
                """,
                (pair_id,),
            ).fetchone()
        return "" if row is None else str(row[0])

    def _freeze_digest(self, run_id: str, freeze_id: str) -> str:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT database_sha256 FROM freezes
                WHERE freeze_id = ? AND run_id = ?
                """,
                (freeze_id, run_id),
            ).fetchone()
            unresolved = connection.execute(
                """
                SELECT count(*) FROM invariant_violations
                WHERE run_id = ? AND resolved_at IS NULL
                """,
                (run_id,),
            ).fetchone()[0]
        if row is None or unresolved:
            raise ReportError("primary report requires a valid freeze and zero invariants")
        return str(row["database_sha256"])


class ScaleReportBuilder:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def build(
        self,
        *,
        run_id: str,
        destination: Path,
    ) -> ScaleSummary:
        with self.store.connect(read_only=True) as connection:
            groups = connection.execute(
                """
                SELECT condition.carrier_sequence, attempt.arm, count(*) AS count_rows
                FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ? AND attempt.attempt_kind = 'primary'
                GROUP BY condition.carrier_sequence, attempt.arm
                """,
                (run_id,),
            ).fetchall()
            attempts = connection.execute(
                """
                SELECT attempt.attempt_id, attempt.state,
                       EXISTS(
                           SELECT 1 FROM transactions AS transaction_record
                           JOIN intents AS intent
                             ON intent.intent_id = transaction_record.intent_id
                           JOIN stages AS stage ON stage.stage_id = intent.stage_id
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
                       ) AS deadline_terminal,
                       coalesce(backfill.state, 'resolved') AS backfill_state
                FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                LEFT JOIN attempt_backfill_status AS backfill
                  ON backfill.attempt_id = attempt.attempt_id
                WHERE condition.run_id = ? AND attempt.attempt_kind = 'primary'
                """,
                (run_id,),
            ).fetchall()
            retries = connection.execute(
                """
                SELECT count(*) FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ? AND attempt.attempt_kind = 'retry'
                """,
                (run_id,),
            ).fetchone()[0]
            physical, input_bytes = connection.execute(
                """
                SELECT count(DISTINCT transaction_record.transaction_id),
                       coalesce(sum(resource.input_bytes), 0)
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                LEFT JOIN transaction_resources AS resource
                  ON resource.transaction_id = transaction_record.transaction_id
                WHERE condition.run_id = ?
                """,
                (run_id,),
            ).fetchone()
            durations = connection.execute(
                """
                SELECT count(*) FROM clock_measurements AS measurement
                JOIN attempts AS attempt
                  ON attempt.attempt_id = measurement.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ?
                """,
                (run_id,),
            ).fetchone()[0]
            state_rows = connection.execute(
                """
                SELECT attempt.state, count(*) AS count_rows
                FROM attempts AS attempt
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ? AND attempt.attempt_kind = 'primary'
                GROUP BY attempt.state ORDER BY attempt.state
                """,
                (run_id,),
            ).fetchall()
            eventual_rows = connection.execute(
                """
                SELECT outcome.outcome, count(*) AS count_rows
                FROM attempt_outcome_observations AS outcome
                JOIN attempts AS attempt
                  ON attempt.attempt_id = outcome.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ?
                  AND outcome.outcome_kind = 'eventual'
                GROUP BY outcome.outcome ORDER BY outcome.outcome
                """,
                (run_id,),
            ).fetchall()
        group_map = {
            (str(row["carrier_sequence"]), str(row["arm"])): int(row["count_rows"])
            for row in groups
        }
        expected = {(condition, arm): 1_250 for condition in CONDITIONS for arm in ARMS}
        if group_map != expected or len(attempts) != 10_000:
            raise ReportError("scale run must reconcile exactly 1,250 per condition/arm")
        submitted = sum(int(row["submitted"]) for row in attempts)
        not_submitted = sum(row["state"] == "not_submitted" for row in attempts)
        terminal = sum(int(row["deadline_terminal"]) for row in attempts)
        pending = sum(row["backfill_state"] == "pending" for row in attempts)
        if 10_000 != submitted + not_submitted or submitted != terminal + pending:
            raise ReportError("scale submitted/not-submitted/terminal identity failed")
        summary = ScaleSummary(
            run_id,
            10_000,
            submitted,
            not_submitted,
            terminal,
            pending,
            int(retries),
            int(physical),
            int(input_bytes),
            int(durations),
            "bounded runner and evidence-pipeline observation; not carrier capacity",
        )
        destination.mkdir(parents=True, exist_ok=False)
        document = {
            "schema_version": "xir-lab-scale-outcome-report-v1",
            **asdict(summary),
            "condition_arm_counts": {
                f"{condition}/{arm}": group_map[(condition, arm)]
                for condition in CONDITIONS
                for arm in ARMS
            },
            "primary_state_counts": {
                str(row["state"]): int(row["count_rows"]) for row in state_rows
            },
            "eventual_outcome_counts": {
                str(row["outcome"]): int(row["count_rows"])
                for row in eventual_rows
            },
        }
        (destination / "scale-report.json").write_bytes(
            rfc8785.dumps(document) + b"\n"
        )
        return summary


def _condition_svg(summaries: tuple[ConditionSummary, ...]) -> str:
    bars = []
    for index, summary in enumerate(summaries):
        x = 60 + index * 120
        height = min(160, summary.eligible_pairs * 5)
        y = 210 - height
        bars.append(
            f'<rect x="{x}" y="{y}" width="70" height="{height}" fill="#315b7d"/>'
            f'<text x="{x + 35}" y="232" text-anchor="middle">{summary.condition}</text>'
            f'<text x="{x + 35}" y="{max(18, y - 6)}" text-anchor="middle">'
            f"{summary.eligible_pairs}/{summary.planned_pairs}</text>"
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="560" height="260" '
        'viewBox="0 0 560 260" role="img">'
        "<title>Eligible primary pairs by carrier condition</title>"
        '<rect width="560" height="260" fill="white"/>'
        '<text x="280" y="18" text-anchor="middle" font-weight="bold">'
        "Eligible / planned primary pairs</text>"
        + "".join(bars)
        + "</svg>\n"
    )
