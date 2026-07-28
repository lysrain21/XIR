"""Designated-primary eligibility and pair-first overhead statistics."""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from xir_lab.evidence.store import EvidenceStore

Metric = Literal[
    "gas_used",
    "input_bytes",
    "execution_fee_wei",
    "l1_data_fee_wei",
    "carrier_payment_wei",
    "transaction_value_wei",
    "transaction_count",
]


class OverheadError(RuntimeError):
    """Raised when pair-first analysis would use ineligible evidence."""


@dataclass(frozen=True)
class PairDecision:
    pair_id: str
    baseline_attempt_id: str
    xir_attempt_id: str
    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PairValue:
    pair_id: str
    condition: str
    chain_id: int
    accounting_bucket: str
    metric: Metric
    baseline_value: int | None
    xir_value: int | None
    difference: int | None
    relative_difference: float | None
    unavailable_reason: str | None


@dataclass(frozen=True)
class PairAggregate:
    condition: str
    chain_id: int
    accounting_bucket: str
    metric: Metric
    eligible_count: int
    median: float
    interquartile_range: float
    minimum: int
    maximum: int


class PairFirstAnalyzer:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def decide_pairs(self, *, run_id: str) -> tuple[PairDecision, ...]:
        with self.store.connect(read_only=True) as connection:
            pairs = connection.execute(
                """
                SELECT pair_record.pair_id, condition.carrier_sequence
                FROM pairs AS pair_record
                JOIN conditions AS condition
                  ON condition.condition_id = pair_record.condition_id
                WHERE condition.run_id = ?
                ORDER BY pair_record.pair_id
                """,
                (run_id,),
            ).fetchall()
        decisions: list[PairDecision] = []
        for pair in pairs:
            pair_id = str(pair["pair_id"])
            with self.store.connect(read_only=True) as connection:
                attempts = connection.execute(
                    """
                    SELECT * FROM attempts
                    WHERE pair_id = ? AND attempt_kind = 'primary'
                    ORDER BY arm
                    """,
                    (pair_id,),
                ).fetchall()
            baseline = [row for row in attempts if row["arm"] == "baseline"]
            xir = [row for row in attempts if row["arm"] == "xir"]
            reasons: list[str] = []
            if len(baseline) != 1 or len(xir) != 1:
                reasons.append("designated_primary_arms_missing_or_duplicated")
                decisions.append(
                    PairDecision(
                        pair_id,
                        "" if not baseline else str(baseline[0]["attempt_id"]),
                        "" if not xir else str(xir[0]["attempt_id"]),
                        False,
                        tuple(reasons),
                    )
                )
                continue
            baseline_id = str(baseline[0]["attempt_id"])
            xir_id = str(xir[0]["attempt_id"])
            for row in (baseline[0], xir[0]):
                attempt_id = str(row["attempt_id"])
                if row["state"] != "delivered":
                    reasons.append(f"{row['arm']}_not_delivered")
                reasons.extend(self._attempt_evidence_reasons(attempt_id, str(row["arm"])))
            baseline_effect = self._effect(baseline_id)
            xir_effect = self._effect(xir_id)
            if baseline_effect is None or xir_effect is None:
                reasons.append("destination_effect_missing")
            elif baseline_effect != xir_effect:
                reasons.append("destination_effect_mismatch")
            decision = PairDecision(
                pair_id,
                baseline_id,
                xir_id,
                not reasons,
                tuple(sorted(set(reasons))),
            )
            decisions.append(decision)
            with self.store.write() as connection:
                connection.execute(
                    """
                    INSERT INTO pair_eligibility_decisions(
                        pair_id, baseline_attempt_id, xir_attempt_id,
                        eligible, reasons_json, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pair_id) DO UPDATE SET
                        baseline_attempt_id = excluded.baseline_attempt_id,
                        xir_attempt_id = excluded.xir_attempt_id,
                        eligible = excluded.eligible,
                        reasons_json = excluded.reasons_json,
                        decided_at = excluded.decided_at
                    """,
                    (
                        decision.pair_id,
                        decision.baseline_attempt_id,
                        decision.xir_attempt_id,
                        int(decision.eligible),
                        json.dumps(decision.reasons, separators=(",", ":")),
                        datetime.now(UTC).isoformat(),
                    ),
                )
        return tuple(decisions)

    def pair_values(
        self,
        *,
        run_id: str,
        metrics: tuple[Metric, ...],
    ) -> tuple[PairValue, ...]:
        decisions = self.decide_pairs(run_id=run_id)
        values: list[PairValue] = []
        for decision in decisions:
            if not decision.eligible:
                continue
            with self.store.connect(read_only=True) as connection:
                condition = str(
                    connection.execute(
                        """
                        SELECT condition.carrier_sequence
                        FROM pairs AS pair_record
                        JOIN conditions AS condition
                          ON condition.condition_id = pair_record.condition_id
                        WHERE pair_record.pair_id = ?
                        """,
                        (decision.pair_id,),
                    ).fetchone()[0]
                )
                coordinates = connection.execute(
                    """
                    SELECT DISTINCT chain_id, accounting_bucket
                    FROM stages
                    WHERE attempt_id IN (?, ?)
                      AND chain_id IS NOT NULL
                      AND accounting_bucket IS NOT NULL
                    ORDER BY chain_id, accounting_bucket
                    """,
                    (
                        decision.baseline_attempt_id,
                        decision.xir_attempt_id,
                    ),
                ).fetchall()
            for coordinate in coordinates:
                chain_id = int(coordinate["chain_id"])
                bucket = str(coordinate["accounting_bucket"])
                for metric in metrics:
                    baseline, baseline_reason = self._metric(
                        decision.baseline_attempt_id,
                        chain_id,
                        bucket,
                        metric,
                    )
                    xir, xir_reason = self._metric(
                        decision.xir_attempt_id,
                        chain_id,
                        bucket,
                        metric,
                    )
                    unavailable = baseline_reason or xir_reason
                    difference = (
                        None
                        if unavailable is not None
                        or baseline is None
                        or xir is None
                        else xir - baseline
                    )
                    relative: float | None = None
                    if (
                        difference is not None
                        and baseline is not None
                        and baseline != 0
                    ):
                        relative = difference / baseline
                    if (
                        unavailable is None
                        and difference is not None
                        and baseline == 0
                    ):
                        unavailable = "relative_baseline_zero"
                    values.append(
                        PairValue(
                            decision.pair_id,
                            condition,
                            chain_id,
                            bucket,
                            metric,
                            baseline,
                            xir,
                            difference,
                            relative,
                            unavailable,
                        )
                    )
        return tuple(values)

    @staticmethod
    def aggregate(values: tuple[PairValue, ...]) -> tuple[PairAggregate, ...]:
        groups: dict[tuple[str, int, str, Metric], list[int]] = {}
        for value in values:
            if value.difference is None:
                continue
            key = (
                value.condition,
                value.chain_id,
                value.accounting_bucket,
                value.metric,
            )
            groups.setdefault(key, []).append(value.difference)
        result: list[PairAggregate] = []
        for key, differences in sorted(groups.items()):
            ordered = sorted(differences)
            q1, q3 = _quartiles(ordered)
            result.append(
                PairAggregate(
                    *key,
                    eligible_count=len(ordered),
                    median=float(statistics.median(ordered)),
                    interquartile_range=q3 - q1,
                    minimum=ordered[0],
                    maximum=ordered[-1],
                )
            )
        return tuple(result)

    def _attempt_evidence_reasons(
        self,
        attempt_id: str,
        arm: str,
    ) -> list[str]:
        reasons: list[str] = []
        with self.store.connect(read_only=True) as connection:
            transactions = connection.execute(
                """
                SELECT transaction_record.transaction_id,
                       transaction_record.state,
                       resource.transaction_id AS resource_id,
                       stage.accounting_bucket
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                LEFT JOIN transaction_resources AS resource
                  ON resource.transaction_id = transaction_record.transaction_id
                WHERE stage.attempt_id = ?
                """,
                (attempt_id,),
            ).fetchall()
            if not transactions:
                reasons.append(f"{arm}_no_physical_transaction")
            for transaction in transactions:
                transaction_id = str(transaction["transaction_id"])
                if transaction["state"] != "finalized":
                    reasons.append(f"{arm}_nonfinal_transaction")
                if transaction["resource_id"] is None:
                    reasons.append(f"{arm}_resource_missing")
                if transaction["accounting_bucket"] is None:
                    reasons.append(f"{arm}_bucket_missing")
                latest = connection.execute(
                    """
                    SELECT current.observation_state, current.canonical
                    FROM transaction_finality_observations AS current
                    WHERE current.transaction_id = ?
                      AND NOT EXISTS (
                        SELECT 1 FROM transaction_finality_observations AS later
                        WHERE later.supersedes_observation_id =
                              current.finality_observation_id
                      )
                    """,
                    (transaction_id,),
                ).fetchone()
                if (
                    latest is None
                    or latest["observation_state"] != "finalized"
                    or latest["canonical"] != 1
                ):
                    reasons.append(f"{arm}_canonical_finality_missing")
        return reasons

    def _effect(self, attempt_id: str) -> tuple[str, str, int] | None:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT destination_effect_id, predicate_sha256, succeeded
                FROM destination_effects WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
        if row is None:
            return None
        return (
            str(row["destination_effect_id"]),
            str(row["predicate_sha256"]),
            int(row["succeeded"]),
        )

    def _metric(
        self,
        attempt_id: str,
        chain_id: int,
        bucket: str,
        metric: Metric,
    ) -> tuple[int | None, str | None]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT resource.*
                FROM transaction_resources AS resource
                JOIN transactions AS transaction_record
                  ON transaction_record.transaction_id = resource.transaction_id
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE stage.attempt_id = ? AND stage.chain_id = ?
                  AND stage.accounting_bucket = ?
                ORDER BY resource.transaction_id
                """,
                (attempt_id, chain_id, bucket),
            ).fetchall()
            stage = connection.execute(
                """
                SELECT count(*) AS count_rows,
                       sum(state != 'completed') AS incomplete
                FROM stages
                WHERE attempt_id = ? AND chain_id = ?
                  AND accounting_bucket = ?
                """,
                (attempt_id, chain_id, bucket),
            ).fetchone()
        if not rows:
            if stage["count_rows"] and not stage["incomplete"]:
                return 0, None
            return None, "bucket_completeness_unproved"
        if metric == "transaction_count":
            return len(rows), None
        if metric == "l1_data_fee_wei":
            if any(row["l1_data_fee_wei"] is None for row in rows):
                return None, "l1_data_fee_unavailable"
            return sum(int(row["l1_data_fee_wei"]) for row in rows), None
        return sum(int(row[metric]) for row in rows), None


def _quartiles(values: list[int]) -> tuple[float, float]:
    if len(values) == 1:
        only = float(values[0])
        return only, only
    midpoint = len(values) // 2
    lower = values[:midpoint]
    upper = values[-midpoint:]
    return float(statistics.median(lower)), float(statistics.median(upper))
