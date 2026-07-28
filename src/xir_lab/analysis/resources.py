"""Separate per-chain resource, funding, balance, and logical-label views."""

from __future__ import annotations

import json
from dataclasses import dataclass

from xir_lab.evidence.store import EvidenceStore


@dataclass(frozen=True)
class TransactionResourceRow:
    attempt_id: str
    transaction_id: str
    chain_id: int
    accounting_bucket: str
    gas_used: int
    input_bytes: int
    effective_gas_price_wei: int
    execution_fee_wei: int
    l1_data_fee_wei: int | None
    l1_data_fee_unavailable_reason: str | None
    carrier_quote_wei: int | None
    carrier_payment_wei: int
    transaction_value_wei: int
    funding_attribution: str


@dataclass(frozen=True)
class BalanceChangeRow:
    attempt_id: str
    chain_id: int
    account: str
    before_balance_wei: int
    after_balance_wei: int
    change_wei: int
    funding_attribution: str


@dataclass(frozen=True)
class LogicalLabelRow:
    transaction_id: str
    attempt_id: str
    labels: tuple[str, ...]


class ResourceReporter:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def transaction_rows(self, *, run_id: str) -> tuple[TransactionResourceRow, ...]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT stage.attempt_id, resource.*, stage.accounting_bucket,
                       (
                           SELECT CAST(quote.carrier_payment_wei AS INTEGER)
                           FROM carrier_quote_observations AS quote
                           WHERE quote.stage_id = stage.stage_id
                       ) AS carrier_quote_wei
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
                ORDER BY resource.chain_id, stage.accounting_bucket,
                         resource.transaction_id
                """,
                (run_id,),
            ).fetchall()
        return tuple(
            TransactionResourceRow(
                attempt_id=str(row["attempt_id"]),
                transaction_id=str(row["transaction_id"]),
                chain_id=int(row["chain_id"]),
                accounting_bucket=str(row["accounting_bucket"]),
                gas_used=int(row["gas_used"]),
                input_bytes=int(row["input_bytes"]),
                effective_gas_price_wei=int(row["effective_gas_price_wei"]),
                execution_fee_wei=int(row["execution_fee_wei"]),
                l1_data_fee_wei=(
                    None
                    if row["l1_data_fee_wei"] is None
                    else int(row["l1_data_fee_wei"])
                ),
                l1_data_fee_unavailable_reason=(
                    None
                    if row["l1_data_fee_unavailable_reason"] is None
                    else str(row["l1_data_fee_unavailable_reason"])
                ),
                carrier_quote_wei=(
                    None
                    if row["carrier_quote_wei"] is None
                    else int(row["carrier_quote_wei"])
                ),
                carrier_payment_wei=int(row["carrier_payment_wei"]),
                transaction_value_wei=int(row["transaction_value_wei"]),
                funding_attribution=str(row["funding_attribution"]),
            )
            for row in rows
        )

    def balance_changes(self, *, run_id: str) -> tuple[BalanceChangeRow, ...]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT snapshot.attempt_id, snapshot.chain_id, snapshot.account,
                       min(snapshot.block_number) AS first_block,
                       max(snapshot.block_number) AS last_block
                FROM account_snapshots AS snapshot
                JOIN attempts AS attempt
                  ON attempt.attempt_id = snapshot.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ? AND snapshot.attempt_id IS NOT NULL
                GROUP BY snapshot.attempt_id, snapshot.chain_id, snapshot.account
                ORDER BY snapshot.attempt_id, snapshot.chain_id, snapshot.account
                """,
                (run_id,),
            ).fetchall()
            result: list[BalanceChangeRow] = []
            for row in rows:
                before = connection.execute(
                    """
                    SELECT balance_wei FROM account_snapshots
                    WHERE attempt_id = ? AND chain_id = ? AND account = ?
                      AND block_number = ? ORDER BY snapshot_id LIMIT 1
                    """,
                    (
                        row["attempt_id"],
                        row["chain_id"],
                        row["account"],
                        row["first_block"],
                    ),
                ).fetchone()
                after = connection.execute(
                    """
                    SELECT balance_wei FROM account_snapshots
                    WHERE attempt_id = ? AND chain_id = ? AND account = ?
                      AND block_number = ? ORDER BY snapshot_id DESC LIMIT 1
                    """,
                    (
                        row["attempt_id"],
                        row["chain_id"],
                        row["account"],
                        row["last_block"],
                    ),
                ).fetchone()
                before_value = int(before["balance_wei"])
                after_value = int(after["balance_wei"])
                result.append(
                    BalanceChangeRow(
                        str(row["attempt_id"]),
                        int(row["chain_id"]),
                        str(row["account"]),
                        before_value,
                        after_value,
                        after_value - before_value,
                        "experiment",
                    )
                )
        return tuple(result)

    def logical_labels(self, *, run_id: str) -> tuple[LogicalLabelRow, ...]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT transaction_record.transaction_id, stage.attempt_id,
                       stage.logical_labels_json
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ?
                ORDER BY transaction_record.transaction_id
                """,
                (run_id,),
            ).fetchall()
        return tuple(
            LogicalLabelRow(
                str(row["transaction_id"]),
                str(row["attempt_id"]),
                tuple(json.loads(str(row["logical_labels_json"] or "[]"))),
            )
            for row in rows
        )

    def runner_spending_by_chain(self, *, run_id: str) -> dict[int, int]:
        totals: dict[int, int] = {}
        for row in self.transaction_rows(run_id=run_id):
            if row.funding_attribution != "experiment":
                continue
            totals[row.chain_id] = totals.get(row.chain_id, 0) + (
                row.execution_fee_wei
                + (row.l1_data_fee_wei or 0)
                + row.carrier_payment_wei
                + row.transaction_value_wei
            )
        return totals
