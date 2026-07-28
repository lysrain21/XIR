from __future__ import annotations

from pathlib import Path

from xir_lab.analysis.overhead import PairFirstAnalyzer
from xir_lab.analysis.resources import ResourceReporter
from xir_lab.evidence.store import EvidenceStore

CHAIN = 84_532
PREDICATE = "11" * 32


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    raw_sha256 = store.put_raw(
        b'{"fixture":"resource"}',
        media_type="application/json",
        metadata={"source": "fixture"},
    )
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'primary-v1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("22" * 32,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hh', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-0', 'condition-hh', 0)
            """
        )
        for index, arm in enumerate(("baseline", "xir")):
            attempt_id = f"attempt-{arm}"
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, condition_id, pair_id, arm, attempt_kind,
                    state, created_at
                ) VALUES (?, 'condition-hh', 'pair-0', ?, 'primary',
                          'delivered', '2026-07-26T00:00:00Z')
                """,
                (attempt_id, arm),
            )
            connection.execute(
                """
                INSERT INTO stages(
                    stage_id, attempt_id, ordinal, stage_name,
                    stage_template_id, chain_id, accounting_bucket,
                    logical_labels_json, state
                ) VALUES (?, ?, 0, 'destination', 'template-v1', ?,
                          'destination', '[]', 'completed')
                """,
                (f"stage-{arm}", attempt_id, CHAIN),
            )
            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, stage_id, signer_operation_id, chain_id, nonce,
                    state, payload_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, 'finalized', ?,
                          '2026-07-26T00:00:00Z')
                """,
                (
                    f"intent-{arm}",
                    f"stage-{arm}",
                    f"signop-{arm}",
                    CHAIN,
                    index,
                    "33" * 32,
                ),
            )
            transaction_id = f"transaction-{arm}"
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce,
                    transaction_hash, state
                ) VALUES (?, ?, ?, ?, ?, 'finalized')
                """,
                (
                    transaction_id,
                    f"intent-{arm}",
                    CHAIN,
                    index,
                    f"0x{index + 1:02x}" + "00" * 31,
                ),
            )
            gas = 10 + index * 4
            connection.execute(
                """
                INSERT INTO transaction_resources(
                    transaction_id, chain_id, sender, recipient, input_bytes,
                    transaction_value_wei, gas_used, effective_gas_price_wei,
                    execution_fee_wei, l1_data_fee_wei,
                    l1_data_fee_unavailable_reason, carrier_payment_wei,
                    funding_attribution
                ) VALUES (?, ?, ?, NULL, ?, '0', ?, '2', ?, '3', NULL,
                          ?, 'experiment')
                """,
                (
                    transaction_id,
                    CHAIN,
                    "0x" + "44" * 20,
                    2 + index,
                    gas,
                    str(gas * 2),
                    5 + index,
                ),
            )
            finality_id = f"finality-{arm}"
            connection.execute(
                """
                INSERT INTO transaction_finality_observations(
                    finality_observation_id, transaction_id, chain_id,
                    block_number, block_hash, observation_state, canonical,
                    policy_kind, policy_head_block, observed_at
                ) VALUES (?, ?, ?, 100, ?, 'finalized', 1,
                          'l2-finalized', 100, '2026-07-26T00:01:00Z')
                """,
                (
                    finality_id,
                    transaction_id,
                    CHAIN,
                    f"0x{index + 5:02x}" + "00" * 31,
                ),
            )
            connection.execute(
                """
                INSERT INTO destination_effects(
                    attempt_id, transaction_id, destination_effect_id,
                    predicate_sha256, succeeded
                ) VALUES (?, ?, 'counter-increment-v1', ?, 1)
                """,
                (attempt_id, transaction_id, PREDICATE),
            )
            connection.execute(
                """
                INSERT INTO carrier_quote_observations(
                    quote_observation_id, attempt_id, stage_id, leg_index,
                    protocol, request_sha256, carrier_payment_wei, gas_limit,
                    max_fee_per_gas_wei, raw_sha256, quoted_at
                ) VALUES (?, ?, ?, 0, 'hyperlane', ?, ?, 100, '2', ?,
                          '2026-07-26T00:00:00Z')
                """,
                (
                    f"quote-{arm}",
                    attempt_id,
                    f"stage-{arm}",
                    "55" * 32,
                    str(7 + index),
                    raw_sha256,
                ),
            )
            for block, balance in ((99, 100), (100, 90 - index)):
                connection.execute(
                    """
                    INSERT INTO account_snapshots(
                        snapshot_id, attempt_id, chain_id, account,
                        balance_wei, block_number, raw_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"snapshot-{arm}-{block}",
                        attempt_id,
                        CHAIN,
                        "0x" + "44" * 20,
                        str(balance),
                        block,
                        raw_sha256,
                    ),
                )
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, pair_id, arm, attempt_kind,
                original_attempt_kind, retry_of, state, created_at
            ) VALUES (
                'attempt-baseline-retry', 'condition-hh', 'pair-0',
                'baseline', 'retry', 'primary', 'attempt-baseline',
                'delivered', '2026-07-26T00:02:00Z'
            )
            """
        )
    return store


def test_designated_primary_pair_first_values_ignore_retry_success(
    tmp_path: Path,
) -> None:
    analyzer = PairFirstAnalyzer(store=_store(tmp_path))
    decisions = analyzer.decide_pairs(run_id="run-1")
    assert decisions[0].eligible is True
    assert decisions[0].baseline_attempt_id == "attempt-baseline"
    values = analyzer.pair_values(
        run_id="run-1",
        metrics=("gas_used", "execution_fee_wei", "transaction_count"),
    )
    gas = next(value for value in values if value.metric == "gas_used")
    assert (gas.baseline_value, gas.xir_value, gas.difference) == (10, 14, 4)
    assert gas.relative_difference == 0.4
    execution = next(
        value for value in values if value.metric == "execution_fee_wei"
    )
    assert execution.difference == 8
    count = next(value for value in values if value.metric == "transaction_count")
    assert count.difference == 0
    aggregate = analyzer.aggregate(values)
    gas_aggregate = next(item for item in aggregate if item.metric == "gas_used")
    assert (
        gas_aggregate.eligible_count,
        gas_aggregate.median,
        gas_aggregate.interquartile_range,
        gas_aggregate.minimum,
        gas_aggregate.maximum,
    ) == (1, 4.0, 0.0, 4, 4)


def test_effect_mismatch_excludes_pair_instead_of_using_retry(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with store.write() as connection:
        connection.execute(
            """
            UPDATE destination_effects SET predicate_sha256 = ?
            WHERE attempt_id = 'attempt-baseline'
            """,
            ("ff" * 32,),
        )
    analyzer = PairFirstAnalyzer(store=store)
    decision = analyzer.decide_pairs(run_id="run-1")[0]
    assert decision.eligible is False
    assert decision.reasons == ("destination_effect_mismatch",)
    assert analyzer.pair_values(
        run_id="run-1",
        metrics=("gas_used",),
    ) == ()


def test_resource_views_keep_chain_units_funding_and_labels_separate(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with store.write() as connection:
        connection.execute(
            """
            UPDATE transaction_resources SET funding_attribution = 'external'
            WHERE transaction_id = 'transaction-xir'
            """
        )
    reporter = ResourceReporter(store=store)
    rows = reporter.transaction_rows(run_id="run-1")
    assert len(rows) == 2
    baseline = next(
        row for row in rows if row.transaction_id == "transaction-baseline"
    )
    assert baseline.carrier_quote_wei == 7
    assert baseline.l1_data_fee_wei == 3
    assert reporter.runner_spending_by_chain(run_id="run-1") == {
        CHAIN: 20 + 3 + 5
    }
    changes = reporter.balance_changes(run_id="run-1")
    assert {row.change_wei for row in changes} == {-10, -11}
    labels = reporter.logical_labels(run_id="run-1")
    assert len(labels) == 2
    assert all(label.labels == () for label in labels)
