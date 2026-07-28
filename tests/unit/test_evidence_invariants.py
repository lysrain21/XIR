from __future__ import annotations

import gzip
from pathlib import Path

from xir_lab.analysis.invariants import EvidenceInvariantValidator
from xir_lab.analysis.reconcile import RunReconciler
from xir_lab.evidence.store import EvidenceStore


def _run(store: EvidenceStore) -> None:
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("11" * 32,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-1', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-1', 'condition-1', 0)
            """
        )


def test_empty_declared_scope_has_no_cross_table_violations(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    _run(store)
    RunReconciler(store=store).declare_freeze_scope(
        scope_id="scope-1",
        run_id="run-1",
        version=1,
        attempt_ids=(),
    )
    report = EvidenceInvariantValidator(store=store).validate(
        run_id="run-1",
        freeze_scope_id="scope-1",
    )
    assert report.valid is True
    assert report.checked_attempts == 0


def test_validator_detects_linkage_finality_budget_resource_and_raw_failures(
    tmp_path: Path,
) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    _run(store)
    with store.write() as connection:
        for index in range(2):
            attempt_id = f"attempt-{index}"
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, condition_id, pair_id, arm, attempt_kind,
                    state, created_at
                ) VALUES (?, 'condition-1', 'pair-1', 'xir', 'primary',
                          'delivered', '2026-07-26T00:00:00Z')
                """,
                (attempt_id,),
            )
            connection.execute(
                """
                INSERT INTO stages(
                    stage_id, attempt_id, ordinal, stage_name, state
                ) VALUES (?, ?, 0, 'destination', 'completed')
                """,
                (f"stage-{index}", attempt_id),
            )
            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, stage_id, signer_operation_id, chain_id, nonce,
                    state, payload_sha256, signer_id, created_at
                ) VALUES (?, ?, ?, 84532, 7, 'finalized', ?, 'runner',
                          '2026-07-26T00:00:00Z')
                """,
                (
                    f"intent-{index}",
                    f"stage-{index}",
                    f"signop-{index}",
                    "22" * 32,
                ),
            )
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce,
                    transaction_hash, state
                ) VALUES (?, ?, 84532, 7, ?, 'finalized')
                """,
                (
                    f"transaction-{index}",
                    f"intent-{index}",
                    f"0x{index + 1:02x}" + "00" * 31,
                ),
            )
        connection.execute(
            """
            INSERT INTO transaction_resources(
                transaction_id, chain_id, sender, recipient, input_bytes,
                transaction_value_wei, gas_used, effective_gas_price_wei,
                execution_fee_wei, l1_data_fee_wei,
                l1_data_fee_unavailable_reason, carrier_payment_wei,
                funding_attribution
            ) VALUES (
                'transaction-0', 84532, ?, NULL, 1, '0', 10, '2', '999',
                NULL, 'archive_unavailable', '0', 'experiment'
            )
            """,
            ("0x" + "33" * 20,),
        )
        connection.execute(
            """
            INSERT INTO budgets(
                reservation_id, attempt_id, run_id, batch_id, chain_id,
                reserved_wei, provisional_wei, finalized_wei,
                source_in_flight, state, created_at
            ) VALUES (
                'reservation-1', 'attempt-0', 'run-1', 'batch-1', 84532,
                10, 5, 0, 1, 'in_flight', '2026-07-26T00:00:00Z'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO carrier_messages(
                carrier_message_id, attempt_id, leg_index, protocol,
                protocol_identifier
            ) VALUES (
                'carrier-0', 'attempt-0', 0, 'hyperlane', ?
            )
            """,
            ("0x" + "44" * 32,),
        )
    orphan = store.raw_root / "sha256" / "ff" / f"{'ff' * 32}.gz"
    orphan.parent.mkdir(parents=True)
    with gzip.open(orphan, "wb") as handle:
        handle.write(b"orphan")
    RunReconciler(store=store).declare_freeze_scope(
        scope_id="scope-1",
        run_id="run-1",
        version=1,
        attempt_ids=("attempt-0", "attempt-1"),
    )
    report = EvidenceInvariantValidator(store=store).validate(
        run_id="run-1",
        freeze_scope_id="scope-1",
    )
    assert report.valid is False
    assert {
        issue.code for issue in report.issues
    } >= {
        "stage_template",
        "carrier_leg_continuity",
        "carrier_transaction_link",
        "xir_trace_missing",
        "finality",
        "nonce_uniqueness",
        "budget_arithmetic",
        "resource_arithmetic",
        "raw_orphans",
    }
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM invariant_violations
            WHERE run_id = 'run-1' AND resolved_at IS NULL
            """
        ).fetchone()[0] >= 9
