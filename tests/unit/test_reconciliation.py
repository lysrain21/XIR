from __future__ import annotations

from pathlib import Path

import pytest

from xir_lab.analysis.reconcile import (
    CountExpectation,
    ReconciliationError,
    RunReconciler,
)
from xir_lab.evidence.store import EvidenceStore


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'primary-v1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("11" * 32,),
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
                    schedule_index, batch_index, state, created_at
                ) VALUES (?, 'condition-hh', 'pair-0', ?, 'primary',
                          ?, 0, 'delivered', '2026-07-26T00:00:00Z')
                """,
                (attempt_id, arm, index),
            )
            connection.execute(
                """
                INSERT INTO stages(
                    stage_id, attempt_id, ordinal, stage_name, state
                ) VALUES (?, ?, 0, 'destination', 'completed')
                """,
                (f"stage-{arm}", attempt_id),
            )
            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, stage_id, signer_operation_id, chain_id, nonce,
                    state, payload_sha256, created_at
                ) VALUES (?, ?, ?, 84532, ?, 'finalized', ?,
                          '2026-07-26T00:00:00Z')
                """,
                (
                    f"intent-{arm}",
                    f"stage-{arm}",
                    f"signop-{arm}",
                    index,
                    "22" * 32,
                ),
            )
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce,
                    transaction_hash, state
                ) VALUES (?, ?, 84532, ?, ?, 'finalized')
                """,
                (
                    f"transaction-{arm}",
                    f"intent-{arm}",
                    index,
                    f"0x{index + 1:02x}" + "00" * 31,
                ),
            )
            connection.execute(
                """
                INSERT INTO attempt_outcome_observations(
                    outcome_observation_id, attempt_id, outcome_kind, outcome,
                    observed_utc, observer_session_id, observed_monotonic_ns
                ) VALUES (?, ?, 'deadline', 'delivered',
                          '2026-07-26T00:01:00Z', 'boot-a', ?)
                """,
                (f"outcome-{arm}", attempt_id, index + 1),
            )
    return store


def _expectations() -> tuple[CountExpectation, ...]:
    return (
        CountExpectation("HH", "baseline", "primary", 1),
        CountExpectation("HH", "xir", "primary", 1),
    )


def test_reconciles_counts_pairs_and_zero_pending_freeze_scope(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    reconciler = RunReconciler(store=store)
    digest = reconciler.declare_freeze_scope(
        scope_id="scope-1",
        run_id="run-1",
        version=1,
        attempt_ids=("attempt-xir", "attempt-baseline"),
    )
    assert len(digest) == 64
    report = reconciler.reconcile(
        run_id="run-1",
        expectations=_expectations(),
        freeze_scope_id="scope-1",
    )
    reconciler.require_valid(report)
    assert (
        report.planned,
        report.submitted,
        report.not_submitted,
        report.terminal_at_deadline,
        report.pending_backfill,
    ) == (2, 2, 0, 2, 0)


def test_count_gap_pending_backfill_and_pair_gap_record_violations(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    reconciler = RunReconciler(store=store)
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, pair_id, arm, attempt_kind,
                schedule_index, batch_index, state, created_at
            ) VALUES (
                'attempt-extra', 'condition-hh', 'pair-0', 'baseline',
                'primary', 2, 0, 'planned', '2026-07-26T00:00:00Z'
            )
            """
        )
    reconciler.set_backfill_status(
        attempt_id="attempt-baseline",
        state="pending",
        reason_code="receipt_archive_unavailable",
    )
    reconciler.declare_freeze_scope(
        scope_id="scope-1",
        run_id="run-1",
        version=1,
        attempt_ids=("attempt-baseline", "attempt-xir", "attempt-extra"),
    )
    report = reconciler.reconcile(
        run_id="run-1",
        expectations=(
            CountExpectation("HH", "baseline", "primary", 1),
            CountExpectation("HH", "xir", "primary", 1),
        ),
        freeze_scope_id="scope-1",
    )
    assert report.valid is False
    assert {
        issue.code for issue in report.issues
    } >= {
        "condition_arm_kind_count",
        "planned_submission_identity",
        "submitted_terminal_identity",
        "primary_pair_arms",
        "freeze_scope_pending",
    }
    with pytest.raises(ReconciliationError, match="failed"):
        reconciler.require_valid(report)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM invariant_violations
            WHERE run_id = 'run-1' AND resolved_at IS NULL
            """
        ).fetchone()[0] >= 3


def test_prior_freeze_reference_must_match_recorded_database_digest(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO freezes(
                freeze_id, run_id, version, scope_json, database_sha256,
                raw_manifest_sha256, journal_sha256, created_at
            ) VALUES ('prior-1', 'run-1', 1, '{}', ?, ?, ?,
                      '2026-07-26T00:00:00Z')
            """,
            ("aa" * 32, "bb" * 32, "cc" * 32),
        )
    reconciler = RunReconciler(store=store)
    with pytest.raises(ReconciliationError, match="prior freeze"):
        reconciler.declare_freeze_scope(
            scope_id="scope-bad",
            run_id="run-1",
            version=2,
            attempt_ids=("attempt-baseline",),
            prior_freeze_id="prior-1",
            prior_freeze_sha256="ff" * 32,
        )
    reconciler.declare_freeze_scope(
        scope_id="scope-good",
        run_id="run-1",
        version=2,
        attempt_ids=("attempt-baseline",),
        prior_freeze_id="prior-1",
        prior_freeze_sha256="aa" * 32,
    )
