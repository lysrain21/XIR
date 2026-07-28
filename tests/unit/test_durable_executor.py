from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.config.profiles import LiveLimits, load_execution_profile
from xir_lab.config.stages import load_stage_template_set
from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.executor import DurableBatchExecutor, ExecutorError
from xir_lab.execute.scheduler import expand_plan

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "configs" / "profiles" / "pilot-template-v1.json"
STAGES = ROOT / "configs" / "stages" / "v1.json"
NOW = datetime(2026, 7, 26, tzinfo=UTC)


def _executor(tmp_path: Path) -> tuple[EvidenceStore, DurableBatchExecutor]:
    profile = load_execution_profile(PILOT)
    live = replace(
        profile,
        profile_mode="live",
        live_limits=LiveLimits(
            max_retries_per_lineage=1,
            max_batch_attempts=4,
            max_duration_seconds=3_600,
            max_in_flight_attempts=2,
            chain_budget_wei={"11155420": 1, "421614": 1, "84532": 1},
            stop_policy={"fixture": True},
            allow_partial_conditions=False,
        ),
    )
    plan = expand_plan(live, run_id="run-executor")
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    executor = DurableBatchExecutor(
        store=store,
        plan=plan,
        templates=load_stage_template_set(STAGES),
    )
    executor.register_plan(now=NOW)
    controls = RunControlManager(store)
    controls.initialize(
        run_id=plan.run_id,
        decision=ControlDecision("initial", "aa" * 32, "run-start"),
        now=NOW,
    )
    return store, executor


def _finish_fixture_claim(
    store: EvidenceStore,
    executor: DurableBatchExecutor,
    attempt_id: str,
    lease_id: str,
    holder: str,
) -> None:
    with store.write() as connection:
        connection.execute(
            "UPDATE attempts SET state = 'delivered' WHERE attempt_id = ?",
            (attempt_id,),
        )
    executor.leases.release_work(lease_id=lease_id, holder_id=holder)


def test_plan_registration_is_idempotent_and_persists_exact_stage_templates(
    tmp_path: Path,
) -> None:
    store, executor = _executor(tmp_path)
    executor.register_plan(now=NOW)
    with store.connect(read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM attempts").fetchone()[0] == 40
        assert connection.execute("SELECT count(*) FROM pairs").fetchone()[0] == 20
        assert connection.execute("SELECT count(*) FROM stages").fetchone()[0] == 120
        source = connection.execute(
            """
            SELECT chain_id, accounting_bucket, logical_labels_json,
                   stage_template_id
            FROM stages ORDER BY stage_id LIMIT 1
            """
        ).fetchone()
    assert source["chain_id"] in {11_155_420, 421_614, 84_532}
    assert source["accounting_bucket"] in {"source", "intermediate", "destination"}
    assert source["logical_labels_json"].startswith("[")
    assert source["stage_template_id"].endswith("-v1")


def test_claims_are_restart_safe_pair_isolated_inflight_bounded_and_batched(
    tmp_path: Path,
) -> None:
    store, executor = _executor(tmp_path)
    first = executor.claim_next(
        holder_id="worker-a",
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert first is not None
    assert executor.claim_next(
        holder_id="worker-b",
        ttl=timedelta(minutes=5),
        now=NOW,
    ) is None

    restarted = DurableBatchExecutor(
        store=store,
        plan=executor.plan,
        templates=load_stage_template_set(STAGES),
    )
    assert restarted.snapshot(now=NOW).leased == 1
    _finish_fixture_claim(
        store,
        executor,
        first.attempt.attempt_id,
        first.work_lease_id,
        first.holder_id,
    )

    claimed_batches = []
    while len(claimed_batches) < 3:
        claimed = executor.claim_next(
            holder_id=f"worker-{len(claimed_batches)}",
            ttl=timedelta(minutes=5),
            now=NOW + timedelta(seconds=len(claimed_batches) + 1),
        )
        if claimed is None:
            active = executor.snapshot(now=NOW).leased
            assert active <= 2
            break
        claimed_batches.append(claimed)
    assert all(item.attempt.batch_index == 0 for item in claimed_batches)
    assert len({item.attempt.pair_id for item in claimed_batches}) == len(
        claimed_batches
    )


def test_stage_transitions_require_order_and_durable_intent_and_are_idempotent(
    tmp_path: Path,
) -> None:
    store, executor = _executor(tmp_path)
    claim = executor.claim_next(
        holder_id="worker",
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert claim is not None
    with store.connect(read_only=True) as connection:
        stages = connection.execute(
            """
            SELECT stage_id, chain_id FROM stages
            WHERE attempt_id = ? ORDER BY ordinal
            """,
            (claim.attempt.attempt_id,),
        ).fetchall()
    with pytest.raises(ExecutorError, match="prior preregistered"):
        executor.transition_stage(stage_id=stages[1]["stage_id"], to_state="prepared")

    executor.transition_stage(stage_id=stages[0]["stage_id"], to_state="prepared")
    executor.transition_stage(stage_id=stages[0]["stage_id"], to_state="prepared")
    with pytest.raises(ExecutorError, match="durable intent"):
        executor.transition_stage(stage_id=stages[0]["stage_id"], to_state="in_flight")
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES ('intent-0', ?, 'signop-0', ?, 7, 'prepared', ?, ?)
            """,
            (
                stages[0]["stage_id"],
                stages[0]["chain_id"],
                "11" * 32,
                NOW.isoformat(),
            ),
        )
    executor.transition_stage(stage_id=stages[0]["stage_id"], to_state="in_flight")
    executor.transition_stage(stage_id=stages[0]["stage_id"], to_state="completed")
    executor.transition_stage(stage_id=stages[1]["stage_id"], to_state="prepared")


def test_intent_before_broadcast_invariant_detects_forged_state(
    tmp_path: Path,
) -> None:
    store, executor = _executor(tmp_path)
    with store.connect(read_only=True) as connection:
        stage = connection.execute(
            "SELECT stage_id, chain_id FROM stages ORDER BY stage_id LIMIT 1"
        ).fetchone()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES ('intent-forged', ?, 'signop-forged', ?, 7, 'prepared', ?, ?)
            """,
            (stage["stage_id"], stage["chain_id"], "11" * 32, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO transactions(
                transaction_id, intent_id, chain_id, nonce, state
            ) VALUES ('transaction-forged', 'intent-forged', ?, 7, 'submitted')
            """,
            (stage["chain_id"],),
        )
    with pytest.raises(ExecutorError, match="lacks durable signed intent"):
        executor.assert_intent_before_broadcast()
    with store.write() as connection:
        connection.execute(
            "UPDATE intents SET state = 'submitted' WHERE intent_id = 'intent-forged'"
        )
    executor.assert_intent_before_broadcast()


def test_drain_prevents_new_batch_claim_after_restart(tmp_path: Path) -> None:
    store, executor = _executor(tmp_path)
    RunControlManager(store).drain(
        run_id=executor.plan.run_id,
        decision=ControlDecision("drain", "bb" * 32, "operator-drain"),
        now=NOW,
    )
    restarted = DurableBatchExecutor(
        store=store,
        plan=executor.plan,
        templates=load_stage_template_set(STAGES),
    )
    assert restarted.claim_next(
        holder_id="worker",
        ttl=timedelta(minutes=5),
        now=NOW,
    ) is None
