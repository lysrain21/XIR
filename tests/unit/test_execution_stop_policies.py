from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.stop_policies import (
    ExecutionStopPolicy,
    FinancialStopPolicy,
    StopPolicyEngine,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)


def _setup(
    tmp_path: Path,
    *,
    consecutive: int = 3,
    window: int = 5,
    rate: float = 0.6,
    timeouts: int = 3,
) -> tuple[EvidenceStore, RunControlManager, StopPolicyEngine]:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', ?)
            """,
            ("11" * 32, NOW.isoformat()),
        )
    controls = RunControlManager(store)
    controls.initialize(
        run_id="run-1",
        decision=ControlDecision("initial", "aa" * 32, "run-start"),
        now=NOW,
    )
    engine = StopPolicyEngine(
        store=store,
        controls=controls,
        financial=FinancialStopPolicy(60, 1_000),
        execution=ExecutionStopPolicy(
            consecutive_failures=consecutive,
            rolling_window=window,
            rolling_failure_rate=rate,
            timeout_count=timeouts,
        ),
    )
    return store, controls, engine


def test_consecutive_failures_trigger_at_exact_threshold_and_survive_restart(
    tmp_path: Path,
) -> None:
    store, controls, engine = _setup(tmp_path)
    for index in range(2):
        result = engine.record_execution_outcome(
            run_id="run-1",
            outcome_id=f"outcome-{index}",
            failed=True,
            timed_out=False,
            occurred_at=NOW + timedelta(seconds=index),
        )
        assert not result.triggered
    result = engine.record_execution_outcome(
        run_id="run-1",
        outcome_id="outcome-2",
        failed=True,
        timed_out=False,
        occurred_at=NOW + timedelta(seconds=2),
    )
    assert result.policy_code == "consecutive_failures"
    assert controls.state("run-1").mode == "halted"
    assert RunControlManager(store).state("run-1").mode == "halted"


def test_success_resets_consecutive_but_rolling_rate_still_triggers(
    tmp_path: Path,
) -> None:
    _, controls, engine = _setup(tmp_path, consecutive=10)
    failures = (True, False, True, False, True)
    result = None
    for index, failed in enumerate(failures):
        result = engine.record_execution_outcome(
            run_id="run-1",
            outcome_id=f"outcome-{index}",
            failed=failed,
            timed_out=False,
            occurred_at=NOW + timedelta(seconds=index),
        )
    assert result is not None
    assert result.policy_code == "rolling_failure_rate"
    assert controls.state("run-1").mode == "halted"


def test_timeout_counter_is_restart_safe_and_independent_of_failure_streak(
    tmp_path: Path,
) -> None:
    store, _, engine = _setup(
        tmp_path,
        consecutive=10,
        window=10,
        rate=1.0,
        timeouts=2,
    )
    first = engine.record_execution_outcome(
        run_id="run-1",
        outcome_id="timeout-1",
        failed=False,
        timed_out=True,
        occurred_at=NOW,
    )
    assert not first.triggered
    restarted = StopPolicyEngine(
        store=store,
        controls=RunControlManager(store),
        financial=FinancialStopPolicy(60, 1_000),
        execution=ExecutionStopPolicy(10, 10, 1.0, 2),
    )
    second = restarted.record_execution_outcome(
        run_id="run-1",
        outcome_id="timeout-2",
        failed=False,
        timed_out=True,
        occurred_at=NOW + timedelta(seconds=1),
    )
    assert second.policy_code == "timeout_count"


def test_nonce_gap_rpc_disagreement_and_reorganization_are_hard_stops(
    tmp_path: Path,
) -> None:
    _, controls, engine = _setup(tmp_path / "nonce")
    nonce = engine.check_nonce_gap(
        run_id="run-1",
        chain_id=11_155_420,
        expected_nonce=7,
        observed_nonce=9,
        checked_at=NOW,
    )
    assert nonce.policy_code == "nonce_gap"
    assert controls.state("run-1").mode == "halted"

    _, controls, engine = _setup(tmp_path / "rpc")
    rpc = engine.check_rpc_agreement(
        run_id="run-1",
        subject_id="receipt-1",
        provider_digests={"rpc-a": "aa" * 32, "rpc-b": "bb" * 32},
        checked_at=NOW,
    )
    assert rpc.policy_code == "rpc_disagreement"
    assert controls.state("run-1").mode == "halted"

    _, controls, engine = _setup(tmp_path / "reorg")
    reorg = engine.check_reorganization(
        run_id="run-1",
        chain_id=84_532,
        block_number=100,
        prior_block_hash="0x" + "11" * 32,
        current_block_hash="0x" + "22" * 32,
        checked_at=NOW,
    )
    assert reorg.policy_code == "chain_reorganization"
    assert controls.state("run-1").mode == "halted"


def test_matching_nonce_rpc_and_block_state_pass_without_halt(tmp_path: Path) -> None:
    _, controls, engine = _setup(tmp_path)
    results = (
        engine.check_nonce_gap(
            run_id="run-1",
            chain_id=11_155_420,
            expected_nonce=7,
            observed_nonce=7,
            checked_at=NOW,
        ),
        engine.check_rpc_agreement(
            run_id="run-1",
            subject_id="receipt-1",
            provider_digests={"rpc-a": "aa" * 32, "rpc-b": "aa" * 32},
            checked_at=NOW,
        ),
        engine.check_reorganization(
            run_id="run-1",
            chain_id=84_532,
            block_number=100,
            prior_block_hash="0x" + "11" * 32,
            current_block_hash="0x" + "11" * 32,
            checked_at=NOW,
        ),
    )
    assert all(not result.triggered for result in results)
    assert controls.state("run-1").mode == "running"
