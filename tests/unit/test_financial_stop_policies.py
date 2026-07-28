from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.leases import (
    BudgetLimit,
    LeaseBudgetManager,
    PlannedStageBudget,
)
from xir_lab.execute.stop_policies import (
    FinancialStopPolicy,
    QuoteObservation,
    StopPolicyEngine,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)
CHAIN = 11_155_420


def _setup(
    tmp_path: Path,
    *,
    balance: int = 250,
    floor: int = 50,
    existing: int = 0,
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
    store.insert_attempt(
        attempt_id="attempt-0",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="primary",
    )
    budgets = LeaseBudgetManager(store)
    budgets.configure_limits(
        run_id="run-1",
        limits=(BudgetLimit(CHAIN, 100, 150, 180, floor, balance),),
        observed_at=NOW,
    )
    if existing:
        budgets.reserve_complete_route(
            reservation_id="reservation-0",
            attempt_id="attempt-0",
            batch_id="batch-1",
            stages=(PlannedStageBudget("source", CHAIN, existing),),
            now=NOW,
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
        financial=FinancialStopPolicy(
            max_quote_age_seconds=60,
            max_quote_movement_bps=1_000,
        ),
    )
    return store, controls, engine


@pytest.mark.parametrize(
    ("existing", "batch_id", "requested", "expected"),
    (
        (0, "batch-1", 101, "transaction_budget_exhausted"),
        (100, "batch-1", 60, "batch_budget_exhausted"),
        (100, "batch-2", 90, "run_budget_exhausted"),
    ),
)
def test_budget_exhaustion_triggers_persistent_halt(
    tmp_path: Path,
    existing: int,
    batch_id: str,
    requested: int,
    expected: str,
) -> None:
    _, controls, engine = _setup(tmp_path, existing=existing)
    result = engine.check_budget(
        run_id="run-1",
        batch_id=batch_id,
        chain_id=CHAIN,
        requested_wei=requested,
        checked_at=NOW,
    )
    assert result.triggered
    assert result.policy_code == expected
    assert controls.state("run-1").mode == "halted"


def test_balance_floor_triggers_and_survives_restart(tmp_path: Path) -> None:
    store, _, engine = _setup(tmp_path, balance=170, floor=50, existing=80)
    result = engine.check_budget(
        run_id="run-1",
        batch_id="batch-2",
        chain_id=CHAIN,
        requested_wei=50,
        checked_at=NOW,
    )
    assert result.policy_code == "runner_balance_floor"
    assert RunControlManager(store).state("run-1").mode == "halted"


def test_quote_age_and_movement_are_independent_hard_stops(tmp_path: Path) -> None:
    _, controls, engine = _setup(tmp_path)
    stale = engine.check_quote(
        run_id="run-1",
        quote=QuoteObservation("quote-old", NOW - timedelta(seconds=61), 100, 100),
        checked_at=NOW,
    )
    assert stale.policy_code == "quote_age_exceeded"
    assert controls.state("run-1").mode == "halted"

    _, controls_2, engine_2 = _setup(tmp_path / "movement")
    movement = engine_2.check_quote(
        run_id="run-1",
        quote=QuoteObservation("quote-move", NOW, 111, 100),
        checked_at=NOW,
    )
    assert movement.policy_code == "quote_movement_exceeded"
    assert controls_2.state("run-1").mode == "halted"


def test_quote_and_budget_at_limits_pass_without_stopping(tmp_path: Path) -> None:
    store, controls, engine = _setup(tmp_path)
    quote = engine.check_quote(
        run_id="run-1",
        quote=QuoteObservation("quote-boundary", NOW - timedelta(seconds=60), 110, 100),
        checked_at=NOW,
    )
    budget = engine.check_budget(
        run_id="run-1",
        batch_id="batch-1",
        chain_id=CHAIN,
        requested_wei=100,
        checked_at=NOW,
    )
    assert not quote.triggered
    assert not budget.triggered
    assert controls.state("run-1").mode == "running"
    with store.connect(read_only=True) as connection:
        outcomes = [
            row[0]
            for row in connection.execute(
                "SELECT outcome FROM stop_policy_events ORDER BY event_id"
            )
        ]
    assert outcomes == ["pass", "pass"]
