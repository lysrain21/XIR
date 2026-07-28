from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import (
    ControlDecision,
    RunControlManager,
)
from xir_lab.execute.stop_policies import (
    EvidenceOperationsStopPolicy,
    FinancialStopPolicy,
    StopPolicyEngine,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)


def _setup(
    tmp_path: Path,
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
        evidence_operations=EvidenceOperationsStopPolicy(
            collector_backlog=10,
            collector_heartbeat_seconds=30,
            disk_floor_bytes=1_000,
        ),
    )
    return store, controls, engine


def test_collector_backlog_and_heartbeat_loss_enter_persistent_drain(
    tmp_path: Path,
) -> None:
    store, controls, engine = _setup(tmp_path / "backlog")
    backlog = engine.check_evidence_operations(
        run_id="run-1",
        collector_backlog=11,
        collector_heartbeat_at=NOW,
        disk_available_bytes=1_000,
        checked_at=NOW,
    )
    assert backlog.policy_code == "collector_backlog"
    assert controls.state("run-1").mode == "drain"
    assert RunControlManager(store).state("run-1").mode == "drain"

    _, controls, engine = _setup(tmp_path / "heartbeat")
    heartbeat = engine.check_evidence_operations(
        run_id="run-1",
        collector_backlog=0,
        collector_heartbeat_at=NOW - timedelta(seconds=31),
        disk_available_bytes=1_000,
        checked_at=NOW,
    )
    assert heartbeat.policy_code == "collector_heartbeat_loss"
    assert controls.state("run-1").mode == "drain"


def test_disk_below_floor_enters_halt_not_drain(tmp_path: Path) -> None:
    store, controls, engine = _setup(tmp_path)
    result = engine.check_evidence_operations(
        run_id="run-1",
        collector_backlog=0,
        collector_heartbeat_at=NOW,
        disk_available_bytes=999,
        checked_at=NOW,
    )
    assert result.policy_code == "disk_floor"
    assert controls.state("run-1").mode == "halted"
    assert RunControlManager(store).state("run-1").mode == "halted"


def test_operational_values_at_thresholds_pass(tmp_path: Path) -> None:
    _, controls, engine = _setup(tmp_path)
    result = engine.check_evidence_operations(
        run_id="run-1",
        collector_backlog=10,
        collector_heartbeat_at=NOW - timedelta(seconds=30),
        disk_available_bytes=1_000,
        checked_at=NOW,
    )
    assert not result.triggered
    assert controls.state("run-1").mode == "running"


def test_manual_drain_and_halt_use_control_and_policy_journals(
    tmp_path: Path,
) -> None:
    store, controls, engine = _setup(tmp_path)
    drain = engine.manual_stop(
        run_id="run-1",
        mode="drain",
        decision=ControlDecision("manual-drain", "bb" * 32, "operator-drain"),
        checked_at=NOW,
    )
    assert drain.policy_code == "manual_drain"
    assert controls.state("run-1").mode == "drain"
    controls.resume(
        run_id="run-1",
        decision=ControlDecision("resume", "cc" * 32, "operator-resume"),
        approval_state_changed=False,
        now=NOW,
    )
    halt = engine.manual_stop(
        run_id="run-1",
        mode="halted",
        decision=ControlDecision("manual-halt", "dd" * 32, "operator-halt"),
        checked_at=NOW,
    )
    assert halt.policy_code == "manual_halt"
    assert controls.state("run-1").mode == "halted"
    with store.connect(read_only=True) as connection:
        codes = [
            row[0]
            for row in connection.execute(
                """
                SELECT policy_code FROM stop_policy_events
                ORDER BY occurred_at, event_id
                """
            )
        ]
    assert sorted(codes) == ["manual_drain", "manual_halt"]
