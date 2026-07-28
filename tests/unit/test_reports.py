from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from xir_lab.analysis.invariants import InvariantReport
from xir_lab.analysis.rebuild import OfflineRebuilder
from xir_lab.analysis.reconcile import ReconciliationReport
from xir_lab.analysis.reports import (
    PrimaryReportBuilder,
    ReportError,
    ScaleReportBuilder,
)
from xir_lab.evidence.store import EvidenceStore


def _run(tmp_path: Path, *, profile: str) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', ?, ?, 'running', '2026-07-26T00:00:00Z')
            """,
            (profile, "11" * 32),
        )
    return store


def test_primary_report_names_all_conditions_and_is_manifest_deterministic(
    tmp_path: Path,
) -> None:
    store = _run(tmp_path, profile="primary-v1")
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO freezes(
                freeze_id, run_id, version, scope_json, database_sha256,
                raw_manifest_sha256, journal_sha256, created_at
            ) VALUES ('freeze-1', 'run-1', 1, '{}', ?, ?, ?,
                      '2026-07-26T00:00:00Z')
            """,
            ("aa" * 32, "bb" * 32, "cc" * 32),
        )
    builder = PrimaryReportBuilder(store=store)
    first = builder.build(
        run_id="run-1",
        freeze_id="freeze-1",
        destination=tmp_path / "first",
    )
    second = builder.build(
        run_id="run-1",
        freeze_id="freeze-1",
        destination=tmp_path / "second",
    )
    assert first == second
    document = json.loads(
        (tmp_path / "first" / "primary-conditions.json").read_text()
    )
    assert [item["condition"] for item in document["conditions"]] == [
        "HH",
        "HL",
        "LH",
        "LL",
    ]
    assert {item["execution_state"] for item in document["conditions"]} == {
        "not_executed"
    }
    assert "not summed or priced" in document["unit_limitation"]
    assert set(document) >= {
        "stage_map",
        "per_chain_resources",
        "pair_values",
        "latency",
    }
    assert (tmp_path / "first" / "condition-eligibility.svg").read_bytes() == (
        tmp_path / "second" / "condition-eligibility.svg"
    ).read_bytes()


def test_primary_report_blocks_unresolved_invariant(tmp_path: Path) -> None:
    store = _run(tmp_path, profile="primary-v1")
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO invariant_violations(
                violation_id, run_id, invariant_code, details_json
            ) VALUES ('violation-1', 'run-1', 'fixture', '{}')
            """
        )
    with pytest.raises(ReportError, match="valid freeze"):
        PrimaryReportBuilder(store=store).build(
            run_id="run-1",
            freeze_id="missing",
            destination=tmp_path / "blocked",
        )


def test_scale_report_reconciles_exact_ten_thousand_separately(
    tmp_path: Path,
) -> None:
    store = _run(tmp_path, profile="scale-v1")
    rows = []
    conditions = ("HH", "HL", "LH", "LL")
    with store.write() as connection:
        for condition in conditions:
            connection.execute(
                """
                INSERT INTO conditions(
                    condition_id, run_id, carrier_sequence, state
                ) VALUES (?, 'run-1', ?, 'running')
                """,
                (f"condition-{condition}", condition),
            )
        index = 0
        for condition in conditions:
            for arm in ("baseline", "xir"):
                for _ in range(1_250):
                    rows.append(
                        (
                            f"attempt-{index}",
                            f"condition-{condition}",
                            arm,
                            index,
                            "2026-07-26T00:00:00Z",
                        )
                    )
                    index += 1
        connection.executemany(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, arm, attempt_kind,
                schedule_index, state, created_at
            ) VALUES (?, ?, ?, 'primary', ?, 'not_submitted', ?)
            """,
            rows,
        )
    summary = ScaleReportBuilder(store=store).build(
        run_id="run-1",
        destination=tmp_path / "scale-report",
    )
    assert summary.planned_primary == 10_000
    assert summary.not_submitted_primary == 10_000
    assert summary.submitted_primary == 0
    assert summary.retry_attempts == 0
    assert "not carrier capacity" in summary.claim_label


def test_scale_report_rejects_partial_plan(tmp_path: Path) -> None:
    store = _run(tmp_path, profile="scale-v1")
    with pytest.raises(ReportError, match="1,250"):
        ScaleReportBuilder(store=store).build(
            run_id="run-1",
            destination=tmp_path / "partial",
        )


def test_two_complete_rebuilds_match_with_network_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _run(tmp_path, profile="primary-v1")
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO freezes(
                freeze_id, run_id, version, scope_json, database_sha256,
                raw_manifest_sha256, journal_sha256, created_at
            ) VALUES ('freeze-1', 'run-1', 1, '{}', ?, ?, ?,
                      '2026-07-26T00:00:00Z')
            """,
            ("aa" * 32, "bb" * 32, "cc" * 32),
        )

    def network_forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("offline rebuild attempted a socket")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    rebuilder = OfflineRebuilder(
        store=store,
        schema_root=Path(__file__).resolve().parents[2] / "schemas",
    )
    reconciliation = ReconciliationReport("run-1", 0, 0, 0, 0, 0, ())
    invariants = InvariantReport("run-1", 0, ())
    first = rebuilder.rebuild(
        run_id="run-1",
        freeze_id="freeze-1",
        reconciliation=reconciliation,
        invariants=invariants,
        destination=tmp_path / "rebuild-first",
    )
    second = rebuilder.rebuild(
        run_id="run-1",
        freeze_id="freeze-1",
        reconciliation=reconciliation,
        invariants=invariants,
        destination=tmp_path / "rebuild-second",
    )
    assert first == second
    first_files = {
        path.relative_to(tmp_path / "rebuild-first"): path.read_bytes()
        for path in (tmp_path / "rebuild-first").rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(tmp_path / "rebuild-second"): path.read_bytes()
        for path in (tmp_path / "rebuild-second").rglob("*")
        if path.is_file()
    }
    assert first_files == second_files
