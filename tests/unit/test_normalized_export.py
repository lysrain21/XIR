from __future__ import annotations

import json
from pathlib import Path

import pytest

from xir_lab.analysis.export import ExportError, NormalizedExporter
from xir_lab.analysis.invariants import InvariantIssue, InvariantReport
from xir_lab.analysis.reconcile import (
    ReconciliationIssue,
    ReconciliationReport,
)
from xir_lab.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("11" * 32,),
        )
    return store


def _reports() -> tuple[ReconciliationReport, InvariantReport]:
    return (
        ReconciliationReport("run-1", 0, 0, 0, 0, 0, ()),
        InvariantReport("run-1", 0, ()),
    )


def test_exports_versioned_json_csv_and_is_byte_deterministic(
    tmp_path: Path,
) -> None:
    exporter = NormalizedExporter(
        store=_store(tmp_path),
        schema_root=ROOT / "schemas",
    )
    reconciliation, invariants = _reports()
    first = exporter.export(
        run_id="run-1",
        reconciliation=reconciliation,
        invariants=invariants,
        destination=tmp_path / "first",
    )
    second = exporter.export(
        run_id="run-1",
        reconciliation=reconciliation,
        invariants=invariants,
        destination=tmp_path / "second",
    )
    assert first == second
    assert len(first.artifacts) == 12
    assert (tmp_path / "first" / "attempts.csv").read_bytes() == b""
    validation = json.loads(
        (tmp_path / "first" / "validation.json").read_text()
    )
    assert validation["schema_version"] == "xir-lab-normalized-validation-v1"
    assert {row["validator"] for row in validation["rows"]} == {
        "reconciliation",
        "evidence_invariants",
    }
    for relative in sorted(
        path.relative_to(tmp_path / "first")
        for path in (tmp_path / "first").iterdir()
    ):
        assert (tmp_path / "first" / relative).read_bytes() == (
            tmp_path / "second" / relative
        ).read_bytes()


def test_export_refuses_any_invalid_validation_gate(tmp_path: Path) -> None:
    exporter = NormalizedExporter(
        store=_store(tmp_path),
        schema_root=ROOT / "schemas",
    )
    invalid_reconciliation = ReconciliationReport(
        "run-1",
        1,
        0,
        0,
        0,
        0,
        (ReconciliationIssue("gap", "run-1", "fixture"),),
    )
    invalid_invariants = InvariantReport(
        "run-1",
        1,
        (InvariantIssue("raw_missing", "digest", "fixture"),),
    )
    with pytest.raises(ExportError, match="valid"):
        exporter.export(
            run_id="run-1",
            reconciliation=invalid_reconciliation,
            invariants=InvariantReport("run-1", 0, ()),
            destination=tmp_path / "bad-reconciliation",
        )
    with pytest.raises(ExportError, match="valid"):
        exporter.export(
            run_id="run-1",
            reconciliation=ReconciliationReport("run-1", 0, 0, 0, 0, 0, ()),
            invariants=invalid_invariants,
            destination=tmp_path / "bad-invariants",
        )
