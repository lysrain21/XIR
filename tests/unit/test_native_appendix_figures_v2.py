from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from xir_lab.native.appendix_figures_v2 import (
    COST_NAMESPACE,
    LATENCY_NAMESPACE,
    AppendixFigureError,
    build_two_rebuild_publication,
    load_cost_rows,
    load_latency_rows,
    validate_latency_rows,
)


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def test_latency_rows_preserve_exact_full_and_clean_intervals() -> None:
    rows, provenance = load_latency_rows(_repository())
    assert len(rows) == 24
    assert {row["metric"] for row in rows} == {"median", "p95", "p99"}
    assert {row["sample_id"] for row in rows} == {"full", "clean-prefix"}
    full_lh_p99 = next(
        row
        for row in rows
        if (row["sample_id"], row["route"], row["metric"]) == ("full", "LH", "p99")
    )
    assert full_lh_p99["ci_upper_seconds"] == 42.920713901519775
    assert provenance["frozen_inputs"]["source_csv"]["sha256"].startswith("42d1d013")


def test_latency_row_validation_rejects_changed_interval() -> None:
    rows, _ = load_latency_rows(_repository())
    altered = copy.deepcopy(rows)
    target = next(
        row
        for row in altered
        if (row["sample_id"], row["route"], row["metric"]) == ("full", "LH", "p99")
    )
    target["ci_upper_seconds"] = 42.0
    with pytest.raises(AppendixFigureError, match="longest frozen latency interval changed"):
        validate_latency_rows(altered)


def test_cost_rows_preserve_route_totals_stages_and_boundaries() -> None:
    route_rows, stage_rows, provenance = load_cost_rows(_repository())
    assert len(route_rows) == 4
    assert len(stage_rows) == 4
    by_route = {row["route"]: row for row in route_rows}
    assert by_route["HL"]["coordinator_transactions_total"] == 50_000
    assert by_route["LH"]["coordinator_gas_total"] == 7_287_656_584
    assert by_route["LH"]["coordinator_calldata_bytes_per_attempt"] == 5_636.0
    by_stage = {(row["stage"], row["route"]): row for row in stage_rows}
    assert by_stage[("xir_transition", "LH")]["gas_mean"] == 136_555.5876
    assert "not additive" in provenance["boundaries"]["non_additivity"]
    assert "protocol-agent" in provenance["boundaries"]["excluded_from_route_totals"]


def test_compact_latency_publication_is_native_width_and_byte_identical(
    tmp_path: Path,
) -> None:
    result = build_two_rebuild_publication(
        repository_root=_repository(), output_root=tmp_path / "latency", kind="latency"
    )
    publication = Path(result["publication"])
    audit = json.loads((publication / "visual-audit.json").read_text(encoding="utf-8"))
    rebuild = json.loads(
        (publication / "rebuild-comparison.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((publication / "manifest.json").read_text(encoding="utf-8"))
    assert result["namespace"] == LATENCY_NAMESPACE
    assert audit["native_width_mm"] == 131.6
    assert audit["native_height_mm"] == 52.0
    assert audit["panels"] == ["Median", "P95", "P99"]
    assert audit["minimum_key_font_points"] >= 7.0
    assert rebuild["valid"] is True
    assert len(rebuild["byte_identical_files"]) == 7
    assert manifest["inputs"]["sensitivity_summary"]["sha256"].startswith("5e9d0189")
    assert manifest["preserved_assets"]["figure_1"]["sha256"].startswith("2fa2864e")
    assert (publication / "latency-comparison-compact-v2.pdf").is_file()
    assert (publication / "latency-comparison-compact-v2.svg").is_file()


def test_run003_cost_publication_preserves_scope_and_is_byte_identical(
    tmp_path: Path,
) -> None:
    result = build_two_rebuild_publication(
        repository_root=_repository(), output_root=tmp_path / "cost", kind="cost"
    )
    publication = Path(result["publication"])
    source = json.loads(
        (publication / "run-003-coordinator-cost-v2-source.json").read_text(encoding="utf-8")
    )
    audit = json.loads((publication / "visual-audit.json").read_text(encoding="utf-8"))
    validation = json.loads((publication / "validation.json").read_text(encoding="utf-8"))
    manifest = json.loads((publication / "manifest.json").read_text(encoding="utf-8"))
    assert result["namespace"] == COST_NAMESPACE
    assert audit["native_width_mm"] == 131.6
    assert audit["native_height_mm"] == 76.0
    assert audit["pdf"]["all_fonts_embedded"] is True
    assert audit["pdf"]["type_3_fonts"] is False
    assert source["provenance"]["boundaries"]["historical_scope"] == (
        "accepted run-003 scale phase"
    )
    assert validation["checks"]["stage_non_additivity_boundary"] is True
    assert validation["checks"]["agent_worker_exclusion_boundary"] is True
    assert manifest["scope_boundaries"]["causal_limit"] == "no causal mechanism isolation"
    assert (publication / "run-003-coordinator-cost-v2.pdf").is_file()
    assert (publication / "run-003-coordinator-cost-v2.svg").is_file()
