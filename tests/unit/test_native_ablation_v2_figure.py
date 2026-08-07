from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.native.ablation_v2_figure import (
    FIGURE_1_SHA256,
    OUTPUT_NAMESPACE,
    AblationV2FigureError,
    build_two_rebuild_publication,
    load_frozen_rows,
)


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    levels = {
        "HL": {
            "complete_gas": (600_000.0, 700_000.0, 900_000.0, 1_020_000.0),
            "complete_calldata": (3_000.0, 4_000.0, 5_500.0, 6_000.0),
            "latency_seconds": (7.0, 8.2, 10.1, 11.4),
        },
        "LH": {
            "complete_gas": (610_000.0, 715_000.0, 920_000.0, 1_040_000.0),
            "complete_calldata": (3_100.0, 4_200.0, 5_700.0, 6_300.0),
            "latency_seconds": (6.5, 8.0, 9.8, 10.0),
        },
    }
    layers = ("B0", "B1", "B2", "B3")
    metrics = ("complete_gas", "complete_calldata", "latency_seconds")
    cell_summary: list[dict[str, Any]] = []
    paired_deltas: list[dict[str, Any]] = []
    for route in ("HL", "LH"):
        for layer_index, layer in enumerate(layers):
            cell_summary.append(
                {
                    "route": route,
                    "layer": layer,
                    "n": 1_000,
                    **{
                        f"{metric}_mean": levels[route][metric][layer_index]
                        for metric in metrics
                    },
                }
            )
        for metric in metrics:
            values = levels[route][metric]
            for index, increment in enumerate(("B0->B1", "B1->B2", "B2->B3")):
                estimate = values[index + 1] - values[index]
                margin = max(abs(estimate) * 0.02, 0.01)
                paired_deltas.append(
                    {
                        "route": route,
                        "increment": increment,
                        "metric": metric,
                        "statistic": "mean",
                        "n_pairs": 1_000,
                        "estimate": estimate,
                        "ci_low": estimate - margin,
                        "ci_high": estimate + margin,
                        "confidence": 0.95,
                        "block_length": 16,
                        "bootstrap_repetitions": 4_000,
                    }
                )

    counts = {
        f"{route}_{layer}": 1_000 for route in ("HL", "LH") for layer in layers
    }
    validation: dict[str, Any] = {
        "schema_version": "xir-lab-native-ablation-v2-validation",
        "valid": True,
        "phase": "scale",
        "expected_attempts": 8_000,
        "reconciled_attempts": 8_000,
        "application_effects": 8_000,
        "cell_counts": counts,
        "mechanism_matrix": {layer: [layer] for layer in layers},
        "mechanism_deltas": {layer: [layer] for layer in layers},
        "mechanism_nesting_valid": True,
        "matched_payload_blocks": 1_000,
        "paired_increment_counts": {
            f"{route}_{increment}": 1_000
            for route in ("HL", "LH")
            for increment in ("B0->B1", "B1->B2", "B2->B3")
        },
        "scale_minimum_satisfied": True,
        "physical_lineage_complete": True,
        "complete_physical_transactions": 62_000,
        "reconciliation_errors": [],
        "b1_exact_wire_checks": 2_000,
        "b1_exact_wire_rebuild_valid": True,
        "b1_layerzero_size_checks": 2_000,
        "b1_layerzero_size_valid": True,
        "coordinator_retry_count": 0,
        "retry_free_complete_lineage": True,
        "analyzer_transaction_read_retry_count": 0,
        "operational_incident_count": 1,
        "operational_incident_logs_valid": True,
        "operational_incident_source_snapshots_valid": True,
        "operational_incidents_recovered": True,
        "incident_latency_sensitivity_required": True,
        "incident_latency_sensitivity_valid": True,
        "incident_latency_sensitivity_included_attempts": 7_992,
        "incident_latency_sensitivity_excluded_attempts": 8,
        "incident_latency_sensitivity_included_blocks": 999,
        "incident_latency_sensitivity_excluded_blocks": 1,
        "incident_latency_sensitivity_cell_counts": {
            key: 999 for key in counts
        },
        "incident_latency_sensitivity_paired_counts": {
            f"{route}_{increment}": 999
            for route in ("HL", "LH")
            for increment in ("B0->B1", "B1->B2", "B2->B3")
        },
        "administrator_prior_binding_required": True,
        "administrator_prior_binding_valid": True,
        "final_revision_source_lock_required": True,
        "final_revision_source_lock_valid": True,
        "onchain_prior_binding_valid": True,
    }
    digest = "1" * 64
    analysis: dict[str, Any] = {
        "schema_version": "xir-lab-native-ablation-v2-analysis",
        "namespace": "native-ablation-v2",
        "result_role": "final_mechanism_cost_estimate",
        "phase": "scale",
        "config_sha256": digest,
        "analysis_source_sha256": digest,
        "operational_incidents_sha256": digest,
        "deployment_sha256": digest,
        "base_deployment_sha256": digest,
        "final_revision_source_sha256": {
            "gateway": digest,
            "hyperlane": digest,
            "layerzero": digest,
            "encoding": digest,
        },
        "prior_verifier_bindings": {"h_xir_out": {}, "l_xir_out": {}},
        "onchain_prior_verifier_bindings": {"h_xir_out": {}, "l_xir_out": {}},
        "runner_state_sha256": digest,
        "layerzero_state_sha256": digest,
        "attempt_count": 8_000,
        "physical_transaction_count": 62_000,
        "cell_summary": cell_summary,
        "paired_deltas": paired_deltas,
        "stage_costs": [{"route": "HL", "stage": "xir_root_record", "n": 1_000}],
        "incident_latency_sensitivity": {"required": True},
        "incident_free_latency_summary": [
            {"route": row["route"], "layer": row["layer"], "n": 999}
            for row in cell_summary
        ],
        "incident_free_latency_deltas": [paired_deltas[0]],
        "validation": validation,
        "semantic_digest": "2" * 64,
    }
    return analysis, validation


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_publication(
    path: Path,
    analysis: dict[str, Any],
    validation: dict[str, Any],
) -> None:
    path.mkdir(parents=True)
    (path / "analysis.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (path / "validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_csv(path / "cell-summary.csv", analysis["cell_summary"])
    _write_csv(path / "paired-deltas.csv", analysis["paired_deltas"])
    files = []
    for name in (
        "analysis.json",
        "validation.json",
        "cell-summary.csv",
        "paired-deltas.csv",
    ):
        item = path / name
        files.append({"path": name, "bytes": item.stat().st_size, "sha256": _sha256(item)})
    manifest = {
        "schema_version": "xir-lab-native-ablation-v2-manifest",
        "namespace": "native-ablation-v2",
        "files": files,
    }
    manifest_path = path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (path / "manifest.sha256").write_text(
        f"{_sha256(manifest_path)}  manifest.json\n", encoding="utf-8"
    )
    (path / "publication-validation.json").write_text(
        json.dumps(
            {
                "valid": True,
                "manifest_mismatches": [],
                "forbidden_publishable_content": [],
                "experiment_validation": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _triplet(tmp_path: Path) -> dict[str, Path]:
    analysis, validation = _fixture_documents()
    paths = {
        "source_publication": tmp_path / "source",
        "rebuild_a_publication": tmp_path / "rebuild-a",
        "rebuild_b_publication": tmp_path / "rebuild-b",
    }
    for path in paths.values():
        _write_publication(path, analysis, validation)
    return paths


def test_v2_input_contract_selects_exact_primary_rows(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    rows, provenance = load_frozen_rows(repository_root=_repository(), **paths)
    assert len(rows) == 24
    assert {(row["route"], row["layer"]) for row in rows} == {
        (route, layer)
        for route in ("HL", "LH")
        for layer in ("B0", "B1", "B2", "B3")
    }
    assert len([row for row in rows if row["confidence"] == 0.95]) == 18
    assert all(
        row["interval_scope"] == "one_adjacent_paired_increment_only"
        for row in rows
        if row["layer"] != "B0"
    )
    assert provenance["statistics_recomputed"] is False
    assert provenance["figure_1_sha256"] == FIGURE_1_SHA256


def test_v1_namespace_is_a_hard_failure_before_publication(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    analysis_path = paths["source_publication"] / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["namespace"] = "native-ablation-v1"
    analysis["result_role"] = "revision_evidence_only"
    analysis_path.write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    output = tmp_path / "must-not-exist"
    with pytest.raises(AblationV2FigureError, match="refusing non-final ablation namespace"):
        build_two_rebuild_publication(
            repository_root=_repository(), output_root=output, **paths
        )
    assert not output.exists()


def test_rebuild_manifest_or_source_drift_fails_closed(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    with (paths["rebuild_b_publication"] / "cell-summary.csv").open(
        "a", encoding="utf-8"
    ) as stream:
        stream.write("tampered\n")
    with pytest.raises(AblationV2FigureError, match="size mismatch"):
        load_frozen_rows(repository_root=_repository(), **paths)


def test_main_figure_is_native_size_self_contained_and_byte_deterministic(
    tmp_path: Path,
) -> None:
    paths = _triplet(tmp_path)
    result = build_two_rebuild_publication(
        repository_root=_repository(),
        output_root=tmp_path / "figure",
        **paths,
    )
    publication = Path(result["publication"])
    assert result["namespace"] == OUTPUT_NAMESPACE
    assert result["valid"] is True
    for name in (
        "mechanism-cost-v2.pdf",
        "mechanism-cost-v2.svg",
        "mechanism-cost-v2-source.csv",
        "mechanism-cost-v2-source.json",
        "visual-audit.json",
        "validation.json",
        "rebuild-comparison.json",
        "manifest.json",
    ):
        assert (publication / name).is_file()

    visual = json.loads((publication / "visual-audit.json").read_text(encoding="utf-8"))
    validation = json.loads((publication / "validation.json").read_text(encoding="utf-8"))
    source = json.loads(
        (publication / "mechanism-cost-v2-source.json").read_text(encoding="utf-8")
    )
    comparison = json.loads(
        (publication / "rebuild-comparison.json").read_text(encoding="utf-8")
    )
    assert visual["native_width_mm"] == 131.6
    assert visual["native_height_mm"] <= 62.0
    assert visual["minimum_native_font_points"] >= 7.1
    assert len(visual["font_roles"]) <= 3
    assert len(visual["line_styles"]) <= 3
    assert len(visual["palette"]) == 3
    assert abs(visual["nominal_content_region_occupancy"] - 0.618) <= 0.015
    assert visual["pdf"]["all_fonts_embedded"] is True
    assert visual["pdf"]["all_fonts_truetype_type42"] is True
    assert all(visual["svg"].values())
    assert validation["valid"] is True
    assert validation["checks"]["all_18_paired_intervals_present"] is True
    assert validation["checks"]["paired_intervals_not_aggregated"] is True
    assert source["interval_semantics"]["cross_layer_aggregation"] == "forbidden"
    assert source["interval_semantics"]["complete_route_interval_claimed"] is False
    assert len(source["rows"]) == 24
    assert comparison["valid"] is True
    assert (tmp_path / "figure/rebuild-a/mechanism-cost-v2.pdf").read_bytes() == (
        tmp_path / "figure/rebuild-b/mechanism-cost-v2.pdf"
    ).read_bytes()
