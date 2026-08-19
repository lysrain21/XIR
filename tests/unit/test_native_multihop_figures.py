from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import matplotlib.pyplot as plt
import pytest
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_analysis import summarize_attempt_metrics
from xir_lab.native.multihop_figures import (
    _audit_figure_geometry_palette,
    build_figure8_family,
    compare_figure8_publications,
    validate_figure8_cell_summary,
)
from xir_lab.native.multihop_scalability import (
    ROUTE_ORDER,
    expected_coordinator_transactions,
    expected_physical_transactions,
    switch_count,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/native/native-multihop-switching-v1.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_visual_admission_rejects_out_of_bounds_text_and_wrong_palette() -> None:
    figure, axis = plt.subplots()
    axis.text(2.0, 2.0, "outside", color="#ff00ff", transform=axis.transAxes)
    audit = _audit_figure_geometry_palette(figure)
    plt.close(figure)
    assert audit["valid"] is False
    assert any("text-out-of-page" in error for error in audit["errors"])
    assert "palette-role-unregistered:#ff00ff" in audit["errors"]


def test_visual_admission_rejects_semantic_color_swap_and_small_text_overlap() -> None:
    figure, axis = plt.subplots()
    line = axis.plot([0, 1], [0, 1], color="#D98B2B")[0]
    line._xir_semantic_role = "xir-switching"
    axis.text(0.5, 0.5, "alpha", fontsize=7.1)
    axis.text(0.5, 0.5, "beta", fontsize=7.1)
    audit = _audit_figure_geometry_palette(figure)
    plt.close(figure)
    assert audit["valid"] is False
    assert any("semantic-role-color-mismatch:xir-switching" in error for error in audit["errors"])
    assert any("text-overlap:alpha|beta" in error for error in audit["errors"])


def test_visual_admission_rejects_missing_and_unregistered_semantic_roles() -> None:
    figure, axis = plt.subplots()
    axis.plot([0, 1], [0, 1], color="#2563A6")
    audit = _audit_figure_geometry_palette(
        figure, expected_semantic_role_counts={"xir-switching": 1}
    )
    plt.close(figure)
    assert audit["valid"] is False
    assert any("semantic-color-artist-unregistered" in error for error in audit["errors"])
    assert any("semantic-role-inventory-mismatch" in error for error in audit["errors"])


def _analysis() -> dict[str, object]:
    cells = []
    for route in ROUTE_ORDER:
        for metric, value in (
            ("gas", 100_000 + 20_000 * len(route) + 7_000 * switch_count(route)),
            ("calldata_bytes", 100 + 40 * len(route) + 8 * switch_count(route)),
            ("latency_seconds", 1.0 + 0.2 * len(route) + 0.05 * switch_count(route)),
        ):
            roles = (
                (
                    "primary_all_finite_clock_attempts_including_incidents",
                    "interruption_free_complete_blocks_sensitivity",
                )
                if metric == "latency_seconds"
                else ("primary_all_validated_effects",)
            )
            for role in roles:
                cells.append(
                    {
                        "route": route,
                        "metric": metric,
                        "sample_role": role,
                        "n": 10_000,
                        "mean": value,
                        "median": value,
                        "p95": value,
                        "p99": value,
                    }
                )
    equivalence = [
        {
            "metric": metric,
            "estimand": (
                "direct_transition_transaction_plus_approved_prior_verifier_"
                "call_slope_per_prefix_receipt"
            ),
            "source_metric": {
                "latency_seconds": "core_switch_latency_seconds",
                "gas": "core_switch_gas",
                "calldata_bytes": "core_switch_calldata_bytes",
            }[metric],
            "estimate": 0.1 * bound,
            "ci_low": -0.2 * bound,
            "ci_high": 0.3 * bound,
            "lower_bound": -bound,
            "upper_bound": bound,
            "equivalent": True,
            "tost_pass": True,
            "n": 30_000,
            "matched_sequence_count": 10_000,
            "sample_role": (
                "primary_all_finite_clock_blocks_including_incidents"
                if metric == "latency_seconds"
                else "primary_all_validated_effects"
            ),
        }
        for metric, bound in (
            ("latency_seconds", 0.5),
            ("gas", 15_000.0),
            ("calldata_bytes", 64.0),
        )
    ]
    transactions = [
        {
            "route": route,
            "observed_physical_transactions_per_attempt": expected_physical_transactions(route),
            "theoretical_physical_transactions_per_attempt": expected_physical_transactions(route),
        }
        for route in ROUTE_ORDER
    ]
    stages = []
    for route in ROUTE_ORDER:
        names = ["root_create_mined", "root_certificate_ready"]
        for hop, protocol in enumerate(route, start=1):
            names.append(f"hop_{hop}_{protocol.lower()}_transport_and_ingress")
            if hop < len(route) and route[hop - 1] != route[hop]:
                names.append(f"hop_{hop + 1}_xir_transition")
        names.extend(["destination_verify_deliver", "destination_effect_observation"])
        for order, name in enumerate(names):
            stages.append(
                {
                    "route": route,
                    "stage": name,
                    "stage_order": order,
                    "latency_median_seconds": 0.1 + order * 0.02,
                    "latency_ci_low": 0.09 + order * 0.02,
                    "latency_ci_high": 0.11 + order * 0.02,
                    "gas_mean": 20_000 + order * 100,
                    "calldata_mean_bytes": 100 + order,
                    "boundary_start": f"{name}:start",
                    "boundary_end": f"{name}:end",
                    "timing_kind": "host_monotonic_transaction_interval",
                    "stage_level": "route_boundary",
                    "n": 10_000,
                    "approved_verifier_work_in_this_transaction": (
                        False if "xir_transition" in name else None
                    ),
                }
            )
        for hop in range(1, len(route)):
            if route[hop - 1] == route[hop]:
                continue
            stage = f"hop_{hop + 1}_switch_outbound_dispatch_with_approved_prior_verification"
            stages.append(
                {
                    "route": route,
                    "stage": stage,
                    "stage_order": hop + 2,
                    "stage_level": "component_diagnostic_non_additive",
                    "n": 10_000,
                    "latency_median_seconds": 0.13,
                    "latency_ci_low": 0.12,
                    "latency_ci_high": 0.14,
                    "gas_mean": 31_000,
                    "calldata_mean_bytes": 128,
                    "boundary_start": f"hop_{hop + 1}_{route[hop].lower()}_dispatch:intended",
                    "boundary_end": f"hop_{hop + 1}_{route[hop].lower()}_dispatch:succeeded",
                    "timing_kind": "host_monotonic_same_dispatch_inclusive_non_additive",
                    "latency_interval_is_non_additive": True,
                    "approved_prior_verifier_executes_inside_this_dispatch": True,
                    "gas_is_inclusive_non_additive_with_hop_transport": True,
                    "latency_is_inclusive_non_additive_with_hop_transport": True,
                }
            )
    for component_order, name in enumerate(
        (
            "layerzero_dvn_execute_mined",
            "layerzero_commit_verification_mined",
            "layerzero_executor_execute_mined",
        )
    ):
        stages.append(
            {
                "route": "LHLH",
                "stage": name,
                "stage_order": 3,
                "component_order": component_order,
                "stage_level": "component_diagnostic",
                "n": 10_000,
                "latency_median_seconds": 0.21 + component_order * 0.04,
                "latency_ci_low": 0.20 + component_order * 0.04,
                "latency_ci_high": 0.22 + component_order * 0.04,
                "gas_mean": 31_000 + component_order * 2_000,
                "calldata_mean_bytes": 128 + component_order * 16,
                "boundary_start": f"{name}:submitted",
                "boundary_end": f"{name}:mined",
                "timing_kind": "worker_monotonic_transaction_interval_non_additive",
                "latency_interval_is_non_additive": True,
            }
        )
    return {
        "schema_version": "xir-lab-native-multihop-analysis-v1",
        "namespace": "native-multihop-switching-v1",
        "phase": "scale",
        "attempt_count": 110_000,
        "cell_summary": cells,
        "equivalence": equivalence,
        "models": [
            {
                "metric": "gas",
                "sample_role": "primary_all_validated_effects",
                "linear": {
                    "n": 80_000,
                    "r_squared": 0.999,
                    "coefficients": {
                        "intercept": 100_000.0,
                        "hop_count": 20_000.0,
                        "switch_count": 7_000.0,
                        "starts_with_l": 500.0,
                    },
                },
                "switch_marginal": {
                    "estimate": 7_000.0,
                    "ci_low": 6_900.0,
                    "ci_high": 7_100.0,
                },
                "quadratic_diagnostic": {"r_squared": 0.999},
                "superlinear_anomaly": False,
            }
        ],
        "transaction_summary": transactions,
        "stage_summary": stages,
    }


def _producer_rows(n: int = 12) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for sequence in range(n):
        for route in ROUTE_ORDER:
            hops = len(route)
            switches = switch_count(route)
            direction = int(route.startswith("L"))
            rows.append(
                {
                    "route": route,
                    "sequence": sequence,
                    "hop_count": hops,
                    "switch_count": switches,
                    "starts_with_l": direction,
                    "coordinator_transactions": expected_coordinator_transactions(route),
                    "physical_transactions": expected_physical_transactions(route),
                    "gas": 100_000 + 20_000 * hops + 7_000 * switches + 500 * direction,
                    "calldata_bytes": 100 + 50 * hops + 8 * switches + direction,
                    "latency_seconds": 1.0 + 0.2 * hops + 0.05 * switches,
                    "switch_stage_gas": 40_000 + 100 * max(hops - 2, 0),
                    "switch_stage_calldata_bytes": 400 + max(hops - 2, 0),
                    "switch_stage_latency_seconds": 0.4 + 0.01 * max(hops - 2, 0),
                    "core_switch_gas": 35_000 + 100 * max(hops - 2, 0),
                    "core_switch_calldata_bytes": 320 + max(hops - 2, 0),
                    "core_switch_latency_seconds": 0.3 + 0.01 * max(hops - 2, 0),
                    "prefix_receipt_count": hops - 1,
                    "encoded_envelope_bytes": 1_000 + 256 * hops,
                    "final_delivery_calldata_bytes": 2_000 + 256 * hops,
                    "theoretical_last_receipt_envelope_byte_increment": 256,
                    "final_gateway_exclusive_residual_gas": 20_000 + 50 * hops,
                    "final_registry_and_verifier_subcall_gas": 10_000 + 25 * hops,
                    "final_receiver_subcall_gas": 5_000,
                    "final_other_direct_subcall_gas": 1_000,
                    "final_trace_execution_gas": 50_000 + 100 * hops,
                }
            )
    return rows


def test_analysis_producer_matches_figure8_cell_admission_contract() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["attempts_per_route"]["scale"] = 12
    config["bootstrap"]["repetitions"] = 20
    analysis = summarize_attempt_metrics(_producer_rows(), config=config)
    validate_figure8_cell_summary(analysis)
    assert len(analysis["cell_summary"]) == 44


def _gateway() -> dict[str, object]:
    curves = []
    for protocol in ("hyperlane", "layerzero", "wormhole", "ccip", "axelar", "relay"):
        for scenario, offset in (
            ("optimistic", 0.02),
            ("central", 0.0),
            ("conservative", -0.02),
        ):
            for added in range(3):
                curves.append(
                    {
                        "protocol": protocol,
                        "scenario": scenario,
                        "added_nodes": added,
                        "reachability_rate": 0.1 + added * 0.05 + offset,
                    }
                )
    return {
        "schema_version": "xir-lab-gateway-deployment-analysis-v1",
        "claim_boundary": "structural_upper_bound_not_observed_xir_delivery",
        "frozen": {
            "node_count": 286,
            "ordered_pair_denominator": 81_510,
            "homogeneous_pairs": 46_187,
            "all_compatible_rate": 0.9686296159980371,
        },
        "gateway_placement": {
            "terminal_k": 1,
            "rounds": [
                {
                    "step": 0,
                    "selected_node": None,
                    "reachable_pairs": 46_187,
                    "reachability_rate": 46_187 / 81_510,
                },
                {
                    "step": 1,
                    "selected_node": "xir:mainnet-arbitrum",
                    "reachable_pairs": 78_953,
                    "reachability_rate": 78_953 / 81_510,
                },
            ],
        },
        "protocol_expansion": curves,
    }


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.iterdir())
        if path.is_file()
    }


def _comparison(path: Path, *, schema_version: str, input_path: Path) -> Path:
    _write_json(
        path,
        {
            "schema_version": schema_version,
            "valid": True,
            "byte_identical_files": {
                input_path.name: hashlib.sha256(input_path.read_bytes()).hexdigest()
            },
        },
    )
    return path


def _frozen_input(
    root: Path,
    *,
    name: str,
    document: object,
    validation_schema: str,
    manifest_schema: str,
) -> Path:
    root.mkdir(parents=True)
    input_path = root / name
    validation_path = root / "validation.json"
    manifest_path = root / "manifest.json"
    _write_json(input_path, document)
    _write_json(
        validation_path,
        {"schema_version": validation_schema, "valid": True},
    )
    manifest = {
        "schema_version": manifest_schema,
        "files": [
            {"path": name, "sha256": hashlib.sha256(input_path.read_bytes()).hexdigest()},
            {
                "path": "validation.json",
                "sha256": hashlib.sha256(validation_path.read_bytes()).hexdigest(),
            },
        ],
    }
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write_json(manifest_path, manifest)
    return input_path


def _comparisons(root: Path, analysis_path: Path, gateway_path: Path) -> tuple[Path, Path]:
    return (
        _comparison(
            root / "multihop-comparison.json",
            schema_version="xir-lab-native-multihop-rebuild-comparison-v1",
            input_path=analysis_path,
        ),
        _comparison(
            root / "gateway-comparison.json",
            schema_version="xir-lab-gateway-deployment-rebuild-comparison-v1",
            input_path=gateway_path,
        ),
    )


def test_figure8_family_is_byte_identical_and_vector_only(tmp_path: Path) -> None:
    analysis = _analysis()
    equivalence = analysis["equivalence"]
    assert isinstance(equivalence, list)
    equivalence.reverse()  # Rendering must bind labels by metric, not row order.
    analysis_path = _frozen_input(
        tmp_path / "analysis-source",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(tmp_path, analysis_path, gateway_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_figure8_family(
        analysis_path=analysis_path,
        gateway_path=gateway_path,
        multihop_comparison_path=multihop_comparison,
        gateway_comparison_path=gateway_comparison,
        output_root=first,
    )
    build_figure8_family(
        analysis_path=analysis_path,
        gateway_path=gateway_path,
        multihop_comparison_path=multihop_comparison,
        gateway_comparison_path=gateway_comparison,
        output_root=second,
    )
    assert _file_hashes(first) == _file_hashes(second)
    comparison = compare_figure8_publications(
        first=first,
        second=second,
        output_path=tmp_path / "comparison.json",
    )
    assert comparison["valid"] is True
    validation = json.loads((first / "visual-validation.json").read_text(encoding="utf-8"))
    assert validation["valid"] is True
    assert validation["minimum_font_pt"] >= 7.1
    assert validation["vector_only"] is True
    assert len(list(first.glob("*.pdf"))) == 3
    assert len(list(first.glob("*.svg"))) == 3
    assert (first / "CAPTION_SUGGESTIONS.md").is_file()
    assert validation["source_row_count"] > 0
    source = json.loads((first / "figure8-source.json").read_text(encoding="utf-8"))
    assert [(row["label"], row["metric"]) for row in source if row.get("panel") == "d"] == [
        ("Latency", "latency_seconds"),
        ("Gas", "gas"),
        ("Calldata", "calldata_bytes"),
    ]


def test_formal_figure8_rejects_pilot_analysis(tmp_path: Path) -> None:
    analysis = _analysis()
    analysis["namespace"] = "native-multihop-switching-pilot-v1"
    analysis["attempt_count"] = 1_100
    analysis["result_role"] = "pilot_diagnostic_only"
    analysis["claim_eligible"] = False
    analysis_path = _frozen_input(
        tmp_path / "pilot-analysis",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(
        tmp_path, analysis_path, gateway_path
    )
    with pytest.raises(LocalTopologyError, match="non-final multihop analysis"):
        build_figure8_family(
            analysis_path=analysis_path,
            gateway_path=gateway_path,
            multihop_comparison_path=multihop_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "output",
        )


def test_figure8_rejects_theoretical_fallback(tmp_path: Path) -> None:
    analysis = _analysis()
    analysis.pop("transaction_summary")
    analysis_path = _frozen_input(
        tmp_path / "analysis-source",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(tmp_path, analysis_path, gateway_path)
    with pytest.raises(LocalTopologyError, match="observed transaction summaries"):
        build_figure8_family(
            analysis_path=analysis_path,
            gateway_path=gateway_path,
            multihop_comparison_path=multihop_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "output",
        )


def test_figure8_rejects_missing_boundaries_and_additive_component_latency(
    tmp_path: Path,
) -> None:
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    analysis = _analysis()
    stage_rows = analysis["stage_summary"]
    assert isinstance(stage_rows, list)
    stage_rows[0].pop("boundary_start")
    missing_path = _frozen_input(
        tmp_path / "missing-source",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    missing_comparison, gateway_comparison = _comparisons(tmp_path, missing_path, gateway_path)
    with pytest.raises(LocalTopologyError, match="boundary or interval"):
        build_figure8_family(
            analysis_path=missing_path,
            gateway_path=gateway_path,
            multihop_comparison_path=missing_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "missing-output",
        )

    analysis = _analysis()
    component = next(
        row
        for row in analysis["stage_summary"]  # type: ignore[union-attr]
        if row.get("stage_level") == "component_diagnostic"
    )
    component["latency_interval_is_non_additive"] = False
    fabricated_path = _frozen_input(
        tmp_path / "fabricated-source",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    fabricated_comparison, gateway_comparison = _comparisons(
        tmp_path, fabricated_path, gateway_path
    )
    with pytest.raises(LocalTopologyError, match="fabricate additive latency"):
        build_figure8_family(
            analysis_path=fabricated_path,
            gateway_path=gateway_path,
            multihop_comparison_path=fabricated_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "fabricated-output",
        )


def test_figure8_rejects_rebuild_comparison_drift(tmp_path: Path) -> None:
    analysis_path = _frozen_input(
        tmp_path / "analysis-source",
        name="analysis.json",
        document=_analysis(),
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(tmp_path, analysis_path, gateway_path)
    analysis_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="byte-identical rebuilds"):
        build_figure8_family(
            analysis_path=analysis_path,
            gateway_path=gateway_path,
            multihop_comparison_path=multihop_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "output",
        )


def test_figure8_labels_failed_tost_as_not_established(tmp_path: Path) -> None:
    analysis = _analysis()
    latency = next(
        row
        for row in analysis["equivalence"]  # type: ignore[union-attr]
        if row["metric"] == "latency_seconds"
    )
    latency["ci_high"] = 0.6
    latency["equivalent"] = False
    latency["tost_pass"] = False
    analysis_path = _frozen_input(
        tmp_path / "analysis-source",
        name="analysis.json",
        document=analysis,
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(tmp_path, analysis_path, gateway_path)
    output = tmp_path / "output"
    build_figure8_family(
        analysis_path=analysis_path,
        gateway_path=gateway_path,
        multihop_comparison_path=multihop_comparison,
        gateway_comparison_path=gateway_comparison,
        output_root=output,
    )
    extracted = subprocess.run(
        ["pdftotext", str(output / "figure8-multihop-main.pdf"), "-"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "not established" in extracted
    assert "path-length-independent switching" not in extracted


def test_figure8_rejects_manifest_drift_before_rendering(tmp_path: Path) -> None:
    analysis_path = _frozen_input(
        tmp_path / "analysis-source",
        name="analysis.json",
        document=_analysis(),
        validation_schema="xir-lab-native-multihop-analysis-validation-v1",
        manifest_schema="xir-lab-native-multihop-analysis-manifest-v1",
    )
    gateway_path = _frozen_input(
        tmp_path / "gateway-source",
        name="gateway-analysis.json",
        document=_gateway(),
        validation_schema="xir-lab-gateway-deployment-validation-v1",
        manifest_schema="xir-lab-gateway-deployment-manifest-v1",
    )
    multihop_comparison, gateway_comparison = _comparisons(tmp_path, analysis_path, gateway_path)
    validation = analysis_path.parent / "validation.json"
    validation.write_text("{}\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="manifest/validation drift"):
        build_figure8_family(
            analysis_path=analysis_path,
            gateway_path=gateway_path,
            multihop_comparison_path=multihop_comparison,
            gateway_comparison_path=gateway_comparison,
            output_root=tmp_path / "output",
        )
    assert not (tmp_path / "output").exists()
