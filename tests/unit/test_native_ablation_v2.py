from __future__ import annotations

import json
from pathlib import Path

from xir_lab.native.ablation_v1 import (
    ROUTES,
    _write_manifest,
    ablation_route_id,
    build_ablation_plan,
    final_revision_bindings_valid,
    load_ablation_config,
    load_operational_incident_document,
    write_plan,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_V1 = ROOT / "configs" / "native" / "native-ablation-v1.json"
CONFIG_V2 = ROOT / "configs" / "native" / "native-ablation-v2.json"


def test_v2_plan_has_versioned_namespace_and_disjoint_identifiers(tmp_path: Path) -> None:
    v1 = build_ablation_plan(config_path=CONFIG_V1, phase="smoke")
    v2 = build_ablation_plan(config_path=CONFIG_V2, phase="smoke")
    assert len(v2) == 16
    assert all(item.attempt.attempt_id.startswith("ablv2_") for item in v2)
    assert all(item.attempt.execution_class == "native_ablation_v2" for item in v2)
    assert {item.attempt.attempt_id for item in v1}.isdisjoint(
        item.attempt.attempt_id for item in v2
    )
    output = tmp_path / "plan.json"
    first = write_plan(output, v2, namespace="native-ablation-v2")
    second = write_plan(output, v2, namespace="native-ablation-v2")
    document = json.loads(output.read_text(encoding="utf-8"))
    assert first == second
    assert document["schema_version"] == "xir-lab-native-ablation-v2-plan"
    assert document["namespace"] == "native-ablation-v2"
    assert set(document["cells"].values()) == {2}


def test_v2_route_ids_do_not_reuse_v1_state() -> None:
    for route in ROUTES:
        for layer in ("B0", "B1"):
            assert ablation_route_id(route, layer, version=1) != ablation_route_id(
                route, layer, version=2
            )


def test_v2_manifest_uses_versioned_schema(tmp_path: Path) -> None:
    (tmp_path / "analysis.json").write_text("{}\n", encoding="utf-8")
    _write_manifest(tmp_path, namespace="native-ablation-v2")
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "xir-lab-native-ablation-v2-manifest"
    assert manifest["namespace"] == "native-ablation-v2"


def test_v2_config_is_frozen_at_eight_thousand_attempts() -> None:
    config, digest = load_ablation_config(CONFIG_V2)
    assert config["scale_attempts_per_cell"] == 1000
    assert config["concurrency"] == 16
    assert len(digest) == 64
    plan = build_ablation_plan(config_path=CONFIG_V2, phase="scale")
    assert len(plan) == 8000
    assert len({item.pair_id for item in plan}) == 1000


def test_final_revision_binding_gate_matches_both_outbound_adapters() -> None:
    deployment = {
        "chains": {"intermediate": {"h_in": "0xAA", "l_in": "0xBB"}},
        "prior_verifier_bindings": {
            "h_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
            "l_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
        },
    }
    assert final_revision_bindings_valid(deployment)
    deployment["prior_verifier_bindings"]["l_xir_out"]["H_AB"] = "0xcc"
    assert not final_revision_bindings_valid(deployment)


def test_v2_operational_incident_document_uses_versioned_schema(tmp_path: Path) -> None:
    incident_path = tmp_path / "operational-incidents.json"
    incident_path.write_text(
        json.dumps(
            {
                "schema_version": "xir-lab-native-ablation-v2-operational-incidents",
                "namespace": "native-ablation-v2",
                "incidents": [
                    {
                        "incident_id": "scale-rpc-receipt-001",
                        "phase": "scale",
                        "observed_at_utc": "2026-08-07T12:00:00Z",
                        "runner_pid": 1,
                        "resume_pid": 2,
                        "completed_attempts_before_exit": 4525,
                        "affected_attempt_id": "ablv2_example",
                        "route": "HL",
                        "layer": "B3",
                        "route_sequence": 564,
                        "operation": "destination receipt polling",
                        "exception_class": "ConnectionError",
                        "exception_code": -1,
                        "exception_message": "remote disconnected",
                        "read_only_rpc_failure": True,
                        "native_hops_committed": 2,
                        "destination_effect_observed_before_resume": True,
                        "committed_stage_summary": ["both native hops committed"],
                        "recovery": "same durable state and signed transaction",
                        "polling_change": "none",
                        "treatment_changed": False,
                        "status": "recovered",
                        "attempt_in_final_denominator": True,
                        "runner_log_relative_path": "runs/scale/incidents/traceback.log",
                        "runner_log_sha256": "0" * 64,
                        "pre_resume_audit_relative_path": "runs/scale/incidents/pre.json",
                        "pre_resume_audit_sha256": "1" * 64,
                        "post_resume_audit_relative_path": "runs/scale/incidents/post.json",
                        "post_resume_audit_sha256": "2" * 64,
                    }
                ],
                "latency_sensitivity": {
                    "phase": "scale",
                    "rule_id": "exclude-complete-incident-route-sequence-blocks-v1",
                    "selection_unit": "deterministic_interleave_block",
                    "excluded_route_sequences": [564],
                    "exclusion_reason": "process interruption overlapped the block",
                    "full_matched_blocks": 1000,
                    "expected_included_blocks": 999,
                    "expected_excluded_blocks": 1,
                    "expected_included_attempts": 7992,
                    "expected_excluded_attempts": 8,
                    "expected_included_per_cell": 999,
                    "ordering": "ascending route_sequence",
                    "interval_method": "paired moving-block bootstrap",
                },
            }
        ),
        encoding="utf-8",
    )
    incidents, sensitivity = load_operational_incident_document(
        incident_path, phase="scale"
    )
    assert [item["incident_id"] for item in incidents] == ["scale-rpc-receipt-001"]
    assert sensitivity is not None
    assert sensitivity["expected_included_attempts"] == 7992
