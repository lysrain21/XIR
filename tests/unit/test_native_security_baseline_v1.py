from __future__ import annotations

import json
from pathlib import Path

import pytest
from eth_abi.abi import decode

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import PROFILE_HASHES
from xir_lab.native.security_baseline_v1 import (
    CASES,
    ROUTES,
    _write_baseline_manifest,
    b0_carrier_payload,
    build_baseline_plan,
    build_case_route_payload,
    capability_rows,
    load_baseline_config,
    matched_inactive_profile,
    partition_baseline_block,
    rebuild_baseline_publication,
    validate_baseline_plan,
    validate_baseline_publication,
    write_baseline_plan,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "native" / "native-security-baseline-v1.json"


def test_plan_has_300_dynamic_attempts_and_static_rows_are_separate(
    tmp_path: Path,
) -> None:
    config, digest = load_baseline_config(CONFIG)
    assert len(digest) == 64
    plan = build_baseline_plan(CONFIG)
    assert len(plan) == 300
    assert len(capability_rows()) == 7
    assert all("attempt_id" not in row for row in capability_rows())
    for route in ROUTES:
        for case_name in CASES:
            assert (
                sum(
                    item.entry.attempt.route == route and item.case_name == case_name
                    for item in plan
                )
                == 30
            )
    output = tmp_path / "plan.json"
    first = write_baseline_plan(output, plan)
    second = write_baseline_plan(output, plan)
    assert first == second
    assert json.loads(output.read_text(encoding="utf-8"))["attempt_count"] == 300
    assert int(config["repetitions"]) == 30
    assert config["registry_mutation_serial"] is True


def test_plan_is_deterministic_interleaved_and_matched() -> None:
    first = build_baseline_plan(CONFIG)
    second = build_baseline_plan(CONFIG)
    assert first == second
    for repetition in range(30):
        block = [item for item in first if item.repetition == repetition]
        assert {(item.entry.attempt.route, item.case_name) for item in block} == {
            (route, case_name) for route in ROUTES for case_name in CASES
        }
        assert sorted(item.entry.interleave_slot for item in block) == list(range(10))
        ordinary, inactive = partition_baseline_block(block)
        assert len(ordinary) == 8
        assert len(inactive) == 2
        assert all(item.case_name == "inactive_profile_unchecked" for item in inactive)


def test_between_hop_payload_and_route_label_substitutions_are_exact() -> None:
    config, _ = load_baseline_config(CONFIG)
    seed = str(config["fixed_seed"])
    plan = build_baseline_plan(CONFIG)
    payload_case = next(
        item
        for item in plan
        if item.entry.attempt.route == "HL" and item.case_name == "between_hop_payload_substitution"
    )
    original = decode(
        ["(bytes32,bytes2,uint64,bytes)"],
        build_case_route_payload(payload_case, seed=seed),
    )[0]
    mutated = decode(
        ["(bytes32,bytes2,uint64,bytes)"],
        build_case_route_payload(payload_case, seed=seed, mutated_application=True),
    )[0]
    assert original[:3] == mutated[:3]
    assert original[3] != mutated[3]

    route_case = next(
        item
        for item in plan
        if item.entry.attempt.route == "HL" and item.case_name == "route_label_substitution"
    )
    route_original = decode(
        ["(bytes32,bytes2,uint64,bytes)"],
        build_case_route_payload(route_case, seed=seed),
    )[0]
    route_mutated = decode(
        ["(bytes32,bytes2,uint64,bytes)"],
        build_case_route_payload(route_case, seed=seed, substituted_route_label=True),
    )[0]
    assert bytes(route_original[1]) == b"HL"
    assert bytes(route_mutated[1]) == b"LH"
    assert route_original[0] == route_mutated[0]
    assert route_original[2:] == route_mutated[2:]
    layer, inner = decode(["uint8", "bytes"], b0_carrier_payload(bytes(route_mutated[3])))
    assert layer == 0
    assert bytes(inner) == bytes(route_mutated[3])


def test_capability_rows_distinguish_absence_from_dynamic_cases() -> None:
    rows = {str(row["field"]): row for row in capability_rows()}
    for field in (
        "prior_hop_native_message_id",
        "verifier_profile_or_version",
        "registry_version_or_status",
        "ordered_receipt_history",
    ):
        assert rows[field]["expressible"] is False
        assert rows[field]["enforcement_stage"] == "none"
    assert rows["application_route_payload"]["expressible"] is True
    assert rows["first_hop_native_authentication"]["expressible"] is True
    assert rows["first_hop_native_authentication"]["destination_visible"] is False
    assert matched_inactive_profile("HL") == PROFILE_HASHES["H_AB"]
    assert matched_inactive_profile("LH") == PROFILE_HASHES["L_AB"]


def test_validator_rejects_missing_dynamic_cell() -> None:
    plan = list(build_baseline_plan(CONFIG))
    with pytest.raises(LocalTopologyError, match="unbalanced"):
        validate_baseline_plan(plan[:-1], repetitions=30)


def test_publication_manifest_and_secret_scan(tmp_path: Path) -> None:
    (tmp_path / "validation.json").write_text('{"valid": true}\n', encoding="utf-8")
    (tmp_path / "baseline-capability.csv").write_text(
        "field,expressible\nhistory,false\n", encoding="utf-8"
    )
    _write_baseline_manifest(tmp_path)
    assert validate_baseline_publication(tmp_path)["valid"]
    (tmp_path / "leak.raw").write_bytes(b"signed data")
    _write_baseline_manifest(tmp_path)
    result = validate_baseline_publication(tmp_path)
    assert not result["valid"]
    assert "leak.raw" in result["forbidden_publishable_content"]


def test_baseline_offline_publication_rebuilds_are_identical(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    summary = [
        {
            "route": route,
            "case_name": case_name,
            "n": 30,
            "delivered": 30,
            "replay_rejected": 30 if case_name == "new_native_envelope_replay" else 0,
            "outcome_matches": 30,
        }
        for route in ROUTES
        for case_name in CASES
    ]
    validation = {
        "schema_version": "xir-lab-native-security-baseline-v1-validation",
        "valid": True,
        "expected_attempts": 300,
        "reconciled_attempts": 300,
        "case_counts": {f"{route}_{case_name}": 30 for route in ROUTES for case_name in CASES},
        "effect_count": 300,
        "replay_rejection_count": 60,
        "coordinator_retry_count": 0,
        "retry_free_complete_lineage": True,
        "analyzer_transaction_read_retry_count": 0,
        "environment_namespace_valid": True,
        "final_revision_prior_binding_valid": True,
        "final_revision_source_lock_valid": True,
        "onchain_prior_binding_valid": True,
        "errors": [],
    }
    analysis = {
        "schema_version": "xir-lab-native-security-baseline-v1-analysis",
        "namespace": "native-security-baseline-v1",
        "config_sha256": "0" * 64,
        "analysis_source_sha256": "a" * 64,
        "deployment_sha256": "1" * 64,
        "environment_namespace": "native-ablation-v2",
        "base_deployment_sha256": "5" * 64,
        "final_revision_source_sha256": {
            "contracts/src/HyperlaneAdapter.sol": "6" * 64,
            "contracts/src/LayerZeroAdapter.sol": "7" * 64,
            "src/xir_lab/native/deployer.py": "8" * 64,
            "src/xir_lab/native/runner.py": "9" * 64,
        },
        "prior_verifier_bindings": {
            "h_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
            "l_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
        },
        "onchain_prior_verifier_bindings": {
            "h_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
            "l_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
        },
        "runner_state_sha256": "2" * 64,
        "worker_state_sha256": "3" * 64,
        "attempt_count": 300,
        "physical_transaction_count": 2400,
        "capability_rows": capability_rows(),
        "case_summary": summary,
        "validation": validation,
        "semantic_digest": "4" * 64,
    }
    (source / "analysis.json").write_text(json.dumps(analysis, sort_keys=True), encoding="utf-8")
    (source / "validation.json").write_text(
        json.dumps(validation, sort_keys=True), encoding="utf-8"
    )
    for name in (
        "baseline-capability.csv",
        "baseline-results.csv",
        "case-summary.csv",
        "physical-transactions.csv",
    ):
        (source / name).write_text("field\nvalue\n", encoding="utf-8")
    _write_baseline_manifest(source)
    first_root = tmp_path / "rebuild-a"
    second_root = tmp_path / "rebuild-b"
    first_result = rebuild_baseline_publication(source_root=source, output_root=first_root)
    second_result = rebuild_baseline_publication(source_root=source, output_root=second_root)
    assert first_result == second_result
    assert {
        path.relative_to(first_root): path.read_bytes()
        for path in first_root.rglob("*")
        if path.is_file()
    } == {
        path.relative_to(second_root): path.read_bytes()
        for path in second_root.rglob("*")
        if path.is_file()
    }
