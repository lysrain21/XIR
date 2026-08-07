from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from xir_lab.native.faults_handoff_v1 import REQUIRED_CASE_CHECKS
from xir_lab.native.faults_recovery_figure_v2 import (
    FIGURE_1_SHA256,
    OUTPUT_NAMESPACE,
    FaultsRecoveryFigureError,
    build_two_rebuild_publication,
    load_final_recovery_source,
)
from xir_lab.native.faults_v1 import FINAL_REVISION_SOURCE_SHA256


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _deployment() -> dict[str, Any]:
    return {
        "schema_version": "xir-lab-native-application-deployment-v1",
        "deployer": "0x" + "01" * 20,
        "runner": "0x" + "02" * 20,
        "root_signer": "0x" + "03" * 20,
        "chains": {
            "intermediate": {
                "h_in": "0x" + "11" * 20,
                "l_in": "0x" + "12" * 20,
            }
        },
        "prior_verifier_bindings": {
            outbound: {
                "H_AB": "0x" + "11" * 20,
                "L_AB": "0x" + "12" * 20,
            }
            for outbound in ("h_xir_out", "l_xir_out")
        },
    }


def _scenarios() -> tuple[tuple[str, str, str], ...]:
    return (
        ("pre_intent", "coordinator", "pre_intent"),
        ("post_intent_pre_sign", "coordinator", "post_intent_pre_sign"),
        ("post_sign_pre_broadcast", "coordinator", "post_sign_pre_broadcast"),
        (
            "post_broadcast_pre_acknowledgement",
            "coordinator",
            "post_broadcast_pre_acknowledgement",
        ),
        (
            "post_acknowledgement_pre_mining",
            "coordinator",
            "post_acknowledgement_pre_mining",
        ),
        ("post_mining_pre_persistence", "coordinator", "post_mining_pre_persistence"),
        (
            "post_persistence_pre_stage_commit",
            "coordinator",
            "post_persistence_pre_stage_commit",
        ),
        ("worker_action_post_submit", "worker", "worker_action_post_submit"),
        (
            "transient_retry_after_broadcast",
            "coordinator",
            "post_broadcast_pre_acknowledgement",
        ),
        ("concurrent_retry", "coordinator", "post_sign_pre_broadcast"),
    )


def _cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    sequence = 0
    for route in ("HL", "LH"):
        for scenario, actor, boundary in _scenarios():
            for repetition in range(3):
                sequence += 1
                attempt_id = "fault_" + f"{sequence:032x}"
                transaction_hash = "0x" + f"{sequence:064x}"
                raw_sha256 = f"{sequence + 1000:064x}"
                effect_hash = "0x" + f"{sequence + 2000:064x}"
                identity = {
                    "attempt_id": attempt_id,
                    "nonce": sequence,
                    "transaction_hash": transaction_hash,
                    "raw_sha256": raw_sha256,
                }
                concurrent = (
                    {"injected": identity, "recoveries": [identity, identity]}
                    if scenario == "concurrent_retry"
                    else None
                )
                worker = (
                    {
                        "expected_guid": "0x" + f"{sequence + 3000:064x}",
                        "injected_guid": "0x" + f"{sequence + 3000:064x}",
                        "actions": [
                            {
                                "action_id": f"action-{index}",
                                "nonce": sequence + index,
                                "transaction_hash": "0x" + f"{sequence + 4000 + index:064x}",
                                "raw_sha256": f"{sequence + 5000 + index:064x}",
                                "status": "succeeded",
                            }
                            for index in range(3)
                        ],
                        "valid": True,
                    }
                    if scenario == "worker_action_post_submit"
                    else None
                )
                injected_details: dict[str, Any] = {
                    "nonce": sequence,
                    "transaction_hash": transaction_hash,
                    "raw_sha256": raw_sha256,
                }
                signal = "process_exit"
                if scenario == "transient_retry_after_broadcast":
                    signal = "transient_retry"
                elif scenario == "concurrent_retry":
                    signal = "concurrent_retry"
                cases.append(
                    {
                        "schema_version": "xir-lab-native-faults-v1-case-result-v1",
                        "case_key": f"{route}:{scenario}:{repetition}",
                        "attempt_id": attempt_id,
                        "route": route,
                        "scenario": scenario,
                        "repetition": repetition,
                        "actor": actor,
                        "boundary": boundary,
                        "signal": signal,
                        "nonce_lineage": [sequence],
                        "transaction_lineage": [transaction_hash],
                        "raw_transaction_lineage": [raw_sha256],
                        "fault_events": [
                            {
                                "event_type": "fault_injected",
                                "details": injected_details,
                            }
                        ],
                        "worker_lineage": worker,
                        "concurrent_recovery_identity": concurrent,
                        "application_event_transaction_hashes": [effect_hash],
                        "checks": {name: True for name in REQUIRED_CASE_CHECKS},
                        "valid": True,
                    }
                )
    return cases


def _groups() -> list[dict[str, Any]]:
    return [
        {
            "route": route,
            "scenario": scenario,
            "boundary": boundary,
            "repetitions": 3,
            "validated": 3,
            "faults_injected": 3,
            "application_events": 3,
            "unique_tx_lineage": 3,
            "unique_raw_tx_lineage": 3,
        }
        for route in ("HL", "LH")
        for scenario, _actor, boundary in _scenarios()
    ]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_publication(
    path: Path,
    *,
    deployment_sha256: str,
    natural_interruptions: bool = False,
    campaign_id: str = "native-faults-v1-frozen",
) -> None:
    path.mkdir(parents=True)
    summary = {
        "schema_version": "xir-lab-native-faults-v1-summary-v1",
        "campaign_id": campaign_id,
        "config_sha256": "a" * 64,
        "deployment_sha256": deployment_sha256,
        "expected_cases": 60,
        "observed_cases": 60,
        "validated_cases": 60,
        "failed_cases": 0,
        "groups": _groups(),
        "valid": True,
    }
    counts = {
        "valid_results": 60,
        "stable_logical_attempt_id": 60,
        "single_nonce_lineage": 60,
        "single_transaction_lineage": 60,
        "single_raw_transaction_lineage": 60,
        "one_destination_effect": 60,
        "concurrent_recovery_cases": 6,
        "concurrent_recovery_shared_signed_identity": 6,
        "worker_recovery_cases": 6,
        "worker_action_recovered": 6,
    }
    validation = {
        "schema_version": "xir-lab-native-faults-v1-validation-v1",
        "campaign_id": campaign_id,
        "expected_cases": 60,
        "counts": counts,
        "valid": True,
    }
    environment = {
        "schema_version": "xir-lab-native-faults-v1-environment-v1",
        "controlled_campaign": True,
        "natural_interruptions_included": natural_interruptions,
        "deployment_scope": "prior-verifier-final-revision-shared-idle",
        "final_revision_source_sha256": FINAL_REVISION_SOURCE_SHA256,
        "overlay_provenance_sha256": "b" * 64,
    }
    _write_json(path / "summary.json", summary)
    _write_json(path / "validation.json", validation)
    _write_json(path / "case-results.json", _cases())
    _write_json(path / "environment.json", environment)
    files = []
    for name in ("summary.json", "validation.json", "case-results.json", "environment.json"):
        item = path / name
        files.append({"path": name, "bytes": item.stat().st_size, "sha256": _sha256(item)})
    manifest = {
        "schema_version": "xir-lab-native-faults-v1-manifest-v1",
        "campaign_id": campaign_id,
        "files": files,
    }
    _write_json(path / "manifest.json", manifest)
    manifest_sha256 = _sha256(path / "manifest.json")
    (path / "manifest.json.sha256").write_text(
        f"{manifest_sha256}  manifest.json\n", encoding="utf-8"
    )
    _write_json(
        path / "manifest-verification.json",
        {"manifest_sha256": manifest_sha256, "valid": True},
    )


def _triplet(
    tmp_path: Path,
    *,
    natural_interruptions: bool = False,
    campaign_id: str = "native-faults-v1-frozen",
) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    deployment = tmp_path / "deployment.json"
    _write_json(deployment, _deployment())
    source = tmp_path / "source"
    _write_publication(
        source,
        deployment_sha256=_sha256(deployment),
        natural_interruptions=natural_interruptions,
        campaign_id=campaign_id,
    )
    rebuild_a = tmp_path / "rebuild-a"
    rebuild_b = tmp_path / "rebuild-b"
    shutil.copytree(source, rebuild_a)
    shutil.copytree(source, rebuild_b)
    return {
        "source_publication": source,
        "rebuild_a_publication": rebuild_a,
        "rebuild_b_publication": rebuild_b,
        "deployment_path": deployment,
    }


def test_final_source_selects_exact_60_cases_and_complete_lineage(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    rows, groups, provenance = load_final_recovery_source(repository_root=_repository(), **paths)
    assert len(rows) == 60
    assert len(groups) == 20
    assert all(len(row["raw_transaction_lineage"]) == 1 for row in rows)
    assert len([row for row in rows if row["concurrent_recovery_identity"]]) == 6
    assert len([row for row in rows if row["worker_lineage"]]) == 6
    assert provenance["runner_root_signer_separated"] is True
    assert provenance["natural_interruptions_included"] is False
    assert provenance["figure_1_sha256"] == FIGURE_1_SHA256


def test_old_or_combined_signer_deployment_fails_before_output(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    deployment = _deployment()
    deployment["root_signer"] = deployment["runner"]
    _write_json(paths["deployment_path"], deployment)
    output = tmp_path / "must-not-exist"
    with pytest.raises(FaultsRecoveryFigureError, match="refusing old"):
        build_two_rebuild_publication(repository_root=_repository(), output_root=output, **paths)
    assert not output.exists()


def test_natural_interruptions_and_non_frozen_sources_fail_closed(tmp_path: Path) -> None:
    natural = _triplet(tmp_path / "natural", natural_interruptions=True)
    with pytest.raises(FaultsRecoveryFigureError, match="natural interruptions"):
        load_final_recovery_source(repository_root=_repository(), **natural)
    smoke = _triplet(tmp_path / "smoke", campaign_id="native-faults-v1-smoke")
    with pytest.raises(FaultsRecoveryFigureError, match="refusing smoke"):
        load_final_recovery_source(repository_root=_repository(), **smoke)


def test_rebuild_drift_fails_closed(tmp_path: Path) -> None:
    paths = _triplet(tmp_path)
    with (paths["rebuild_b_publication"] / "case-results.json").open(
        "a", encoding="utf-8"
    ) as stream:
        stream.write(" ")
    with pytest.raises(FaultsRecoveryFigureError, match="publication is invalid"):
        load_final_recovery_source(repository_root=_repository(), **paths)


def test_native_width_figure_and_lineage_sources_are_byte_deterministic(
    tmp_path: Path,
) -> None:
    paths = _triplet(tmp_path)
    result = build_two_rebuild_publication(
        repository_root=_repository(), output_root=tmp_path / "figure", **paths
    )
    publication = Path(result["publication"])
    assert result["namespace"] == OUTPUT_NAMESPACE
    assert result["valid"] is True
    for name in (
        "recovery-overview-v2.pdf",
        "recovery-overview-v2.svg",
        "recovery-overview-v2-source.csv",
        "recovery-overview-v2-source.json",
        "visual-audit.json",
        "validation.json",
        "rebuild-comparison.json",
        "manifest.json",
    ):
        assert (publication / name).is_file()
    visual = json.loads((publication / "visual-audit.json").read_text(encoding="utf-8"))
    source = json.loads(
        (publication / "recovery-overview-v2-source.json").read_text(encoding="utf-8")
    )
    validation = json.loads((publication / "validation.json").read_text(encoding="utf-8"))
    assert visual["native_width_mm"] == 131.6
    assert visual["native_height_mm"] <= 58.0
    assert visual["minimum_native_font_points"] >= 7.1
    assert len(visual["font_roles"]) == 3
    assert len(visual["line_styles"]) <= 3
    assert len(visual["palette"]) == 3
    assert abs(visual["nominal_content_region_occupancy"] - 0.618) <= 0.015
    assert visual["pdf"]["all_fonts_embedded"] is True
    assert visual["pdf"]["all_fonts_truetype"] is True
    assert visual["pdf"]["raster_images"] == 0
    assert all(value for key, value in visual["svg"].items() if key != "internal_href_count")
    assert len(source["cases"]) == 60
    assert source["lineage_scope"]["raw_signed_transaction_sha256"] is True
    assert source["lineage_scope"]["raw_signed_bytes_published"] is False
    assert validation["valid"] is True
    csv_lines = (
        (publication / "recovery-overview-v2-source.csv").read_text(encoding="utf-8").splitlines()
    )
    assert len(csv_lines) == 61
    assert "raw_transaction_lineage" in csv_lines[0]
    assert (tmp_path / "figure/rebuild-a/recovery-overview-v2.pdf").read_bytes() == (
        tmp_path / "figure/rebuild-b/recovery-overview-v2.pdf"
    ).read_bytes()
