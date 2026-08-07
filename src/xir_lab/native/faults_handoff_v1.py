"""Machine-readable handoff validation for the frozen native-faults-v1 campaign."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

import jsonschema

from xir_lab.localnet.topology import LocalTopologyError

REQUIRED_CASE_CHECKS = frozenset(
    {
        "attempt_identity_stable",
        "one_fault_injected",
        "expected_process_exit_count",
        "destination_stage_succeeded",
        "single_nonce_lineage",
        "single_transaction_lineage",
        "single_raw_transaction_lineage",
        "fault_nonce_matches_recovery",
        "fault_transaction_matches_recovery",
        "fault_raw_matches_recovery",
        "one_application_event",
        "attempt_consumed_once",
        "gateway_consumed",
        "transient_retry_recorded",
        "concurrent_retries_joined",
        "worker_action_recovered",
    }
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def verify_publication(publish: Path) -> str:
    manifest_path = publish / "manifest.json"
    manifest = load_json(manifest_path)
    manifest_sha256 = sha256(manifest_path)
    recorded = (publish / "manifest.json.sha256").read_text(encoding="utf-8").split()[0]
    verification = load_json(publish / "manifest-verification.json")
    errors: list[str] = []
    if recorded != manifest_sha256:
        errors.append("manifest sidecar digest mismatch")
    if verification.get("manifest_sha256") != manifest_sha256:
        errors.append("manifest verification digest mismatch")
    if verification.get("valid") is not True:
        errors.append("manifest verification is not valid")
    for item in cast(list[dict[str, Any]], manifest.get("files", [])):
        path = publish / str(item["path"])
        if not path.is_file():
            errors.append(f"missing publication file: {item['path']}")
        elif path.stat().st_size != int(item["bytes"]) or sha256(path) != item["sha256"]:
            errors.append(f"publication digest mismatch: {item['path']}")
    if errors:
        raise LocalTopologyError("; ".join(errors))
    return manifest_sha256


def concurrent_identity_valid(result: dict[str, Any]) -> bool:
    if result["scenario"] != "concurrent_retry":
        return True
    identity = result.get("concurrent_recovery_identity")
    if not isinstance(identity, dict):
        return False
    recoveries = identity.get("recoveries")
    injected = identity.get("injected")
    return (
        isinstance(recoveries, list)
        and len(recoveries) == 2
        and isinstance(injected, dict)
        and recoveries[0] == recoveries[1] == injected
        and isinstance(injected.get("raw_sha256"), str)
        and len(injected["raw_sha256"]) == 64
        and isinstance(injected.get("nonce"), int)
        and isinstance(injected.get("transaction_hash"), str)
        and str(injected["transaction_hash"]).startswith("0x")
    )


def write_immutable_json(path: Path, document: dict[str, Any]) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    if path.exists():
        if path.read_bytes() != encoded:
            raise LocalTopologyError(f"native-faults-v1 handoff refuses overwrite: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def build_handoff(
    *,
    frozen_publish: Path,
    rebuild_a_publish: Path,
    rebuild_b_publish: Path,
    figure_dir: Path,
    output: Path,
    schema_root: Path,
) -> dict[str, Any]:
    frozen_manifest = verify_publication(frozen_publish)
    rebuild_a_manifest = verify_publication(rebuild_a_publish)
    rebuild_b_manifest = verify_publication(rebuild_b_publish)
    rebuilds_byte_identical = frozen_manifest == rebuild_a_manifest == rebuild_b_manifest
    if not rebuilds_byte_identical:
        raise LocalTopologyError("native-faults-v1 frozen and rebuild manifests differ")

    summary = load_json(frozen_publish / "summary.json")
    validation = load_json(frozen_publish / "validation.json")
    if validation.get("valid") is not True:
        raise LocalTopologyError("native-faults-v1 semantic validation is not valid")
    cases = cast(
        list[dict[str, Any]], json.loads((frozen_publish / "case-results.json").read_text())
    )
    groups = cast(list[dict[str, Any]], summary["groups"])
    all_groups_valid = len(groups) == 20 and all(
        all(
            int(group[field]) == 3
            for field in (
                "repetitions",
                "validated",
                "faults_injected",
                "application_events",
                "unique_tx_lineage",
                "unique_raw_tx_lineage",
            )
        )
        for group in groups
    )
    all_case_checks_valid = len(cases) == 60 and all(
        result.get("valid") is True
        and REQUIRED_CASE_CHECKS <= set(cast(dict[str, Any], result["checks"]))
        and all(bool(value) for value in cast(dict[str, Any], result["checks"]).values())
        for result in cases
    )
    concurrent_cases = [result for result in cases if result["scenario"] == "concurrent_retry"]
    concurrent_valid = len(concurrent_cases) == 6 and all(
        concurrent_identity_valid(result) for result in concurrent_cases
    )

    environment = load_json(frozen_publish / "environment.json")
    figure_source_path = figure_dir / "recovery-overview-v2-source.json"
    figure_source = load_json(figure_source_path)
    pdf_path = figure_dir / "recovery-overview-v2.pdf"
    svg_path = figure_dir / "recovery-overview-v2.svg"
    csv_path = figure_dir / "recovery-overview-v2-source.csv"
    provenance = cast(dict[str, Any], figure_source.get("provenance", {}))
    output_digests = cast(dict[str, Any], figure_source.get("output_sha256", {}))
    if provenance.get("source_summary_sha256") != sha256(frozen_publish / "summary.json"):
        raise LocalTopologyError("recovery overview does not bind the frozen summary")
    if output_digests.get("pdf") != sha256(pdf_path):
        raise LocalTopologyError("recovery overview PDF digest mismatch")
    if output_digests.get("svg") != sha256(svg_path):
        raise LocalTopologyError("recovery overview SVG digest mismatch")
    if output_digests.get("csv") != sha256(csv_path):
        raise LocalTopologyError("recovery overview CSV digest mismatch")

    exact_denominator = (
        summary["expected_cases"] == 60
        and summary["observed_cases"] == 60
        and summary["validated_cases"] == 60
        and summary["failed_cases"] == 0
    )
    document = {
        "schema_version": "xir-lab-native-faults-v1-handoff-v1",
        "campaign_id": summary["campaign_id"],
        "artifacts": {
            "frozen_publish": os.path.relpath(frozen_publish, output.parent),
            "rebuild_a_publish": os.path.relpath(rebuild_a_publish, output.parent),
            "rebuild_b_publish": os.path.relpath(rebuild_b_publish, output.parent),
            "figure_directory": os.path.relpath(figure_dir, output.parent),
        },
        "denominator": {
            "expected": summary["expected_cases"],
            "observed": summary["observed_cases"],
            "validated": summary["validated_cases"],
            "failed": summary["failed_cases"],
            "exact": exact_denominator,
        },
        "matrix": {
            "routes": ["HL", "LH"],
            "scenario_count": 10,
            "group_count": len(groups),
            "repetitions_per_group": 3,
            "all_groups_valid": all_groups_valid,
        },
        "invariants": {
            "stable_logical_attempt_id": all(
                bool(result["checks"]["attempt_identity_stable"]) for result in cases
            ),
            "single_nonce_lineage": all(len(result["nonce_lineage"]) == 1 for result in cases),
            "single_transaction_lineage": all(
                len(result["transaction_lineage"]) == 1 for result in cases
            ),
            "single_raw_transaction_lineage": all(
                len(result["raw_transaction_lineage"]) == 1 for result in cases
            ),
            "one_destination_effect": all(
                len(result["application_event_transaction_hashes"]) == 1 for result in cases
            ),
            "concurrent_recovery_cases": len(concurrent_cases),
            "concurrent_recovery_shared_signed_identity": concurrent_valid,
            "all_case_checks_valid": all_case_checks_valid,
        },
        "digests": {
            "source_bundle_sha256": environment["fault_source_bundle_sha256"],
            "config_sha256": summary["config_sha256"],
            "deployment_sha256": summary["deployment_sha256"],
            "frozen_manifest_sha256": frozen_manifest,
            "rebuild_a_manifest_sha256": rebuild_a_manifest,
            "rebuild_b_manifest_sha256": rebuild_b_manifest,
            "rebuilds_byte_identical": rebuilds_byte_identical,
            "figure_pdf_sha256": sha256(pdf_path),
            "figure_svg_sha256": sha256(svg_path),
            "figure_csv_sha256": sha256(csv_path),
            "figure_source_sha256": sha256(figure_source_path),
        },
        "valid": exact_denominator
        and all_groups_valid
        and all_case_checks_valid
        and concurrent_valid
        and rebuilds_byte_identical,
    }
    schema = json.loads(
        (schema_root / "native-faults-v1-handoff.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(document)
    write_immutable_json(output, document)
    return document
