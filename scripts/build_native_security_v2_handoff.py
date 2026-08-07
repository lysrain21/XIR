#!/usr/bin/env python3
"""Build the final, secret-free native-security-v2 handoff record."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from xir_lab.publication import PublicationError, validate_publishable_file

AUTHORITY_CASES = frozenset({"fake_verifier", "wrong_endpoint"})


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _publication(root: Path) -> dict[str, Any]:
    files = {
        str(path.relative_to(root)): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    manifest_errors: list[str] = []
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        manifest_errors.append("missing SHA256SUMS")
    else:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            expected, name = line.split(maxsplit=1)
            target = root / name.strip()
            if not target.is_file() or _sha256(target) != expected:
                manifest_errors.append(name.strip())
    return {
        "path": str(root),
        "file_count": len(files),
        "files": files,
        "manifest_valid": not manifest_errors,
        "manifest_errors": manifest_errors,
        "summary": _load(root / "summary.json"),
        "offline_validation": (
            _load(root / "offline-validation.json")
            if (root / "offline-validation.json").is_file()
            else None
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-publication", type=Path, required=True)
    parser.add_argument("--rebuild-a", type=Path, required=True)
    parser.add_argument("--rebuild-b", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--deployment-validation", type=Path, required=True)
    parser.add_argument("--smoke-validation", type=Path, required=True)
    parser.add_argument("--remote-preflight", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--remote-run-root", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = _publication(args.source_publication)
    rebuild_a = _publication(args.rebuild_a)
    rebuild_b = _publication(args.rebuild_b)
    comparison = _load(args.comparison)
    deployment_validation = _load(args.deployment_validation)
    smoke_validation = _load(args.smoke_validation)
    preflight = _load(args.remote_preflight)
    lease = _load(args.lease)
    summary = cast(dict[str, Any], source["summary"])
    authority_groups = [
        group
        for group in cast(list[dict[str, Any]], summary["groups"])
        if group["case"] in AUTHORITY_CASES
    ]
    authority_valid = (
        len(authority_groups) == 4
        and all(
            group["repetitions"] == 30
            and group["validated"] == 30
            and group["expected_rejection"] == "UnapprovedPriorVerifier"
            and group["actual_rejection_matches"] == 30
            and group["application_effects"] == 0
            for group in authority_groups
        )
    )
    rebuilds_identical = rebuild_a["files"] == rebuild_b["files"]
    validation = {
        "smoke_valid": smoke_validation.get("valid") is True,
        "deployment_valid": deployment_validation.get("valid") is True,
        "preflight_valid": (
            preflight.get("valid") is True and preflight.get("credentials_included") is False
        ),
        "official_summary_valid": (
            summary.get("valid") is True
            and summary.get("expected_case_runs") == 780
            and summary.get("validated_case_runs") == 780
            and summary.get("failed_case_runs") == 0
        ),
        "source_manifest_valid": source["manifest_valid"] is True,
        "rebuild_a_valid": (
            rebuild_a["offline_validation"] is not None
            and rebuild_a["offline_validation"].get("valid") is True
        ),
        "rebuild_b_valid": (
            rebuild_b["offline_validation"] is not None
            and rebuild_b["offline_validation"].get("valid") is True
        ),
        "comparison_valid": comparison.get("valid") is True,
        "rebuilds_identical": rebuilds_identical,
        "authority_cases_valid": authority_valid,
        "lease_released": lease.get("status") == "RELEASED",
    }
    validation["valid"] = all(validation.values())
    document = {
        "schema_version": "xir-lab-native-security-v2-handoff-v1",
        "campaign_id": "native-security-v2",
        "remote_run_root": args.remote_run_root,
        "exact_denominator": 780,
        "config": {"path": str(args.config), "sha256": _sha256(args.config)},
        "deployment": {
            "path": str(args.deployment),
            "sha256": _sha256(args.deployment),
            "validation_path": str(args.deployment_validation),
            "validation_sha256": _sha256(args.deployment_validation),
            "validation": deployment_validation,
        },
        "campaign_source_lock": preflight["source_provenance"],
        "remote_preflight": {
            "path": str(args.remote_preflight),
            "sha256": _sha256(args.remote_preflight),
            "healthy_validators": preflight.get("healthy_validator_count"),
            "credentials_included": preflight.get("credentials_included"),
        },
        "smoke": {
            "validation_path": str(args.smoke_validation),
            "validation_sha256": _sha256(args.smoke_validation),
        },
        "authority_results": authority_groups,
        "authority_expectation": {
            "case_runs": 120,
            "failed_runner_stage": "second_protocol_dispatch",
            "revert_error": "UnapprovedPriorVerifier",
            "revert_selector": "0x819d4ecb",
            "status": 0,
            "message_id_consumed": False,
            "application_effects": 0,
        },
        "source_publication": source,
        "rebuild_a": rebuild_a,
        "rebuild_b": rebuild_b,
        "comparison": {
            "path": str(args.comparison),
            "sha256": _sha256(args.comparison),
            "document": comparison,
        },
        "lease": {
            "path": str(args.lease),
            "sha256": _sha256(args.lease),
            "status": lease.get("status"),
            "released_utc": lease.get("released_utc", lease.get("released_at")),
        },
        "downstream_rule": (
            "Reuse the native carrier stack, source lock, and approved prior-verifier mapping; "
            "deploy each downstream workload into a fresh isolated application namespace."
        ),
        "validation": validation,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        validate_publishable_file(args.output.parent, args.output)
    except PublicationError as exc:
        document["validation"]["secret_scan_error"] = str(exc)
        document["validation"]["valid"] = False
        args.output.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    report = [
        "# native-security-v2 final handoff",
        "",
        f"- Official denominator: {summary.get('validated_case_runs')}/780",
        f"- Failed official cases: {summary.get('failed_case_runs')}",
        f"- Authority cells: {sum(int(group['validated']) for group in authority_groups)}/120",
        f"- Independent rebuilds identical: {rebuilds_identical}",
        f"- Remote writer lease released: {validation['lease_released']}",
        f"- All gates pass: {document['validation']['valid']}",
        "",
        "Downstream experiments must use a fresh application namespace while preserving the "
        "administrator-approved profile-to-verifier bindings recorded above.",
    ]
    args.output.with_suffix(".md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(args.output)
    if document["validation"]["valid"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
