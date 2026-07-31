#!/usr/bin/env python3
"""Validate the secret-free native run-003 publication bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("publication_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.publication_directory.resolve()
    analysis = load(root / "analysis.json")
    reconciliation = load(root / "reconciliation.json")
    summary = load(root / "final-run-summary.json")
    rebuild = load(root / "offline-rebuild-verification.json")
    manifest = load(root / "manifest-verification.json")
    report = (root / "experiment-report-zh.md").read_text(encoding="utf-8")
    routes = {str(row["route"]): row for row in analysis["per_route"]}
    checks = {
        "reconciliation_valid": reconciliation["valid"] is True,
        "all_reconciliation_invariants_true": all(
            reconciliation["invariants"].values()
        ),
        "logical_denominator_exact": (
            reconciliation["denominator"]["logical_attempts"] == 40_000
            and reconciliation["denominator"]["per_route"] == 10_000
        ),
        "routes_balanced_and_successful": (
            set(routes) == {"HH", "LL", "HL", "LH"}
            and all(
                row["logical_attempts"] == 10_000
                and row["success_rate"] == 1
                for row in routes.values()
            )
        ),
        "xir_attribution_exact": (
            routes["HH"]["xir"] is False
            and routes["LL"]["xir"] is False
            and routes["HL"]["xir"] is True
            and routes["LH"]["xir"] is True
            and reconciliation["observed"]["cumulative_xir_transitions"]
            - 2
            * (
                reconciliation["denominator"]["cumulative_per_route"]
                - reconciliation["denominator"]["per_route"]
            )
            == 20_000
        ),
        "scale_calldata_complete": (
            summary["calldata"]["coordinator"]["matched_transactions"]
            == 120_000
            and summary["calldata"]["layerzero_worker"]["scale_packets"]
            == 40_000
            and summary["calldata"]["layerzero_worker"]["groups"]["all"][
                "transactions"
            ]
            == 120_000
        ),
        "natural_recovery_denominator_preserved": (
            summary["interruptions"]["all_natural"] is True
            and summary["interruptions"]["attempt_denominator_unchanged"] is True
            and summary["interruptions"]["no_replacement_attempts"] is True
            and summary["interruptions"]["recovery_only_transactions"] == 78
        ),
        "final_validators_healthy": (
            summary["validators"]["validator_count"] == 12
            and summary["validators"]["all_running"] is True
            and summary["validators"]["all_healthy"] is True
        ),
        "offline_rebuild_equal": (
            rebuild["equal"] is True
            and rebuild["network_reads_required"] is False
            and rebuild["rebuild_a_semantic_sha256"]
            == rebuild["rebuild_b_semantic_sha256"]
            == analysis["semantic_sha256"]
        ),
        "manifest_verified": manifest["valid"] is True,
        "report_discloses_confounds": (
            "“无中断性能基准”" in report
            and "自然恢复混杂" in report
        ),
        "report_excludes_prior_runs": (
            "run-001" in report
            and "run-002" in report
            and "未进入" in report
        ),
        "report_links_evidence": (
            "/vePFS-Mindverse/user/intern/lucian/xir/runtime/"
            "native-stack-run-003" in report
        ),
    }
    document = {
        "schema_version": "xir-lab-native-publication-validation-v1",
        "valid": all(checks.values()),
        "checks": checks,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    if not document["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
