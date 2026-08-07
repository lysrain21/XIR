#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

FROZEN_FIGURE_ONE_SHA256 = "2fa2864efe9f44357cf9e529fee7ee49415bee15410c9d54cd6ac0cd909a64a2"


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _publication(root: Path) -> dict[str, Any]:
    validation = _load(root / "publication-validation.json")
    return {
        "path": str(root),
        "manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
        "figure_pdf_sha256": hashlib.sha256(
            (root / "mechanism-waterfall.pdf").read_bytes()
        ).hexdigest(),
        "figure_svg_sha256": hashlib.sha256(
            (root / "mechanism-waterfall.svg").read_bytes()
        ).hexdigest(),
        "publication_validation": validation,
        "file_sha256": {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        },
    }


def _main_figure(publication: Path) -> dict[str, Any]:
    manifest = _load(publication / "manifest.json")
    validation = _load(publication / "validation.json")
    comparison = _load(publication / "rebuild-comparison.json")
    files = cast(dict[str, dict[str, Any]], manifest["files"])
    digests_valid = all(
        (publication / name).is_file()
        and (publication / name).stat().st_size == int(item["bytes"])
        and hashlib.sha256((publication / name).read_bytes()).hexdigest() == item["sha256"]
        for name, item in files.items()
    )
    required = {"mechanism-cost-v2.pdf", "mechanism-cost-v2.svg"}
    return {
        "path": str(publication),
        "namespace": manifest.get("namespace"),
        "manifest_sha256": hashlib.sha256(
            (publication / "manifest.json").read_bytes()
        ).hexdigest(),
        "source_semantic_sha256": manifest.get("source_semantic_sha256"),
        "pdf_sha256": files.get("mechanism-cost-v2.pdf", {}).get("sha256", ""),
        "svg_sha256": files.get("mechanism-cost-v2.svg", {}).get("sha256", ""),
        "validation": validation,
        "rebuild_comparison": comparison,
        "digests_valid": digests_valid,
        "valid": (
            manifest.get("namespace") == "native-ablation-v2-main-figure-v1"
            and manifest.get("valid") is True
            and validation.get("valid") is True
            and comparison.get("valid") is True
            and required.issubset(files)
            and digests_valid
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--frozen-source-manifest", type=Path, required=True)
    parser.add_argument("--rebuild-a", type=Path, required=True)
    parser.add_argument("--rebuild-b", type=Path, required=True)
    parser.add_argument("--main-figure-publication", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument(
        "--frozen-figure-one",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "main"
        / "figures"
        / "protocol-xir-reachability-topology.pdf",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    analysis = _load(args.source / "analysis.json")
    plan = _load(args.plan)
    frozen_source = _load(args.frozen_source_manifest)
    source = _publication(args.source)
    first = _publication(args.rebuild_a)
    second = _publication(args.rebuild_b)
    main_figure = _main_figure(args.main_figure_publication)
    identical = first["file_sha256"] == second["file_sha256"]
    figure_one_sha256 = hashlib.sha256(args.frozen_figure_one.read_bytes()).hexdigest()
    document = {
        "schema_version": f"xir-lab-{analysis['namespace']}-handoff",
        "namespace": analysis["namespace"],
        "result_role": analysis["result_role"],
        "remote_root": args.remote_root,
        "frozen_figure_one": {
            "path": str(args.frozen_figure_one),
            "sha256": figure_one_sha256,
            "expected_sha256": FROZEN_FIGURE_ONE_SHA256,
            "valid": figure_one_sha256 == FROZEN_FIGURE_ONE_SHA256,
        },
        "config_sha256": analysis["config_sha256"],
        "analysis_source_sha256": analysis["analysis_source_sha256"],
        "operational_incidents_sha256": analysis["operational_incidents_sha256"],
        "base_deployment_sha256": analysis["base_deployment_sha256"],
        "deployment_sha256": analysis["deployment_sha256"],
        "final_revision_source_sha256": analysis["final_revision_source_sha256"],
        "prior_verifier_bindings": analysis["prior_verifier_bindings"],
        "onchain_prior_verifier_bindings": analysis["onchain_prior_verifier_bindings"],
        "runner_state_sha256": analysis["runner_state_sha256"],
        "layerzero_state_sha256": analysis["layerzero_state_sha256"],
        "plan_sha256": hashlib.sha256(args.plan.read_bytes()).hexdigest(),
        "plan_attempts": plan["attempt_count"],
        "frozen_source": {
            "manifest_path": str(args.frozen_source_manifest),
            "manifest_sha256": hashlib.sha256(
                args.frozen_source_manifest.read_bytes()
            ).hexdigest(),
            "attempt_counts": frozen_source["attempt_counts"],
            "runner_sqlite_quick_check": frozen_source["runner_sqlite_quick_check"],
            "layerzero_sqlite_quick_check": frozen_source["layerzero_sqlite_quick_check"],
            "secret_scan_findings": frozen_source["secret_scan_findings"],
            "valid": frozen_source["valid"],
        },
        "exact_denominator": analysis["validation"]["expected_attempts"],
        "reconciled_attempts": analysis["validation"]["reconciled_attempts"],
        "cell_counts": analysis["validation"]["cell_counts"],
        "matched_payload_blocks": analysis["validation"]["matched_payload_blocks"],
        "semantic_digest": analysis["semantic_digest"],
        "prepublication_exclusions": analysis.get("prepublication_exclusions", []),
        "operational_incidents": analysis.get("operational_incidents", []),
        "incident_latency_sensitivity": analysis["incident_latency_sensitivity"],
        "incident_free_latency_summary": analysis["incident_free_latency_summary"],
        "incident_free_latency_deltas": analysis["incident_free_latency_deltas"],
        "cell_summary": analysis["cell_summary"],
        "paired_point_estimates_and_intervals": analysis["paired_deltas"],
        "measured_stage_costs": analysis["stage_costs"],
        "validation": analysis["validation"],
        "source_publication": source,
        "rebuild_a": first,
        "rebuild_b": second,
        "main_figure": main_figure,
        "offline_rebuilds_identical": identical,
        "all_gates_pass": (
            bool(analysis["validation"]["valid"])
            and bool(source["publication_validation"]["valid"])
            and bool(first["publication_validation"]["valid"])
            and bool(second["publication_validation"]["valid"])
            and identical
            and bool(frozen_source["valid"])
            and frozen_source["attempt_counts"] == {"succeeded": 8000}
            and bool(main_figure["valid"])
            and figure_one_sha256 == FROZEN_FIGURE_ONE_SHA256
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    if not document["all_gates_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
