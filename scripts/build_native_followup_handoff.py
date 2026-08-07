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


def _file_map(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _publication_summary(root: Path) -> dict[str, Any]:
    return {
        "path": str(root),
        "manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
        "publication_validation": _load(root / "publication-validation.json"),
        "file_sha256": _file_map(root),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ablation-source", type=Path, required=True)
    parser.add_argument("--ablation-plan", type=Path, required=True)
    parser.add_argument("--ablation-rebuild-a", type=Path, required=True)
    parser.add_argument("--ablation-rebuild-b", type=Path, required=True)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument("--baseline-plan", type=Path, required=True)
    parser.add_argument("--baseline-rebuild-a", type=Path, required=True)
    parser.add_argument("--baseline-rebuild-b", type=Path, required=True)
    parser.add_argument("--baseline-incident-pre", type=Path, required=True)
    parser.add_argument("--baseline-incident-post", type=Path, required=True)
    parser.add_argument("--baseline-incident-traceback", type=Path, required=True)
    parser.add_argument("--remote-ablation-root", required=True)
    parser.add_argument("--remote-baseline-root", required=True)
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

    ablation = _load(args.ablation_source / "analysis.json")
    baseline = _load(args.baseline_source / "analysis.json")
    ablation_plan = _load(args.ablation_plan)
    baseline_plan = _load(args.baseline_plan)
    ablation_source = _publication_summary(args.ablation_source)
    baseline_source = _publication_summary(args.baseline_source)
    ablation_a = _publication_summary(args.ablation_rebuild_a)
    ablation_b = _publication_summary(args.ablation_rebuild_b)
    baseline_a = _publication_summary(args.baseline_rebuild_a)
    baseline_b = _publication_summary(args.baseline_rebuild_b)
    baseline_incident_pre = _load(args.baseline_incident_pre)
    baseline_incident_post = _load(args.baseline_incident_post)
    ablation_identical = ablation_a["file_sha256"] == ablation_b["file_sha256"]
    baseline_identical = baseline_a["file_sha256"] == baseline_b["file_sha256"]
    figure_one_sha256 = hashlib.sha256(args.frozen_figure_one.read_bytes()).hexdigest()
    document = {
        "schema_version": "xir-lab-native-followup-handoff-v1",
        "frozen_figure_one": {
            "path": str(args.frozen_figure_one),
            "sha256": figure_one_sha256,
            "expected_sha256": FROZEN_FIGURE_ONE_SHA256,
            "valid": figure_one_sha256 == FROZEN_FIGURE_ONE_SHA256,
        },
        "ablation": {
            "remote_root": args.remote_ablation_root,
            "result_role": ablation["result_role"],
            "config_sha256": ablation["config_sha256"],
            "analysis_source_sha256": ablation["analysis_source_sha256"],
            "operational_incidents_sha256": ablation["operational_incidents_sha256"],
            "deployment_sha256": ablation["deployment_sha256"],
            "base_deployment_sha256": ablation.get("base_deployment_sha256", ""),
            "plan_sha256": hashlib.sha256(args.ablation_plan.read_bytes()).hexdigest(),
            "plan_attempts": ablation_plan["attempt_count"],
            "exact_denominator": ablation["validation"]["expected_attempts"],
            "reconciled_attempts": ablation["validation"]["reconciled_attempts"],
            "cell_counts": ablation["validation"]["cell_counts"],
            "matched_payload_blocks": ablation["validation"]["matched_payload_blocks"],
            "semantic_digest": ablation["semantic_digest"],
            "prepublication_exclusions": ablation.get("prepublication_exclusions", []),
            "operational_incidents": ablation.get("operational_incidents", []),
            "incident_latency_sensitivity": ablation.get("incident_latency_sensitivity", {}),
            "incident_free_latency_summary": ablation.get("incident_free_latency_summary", []),
            "incident_free_latency_deltas": ablation.get("incident_free_latency_deltas", []),
            "cell_summary": ablation["cell_summary"],
            "paired_point_estimates_and_intervals": ablation["paired_deltas"],
            "measured_stage_costs": ablation["stage_costs"],
            "figure_pdf_sha256": hashlib.sha256(
                (args.ablation_rebuild_a / "mechanism-waterfall.pdf").read_bytes()
            ).hexdigest(),
            "figure_svg_sha256": hashlib.sha256(
                (args.ablation_rebuild_a / "mechanism-waterfall.svg").read_bytes()
            ).hexdigest(),
            "source_publication": ablation_source,
            "rebuild_a": ablation_a,
            "rebuild_b": ablation_b,
            "offline_rebuilds_identical": ablation_identical,
            "validation": ablation["validation"],
        },
        "baseline": {
            "remote_root": args.remote_baseline_root,
            "config_sha256": baseline["config_sha256"],
            "analysis_source_sha256": baseline["analysis_source_sha256"],
            "deployment_sha256": baseline["deployment_sha256"],
            "environment_namespace": baseline["environment_namespace"],
            "base_deployment_sha256": baseline["base_deployment_sha256"],
            "final_revision_source_sha256": baseline["final_revision_source_sha256"],
            "prior_verifier_bindings": baseline["prior_verifier_bindings"],
            "onchain_prior_verifier_bindings": baseline["onchain_prior_verifier_bindings"],
            "plan_sha256": hashlib.sha256(args.baseline_plan.read_bytes()).hexdigest(),
            "plan_attempts": baseline_plan["attempt_count"],
            "dynamic_denominator": baseline["validation"]["expected_attempts"],
            "static_capability_rows": len(baseline["capability_rows"]),
            "case_counts": baseline["validation"]["case_counts"],
            "semantic_digest": baseline["semantic_digest"],
            "case_summary": baseline["case_summary"],
            "operational_incident": {
                "pre_resume": baseline_incident_pre,
                "post_resume": baseline_incident_post,
                "pre_resume_sha256": hashlib.sha256(
                    args.baseline_incident_pre.read_bytes()
                ).hexdigest(),
                "post_resume_sha256": hashlib.sha256(
                    args.baseline_incident_post.read_bytes()
                ).hexdigest(),
                "traceback_sha256": hashlib.sha256(
                    args.baseline_incident_traceback.read_bytes()
                ).hexdigest(),
                "resolved": (
                    baseline_incident_post.get("final_status") == "succeeded"
                    and bool(baseline_incident_post.get("first_hop_transaction_reused"))
                    and not bool(baseline_incident_post.get("treatment_changed"))
                    and not bool(baseline_incident_post.get("denominator_changed"))
                ),
            },
            "source_publication": baseline_source,
            "rebuild_a": baseline_a,
            "rebuild_b": baseline_b,
            "offline_rebuilds_identical": baseline_identical,
            "validation": baseline["validation"],
        },
        "all_gates_pass": (
            bool(ablation["validation"]["valid"])
            and bool(baseline["validation"]["valid"])
            and bool(ablation_source["publication_validation"]["valid"])
            and bool(baseline_source["publication_validation"]["valid"])
            and bool(ablation_a["publication_validation"]["valid"])
            and bool(ablation_b["publication_validation"]["valid"])
            and bool(baseline_a["publication_validation"]["valid"])
            and bool(baseline_b["publication_validation"]["valid"])
            and ablation_identical
            and baseline_identical
            and baseline_incident_post.get("final_status") == "succeeded"
            and bool(baseline_incident_post.get("first_hop_transaction_reused"))
            and not bool(baseline_incident_post.get("treatment_changed"))
            and not bool(baseline_incident_post.get("denominator_changed"))
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
