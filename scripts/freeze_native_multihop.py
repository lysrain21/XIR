#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_publication import freeze_multihop_sources


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"), required=True)
    for name in (
        "config", "profile", "deployment", "plan", "preflight", "runner-state",
        "worker-state", "trace-state", "hyperlane-processes", "incidents", "output-root",
        "hyperlane-observer",
        "hyperlane-observer-completion",
        "root-signer-audit", "resource-monitor", "resource-segments",
        "effect-baseline", "effect-audit",
        "coordinator-signed-root",
        "phase-authority",
        "preregistration", "review-closure", "review-gate", "topology",
        "identity-manifest", "normalized-stage-schema", "stage-template-schema",
        "validator-volume-attestation",
        "validator-volume-journal",
        "toolchain-preflight",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--smoke-handoff", type=Path)
    parser.add_argument("--publication-smoke-handoff", type=Path)
    args = parser.parse_args()
    manifest = freeze_multihop_sources(
        phase=args.phase,
        config_path=args.config,
        profile_path=args.profile,
        deployment_path=args.deployment,
        plan_path=args.plan,
        preflight_path=args.preflight,
        runner_state_path=args.runner_state,
        worker_state_path=args.worker_state,
        trace_state_path=args.trace_state,
        hyperlane_process_path=args.hyperlane_processes,
        hyperlane_observer_path=args.hyperlane_observer,
        hyperlane_observer_completion_path=args.hyperlane_observer_completion,
        root_signer_audit_path=args.root_signer_audit,
        incident_path=args.incidents,
        resource_monitor_path=args.resource_monitor,
        resource_segments_path=args.resource_segments,
        effect_baseline_path=args.effect_baseline,
        effect_audit_path=args.effect_audit,
        coordinator_signed_root=args.coordinator_signed_root,
        phase_authority_path=args.phase_authority,
        smoke_handoff_path=args.smoke_handoff,
        publication_smoke_handoff_path=args.publication_smoke_handoff,
        preregistration_path=args.preregistration,
        review_closure_path=args.review_closure,
        review_gate_path=args.review_gate,
        topology_path=args.topology,
        identity_manifest_path=args.identity_manifest,
        validator_volume_attestation_path=args.validator_volume_attestation,
        validator_volume_journal_path=args.validator_volume_journal,
        toolchain_preflight_path=args.toolchain_preflight,
        normalized_stage_schema_path=args.normalized_stage_schema,
        stage_template_schema_path=args.stage_template_schema,
        output_root=args.output_root,
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
