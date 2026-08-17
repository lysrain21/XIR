#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from xir_lab.native.multihop_analysis import publish_multihop_analysis
from xir_lab.native.multihop_scalability import MultihopPhase


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--component-lock", type=Path)
    parser.add_argument("--source-lock-root", type=Path)
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"), required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--worker-state", type=Path, required=True)
    parser.add_argument("--hyperlane-processes", type=Path, required=True)
    parser.add_argument("--root-signer-audit", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--trace-state", type=Path, required=True)
    parser.add_argument("--incidents", type=Path, required=True)
    parser.add_argument("--resource-monitor", type=Path, required=True)
    parser.add_argument("--effect-audit", type=Path, required=True)
    parser.add_argument("--provenance-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    manifest = publish_multihop_analysis(
        config_path=args.config,
        profile_path=args.profile,
        component_lock_path=args.component_lock,
        source_lock_root=args.source_lock_root,
        phase=cast(MultihopPhase, args.phase),
        runner_state_path=args.runner_state,
        worker_state_path=args.worker_state,
        hyperlane_process_path=args.hyperlane_processes,
        root_signer_audit_path=args.root_signer_audit,
        deployment_path=args.deployment,
        trace_state_path=args.trace_state,
        incident_path=args.incidents,
        resource_monitor_path=args.resource_monitor,
        effect_audit_path=args.effect_audit,
        provenance_root=args.provenance_root,
        output_root=args.output_root,
    )
    print(f"semantic_sha256={manifest['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
