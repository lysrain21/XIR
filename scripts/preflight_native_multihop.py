#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_execution import verify_execution_authority
from xir_lab.native.multihop_preflight import run_multihop_preflight


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--review-gate", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--lease-token", type=Path, required=True)
    parser.add_argument("--validator-volume-attestation", type=Path, required=True)
    parser.add_argument("--validator-volume-journal", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_execution_authority(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        preregistration_path=args.preregistration,
        review_gate_path=args.review_gate,
        lease_path=args.lease,
        lease_token_path=args.lease_token,
    )
    document = run_multihop_preflight(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        topology_path=args.topology,
        identity_path=args.identity,
        config_path=args.config,
        deployment_path=args.deployment,
        preregistration_path=args.preregistration,
        review_gate_path=args.review_gate,
        validator_volume_attestation_path=args.validator_volume_attestation,
        validator_volume_journal_path=args.validator_volume_journal,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"semantic_sha256={document['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
