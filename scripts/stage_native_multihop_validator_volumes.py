#!/usr/bin/env python3
"""Create, verify, or remove authority-bound multihop validator volumes."""

from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.localnet.multihop_volume_bootstrap import (
    build_validator_volume_plan,
    recover_validator_volume_transaction,
    remove_existing_validator_volumes,
    stage_validator_volumes,
    verify_existing_validator_volumes,
)
from xir_lab.native.multihop_execution import verify_execution_authority


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("stage", "verify-existing", "remove-existing", "recover-incomplete"),
    )
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--identity-manifest", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--review-gate", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--lease-token", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--recovery-output", type=Path)
    parser.add_argument("--failure-output", type=Path)
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
    plan = build_validator_volume_plan(
        runtime_root=args.runtime_root,
        topology_path=args.topology,
        identity_manifest_path=args.identity_manifest,
        compose_path=args.compose,
    )
    if args.action == "stage":
        if args.failure_output is None:
            parser.error("stage requires --failure-output")
        document = stage_validator_volumes(
            plan=plan,
            runtime_root=args.runtime_root,
            output_path=args.attestation,
            journal_path=args.journal,
            failure_output_path=args.failure_output,
        )
        print(f"validator_volumes={document['validator_volume_count']}")
        print(f"semantic_sha256={document['semantic_sha256']}")
    elif args.action == "verify-existing":
        document = verify_existing_validator_volumes(
            plan=plan,
            runtime_root=args.runtime_root,
            attestation_path=args.attestation,
            journal_path=args.journal,
        )
        print(f"validator_volumes={document['validator_volume_count']}")
        print(f"semantic_sha256={document['semantic_sha256']}")
    elif args.action == "remove-existing":
        if args.recovery_output is None:
            parser.error("remove-existing requires --recovery-output")
        remove_existing_validator_volumes(
            plan=plan,
            runtime_root=args.runtime_root,
            attestation_path=args.attestation,
            journal_path=args.journal,
            recovery_output_path=args.recovery_output,
        )
        print("validator_volumes_removed=20")
    else:
        if args.recovery_output is None:
            parser.error("recover-incomplete requires --recovery-output")
        document = recover_validator_volume_transaction(
            plan=plan,
            runtime_root=args.runtime_root,
            journal_path=args.journal,
            recovery_output_path=args.recovery_output,
        )
        print(f"validator_volume_recovery={document['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
