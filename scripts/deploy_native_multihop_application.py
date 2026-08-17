#!/usr/bin/env python3
"""Deploy the fresh five-chain route-specific native multihop application."""

from __future__ import annotations

import argparse
from pathlib import Path

from eth_account import Account

from xir_lab.native.multihop_deployer import NativeMultihopDeployer
from xir_lab.native.multihop_execution import verify_execution_authority


def _key(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    return value if value.startswith("0x") else "0x" + value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--review-gate", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--lease-token", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployer-key-file", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    parser.add_argument("--root-signer-key-file", type=Path, required=True)
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
    runner = Account.from_key(_key(args.runner_key_file)).address
    root_signer = Account.from_key(_key(args.root_signer_key_file)).address
    deployer = NativeMultihopDeployer(
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        profile_path=args.profile,
        private_key=_key(args.deployer_key_file),
        runner_address=runner,
        root_signer_address=root_signer,
    )
    document = deployer.run()
    print(f"deployment_sha256={document['deployment_sha256']}")
    print(f"deployment_transactions={document['deployment_gas']['transaction_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
