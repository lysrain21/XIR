#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from eth_account import Account

from xir_lab.native.ablation_v1 import NativeAblationDeployer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--base-deployment", type=Path, required=True)
    parser.add_argument("--deployer-key-file", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    args = parser.parse_args()
    runner_key = args.runner_key_file.read_text(encoding="utf-8").strip()
    deployer = NativeAblationDeployer(
        repository_root=Path(__file__).resolve().parents[1],
        runtime_root=args.runtime_root,
        profile_path=args.profile,
        base_deployment_path=args.base_deployment,
        deployer_private_key=args.deployer_key_file.read_text(encoding="utf-8").strip(),
        runner_address=Account.from_key(runner_key).address,
    )
    document = deployer.run()
    print(args.runtime_root / "native-ablation-v1" / "deployment" / "deployment.json")
    print(document["base_deployment_sha256"])


if __name__ == "__main__":
    main()
