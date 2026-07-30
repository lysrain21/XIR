#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.deployer import NativeApplicationDeployer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    private_key = args.key_file.read_text(encoding="utf-8").strip()
    from eth_account import Account

    runner_address = Account.from_key(
        args.runner_key_file.read_text(encoding="utf-8").strip()
    ).address
    deployer = NativeApplicationDeployer(
        repository_root=repository_root,
        runtime_root=args.runtime_root,
        profile_path=args.profile,
        private_key=private_key,
        runner_address=runner_address,
    )
    deployer.run()


if __name__ == "__main__":
    main()
