#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_account import Account

from xir_lab.native.hyperlane import HyperlanePublicIdentities
from xir_lab.native.multihop_hyperlane import (
    capture_multihop_hyperlane_deployment_evidence,
    materialize_multihop_hyperlane_registry,
    render_multihop_hyperlane_agent_configs,
    render_multihop_hyperlane_deployment_inputs,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "stage", choices=("deployment", "registry", "agents", "evidence")
    )
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--validator-address")
    parser.add_argument("--relayer-address")
    parser.add_argument("--owner-address")
    parser.add_argument("--start-blocks", type=Path)
    parser.add_argument("--end-blocks", type=Path)
    args = parser.parse_args()
    if args.stage == "deployment":
        if args.key_file is None or not args.validator_address or not args.relayer_address:
            parser.error("deployment requires key, validator, and relayer")
        account = Account.from_key(args.key_file.read_text(encoding="ascii").strip())
        render_multihop_hyperlane_deployment_inputs(
            profile_path=args.profile,
            identities=HyperlanePublicIdentities(
                owner_address=account.address,
                validator_address=args.validator_address,
                relayer_address=args.relayer_address,
            ),
            runtime_root=args.runtime_root,
        )
    elif args.stage == "registry":
        materialize_multihop_hyperlane_registry(
            profile_path=args.profile, runtime_root=args.runtime_root
        )
    elif args.stage == "agents":
        render_multihop_hyperlane_agent_configs(
            profile_path=args.profile, runtime_root=args.runtime_root
        )
    else:
        if not args.owner_address or args.start_blocks is None:
            parser.error("evidence requires owner-address and start-blocks")
        starts = json.loads(args.start_blocks.read_text(encoding="utf-8"))
        ends = (
            None
            if args.end_blocks is None
            else json.loads(args.end_blocks.read_text(encoding="utf-8"))
        )
        capture_multihop_hyperlane_deployment_evidence(
            profile_path=args.profile,
            runtime_root=args.runtime_root,
            owner_address=args.owner_address,
            start_blocks={str(key): int(value) for key, value in starts.items()},
            end_blocks=(
                None
                if ends is None
                else {str(key): int(value) for key, value in ends.items()}
            ),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
