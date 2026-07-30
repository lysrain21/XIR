#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from eth_account import Account

from xir_lab.native.hyperlane import (
    HyperlanePublicIdentities,
    render_hyperlane_agent_configs,
    render_hyperlane_deployment_inputs,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("deployment", "agents"))
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--validator-address")
    parser.add_argument("--relayer-address")
    args = parser.parse_args()
    if args.stage == "deployment":
        if args.key_file is None:
            parser.error("--key-file is required for deployment rendering")
        account = Account.from_key(
            args.key_file.read_text(encoding="utf-8").strip()
        )
        if args.validator_address is None or args.relayer_address is None:
            parser.error(
                "--validator-address and --relayer-address are required for deployment rendering"
            )
        render_hyperlane_deployment_inputs(
            profile_path=args.profile,
            identities=HyperlanePublicIdentities(
                owner_address=account.address,
                validator_address=args.validator_address,
                relayer_address=args.relayer_address,
            ),
            runtime_root=args.runtime_root,
        )
    else:
        render_hyperlane_agent_configs(
            profile_path=args.profile, runtime_root=args.runtime_root
        )


if __name__ == "__main__":
    main()
