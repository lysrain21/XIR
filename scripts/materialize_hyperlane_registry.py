#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

NAMES = {
    "source": "xirlocalsource",
    "intermediate": "xirlocalintermediate",
    "destination": "xirlocaldestination",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    for chain in profile["chains"]:
        deployment = json.loads(
            (
                args.runtime_root
                / "hyperlane"
                / "native-deployments"
                / f"{chain['chain_id']}.json"
            ).read_text(encoding="utf-8")
        )
        contracts = deployment["contracts"]
        addresses = {
            "mailbox": contracts["mailbox"],
            "merkleTreeHook": contracts["merkleTreeHook"],
            "validatorAnnounce": contracts["validatorAnnounce"],
            "defaultIsm": contracts["defaultIsm"],
            "staticMessageIdMultisigIsmFactory": contracts[
                "staticMessageIdMultisigIsmFactory"
            ],
            "protocolFee": contracts["protocolFee"],
            # Hyperlane 5857ead requires this key even when enforcement is
            # disabled. The locked London chains cannot execute its Cancun-only
            # IGP implementation, so this non-used compatibility field points
            # to a deployed official ProtocolFee hook and is disclosed below.
            "interchainGasPaymaster": contracts["protocolFee"],
        }
        path = (
            args.runtime_root
            / "hyperlane"
            / "registry"
            / "chains"
            / NAMES[chain["route_role"]]
            / "addresses.yaml"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(addresses, sort_keys=True), encoding="utf-8"
        )
    compatibility = {
        "schema_version": "xir-lab-hyperlane-agent-compatibility-v1",
        "hyperlane_commit": "5857ead81a8783d168d48d370be72de88d5fb230",
        "locked_evm_version": "london",
        "agent_required_field": "interchainGasPaymaster",
        "configured_address_kind": "official-ProtocolFee-hook-alias",
        "igp_deployed": False,
        "igp_called_by_formal_workload": False,
        "gas_payment_enforcement": "none",
        "reason": (
            "The pinned IGP source uses Cancun TSTORE/TLOAD and cannot be "
            "compiled for the retained London chains."
        ),
    }
    compatibility_path = (
        args.runtime_root / "hyperlane" / "agent-compatibility.json"
    )
    compatibility_path.write_text(
        json.dumps(compatibility, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
