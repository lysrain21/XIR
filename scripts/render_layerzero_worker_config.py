#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    chains = []
    for item in profile["chains"]:
        chain_id = int(item["chain_id"])
        deployment = json.loads(
            (
                args.runtime_root
                / "layerzero"
                / "deployments"
                / f"{chain_id}.json"
            ).read_text(encoding="utf-8")
        )
        contracts = deployment["contracts"]
        start_block = int(
            (
                args.runtime_root
                / "layerzero"
                / "deployments"
                / f"{chain_id}.start-block"
            ).read_text(encoding="utf-8")
        )
        chains.append(
            {
                "chain_id": chain_id,
                "eid": int(item["layerzero_eid"]),
                "rpc_url": item["rpc_url"],
                "endpoint": contracts["endpoint_v2"],
                "receive_uln": contracts["receive_uln_302"],
                "dvn": contracts["dvn"],
                "executor": contracts["executor"],
                "start_block": start_block,
            }
        )
    document = {
        "schema_version": "xir-lab-layerzero-worker-config-v1",
        "classification": "self-hosted-research-worker",
        "managed_layerzero_service": False,
        "chains": chains,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
