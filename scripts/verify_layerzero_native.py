#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.layerzero import (
    FORMAL_COMPONENTS,
    inspect_layerzero_effective_configuration,
    verify_formal_component_set,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--subject-address", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    all_eids = [int(chain["layerzero_eid"]) for chain in profile["chains"]]
    chains = []
    verify_formal_component_set(set(FORMAL_COMPONENTS))
    for chain in profile["chains"]:
        chain_id = int(chain["chain_id"])
        deployment = json.loads(
            (
                args.runtime_root
                / "layerzero"
                / "deployments"
                / f"{chain_id}.json"
            ).read_text(encoding="utf-8")
        )
        local_eid = int(chain["layerzero_eid"])
        chains.append(
            inspect_layerzero_effective_configuration(
                rpc_url=chain["rpc_url"],
                local_eid=local_eid,
                remote_eids=[eid for eid in all_eids if eid != local_eid],
                subject_address=args.subject_address,
                contracts=deployment["contracts"],
            )
        )
    document = {
        "schema_version": "xir-lab-layerzero-effective-config-v1",
        "formal_components": sorted(FORMAL_COMPONENTS),
        "forbidden_components_present": [],
        "worker_classification": "self-hosted-research-worker",
        "managed_layerzero_service": False,
        "chains": chains,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
