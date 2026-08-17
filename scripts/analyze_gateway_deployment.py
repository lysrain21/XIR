#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.gateway_deployment import analyze_gateway_deployment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--mainnet", type=Path, required=True)
    parser.add_argument("--semantic", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--multihop-deployment", type=Path)
    parser.add_argument("--hyperlane-evidence", type=Path)
    parser.add_argument("--layerzero-evidence", type=Path)
    args = parser.parse_args()
    document = analyze_gateway_deployment(
        topology_path=args.topology,
        mainnet_path=args.mainnet,
        semantic_path=args.semantic,
        multihop_deployment_path=args.multihop_deployment,
        hyperlane_evidence_path=args.hyperlane_evidence,
        layerzero_evidence_path=args.layerzero_evidence,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"semantic_sha256={document['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
