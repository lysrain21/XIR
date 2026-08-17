#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.gateway_deployment import (
    analyze_gateway_deployment,
    publish_gateway_deployment_document,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--mainnet", type=Path, required=True)
    parser.add_argument("--semantic", type=Path, required=True)
    parser.add_argument("--multihop-deployment", type=Path, required=True)
    parser.add_argument("--hyperlane-evidence", type=Path, required=True)
    parser.add_argument("--layerzero-evidence", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    document = analyze_gateway_deployment(
        topology_path=args.topology,
        mainnet_path=args.mainnet,
        semantic_path=args.semantic,
        multihop_deployment_path=args.multihop_deployment,
        hyperlane_evidence_path=args.hyperlane_evidence,
        layerzero_evidence_path=args.layerzero_evidence,
    )
    manifest = publish_gateway_deployment_document(
        document=document,
        output_root=args.output_root,
        topology_path=args.topology,
        mainnet_path=args.mainnet,
        semantic_path=args.semantic,
        multihop_deployment_path=args.multihop_deployment,
        hyperlane_evidence_path=args.hyperlane_evidence,
        layerzero_evidence_path=args.layerzero_evidence,
    )
    print(f"semantic_sha256={manifest['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
