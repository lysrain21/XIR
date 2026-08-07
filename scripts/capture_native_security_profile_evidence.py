#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.security_v1_profile_evidence import capture_profile_transactions


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("Freeze public setProfile transaction inputs for native-security-v1.")
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--rpc-url", required=True)
    args = parser.parse_args()
    result = capture_profile_transactions(
        config_path=args.config,
        deployment_path=args.deployment,
        evidence_root=args.evidence_root,
        rpc_url=args.rpc_url,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
