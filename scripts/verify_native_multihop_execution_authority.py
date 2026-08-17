#!/usr/bin/env python3
"""Verify the closure-bound review gate and active writer lease."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_execution import verify_execution_authority


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--review-gate", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--lease-token", type=Path, required=True)
    args = parser.parse_args()
    result = verify_execution_authority(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        runtime_root=args.runtime_root,
        preregistration_path=args.preregistration,
        review_gate_path=args.review_gate,
        lease_path=args.lease,
        lease_token_path=args.lease_token,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
