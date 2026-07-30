#!/usr/bin/env python3
"""Capture and verify official Hyperlane deployment evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.hyperlane import capture_hyperlane_deployment_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--owner-address", required=True)
    parser.add_argument("--start-blocks", type=Path, required=True)
    parser.add_argument("--end-blocks", type=Path)
    args = parser.parse_args()
    start_blocks = json.loads(args.start_blocks.read_text(encoding="utf-8"))
    if not isinstance(start_blocks, dict):
        raise SystemExit("start-blocks root must be an object")
    end_blocks = (
        None
        if args.end_blocks is None
        else json.loads(args.end_blocks.read_text(encoding="utf-8"))
    )
    if end_blocks is not None and not isinstance(end_blocks, dict):
        raise SystemExit("end-blocks root must be an object")
    document = capture_hyperlane_deployment_evidence(
        profile_path=args.profile,
        runtime_root=args.runtime_root,
        owner_address=args.owner_address,
        start_blocks={str(key): int(value) for key, value in start_blocks.items()},
        end_blocks=(
            None
            if end_blocks is None
            else {str(key): int(value) for key, value in end_blocks.items()}
        ),
    )
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
