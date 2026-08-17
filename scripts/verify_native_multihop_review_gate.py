#!/usr/bin/env python3
"""Fail closed before any five-chain deployment transaction is submitted."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_preflight import verify_multihop_review_gate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = verify_multihop_review_gate(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        preregistration_path=args.preregistration,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"semantic_sha256={document['semantic_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
