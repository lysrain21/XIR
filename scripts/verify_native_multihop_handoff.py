#!/usr/bin/env python3
"""Recompute and verify one persisted multihop phase handoff."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_publication import verify_multihop_handoff


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-source", type=Path, required=True)
    parser.add_argument("--source-publication", type=Path, required=True)
    parser.add_argument("--rebuild-a", type=Path, required=True)
    parser.add_argument("--rebuild-b", type=Path, required=True)
    parser.add_argument("--review-closure", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    args = parser.parse_args()
    handoff = verify_multihop_handoff(
        frozen_source_root=args.frozen_source,
        source_publication=args.source_publication,
        rebuild_a=args.rebuild_a,
        rebuild_b=args.rebuild_b,
        comparison_path=args.comparison,
        review_closure_path=args.review_closure,
        handoff_path=args.handoff,
    )
    print(json.dumps(handoff, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
