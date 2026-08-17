#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_publication import (
    build_multihop_handoff,
    compare_multihop_rebuilds,
)


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
    compare_multihop_rebuilds(
        source_publication=args.source_publication,
        rebuild_a=args.rebuild_a,
        rebuild_b=args.rebuild_b,
        output_path=args.comparison,
    )
    handoff = build_multihop_handoff(
        frozen_source_root=args.frozen_source,
        source_publication=args.source_publication,
        rebuild_a=args.rebuild_a,
        rebuild_b=args.rebuild_b,
        comparison_path=args.comparison,
        review_closure_path=args.review_closure,
        output_path=args.handoff,
    )
    print(json.dumps(handoff, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
