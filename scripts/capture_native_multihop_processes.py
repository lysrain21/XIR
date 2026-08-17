#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_analysis import capture_hyperlane_processes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--start-blocks", type=Path, required=True)
    parser.add_argument("--end-blocks", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    starts = json.loads(args.start_blocks.read_text(encoding="utf-8"))
    ends = json.loads(args.end_blocks.read_text(encoding="utf-8"))
    document = capture_hyperlane_processes(
        profile_path=args.profile,
        runtime_root=args.runtime_root,
        start_blocks={str(key): int(value) for key, value in starts.items()},
        end_blocks={str(key): int(value) for key, value in ends.items()},
        observer_path=args.observer,
        output_path=args.output,
    )
    print(f"messages={len(document['messages'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
