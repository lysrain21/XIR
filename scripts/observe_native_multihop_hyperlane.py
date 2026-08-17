#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_hyperlane_observer import observe_hyperlane_relayer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--relayer-address", required=True)
    parser.add_argument("--start-blocks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("--target-blocks", type=Path)
    parser.add_argument("--completion", type=Path)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    starts = json.loads(args.start_blocks.read_text(encoding="utf-8"))
    observe_hyperlane_relayer(
        profile_path=args.profile,
        runtime_root=args.runtime_root,
        relayer_address=args.relayer_address,
        start_blocks={str(key): int(value) for key, value in starts.items()},
        output_path=args.output,
        stop_file=args.stop_file,
        poll_seconds=args.poll_seconds,
        append=args.append,
        target_blocks_path=args.target_blocks,
        completion_path=args.completion,
        ready_path=args.ready,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
