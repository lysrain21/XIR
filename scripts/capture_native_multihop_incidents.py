#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_analysis import capture_multihop_incidents


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--worker-state", type=Path, required=True)
    parser.add_argument("--hyperlane-processes", type=Path, required=True)
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = capture_multihop_incidents(
        runner_state_path=args.runner_state,
        worker_state_path=args.worker_state,
        hyperlane_process_path=args.hyperlane_processes,
        phase=args.phase,
        output_path=args.output,
    )
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
