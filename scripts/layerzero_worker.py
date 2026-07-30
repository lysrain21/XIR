#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from pathlib import Path

from xir_lab.native.layerzero_worker import (
    LayerZeroWorker,
    LayerZeroWorkerState,
    load_worker_chains,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("once", "run"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--batch-packets", type=int, default=100)
    args = parser.parse_args()
    private_key = args.key_file.read_text(encoding="utf-8").strip()
    worker = LayerZeroWorker(
        chains=load_worker_chains(args.config),
        private_key=private_key,
        state=LayerZeroWorkerState(args.state),
        raw_root=args.raw_root,
        batch_packets=args.batch_packets,
    )
    while True:
        worker.collect()
        worker.process()
        if args.command == "once":
            return
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
