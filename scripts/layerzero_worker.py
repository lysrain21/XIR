#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from requests import RequestException
from web3.exceptions import Web3RPCError

from xir_lab.native.layerzero_worker import (
    LayerZeroWorker,
    LayerZeroWorkerState,
    load_worker_chains,
)
from xir_lab.native.rpc import is_transient_rpc_error


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
    transient_error_count = 0
    while True:
        try:
            worker.collect()
            worker.process()
        except (RequestException, Web3RPCError) as exc:
            if not is_transient_rpc_error(exc):
                raise
            if args.command == "once":
                raise
            transient_error_count += 1
            print(
                json.dumps(
                    {
                        "event": "transient_rpc_error",
                        "error_class": type(exc).__name__,
                        "error": str(exc),
                        "retry_count": transient_error_count,
                        "retry_delay_seconds": args.poll_seconds,
                        "observed_at": time.time(),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            time.sleep(args.poll_seconds)
            continue
        if args.command == "once":
            return
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
