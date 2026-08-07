#!/usr/bin/env python3
"""Run the official LayerZero worker with a native-faults-v1 state wrapper."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from requests import RequestException
from web3.exceptions import Web3RPCError

from xir_lab.native.faults_v1 import (
    FAULT_EXIT_CODE,
    FaultingLayerZeroWorkerState,
    FaultInjector,
    FaultLedger,
    InjectedNativeFault,
)
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
    parser.add_argument("--fault-ledger", type=Path, required=True)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--batch-packets", type=int, default=1)
    args = parser.parse_args()

    state = LayerZeroWorkerState(args.state)
    injector = FaultInjector(
        ledger=FaultLedger(args.fault_ledger), actor="worker", attempt_id=None
    )
    worker = LayerZeroWorker(
        chains=load_worker_chains(args.config),
        private_key=args.key_file.read_text(encoding="utf-8").strip(),
        state=FaultingLayerZeroWorkerState(state, injector),  # type: ignore[arg-type]
        raw_root=args.raw_root,
        batch_packets=args.batch_packets,
    )
    transient_error_count = 0
    try:
        while True:
            try:
                worker.collect()
                worker.process()
            except (RequestException, Web3RPCError) as exc:
                if not is_transient_rpc_error(exc) or args.command == "once":
                    raise
                transient_error_count += 1
                print(
                    json.dumps(
                        {
                            "event": "transient_rpc_error",
                            "error_class": type(exc).__name__,
                            "retry_count": transient_error_count,
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
    except InjectedNativeFault as exc:
        print(
            json.dumps(
                {"event": "controlled_worker_exit", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(FAULT_EXIT_CODE) from exc


if __name__ == "__main__":
    main()
