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
from xir_lab.native.multihop_execution import verify_multihop_profile_write_authority
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
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--preregistration", type=Path)
    parser.add_argument("--review-gate", type=Path)
    parser.add_argument("--lease", type=Path)
    parser.add_argument("--lease-token", type=Path)
    args = parser.parse_args()
    runtime_root = args.runtime_root
    multihop_profile = False
    if runtime_root is not None:
        profile_path = runtime_root / "profile.json"
        if profile_path.is_file():
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            multihop_profile = (
                profile.get("schema_version") == "xir-lab-native-multihop-five-chain-profile-v1"
            )
            verify_multihop_profile_write_authority(
                profile=profile,
                workspace_root=args.workspace_root,
                repository_root=args.repository_root,
                runtime_root=runtime_root,
                preregistration_path=args.preregistration,
                review_gate_path=args.review_gate,
                lease_path=args.lease,
                lease_token_path=args.lease_token,
            )
    config = json.loads(args.config.read_text(encoding="utf-8"))
    config_chains = config.get("chains")
    five_chain_config = isinstance(config_chains, list) and len(config_chains) == 5
    if five_chain_config:
        if config.get("schema_version") != "xir-lab-layerzero-worker-config-v1":
            raise RuntimeError("five-chain multihop worker config schema is missing or invalid")
        if runtime_root is None:
            raise RuntimeError(
                "five-chain multihop worker requires review closure and live lease authority"
            )
        if not multihop_profile:
            raise RuntimeError("five-chain multihop worker profile is unavailable")
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
