#!/usr/bin/env python3
"""Record, verify, or signal a multihop process using durable identity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_process_identity import (
    record_process_identity,
    signal_verified_process,
    verify_process_identity,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("record", "verify", "signal"))
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--expected-token")
    parser.add_argument("--signal", choices=("SIGCONT", "SIGTERM", "SIGKILL"))
    args = parser.parse_args()
    if args.action == "record":
        if args.pid is None or args.runtime_root is None or args.expected_token is None:
            parser.error("record requires --pid, --runtime-root, and --expected-token")
        document = record_process_identity(
            pid=args.pid,
            identity_path=args.identity,
            runtime_root=args.runtime_root,
            expected_token=args.expected_token,
        )
    elif args.action == "signal":
        if args.signal is None:
            parser.error("signal requires --signal")
        document = signal_verified_process(args.identity, args.signal)
    else:
        document = verify_process_identity(args.identity)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
