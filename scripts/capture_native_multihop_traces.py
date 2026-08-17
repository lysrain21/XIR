#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_traces import capture_multihop_traces


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"), required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--worker-state", type=Path, required=True)
    parser.add_argument("--hyperlane-processes", type=Path, required=True)
    parser.add_argument("--root-signer-audit", type=Path, required=True)
    parser.add_argument("--trace-state", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()
    summary = capture_multihop_traces(
        repository_root=args.repository_root,
        config_path=args.config,
        deployment_path=args.deployment,
        phase=args.phase,
        runner_state_path=args.runner_state,
        worker_state_path=args.worker_state,
        hyperlane_process_path=args.hyperlane_processes,
        root_signer_audit_path=args.root_signer_audit,
        trace_state_path=args.trace_state,
        concurrency=args.concurrency,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
