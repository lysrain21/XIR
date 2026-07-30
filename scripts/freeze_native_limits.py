#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("--batch-attempts", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    samples: list[dict[str, Any]] = [
        json.loads(line)
        for line in args.resources.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if (
        analysis.get("reconciled") is not True
        or analysis.get("resource_sampling_gaps") != 0
        or not samples
    ):
        raise SystemExit("measured limits require reconciled gap-free rehearsal")
    queues = [
        int(sample["queues"]["layerzero"].get("observed", 0))
        for sample in samples
        if "observed" in sample.get("queues", {}).get("layerzero", {})
    ]
    payload = {
        "schema_version": "xir-lab-native-measured-limits-v1",
        "eligible": True,
        "concurrency": args.concurrency,
        "batch_attempts": args.batch_attempts,
        "layerzero_batch_packets": 100,
        "confirmation_depth": 1,
        "monitor_interval_seconds": 5,
        "rehearsal_wall_seconds": analysis["phase_wall_seconds"],
        "rehearsal_throughput_logical_attempts_per_second": analysis[
            "throughput_logical_attempts_per_second"
        ],
        "maximum_observed_layerzero_pending_packets": max(queues, default=0),
        "resource_extrema": analysis["resource_extrema"],
    }
    payload["semantic_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
