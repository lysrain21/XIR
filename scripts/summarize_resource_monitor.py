#!/usr/bin/env python3
"""Summarize scale resource samples and validator restart counts."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    rows: list[dict[str, Any]] = []
    for path in arguments.input:
        rows.extend(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        )
    if not rows or any(item["container_count"] != 12 for item in rows):
        raise RuntimeError("resource evidence requires twelve-container samples")

    names = subprocess.run(
        (
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=org.xir.environment=controlled-local-qbft",
            "--format",
            "{{.Names}}",
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    inspections = json.loads(
        subprocess.run(
            ("docker", "inspect", *names),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    restart_counts = {
        item["Name"].removeprefix("/"): int(item["RestartCount"])
        for item in inspections
    }
    restart_outcomes = [
        f"{name}:automatic-restart-and-health-recovery"
        for name, count in sorted(restart_counts.items())
        if count > 0
    ]
    document = {
        "schema_version": "xir-lab-local-scale-resources-v1",
        "sample_count": len(rows),
        "sampled_from": rows[0]["observed_at"],
        "sampled_through": rows[-1]["observed_at"],
        "peak_cpu_percent": max(item["aggregate_cpu_percent"] for item in rows),
        "peak_memory_bytes": max(item["aggregate_memory_bytes"] for item in rows),
        "validator_restart_counts": restart_counts,
        "restart_outcomes": restart_outcomes,
        "coverage_note": (
            "Samples cover both main scale execution segments; the final "
            "100-transaction recovery tail is represented by final health "
            "and restart evidence but was not resource-sampled."
        ),
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
