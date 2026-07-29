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
    names_in_samples = sorted(
        {
            str(container["name"])
            for row in rows
            for container in row.get("containers", [])
        }
    )
    if len(names_in_samples) != 12:
        raise RuntimeError("resource evidence lacks per-validator samples")

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
    per_validator: dict[str, dict[str, Any]] = {}
    for name in names_in_samples:
        samples = [
            container
            for row in rows
            for container in row["containers"]
            if container["name"] == name
        ]
        per_validator[name] = {
            "sample_count": len(samples),
            "peak_cpu_percent": max(item["cpu_percent"] for item in samples),
            "peak_memory_bytes": max(item["memory_bytes"] for item in samples),
            "memory_limit_bytes": samples[0]["memory_limit_bytes"],
            "network_rx_bytes_delta": (
                samples[-1]["network_rx_bytes"] - samples[0]["network_rx_bytes"]
            ),
            "network_tx_bytes_delta": (
                samples[-1]["network_tx_bytes"] - samples[0]["network_tx_bytes"]
            ),
            "block_read_bytes_delta": (
                samples[-1]["block_read_bytes"] - samples[0]["block_read_bytes"]
            ),
            "block_write_bytes_delta": (
                samples[-1]["block_write_bytes"] - samples[0]["block_write_bytes"]
            ),
            "max_sampled_restart_count": max(
                item["restart_count"] for item in samples
            ),
            "unhealthy_sample_count": sum(
                item["health"] != "healthy" for item in samples
            ),
        }
    document = {
        "schema_version": "xir-lab-local-scale-resources-v1",
        "sample_count": len(rows),
        "sampled_from": rows[0]["observed_at"],
        "sampled_through": rows[-1]["observed_at"],
        "peak_cpu_percent": max(item["aggregate_cpu_percent"] for item in rows),
        "peak_memory_bytes": max(item["aggregate_memory_bytes"] for item in rows),
        "peak_host_load_average_1m": max(
            item["host"]["load_average_1m"] for item in rows
        ),
        "minimum_host_memory_available_bytes": min(
            item["host"]["memory_available_bytes"] for item in rows
        ),
        "minimum_runtime_filesystem_available_bytes": min(
            item.get("runtime_filesystem", {}).get(
                "available_bytes", 2**63 - 1
            )
            for item in rows
        ),
        "per_validator": per_validator,
        "validator_restart_counts": restart_counts,
        "restart_outcomes": restart_outcomes,
        "coverage_note": "Samples cover the full designated scale command interval.",
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
