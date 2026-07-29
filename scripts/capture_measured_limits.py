#!/usr/bin/env python3
"""Freeze rehearsal-derived batching and sampled container resource limits."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


def docker(*arguments: str) -> str:
    return subprocess.run(
        ("docker", *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def bytes_value(value: str) -> int:
    factors = {
        "B": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
    }
    normalized = value.strip().replace(" ", "")
    for unit in sorted(factors, key=len, reverse=True):
        if normalized.endswith(unit):
            return int(float(normalized.removesuffix(unit)) * factors[unit])
    raise ValueError(f"unsupported Docker memory value: {value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rehearsal-command", type=Path, required=True)
    parser.add_argument("--outage-evidence", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, required=True)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    rehearsal = json.loads(arguments.rehearsal_command.read_text(encoding="utf-8"))
    outage = json.loads(arguments.outage_evidence.read_text(encoding="utf-8"))
    summary = rehearsal["details"]["summary"]
    names = docker(
        "ps",
        "--filter",
        "label=org.xir.environment=controlled-local-qbft",
        "--format",
        "{{.Names}}",
    ).splitlines()
    if len(names) != 12 or outage.get("eligible") is not True:
        raise RuntimeError("twelve healthy validators and outage recovery are required")

    aggregate_cpu_samples: list[float] = []
    aggregate_memory_samples: list[int] = []
    for index in range(arguments.samples):
        rows = docker(
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            *names,
        ).splitlines()
        values: list[dict[str, Any]] = [json.loads(row) for row in rows]
        aggregate_cpu_samples.append(
            sum(float(item["CPUPerc"].removesuffix("%")) for item in values)
        )
        aggregate_memory_samples.append(
            sum(bytes_value(item["MemUsage"].split("/", 1)[0]) for item in values)
        )
        if index + 1 < arguments.samples:
            time.sleep(1)

    inspections = json.loads(docker("inspect", *names))
    configured_memory = sum(int(item["HostConfig"]["Memory"]) for item in inspections)
    per_validator_memory_limits = {
        item["Name"].removeprefix("/"): int(item["HostConfig"]["Memory"])
        for item in inspections
    }
    if min(per_validator_memory_limits.values()) < 1024**3:
        raise RuntimeError("every validator requires at least 1 GiB")
    configured_cpu = sum(
        int(item["HostConfig"]["NanoCpus"]) / 1_000_000_000 * 100
        for item in inspections
    )
    runtime_usage = shutil.disk_usage(arguments.runtime_root)
    rehearsal_database = arguments.runtime_root / "evidence" / "rehearsal.sqlite"
    rehearsal_database_bytes = rehearsal_database.stat().st_size
    projected_scale_evidence_bytes = rehearsal_database_bytes * 40
    frozen_reserve_bytes = 6 * 1024**3
    if runtime_usage.free < projected_scale_evidence_bytes + frozen_reserve_bytes:
        raise RuntimeError("projected scale evidence violates filesystem reserve")
    document = {
        "schema_version": "xir-lab-local-measured-limits-v1",
        "measurement_scope": "five post-rehearsal container snapshots",
        "batch_size": arguments.batch_size,
        "rehearsal_attempts": summary["attempts"],
        "rehearsal_physical_transactions": summary["physical_transactions"],
        "rehearsal_elapsed_seconds": summary["elapsed_seconds"],
        "rehearsal_physical_transactions_per_second": (
            summary["physical_transactions"] / summary["elapsed_seconds"]
        ),
        "peak_cpu_percent": max(aggregate_cpu_samples),
        "peak_memory_bytes": max(aggregate_memory_samples),
        "configured_cpu_ceiling_percent": configured_cpu,
        "configured_memory_ceiling_bytes": configured_memory,
        "per_validator_memory_limit_bytes": per_validator_memory_limits,
        "minimum_validator_memory_limit_bytes": min(
            per_validator_memory_limits.values()
        ),
        "rehearsal_database_bytes": rehearsal_database_bytes,
        "projected_scale_evidence_bytes": projected_scale_evidence_bytes,
        "runtime_filesystem_available_bytes": runtime_usage.free,
        "frozen_filesystem_reserve_bytes": frozen_reserve_bytes,
        "cpu_samples_percent": aggregate_cpu_samples,
        "memory_samples_bytes": aggregate_memory_samples,
        "restart_outcomes": [
            (
                f"{outage['network_id']}/{outage['stopped_validator']}:"
                "continued-finality-and-caught-up"
            )
        ],
        "claim_note": (
            "Resource peaks are sampled controlled-host observations, not "
            "production capacity or public-network measurements."
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
