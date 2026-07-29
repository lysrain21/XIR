#!/usr/bin/env python3
"""Sample aggregate XIR validator resources until a stop marker appears."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
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
        "kB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--runtime-root", type=Path)
    arguments = parser.parse_args()
    names = docker(
        "ps",
        "--filter",
        "label=org.xir.environment=controlled-local-qbft",
        "--format",
        "{{.Names}}",
    ).splitlines()
    if len(names) != 12:
        raise RuntimeError("resource monitor requires exactly twelve validators")

    with arguments.output.open("x", encoding="utf-8") as stream:
        while not arguments.stop_file.exists():
            rows = docker(
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                *names,
            ).splitlines()
            values: list[dict[str, Any]] = [json.loads(row) for row in rows]
            inspections = {
                item["Name"].removeprefix("/"): item
                for item in json.loads(docker("inspect", *names))
            }
            containers = []
            for item in values:
                name = str(item["Name"])
                network_rx, network_tx = (
                    bytes_value(value) for value in item["NetIO"].split("/")
                )
                block_read, block_write = (
                    bytes_value(value) for value in item["BlockIO"].split("/")
                )
                inspection = inspections[name]
                containers.append(
                    {
                        "name": name,
                        "cpu_percent": float(item["CPUPerc"].removesuffix("%")),
                        "memory_bytes": bytes_value(
                            item["MemUsage"].split("/", 1)[0]
                        ),
                        "memory_limit_bytes": int(
                            inspection["HostConfig"]["Memory"]
                        ),
                        "network_rx_bytes": network_rx,
                        "network_tx_bytes": network_tx,
                        "block_read_bytes": block_read,
                        "block_write_bytes": block_write,
                        "restart_count": int(inspection["RestartCount"]),
                        "health": inspection["State"]
                        .get("Health", {})
                        .get("Status", "none"),
                    }
                )
            memory: dict[str, int] = {}
            for line in Path("/proc/meminfo").read_text(
                encoding="utf-8"
            ).splitlines():
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    key, value, _ = line.split()
                    memory[key.removesuffix(":")] = int(value) * 1024
            sample = {
                "observed_at": datetime.now(UTC).isoformat(),
                "container_count": len(values),
                "containers": containers,
                "aggregate_cpu_percent": sum(
                    item["cpu_percent"] for item in containers
                ),
                "aggregate_memory_bytes": sum(
                    item["memory_bytes"] for item in containers
                ),
                "host": {
                    "load_average_1m": os.getloadavg()[0],
                    "memory_total_bytes": memory["MemTotal"],
                    "memory_available_bytes": memory["MemAvailable"],
                },
            }
            if arguments.runtime_root is not None:
                usage = shutil.disk_usage(arguments.runtime_root)
                sample["runtime_filesystem"] = {
                    "path": str(arguments.runtime_root.resolve()),
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "available_bytes": usage.free,
                }
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            time.sleep(arguments.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
