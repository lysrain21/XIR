#!/usr/bin/env python3
"""Sample aggregate XIR validator resources until a stop marker appears."""

from __future__ import annotations

import argparse
import json
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
    factors = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
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
            sample = {
                "observed_at": datetime.now(UTC).isoformat(),
                "container_count": len(values),
                "aggregate_cpu_percent": sum(
                    float(item["CPUPerc"].removesuffix("%")) for item in values
                ),
                "aggregate_memory_bytes": sum(
                    bytes_value(item["MemUsage"].split("/", 1)[0])
                    for item in values
                ),
            }
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            time.sleep(arguments.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
