#!/usr/bin/env python3
"""Set and attest the dedicated validators' memory limit without broad changes."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

PROJECT = "xir-local-scale"
TARGET_BYTES = 1024**3


def docker(*arguments: str) -> str:
    return subprocess.run(
        ("docker", *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def inspect(names: list[str]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], json.loads(docker("inspect", *names)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    targets = docker(
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={PROJECT}",
        "--filter",
        "label=org.xir.environment=controlled-local-qbft",
        "--format",
        "{{.Names}}",
    ).splitlines()
    all_names = docker("ps", "-a", "--format", "{{.Names}}").splitlines()
    unrelated = sorted(set(all_names) - set(targets))
    if len(targets) != 12:
        raise RuntimeError("expected exactly twelve dedicated validator containers")
    before = {
        item["Name"].removeprefix("/"): {
            "memory_bytes": int(item["HostConfig"]["Memory"]),
            "memory_swap_bytes": int(item["HostConfig"]["MemorySwap"]),
            "restart_count": int(item["RestartCount"]),
            "running": bool(item["State"]["Running"]),
        }
        for item in inspect(targets)
    }
    docker("update", "--memory", "1g", "--memory-swap", "1g", *targets)
    after = {
        item["Name"].removeprefix("/"): {
            "memory_bytes": int(item["HostConfig"]["Memory"]),
            "memory_swap_bytes": int(item["HostConfig"]["MemorySwap"]),
            "restart_count": int(item["RestartCount"]),
            "running": bool(item["State"]["Running"]),
        }
        for item in inspect(targets)
    }
    if any(item["memory_bytes"] < TARGET_BYTES for item in after.values()):
        raise RuntimeError("validator memory update did not reach 1 GiB")
    unrelated_after = docker("ps", "-a", "--format", "{{.Names}}").splitlines()
    document = {
        "schema_version": "xir-lab-validator-resource-attestation-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "target_memory_bytes": TARGET_BYTES,
        "target_count": len(targets),
        "targets": sorted(targets),
        "before": before,
        "after": after,
        "unrelated_container_names_before": unrelated,
        "unrelated_container_names_after": sorted(
            set(unrelated_after) - set(targets)
        ),
        "unrelated_container_set_unchanged": unrelated
        == sorted(set(unrelated_after) - set(targets)),
    }
    if not document["unrelated_container_set_unchanged"]:
        raise RuntimeError("unrelated container set changed during resource update")
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
