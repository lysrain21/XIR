#!/usr/bin/env python3
"""Freeze a secret-free manifest over raw and aggregate experiment evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*arguments: str) -> str:
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    runtime = arguments.runtime_root.resolve()
    repository = arguments.repository_root.resolve()
    output = arguments.output.resolve()
    companion = output.with_suffix(output.suffix + ".sha256")
    files: list[dict[str, Any]] = []
    for path in sorted(runtime.rglob("*")):
        if (
            not path.is_file()
            or path == output
            or path == companion
            or "private" in path.relative_to(runtime).parts
        ):
            continue
        relative = path.relative_to(runtime)
        files.append(
            {
                "path": relative.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
                "classification": (
                    "raw-evidence"
                    if relative.parts[0] in {"evidence", "logs"}
                    or relative.suffix in {".ndjson", ".sqlite"}
                    else "provenance-or-aggregate"
                ),
            }
        )
    source_files = [
        path
        for path in sorted(repository.rglob("*"))
        if path.is_file()
        and not any(
            part
            in {
                ".git",
                ".venv",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                "__pycache__",
                "cache",
            }
            for part in path.relative_to(repository).parts
        )
    ]
    source_payload = "\n".join(
        f"{sha256(path)}  {path.relative_to(repository).as_posix()}"
        for path in source_files
    ).encode()
    docker_names = command(
        "docker",
        "ps",
        "-a",
        "--filter",
        "label=org.xir.environment=controlled-local-qbft",
        "--format",
        "{{.Names}}",
    ).splitlines()
    inspections = json.loads(command("docker", "inspect", *docker_names))
    validators = {
        item["Name"].removeprefix("/"): {
            "image": item["Image"],
            "memory_limit_bytes": int(item["HostConfig"]["Memory"]),
            "restart_count": int(item["RestartCount"]),
            "status": item["State"]["Status"],
            "health": item["State"].get("Health", {}).get("Status", "none"),
        }
        for item in inspections
    }
    document = {
        "schema_version": "xir-lab-four-route-evidence-manifest-v1",
        "run_id": runtime.name,
        "frozen_at": datetime.now(UTC).isoformat(),
        "runtime_root": str(runtime),
        "source_tree_sha256": hashlib.sha256(source_payload).hexdigest(),
        "source_file_count": len(source_files),
        "evidence_file_count": len(files),
        "evidence_total_bytes": sum(item["bytes"] for item in files),
        "files": files,
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
            "memory_total_bytes": next(
                int(line.split()[1]) * 1024
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemTotal:")
            ),
        },
        "tools": {
            "python": platform.python_version(),
            "docker_server": command(
                "docker", "version", "--format", "{{.Server.Version}}"
            ),
            "forge": command("forge", "--version").splitlines()[0],
        },
        "validators": validators,
        "secret_exclusions": [
            "runtime private directory",
            "environment values",
            "signing keys and signed transaction spool bytes",
        ],
    }
    output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    companion.write_text(f"{sha256(output)}  {output.name}\n", encoding="ascii")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
