"""Reusable monitoring helpers for native-protocol experiments."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any


def capacity_stop_reason(
    *,
    docker_free_bytes: int,
    gpfs_free_bytes: int,
    minimum_docker_free_bytes: int,
    minimum_gpfs_free_bytes: int,
) -> dict[str, int] | None:
    """Return exact filesystem reserve breaches, if any."""

    breaches: dict[str, int] = {}
    if docker_free_bytes < minimum_docker_free_bytes:
        breaches["docker_free_bytes"] = docker_free_bytes
    if gpfs_free_bytes < minimum_gpfs_free_bytes:
        breaches["gpfs_free_bytes"] = gpfs_free_bytes
    if not breaches:
        return None
    return {
        **breaches,
        "minimum_docker_free_bytes": minimum_docker_free_bytes,
        "minimum_gpfs_free_bytes": minimum_gpfs_free_bytes,
    }


def write_stop_request(path: Path, payload: dict[str, Any]) -> None:
    """Atomically persist a durable stop-submission request."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def sqlite_counts(path: Path, queries: dict[str, str]) -> dict[str, Any]:
    """Read named scalar counters without mutating the observed database."""
    if not path.is_file():
        return {"path": str(path), "gap_error": "database_missing"}
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        values = {
            name: int(connection.execute(query).fetchone()[0])
            for name, query in queries.items()
        }
        connection.close()
        return {"path": str(path), **values}
    except sqlite3.Error as exc:
        return {"path": str(path), "gap_error": type(exc).__name__}
