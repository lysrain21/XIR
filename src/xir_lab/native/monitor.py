"""Reusable monitoring helpers for native-protocol experiments."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


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
