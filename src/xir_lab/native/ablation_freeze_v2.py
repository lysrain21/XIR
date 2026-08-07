"""Immutable source snapshot helpers for native-ablation-v2."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sqlite_backup(source: Path, destination: Path) -> str:
    with (
        sqlite3.connect(f"file:{source}?mode=ro", uri=True) as input_db,
        sqlite3.connect(destination) as output_db,
    ):
        input_db.backup(output_db)
    with sqlite3.connect(f"file:{destination}?mode=ro", uri=True) as frozen_db:
        result = str(frozen_db.execute("PRAGMA quick_check").fetchone()[0])
    if result != "ok":
        raise RuntimeError(f"SQLite quick_check failed for {destination}: {result}")
    return result


def attempt_counts(path: Path) -> dict[str, int]:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        return {
            str(status): int(count)
            for status, count in connection.execute(
                "SELECT status, COUNT(*) FROM attempts GROUP BY status ORDER BY status"
            )
        }


def secret_scan(root: Path) -> list[str]:
    findings: list[str] = []
    text_suffixes = {".json", ".log", ".txt"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.startswith("frozen-source-manifest"):
            continue
        relative = str(path.relative_to(root))
        if path.suffix.lower() in {".key", ".raw"} or "private-signed" in relative:
            findings.append(relative)
        if path.suffix.lower() in text_suffixes:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for token in ("private_key", "raw_transaction_hex", "mnemonic"):
                if token in text:
                    findings.append(f"{relative}:{token}")
    return sorted(set(findings))
