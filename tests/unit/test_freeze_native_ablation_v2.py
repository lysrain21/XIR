from __future__ import annotations

import sqlite3
from pathlib import Path

from xir_lab.native.ablation_freeze_v2 import attempt_counts, secret_scan, sqlite_backup


def test_freeze_helpers_backup_and_scan_secret_free_source(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE attempts (status TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO attempts(status) VALUES (?)", [("succeeded",), ("succeeded",)]
        )
    destination = tmp_path / "frozen" / "runner.sqlite"
    destination.parent.mkdir()
    assert sqlite_backup(source, destination) == "ok"
    assert attempt_counts(destination) == {"succeeded": 2}
    (destination.parent / "config.json").write_text('{"safe": true}\n', encoding="utf-8")
    assert secret_scan(destination.parent) == []


def test_secret_scan_rejects_publishable_raw_transaction(tmp_path: Path) -> None:
    (tmp_path / "transaction.raw").write_bytes(b"signed")
    assert secret_scan(tmp_path) == ["transaction.raw"]
