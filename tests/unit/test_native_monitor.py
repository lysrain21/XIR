from pathlib import Path

from xir_lab.native.monitor import sqlite_counts


def test_monitor_records_explicit_database_gap(tmp_path: Path) -> None:
    result = sqlite_counts(
        tmp_path / "missing.sqlite", {"rows": "SELECT COUNT(*) FROM packets"}
    )
    assert result["gap_error"] == "database_missing"
