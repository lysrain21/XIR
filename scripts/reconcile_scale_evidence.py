#!/usr/bin/env python3
"""Build an exact reconciliation record from the final scale SQLite ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--signed-spool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    with sqlite3.connect(
        f"file:{arguments.database}?mode=ro",
        uri=True,
    ) as connection:
        states = dict(
            connection.execute(
                "SELECT state, count(*) FROM local_stages GROUP BY state"
            ).fetchall()
        )
        stages = dict(
            connection.execute(
                "SELECT stage, count(*) FROM local_stages GROUP BY stage"
            ).fetchall()
        )
        cells = {
            f"{condition}/{arm}": count
            for condition, arm, count in connection.execute(
                """
                SELECT condition, arm, count(*)
                FROM local_stages
                GROUP BY condition, arm
                """
            ).fetchall()
        }
        row = connection.execute(
            """
            SELECT count(*), count(DISTINCT attempt_id),
                   count(DISTINCT transaction_hash),
                   coalesce(sum(gas_used), 0),
                   coalesce(sum(calldata_bytes), 0),
                   sum(block_number IS NULL),
                   min(submitted_at), max(finalized_at)
            FROM local_stages
            """
        ).fetchone()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    spool_files = sum(item.is_file() for item in arguments.signed_spool.rglob("*"))
    checks = {
        "sqlite_integrity": integrity == "ok",
        "all_finalized": states == {"finalized": 30_000},
        "stage_balance": stages == {0: 10_000, 1: 10_000, 2: 10_000},
        "condition_arm_balance": set(cells.values()) == {3_750},
        "attempt_identity_count": int(row[1]) == 10_000,
        "transaction_hash_uniqueness": int(row[2]) == 30_000,
        "receipts_complete": int(row[5]) == 0,
        "signed_spool_empty": spool_files == 0,
    }
    document = {
        "schema_version": "xir-lab-local-scale-reconciliation-v1",
        "eligible": all(checks.values()),
        "checks": checks,
        "states": states,
        "stages": {str(key): value for key, value in stages.items()},
        "condition_arm_stage_rows": cells,
        "counts": {
            "physical_transactions": int(row[0]),
            "distinct_attempts": int(row[1]),
            "distinct_transaction_hashes": int(row[2]),
            "gas_used": int(row[3]),
            "calldata_bytes": int(row[4]),
            "signed_spool_files": spool_files,
        },
        "observed_from_epoch_seconds": float(row[6]),
        "observed_through_epoch_seconds": float(row[7]),
        "evidence_sha256": hashlib.sha256(arguments.database.read_bytes()).hexdigest(),
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
