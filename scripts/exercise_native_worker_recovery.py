#!/usr/bin/env python3
"""Interrupt and resume one in-flight LayerZero worker action."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(UTC).isoformat()


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def action(connection: sqlite3.Connection) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT action_id, guid, stage, destination_chain_id, nonce, target,
               calldata_sha256, transaction_hash, status
        FROM actions
        WHERE status IN ('signed', 'submitted')
          AND transaction_hash IS NOT NULL
        ORDER BY intended_at DESC
        LIMIT 1
        """
    ).fetchone()
    return None if row is None else dict(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    connection = sqlite3.connect(
        args.runtime_root / "layerzero" / "worker.sqlite"
    )
    connection.row_factory = sqlite3.Row
    deadline = time.monotonic() + args.timeout
    selected = None
    while time.monotonic() < deadline:
        selected = action(connection)
        if selected is not None:
            break
        time.sleep(0.05)
    if selected is None:
        raise RuntimeError("no in-flight LayerZero action observed")
    pid_path = args.runtime_root / "pids" / "layerzero-worker.pid"
    old_pid = int(pid_path.read_text(encoding="ascii"))
    if not pid_alive(old_pid):
        raise RuntimeError("LayerZero worker stopped before interruption")
    interrupted_at = now()
    os.kill(old_pid, signal.SIGTERM)
    for _ in range(100):
        if not pid_alive(old_pid):
            break
        time.sleep(0.05)
    if pid_alive(old_pid):
        raise RuntimeError("LayerZero worker did not stop after SIGTERM")
    subprocess.run(
        [
            str(args.repository_root / "scripts" / "native_stack_processes.sh"),
            "start-worker",
            str(args.runtime_root),
        ],
        cwd=args.repository_root,
        check=True,
    )
    new_pid = int(pid_path.read_text(encoding="ascii"))
    if new_pid == old_pid or not pid_alive(new_pid):
        raise RuntimeError("LayerZero worker restart did not produce a new PID")
    while time.monotonic() < deadline:
        row = connection.execute(
            "SELECT status, transaction_hash FROM actions WHERE action_id=?",
            (selected["action_id"],),
        ).fetchone()
        if row is not None and row["status"] == "succeeded":
            if row["transaction_hash"] != selected["transaction_hash"]:
                raise RuntimeError("recovery changed the transaction identity")
            observations = [
                dict(item)
                for item in connection.execute(
                    """
                    SELECT state, raw_sha256, detail_json, observed_at
                    FROM observations WHERE action_id=?
                    ORDER BY observation_id
                    """,
                    (selected["action_id"],),
                ).fetchall()
            ]
            result = {
                "schema_version": "xir-lab-native-worker-recovery-v1",
                "interrupted_at": interrupted_at,
                "completed_at": now(),
                "old_pid": old_pid,
                "new_pid": int(pid_path.read_text(encoding="ascii")),
                "initial_restart_pid": new_pid,
                "selected_action": selected,
                "final_status": row["status"],
                "same_action_id": True,
                "same_transaction_hash": True,
                "new_logical_attempt_created": False,
                "observations": observations,
                "valid": True,
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return
        time.sleep(0.1)
    raise RuntimeError("interrupted LayerZero action did not recover")


if __name__ == "__main__":
    main()
