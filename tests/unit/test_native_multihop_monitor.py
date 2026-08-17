from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))
import monitor_native_multihop_resources as monitor


def test_stop_request_still_writes_final_sample_and_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "chains": [
                    {"rpc_url": f"http://chain-{role}"} for role in "abcde"
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    identity = tmp_path / "identity.json"
    identity.write_text(
        json.dumps({"payload": {"topology_sha256": "11" * 32}}) + "\n",
        encoding="utf-8",
    )
    stop = tmp_path / "monitor.stop"
    stop.touch()
    output = tmp_path / "resource-samples.segment-000.jsonl"
    completion = tmp_path / "resource-samples.segment-000.completion.json"
    ready = tmp_path / "resource-monitor-ready.segment-000.json"
    monkeypatch.setattr(monitor, "_validator_samples", lambda _digest: [])
    monkeypatch.setattr(
        monitor,
        "_rpc",
        lambda _url, method: {
            "eth_blockNumber": "0x1",
            "net_peerCount": "0x4",
            "eth_syncing": False,
        }[method],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitor_native_multihop_resources.py",
            "--runtime-root",
            str(runtime),
            "--profile",
            str(profile),
            "--identity-manifest",
            str(identity),
            "--runner-state",
            str(tmp_path / "runner.sqlite"),
            "--runner-pid",
            str(tmp_path / "runner.pid"),
            "--output",
            str(output),
            "--completion",
            str(completion),
            "--ready",
            str(ready),
            "--sequence-start",
            "17",
            "--stop-file",
            str(stop),
            "--submission-stop-file",
            str(tmp_path / "submission.stop"),
            "--minimum-runtime-free-bytes",
            "0",
            "--interval",
            "5",
        ],
    )
    assert monitor.main() == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    done = json.loads(completion.read_text(encoding="utf-8"))
    readiness = json.loads(ready.read_text(encoding="utf-8"))
    assert [row["sequence"] for row in rows] == [17]
    assert done["valid"] is True
    assert done["sequence_start"] == 17
    assert done["sequence_end"] == 17
    assert done["last_utc_ns"] == rows[-1]["utc_ns"]
    assert readiness["valid"] is True
    assert readiness["monitor_process_id"] == os.getpid()
    assert readiness["first_sequence"] == 17
    assert readiness["first_utc_ns"] == rows[0]["utc_ns"]


def test_stop_completion_covers_durable_runner_event_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "chains": [
                    {"rpc_url": f"http://chain-{role}"} for role in "abcde"
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    identity = tmp_path / "identity.json"
    identity.write_text(
        json.dumps({"payload": {"topology_sha256": "22" * 32}}) + "\n",
        encoding="utf-8",
    )
    runner_state = tmp_path / "runner.sqlite"
    with sqlite3.connect(runner_state) as connection:
        connection.execute("CREATE TABLE events (utc_ns INTEGER NOT NULL)")
        connection.execute("INSERT INTO events (utc_ns) VALUES (150)")
    stop = tmp_path / "monitor.stop"
    stop.touch()
    output = tmp_path / "resource-samples.segment-000.jsonl"
    completion = tmp_path / "resource-samples.segment-000.completion.json"
    ready = tmp_path / "resource-monitor-ready.segment-000.json"
    monkeypatch.setattr(monitor, "_validator_samples", lambda _digest: [])
    monkeypatch.setattr(
        monitor,
        "_rpc",
        lambda _url, method: {
            "eth_blockNumber": "0x1",
            "net_peerCount": "0x4",
            "eth_syncing": False,
        }[method],
    )
    utc_values = iter((100, 200))
    monkeypatch.setattr(monitor.time, "time_ns", lambda: next(utc_values))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitor_native_multihop_resources.py",
            "--runtime-root",
            str(runtime),
            "--profile",
            str(profile),
            "--identity-manifest",
            str(identity),
            "--runner-state",
            str(runner_state),
            "--runner-pid",
            str(tmp_path / "runner.pid"),
            "--output",
            str(output),
            "--completion",
            str(completion),
            "--ready",
            str(ready),
            "--sequence-start",
            "23",
            "--stop-file",
            str(stop),
            "--submission-stop-file",
            str(tmp_path / "submission.stop"),
            "--minimum-runtime-free-bytes",
            "0",
            "--interval",
            "5",
        ],
    )
    assert monitor.main() == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    done = json.loads(completion.read_text(encoding="utf-8"))
    assert [row["sequence"] for row in rows] == [23, 24]
    assert done["sample_count"] == 2
    assert done["last_utc_ns"] == 200
    assert done["last_utc_ns"] >= 150
