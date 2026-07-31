#!/usr/bin/env python3
"""Build machine-readable closeout metrics from frozen native-run evidence."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import statistics
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from eth_account._utils.legacy_transactions import Transaction
from eth_account.typed_transactions.typed_transaction import TypedTransaction
from eth_utils.crypto import keccak
from hexbytes import HexBytes


def percentile(values: list[int] | list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def distribution(values: Iterable[int]) -> dict[str, int | float]:
    measured = list(values)
    return {
        "transactions": len(measured),
        "total_bytes": sum(measured),
        "mean_bytes": statistics.fmean(measured) if measured else 0.0,
        "median_bytes": percentile(measured, 0.50),
        "p95_bytes": percentile(measured, 0.95),
        "p99_bytes": percentile(measured, 0.99),
        "minimum_bytes": min(measured, default=0),
        "maximum_bytes": max(measured, default=0),
    }


def calldata_bytes(raw_value: str | bytes) -> int:
    raw = HexBytes(raw_value.strip() if isinstance(raw_value, str) else raw_value)
    if raw[0] <= 0x7F:
        transaction = TypedTransaction.from_bytes(raw).as_dict()
    else:
        transaction = Transaction.from_bytes(raw).as_dict()
    data = transaction.get("data", b"")
    return len(HexBytes(data))


def signed_transaction_metrics(path: Path) -> tuple[str, int]:
    raw_transaction = path.read_bytes()
    return keccak(raw_transaction).hex(), calldata_bytes(raw_transaction)


def coordinator_calldata(
    runtime: Path,
) -> tuple[dict[str, Any], tuple[float, float]]:
    phase = runtime / "runs" / "scale"
    connection = sqlite3.connect(phase / "runner.sqlite")
    rows = connection.execute(
        """
        SELECT a.route, s.stage, lower(s.transaction_hash), s.detail_json
        FROM stages s
        JOIN attempts a ON a.attempt_id = s.attempt_id
        WHERE a.phase = 'scale' AND s.state = 'succeeded'
          AND s.transaction_hash IS NOT NULL
        """
    ).fetchall()
    transaction_coordinates = {
        str(transaction_hash).removeprefix("0x"): (str(route), str(stage))
        for route, stage, transaction_hash, _ in rows
    }
    phase_interval = connection.execute(
        """
        SELECT MIN(started_at), MAX(finished_at)
        FROM attempts
        WHERE phase = 'scale'
        """
    ).fetchone()
    assert phase_interval[0] is not None and phase_interval[1] is not None
    connection.close()

    grouped: dict[str, list[int]] = defaultdict(list)
    matched: set[str] = set()
    raw_directory = phase / "private-signed-transactions"
    paths = list(raw_directory.glob("*.raw"))
    with ThreadPoolExecutor(max_workers=16) as executor:
        transaction_metrics = executor.map(signed_transaction_metrics, paths)
    for transaction_hash, size in transaction_metrics:
        coordinates = transaction_coordinates.get(transaction_hash)
        if coordinates is None:
            continue
        route, stage = coordinates
        grouped["all"].append(size)
        grouped[f"route:{route}"].append(size)
        grouped[f"stage:{stage}"].append(size)
        grouped[f"route_stage:{route}:{stage}"].append(size)
        matched.add(transaction_hash)
    missing = sorted(set(transaction_coordinates) - matched)
    if missing:
        raise SystemExit(
            f"missing raw signed coordinator transactions: {len(missing)}"
        )
    return (
        {
            "scope": "scale current successful coordinator stages",
            "expected_transactions": len(transaction_coordinates),
            "matched_transactions": len(matched),
            "groups": {
                name: distribution(values) for name, values in sorted(grouped.items())
            },
        },
        (float(phase_interval[0]), float(phase_interval[1])),
    )


def layerzero_worker_calldata(
    runtime: Path, phase_interval: tuple[float, float]
) -> dict[str, Any]:
    connection = sqlite3.connect(runtime / "layerzero" / "worker.sqlite")
    rows = connection.execute(
        """
        SELECT a.guid, a.stage, a.destination_chain_id, a.raw_transaction_hex
        FROM actions a
        JOIN packets p ON p.guid = a.guid
        WHERE a.status = 'succeeded' AND a.raw_transaction_hex IS NOT NULL
        """
    ).fetchall()
    grouped: dict[str, list[int]] = defaultdict(list)
    started_at = datetime.fromtimestamp(phase_interval[0], UTC).isoformat()
    finished_at = datetime.fromtimestamp(phase_interval[1], UTC).isoformat()
    packet_rows = connection.execute(
        """
        SELECT guid
        FROM packets
        WHERE observed_at >= ? AND observed_at <= ?
        """,
        (started_at, finished_at),
    ).fetchall()
    scale_guids = {
        str(row[0])
        for row in packet_rows
    }
    for guid, stage, destination_chain_id, raw_hex in rows:
        if str(guid) not in scale_guids:
            continue
        size = calldata_bytes(str(raw_hex))
        grouped["all"].append(size)
        grouped[f"stage:{stage}"].append(size)
        grouped[f"destination_chain:{destination_chain_id}"].append(size)
    connection.close()
    if len(scale_guids) != 40_000:
        raise SystemExit(
            f"expected 40000 scale LayerZero packets, found {len(scale_guids)}"
        )
    if len(grouped["all"]) != 120_000:
        raise SystemExit(
            "expected 120000 scale LayerZero worker actions, found "
            f"{len(grouped['all'])}"
        )
    return {
        "scope": "LayerZero worker actions observed within the scale wall interval",
        "scale_interval": {
            "started_at": started_at,
            "finished_at": finished_at,
        },
        "scale_packets": len(scale_guids),
        "groups": {
            name: distribution(values) for name, values in sorted(grouped.items())
        },
    }


def resource_summary(runtime: Path) -> dict[str, Any]:
    samples = [
        json.loads(line)
        for line in (runtime / "runs" / "scale" / "resources.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    timestamps = [
        datetime.fromisoformat(str(sample["observed_at"])).timestamp()
        for sample in samples
    ]
    intervals = [
        later - earlier for earlier, later in zip(timestamps, timestamps[1:])
    ]
    generations: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    for sample in samples:
        observed_at = str(sample["observed_at"])
        for process in sample.get("processes", []):
            if process.get("pid") is None:
                continue
            process_id = str(process["process_id"])
            pid = int(process["pid"])
            generation = generations[process_id].setdefault(
                pid,
                {
                    "pid": pid,
                    "first_observed_at": observed_at,
                    "last_observed_at": observed_at,
                    "samples": 0,
                },
            )
            generation["last_observed_at"] = observed_at
            generation["samples"] += 1
    return {
        "samples": len(samples),
        "first_observed_at": samples[0]["observed_at"],
        "last_observed_at": samples[-1]["observed_at"],
        "nominal_interval_seconds": 5,
        "interval_seconds": {
            "median": percentile(intervals, 0.50),
            "p95": percentile(intervals, 0.95),
            "maximum": max(intervals, default=0.0),
        },
        "declared_gap_records": sum(len(sample.get("gaps", [])) for sample in samples),
        "process_generations": {
            process_id: sorted(items.values(), key=lambda item: item["first_observed_at"])
            for process_id, items in sorted(generations.items())
        },
    }


def docker_state() -> dict[str, Any]:
    environment = dict(os.environ)
    environment.setdefault("DOCKER_API_VERSION", "1.43")
    identifiers = subprocess.check_output(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            "label=com.docker.compose.project=xir-local-scale",
        ],
        text=True,
        env=environment,
    ).split()
    inspected = json.loads(
        subprocess.check_output(
            ["docker", "inspect", *identifiers], text=True, env=environment
        )
    )
    containers = []
    for item in inspected:
        state = item["State"]
        health = state.get("Health", {}).get("Status")
        containers.append(
            {
                "name": str(item["Name"]).removeprefix("/"),
                "id": item["Id"],
                "status": state["Status"],
                "health": health,
                "restart_count": item["RestartCount"],
                "oom_killed": state["OOMKilled"],
                "started_at": state["StartedAt"],
                "memory_limit_bytes": item["HostConfig"]["Memory"],
                "mounts": [
                    {
                        "name": mount.get("Name"),
                        "source": mount["Source"],
                        "destination": mount["Destination"],
                    }
                    for mount in item["Mounts"]
                ],
            }
        )
    containers.sort(key=lambda item: item["name"])
    if len(containers) != 12:
        raise SystemExit(f"expected 12 validators, found {len(containers)}")
    return {
        "validators": containers,
        "validator_count": len(containers),
        "total_restart_count": sum(item["restart_count"] for item in containers),
        "all_running": all(item["status"] == "running" for item in containers),
        "all_healthy": all(item["health"] == "healthy" for item in containers),
    }


def interruption_summary(runtime: Path) -> dict[str, Any]:
    events = []
    recovery_only_transactions = 0
    root = runtime / "provenance" / "natural-interruptions"
    for event_path in sorted(root.glob("*/event.json")):
        document = json.loads(event_path.read_text(encoding="utf-8"))
        count = int(document.get("recovery_transaction_count", 0))
        if (
            document.get("recovery_root_transaction_hash")
            and document.get("same_nonce_cancellation_transaction_hash")
        ):
            count = 2
        recovery_only_transactions += count
        events.append(
            {
                "event_id": event_path.parent.name,
                "classification": document["classification"],
                "intentional_fault_injection": document[
                    "intentional_fault_injection"
                ],
                "attempt_denominator_changed": document[
                    "attempt_denominator_changed"
                ],
                "replacement_attempts_created": document[
                    "replacement_attempts_created"
                ],
                "recovery_only_transactions": count,
                "resolution": document["resolution"],
            }
        )
    return {
        "event_count": len(events),
        "events": events,
        "all_natural": all(not item["intentional_fault_injection"] for item in events),
        "attempt_denominator_unchanged": all(
            not item["attempt_denominator_changed"] for item in events
        ),
        "no_replacement_attempts": all(
            not item["replacement_attempts_created"] for item in events
        ),
        "recovery_only_transactions": recovery_only_transactions,
    }


def storage_summary(runtime: Path) -> dict[str, Any]:
    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {"files": 0, "bytes": 0}
    )
    total_files = 0
    total_bytes = 0
    for path in runtime.rglob("*"):
        if not path.is_file():
            continue
        size = path.stat().st_size
        relative = path.relative_to(runtime)
        group = relative.parts[0]
        groups[group]["files"] += 1
        groups[group]["bytes"] += size
        total_files += 1
        total_bytes += size
    return {
        "runtime_root": str(runtime.resolve()),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "top_level": dict(sorted(groups.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime_root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime_root.resolve()
    coordinator, phase_interval = coordinator_calldata(runtime)
    document = {
        "schema_version": "xir-lab-native-closeout-summary-v1",
        "run_id": runtime.name,
        "calldata": {
            "coordinator": coordinator,
            "layerzero_worker": layerzero_worker_calldata(
                runtime, phase_interval
            ),
            "hyperlane_process": {
                "scope": "not decoded into aggregate calldata metrics",
                "reason": (
                    "official Hyperlane relayer transactions are evidenced by "
                    "on-chain process lineage but raw signed agent transactions "
                    "are not retained by the pinned agent"
                ),
            },
        },
        "resources": resource_summary(runtime),
        "validators": docker_state(),
        "interruptions": interruption_summary(runtime),
        "storage": storage_summary(runtime),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
