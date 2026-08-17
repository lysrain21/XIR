#!/usr/bin/env python3
"""Continuously record five-chain host/process/RPC contention metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

from xir_lab.native.monitor import write_stop_request


def _rpc(url: str, method: str) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": []}
        ).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        document = json.loads(response.read())
    if document.get("error") is not None:
        raise RuntimeError(str(document["error"]))
    return document["result"]


def _database_counts(path: Path) -> dict[str, int | str]:
    if not path.is_file():
        return {"status": "not_created"}
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            return {
                "status": "observed",
                "running": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM attempts WHERE status='running'"
                    ).fetchone()[0]
                ),
                "succeeded": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM attempts WHERE status='succeeded'"
                    ).fetchone()[0]
                ),
                "attempt_errors": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM attempt_errors"
                    ).fetchone()[0]
                ),
            }
    except sqlite3.Error as exc:
        return {"status": "gap", "error": type(exc).__name__}


def _runner_last_event_utc_ns(path: Path) -> int:
    """Return the durable runner event tail after the runner has stopped.

    A missing database is valid only before the runner creates its state.  Once
    the database exists, a malformed or unreadable event ledger must fail the
    monitor rather than permit a completion that does not cover the runner.
    """

    if not path.is_file():
        return 0
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        row = connection.execute(
            "SELECT COALESCE(MAX(utc_ns),0) FROM events"
        ).fetchone()
    if row is None:
        raise RuntimeError("runner event tail query returned no row")
    return int(row[0])


def _process(name: str, pid_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "pid_file": str(pid_path)}
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        vm_rss = next(
            line for line in status.splitlines() if line.startswith("VmRSS:")
        )
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        result.update(
            {
                "healthy": True,
                "pid": pid,
                "rss_bytes": int(vm_rss.split()[1]) * 1024,
                "cpu_ticks": int(stat[13]) + int(stat[14]),
                "start_ticks": int(stat[21]),
            }
        )
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        result.update({"healthy": False, "gap_error": type(exc).__name__})
    return result


def _write_ready(path: Path, *, output: Path, sample: dict[str, Any], line: str) -> None:
    if path.exists():
        raise RuntimeError("multihop resource readiness output already exists")
    document = {
        "schema_version": "xir-lab-native-multihop-resource-monitor-ready-v1",
        "valid": True,
        "output_path": output.name,
        "monitor_process_id": os.getpid(),
        "boot_id": sample["boot_id"],
        "first_sequence": sample["sequence"],
        "first_utc_ns": sample["utc_ns"],
        "first_sample_sha256": hashlib.sha256(line.encode()).hexdigest(),
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _validator_samples(topology_sha256: str) -> list[dict[str, Any]]:
    names = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=org.xir.topology-sha256={topology_sha256}",
            "--format",
            "{{.Names}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.splitlines()
    if len(names) != 20:
        raise RuntimeError(f"expected 20 validators, observed {len(names)}")
    output = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", *names],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    return [json.loads(line) for line in output.splitlines()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--identity-manifest", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--runner-pid", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--completion", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--sequence-start", type=int, default=0)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--submission-stop-file", type=Path, required=True)
    parser.add_argument("--minimum-runtime-free-bytes", type=int, required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("multihop resource output already exists")
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    identity = json.loads(args.identity_manifest.read_text(encoding="utf-8"))
    topology_sha256 = str(identity["payload"]["topology_sha256"])
    chains = profile["chains"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.completion.exists() or args.sequence_start < 0:
        raise RuntimeError("multihop resource segment completion already exists or is invalid")
    sequence = args.sequence_start
    sample_count = 0
    last_utc_ns = 0
    with args.output.open("x", encoding="utf-8") as stream:
        while True:
            memory: dict[str, int] = {}
            for line in Path("/proc/meminfo").read_text(
                encoding="ascii"
            ).splitlines():
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    key, raw = line.split(":", 1)
                    memory[key] = int(raw.strip().split()[0]) * 1024
            disk = shutil.disk_usage(args.runtime_root)
            sample: dict[str, Any] = {
                "schema_version": "xir-lab-native-multihop-resource-sample-v1",
                "sequence": sequence,
                "utc_ns": time.time_ns(),
                "monotonic_ns": time.monotonic_ns(),
                "boot_id": Path("/proc/sys/kernel/random/boot_id")
                .read_text(encoding="ascii")
                .strip(),
                "load_average": list(os.getloadavg()),
                "memory": {
                    "total_bytes": memory["MemTotal"],
                    "available_bytes": memory["MemAvailable"],
                },
                "runtime_disk": {
                    "total_bytes": disk.total,
                    "used_bytes": disk.used,
                    "available_bytes": disk.free,
                },
                "runner_database": _database_counts(args.runner_state),
                "processes": [],
                "validators": [],
                "chains": [],
                "gaps": [],
            }
            pid_root = args.runtime_root / "hyperlane/agents/pids"
            pid_paths = {
                "runner": args.runner_pid,
                "layerzero-worker": args.runtime_root / "pids/layerzero-worker.pid",
                "relayer": pid_root / "relayer.pid",
                **{
                    f"validator-{role}": pid_root
                    / f"validator-xirlocalchain{role}.pid"
                    for role in "abcde"
                },
            }
            sample["processes"] = [
                _process(name, path) for name, path in sorted(pid_paths.items())
            ]
            try:
                sample["validators"] = _validator_samples(topology_sha256)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                sample["gaps"].append(
                    {"scope": "validators", "error": str(exc)}
                )
            for role, chain in zip("abcde", chains, strict=True):
                try:
                    sample["chains"].append(
                        {
                            "role": role,
                            "block_number": int(
                                _rpc(str(chain["rpc_url"]), "eth_blockNumber"), 16
                            ),
                            "peer_count": int(
                                _rpc(str(chain["rpc_url"]), "net_peerCount"), 16
                            ),
                            "syncing": _rpc(str(chain["rpc_url"]), "eth_syncing"),
                        }
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    sample["gaps"].append(
                        {"scope": f"rpc:{role}", "error": type(exc).__name__}
                    )
            if disk.free < args.minimum_runtime_free_bytes:
                write_stop_request(
                    args.submission_stop_file,
                    {
                        "schema_version": "xir-lab-submission-stop-v1",
                        "reason": "runtime_filesystem_reserve_breached",
                        "utc_ns": sample["utc_ns"],
                        "runtime_filesystem_available_bytes": disk.free,
                        "minimum_runtime_filesystem_available_bytes": (
                            args.minimum_runtime_free_bytes
                        ),
                    },
                )
            line = json.dumps(sample, sort_keys=True) + "\n"
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
            if sample_count == 0:
                _write_ready(args.ready, output=args.output, sample=sample, line=line)
            last_utc_ns = int(sample["utc_ns"])
            sequence += 1
            sample_count += 1
            if args.stop_file.exists():
                # The campaign writes the stop request only after wait(2) has
                # reaped the runner, so the event tail is stable here.  If the
                # current sample predates that tail, immediately take another
                # sample before admitting the segment completion.
                if last_utc_ns >= _runner_last_event_utc_ns(args.runner_state):
                    break
                continue
            time.sleep(args.interval)
    if sample_count <= 0:
        raise RuntimeError("multihop resource segment contains no samples")
    completion = {
        "schema_version": "xir-lab-native-multihop-resource-segment-completion-v1",
        "valid": True,
        "path": args.output.name,
        "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "sample_count": sample_count,
        "sequence_start": args.sequence_start,
        "sequence_end": sequence - 1,
        "last_utc_ns": last_utc_ns,
    }
    temporary = args.completion.with_name(f".{args.completion.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(completion, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, args.completion)
    directory_fd = os.open(args.completion.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
