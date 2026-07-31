#!/usr/bin/env python3
"""Append full host, validator, agent, worker, queue, RPC, and GPFS samples."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xir_lab.native.monitor import (
    capacity_stop_reason,
    sqlite_counts,
    write_stop_request,
)


def rpc(url: str, method: str) -> Any:
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


def process_sample(name: str, pid_file: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"process_id": name, "pid_file": str(pid_file)}
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        status: dict[str, str] = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                status[key] = value.strip()
        io_values: dict[str, int] = {}
        for line in Path(f"/proc/{pid}/io").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            io_values[key] = int(value.strip())
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
        result.update(
            {
                "pid": pid,
                "healthy": True,
                "rss_bytes": int(status["VmRSS"].split()[0]) * 1024,
                "read_bytes": io_values.get("read_bytes"),
                "write_bytes": io_values.get("write_bytes"),
                "cpu_ticks": int(stat[13]) + int(stat[14]),
                "start_ticks": int(stat[21]),
            }
        )
    except (OSError, ValueError, KeyError) as exc:
        result.update({"healthy": False, "gap_error": type(exc).__name__})
    return result


def docker_samples() -> list[dict[str, Any]]:
    environment = {**os.environ, "DOCKER_API_VERSION": "1.43"}
    command = subprocess.run(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    rows = []
    for line in command.stdout.splitlines():
        item = json.loads(line)
        name = str(item.get("Name", ""))
        if name.startswith("xir-local-scale-"):
            rows.append(item)
    if len(rows) != 12:
        raise RuntimeError(f"expected 12 validators, observed {len(rows)}")
    return rows


def directory_bytes(path: Path) -> int:
    return sum(
        item.stat().st_size
        for item in path.rglob("*")
        if item.is_file() and not item.is_symlink()
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("smoke", "rehearsal", "scale", "recovery"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--submission-stop-file", type=Path, required=True)
    parser.add_argument("--minimum-docker-free-bytes", type=int, required=True)
    parser.add_argument("--minimum-gpfs-free-bytes", type=int, required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    previous_pids: dict[str, int] = {}
    sequence = 0
    while not args.stop_file.exists():
        observed = datetime.now(UTC).isoformat()
        sample: dict[str, Any] = {
            "schema_version": "xir-lab-native-resource-sample-v1",
            "sequence": sequence,
            "phase": args.phase,
            "observed_at": observed,
            "load_average": list(os.getloadavg()),
            "host": {},
            "validators": [],
            "processes": [],
            "queues": {},
            "chains": [],
            "restarts": [],
            "gaps": [],
        }
        try:
            memory = {}
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                key, value = line.split(":", 1)
                memory[key] = int(value.strip().split()[0]) * 1024
            gpfs = shutil.disk_usage(args.runtime_root)
            docker = shutil.disk_usage("/ebs/docker/165536.165536")
            sample["host"] = {
                "memory_available_bytes": memory["MemAvailable"],
                "gpfs_free_bytes": gpfs.free,
                "docker_free_bytes": docker.free,
                "evidence_bytes": sum(
                    directory_bytes(path)
                    for path in (
                        args.runtime_root / "runs",
                        args.runtime_root / "layerzero",
                        args.runtime_root / "hyperlane",
                    )
                    if path.exists()
                ),
            }
            stop_reason = capacity_stop_reason(
                docker_free_bytes=docker.free,
                gpfs_free_bytes=gpfs.free,
                minimum_docker_free_bytes=args.minimum_docker_free_bytes,
                minimum_gpfs_free_bytes=args.minimum_gpfs_free_bytes,
            )
            if stop_reason is not None:
                write_stop_request(
                    args.submission_stop_file,
                    {
                        "schema_version": "xir-lab-submission-stop-v1",
                        "reason": "filesystem_reserve_breached",
                        "observed_at": observed,
                        **stop_reason,
                    },
                )
        except (OSError, KeyError) as exc:
            sample["gaps"].append({"scope": "host", "error": type(exc).__name__})
        try:
            sample["validators"] = docker_samples()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            sample["gaps"].append({"scope": "validators", "error": str(exc)})
        pid_root = args.runtime_root / "hyperlane" / "agents" / "pids"
        pid_files = {
            path.stem: path for path in sorted(pid_root.glob("*.pid"))
        }
        for name in ("layerzero-worker", "native-runner", "native-monitor"):
            pid_files[name] = args.runtime_root / "pids" / f"{name}.pid"
        for name, path in pid_files.items():
            process = process_sample(name, path)
            sample["processes"].append(process)
            pid = process.get("pid")
            if isinstance(pid, int):
                prior = previous_pids.get(name)
                if prior is not None and prior != pid:
                    sample["restarts"].append(
                        {"process_id": name, "prior_pid": prior, "new_pid": pid}
                    )
                previous_pids[name] = pid
        sample["queues"] = {
            "layerzero": sqlite_counts(
                args.runtime_root / "layerzero" / "worker.sqlite",
                {
                    "observed": "SELECT COUNT(*) FROM packets WHERE status='observed'",
                    "delivered": "SELECT COUNT(*) FROM packets WHERE status='delivered'",
                    "failed_actions": "SELECT COUNT(*) FROM actions WHERE status='failed'",
                },
            ),
            "runner": sqlite_counts(
                args.runtime_root / "runs" / args.phase / "runner.sqlite",
                {
                    "running": "SELECT COUNT(*) FROM attempts WHERE status='running'",
                    "succeeded": "SELECT COUNT(*) FROM attempts WHERE status='succeeded'",
                    "failed_stages": "SELECT COUNT(*) FROM stages WHERE state='failed'",
                },
            ),
        }
        for chain in (
            ("source", "http://127.0.0.1:18545"),
            ("intermediate", "http://127.0.0.1:28545"),
            ("destination", "http://127.0.0.1:38545"),
        ):
            try:
                sample["chains"].append(
                    {
                        "role": chain[0],
                        "block_number": int(rpc(chain[1], "eth_blockNumber"), 16),
                        "peer_count": int(rpc(chain[1], "net_peerCount"), 16),
                        "syncing": rpc(chain[1], "eth_syncing"),
                    }
                )
            except (OSError, RuntimeError, ValueError) as exc:
                sample["gaps"].append(
                    {"scope": f"rpc:{chain[0]}", "error": type(exc).__name__}
                )
        with args.output.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        sequence += 1
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
