#!/usr/bin/env python3
"""Create a no-overwrite private runtime overlay for native-faults-v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from eth_account import Account

from xir_lab.native.faults_v1 import (
    FINAL_REVISION_SOURCE_SHA256,
    final_revision_deployment_contract_valid,
    final_revision_prior_verifier_bindings_valid,
    final_revision_source_lock_valid,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def copy_public(source: Path, destination: Path) -> dict[str, object]:
    shutil.copyfile(source, destination)
    return {
        "source": str(source),
        "destination": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": sha256(destination),
    }


def inspect_worker_state(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=60)
    counts = {
        "packets": int(connection.execute("SELECT count(*) FROM packets").fetchone()[0]),
        "pending_packets": int(
            connection.execute(
                "SELECT count(*) FROM packets WHERE status != 'delivered'"
            ).fetchone()[0]
        ),
        "actions": int(connection.execute("SELECT count(*) FROM actions").fetchone()[0]),
        "pending_actions": int(
            connection.execute(
                "SELECT count(*) FROM actions WHERE status != 'succeeded'"
            ).fetchone()[0]
        ),
    }
    connection.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-runtime", type=Path, required=True)
    parser.add_argument("--source-deployment", type=Path, required=True)
    parser.add_argument("--target-runtime", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_runtime.resolve()
    target = args.target_runtime.resolve()
    if source == target or source in target.parents or target in source.parents:
        raise SystemExit("source and target runtime roots must be disjoint")
    if target.exists():
        raise SystemExit("target runtime already exists; refusing overwrite")
    pid_path = source / "pids" / "layerzero-worker.pid"
    if pid_path.is_file() and process_alive(int(pid_path.read_text(encoding="ascii"))):
        raise SystemExit("stop the source LayerZero worker before taking the overlay snapshot")
    required = {
        "profile": source / "profile.json",
        "deployment": args.source_deployment.resolve(),
        "worker_config": source / "layerzero" / "worker-config.json",
        "worker_state": source / "layerzero" / "worker.sqlite",
        "runner_key": source / "private" / "accounts" / "runner.key",
        "root_signer_key": source / "private" / "accounts" / "root-signer.key",
        "worker_key": source / "private" / "accounts" / "layerzero-worker.key",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise SystemExit("source runtime is incomplete: " + ", ".join(missing))
    worker_counts = inspect_worker_state(required["worker_state"])
    if worker_counts["pending_packets"] or worker_counts["pending_actions"]:
        raise SystemExit("source LayerZero worker has pending packets or actions")
    for name in ("profile", "deployment", "worker_config"):
        json.loads(required[name].read_text(encoding="utf-8"))
    deployment = json.loads(required["deployment"].read_text(encoding="utf-8"))
    if not final_revision_prior_verifier_bindings_valid(deployment):
        raise SystemExit("source deployment lacks final-revision prior-verifier bindings")
    repository = Path(__file__).resolve().parents[1]
    if not final_revision_source_lock_valid(repository):
        raise SystemExit("repository does not match the final-revision source lock")
    if not final_revision_deployment_contract_valid(deployment):
        raise SystemExit("source deployment is not the separated-signer final revision")
    identities = {
        role: Account.from_key(source_key.read_text(encoding="ascii").strip()).address.lower()
        for role, source_key in (
            ("runner", required["runner_key"]),
            ("root-signer", required["root_signer_key"]),
            ("layerzero-worker", required["worker_key"]),
        )
    }
    if identities["runner"] != str(deployment["runner"]).lower():
        raise SystemExit("runner key does not match the source deployment")
    if (
        identities["root-signer"] != str(deployment["root_signer"]).lower()
        or identities["root-signer"] == identities["runner"]
    ):
        raise SystemExit("root signer is not separated or does not match the deployment")

    target.mkdir(parents=True, exist_ok=False)
    for relative in (
        "native-application",
        "layerzero/worker-receipts",
        "private/accounts",
        "provenance",
        "pids",
        "logs",
    ):
        (target / relative).mkdir(parents=True, exist_ok=False)
    os.chmod(target / "private", 0o700)
    os.chmod(target / "private" / "accounts", 0o700)

    public_files = [
        copy_public(required["profile"], target / "profile.json"),
        copy_public(required["deployment"], target / "native-application" / "deployment.json"),
        copy_public(required["worker_config"], target / "layerzero" / "worker-config.json"),
    ]
    for role, source_key in (
        ("runner", required["runner_key"]),
        ("root-signer", required["root_signer_key"]),
        ("layerzero-worker", required["worker_key"]),
    ):
        destination = target / "private" / "accounts" / f"{role}.key"
        shutil.copyfile(source_key, destination)
        os.chmod(destination, 0o600)

    source_connection = sqlite3.connect(
        f"file:{required['worker_state']}?mode=ro", uri=True, timeout=60
    )
    destination_state = target / "layerzero" / "worker.sqlite"
    destination_connection = sqlite3.connect(destination_state)
    source_connection.backup(destination_connection)
    destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    destination_connection.commit()
    destination_connection.close()
    source_connection.close()

    provenance = {
        "schema_version": "xir-lab-native-faults-v1-overlay-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "source_runtime": str(source),
        "target_runtime": str(target),
        "deployment_scope": "prior-verifier-final-revision-shared-idle",
        "source_deployment_sha256": sha256(required["deployment"]),
        "prior_verifier_bindings": deployment["prior_verifier_bindings"],
        "final_revision_source_sha256": FINAL_REVISION_SOURCE_SHA256,
        "source_worker_stopped": True,
        "worker_database": {
            "source_sha256": sha256(required["worker_state"]),
            "snapshot_sha256": sha256(destination_state),
            "snapshot_bytes": destination_state.stat().st_size,
            **worker_counts,
        },
        "public_files": public_files,
        "role_addresses": identities,
        "private_keys_published": False,
    }
    provenance_path = target / "provenance" / "overlay.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({**provenance, "provenance_sha256": sha256(provenance_path)}, indent=2))


if __name__ == "__main__":
    main()
