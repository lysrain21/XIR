#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from xir_lab.native.replication import (
    validate_capacity,
    validate_distinct_role_identities,
    validate_replication_paths,
    validate_validator_inventory,
)

GIB = 1024**3


def validator_inventory() -> list[dict[str, str]]:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project=xir-local-scale",
            "--format",
            "{{json .}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "DOCKER_API_VERSION": "1.43"},
    )
    return [
        {"name": str(row["Names"]), "status": str(row["Status"])}
        for row in (json.loads(line) for line in result.stdout.splitlines() if line)
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("fresh", "qualified"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--prior-runtime-root", type=Path, required=True)
    parser.add_argument(
        "--docker-root",
        type=Path,
        default=Path("/ebs/docker/165536.165536"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    validate_replication_paths(
        args.runtime_root,
        args.prior_runtime_root,
        require_empty=args.mode == "fresh",
    )
    docker = shutil.disk_usage(args.docker_root)
    gpfs = shutil.disk_usage(args.runtime_root.parent)
    validate_capacity(
        docker_free_bytes=docker.free,
        gpfs_free_bytes=gpfs.free,
        minimum_docker_free_bytes=28 * GIB,
        minimum_gpfs_free_bytes=40 * GIB,
    )
    payload: dict[str, object] = {
        "schema_version": "xir-lab-native-clean-replication-preflight-v1",
        "mode": args.mode,
        "runtime_root": str(args.runtime_root.resolve()),
        "prior_runtime_root": str(args.prior_runtime_root.resolve()),
        "docker_free_bytes": docker.free,
        "gpfs_free_bytes": gpfs.free,
        "minimum_docker_free_bytes": 28 * GIB,
        "minimum_gpfs_free_bytes": 40 * GIB,
        "observed_at": datetime.now(UTC).isoformat(),
        "valid": True,
    }
    if args.mode == "qualified":
        rows = validator_inventory()
        validate_validator_inventory(rows)
        if not (args.runtime_root / "native-application/deployment.json").is_file():
            raise SystemExit("replication deployment evidence is unavailable")
        current_identities = json.loads(
            (args.runtime_root / "provenance/public-identities.json").read_text(
                encoding="utf-8"
            )
        )
        prior_identities = json.loads(
            (
                args.prior_runtime_root
                / "provenance/public-identities.json"
            ).read_text(encoding="utf-8")
        )
        validate_distinct_role_identities(
            current_identities["roles"], prior_identities["roles"]
        )
        payload["validators"] = rows
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
