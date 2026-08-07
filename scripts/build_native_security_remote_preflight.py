#!/usr/bin/env python3
"""Build the secret-free remote preflight/immutability record for security-v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from xir_lab.native.publication import sha256_file, verify_manifest
from xir_lab.publication import PublicationError, validate_publishable_file

SECURITY_SOURCE_FILES = {
    "v1": (
        "configs/native/native-security-v1.json",
        "schemas/native-security-v1-config.schema.json",
        "contracts/src/XIREncoding.sol",
        "contracts/src/XIRGateway.sol",
        "contracts/src/HyperlaneAdapter.sol",
        "contracts/src/LayerZeroAdapter.sol",
        "contracts/test/SecuritySpliceRegression.t.sol",
        "src/xir_lab/native/root_signer.py",
        "src/xir_lab/native/runner.py",
        "src/xir_lab/native/security_v1.py",
    ),
    "v2": (
        "configs/native/native-security-v2.json",
        "schemas/native-security-v2-config.schema.json",
        "contracts/src/XIREncoding.sol",
        "contracts/src/XIRGateway.sol",
        "contracts/src/HyperlaneAdapter.sol",
        "contracts/src/LayerZeroAdapter.sol",
        "contracts/src/NativeSecurityPriorVerifierFixture.sol",
        "contracts/test/RunnerAuthorityRegression.t.sol",
        "contracts/test/SecuritySpliceRegression.t.sol",
        "scripts/deploy_native_application.py",
        "scripts/run_native_security_v2.py",
        "src/xir_lab/native/deployer.py",
        "src/xir_lab/native/root_signer.py",
        "src/xir_lab/native/runner.py",
        "src/xir_lab/native/security_v1.py",
        "src/xir_lab/native/security_v2.py",
    ),
}


def _json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _disk(path: Path) -> dict[str, int | str]:
    value = os.statvfs(path)
    return {
        "path": str(path),
        "total_bytes": value.f_blocks * value.f_frsize,
        "available_bytes": value.f_bavail * value.f_frsize,
    }


def _memory() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            values[f"{key.lower()}_bytes"] = int(parts[0]) * 1024
    return values


def _docker_root() -> Path:
    result = subprocess.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(result.stdout.strip())


def _host_fingerprint() -> dict[str, Any]:
    keys = sorted(Path("/etc/ssh").glob("ssh_host_*_key.pub"))
    digests = [sha256_file(path) for path in keys]
    return {
        "source": "ssh_host_public_key_bundle",
        "public_key_count": len(digests),
        "sha256": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
        "hostname_included": False,
    }


def _validator_status(names: list[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for name in names:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .State}}",
                name,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        state: dict[str, Any] = {}
        if result.returncode == 0:
            state = cast(dict[str, Any], json.loads(result.stdout))
        health = cast(dict[str, Any], state.get("Health", {})).get("Status")
        output.append(
            {
                "name": name,
                "inspect_succeeded": result.returncode == 0,
                "running": state.get("Running") is True,
                "status": state.get("Status"),
                "health": health,
                "valid": (
                    result.returncode == 0 and state.get("Running") is True and health == "healthy"
                ),
            }
        )
    return output


def _pid_status(label: str, path: Path) -> dict[str, Any]:
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
        process_root = Path("/proc") / str(pid)
        stat = (process_root / "stat").read_text(encoding="utf-8").split()
        command = (process_root / "comm").read_text(encoding="utf-8").strip()
        state = stat[2]
        alive = state != "Z"
    except (FileNotFoundError, OSError, ValueError, IndexError):
        pid = None
        command = None
        state = None
        alive = False
    return {
        "label": label,
        "pid_file": str(path),
        "pid": pid,
        "command_name": command,
        "process_state": state,
        "alive": alive,
        "valid": alive,
    }


def _source_provenance(
    repository_root: Path,
    repository_revision: str | None,
    source_files: tuple[str, ...],
) -> dict[str, Any]:
    if repository_revision is None:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError("repository has no Git metadata; --repository-revision is required")
        repository_revision = result.stdout.strip()
    entries: list[dict[str, Any]] = []
    for relative in source_files:
        path = repository_root / relative
        entries.append(
            {
                "relative_path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    semantic = hashlib.sha256(
        "\n".join(f"{entry['sha256']}  {entry['relative_path']}" for entry in entries).encode()
    ).hexdigest()
    return {
        "repository_revision": repository_revision,
        "selected_source_tree_sha256": semantic,
        "selected_source_file_count": len(entries),
        "files": entries,
    }


def _verify_frozen_run(*, frozen_runtime_root: Path, frozen_manifest_path: Path) -> dict[str, Any]:
    manifest = _json(frozen_manifest_path)
    expected_manifest_sha256 = (
        frozen_manifest_path.with_suffix(frozen_manifest_path.suffix + ".sha256")
        .read_text(encoding="utf-8")
        .split()[0]
    )
    manifest_sha256 = sha256_file(frozen_manifest_path)
    strict_errors = verify_manifest(manifest, frozen_runtime_root)
    if manifest_sha256 != expected_manifest_sha256:
        strict_errors.append("manifest_sha256")
    prior_verification_path = frozen_manifest_path.parent / "manifest-verification.json"
    prior = _json(prior_verification_path)
    if prior.get("valid") is not True:
        strict_errors.append("prior_manifest_verification")
    expected_transient = "sha256:layerzero/worker.sqlite-shm"
    transient_errors = [error for error in strict_errors if error == expected_transient]
    durable_errors = [error for error in strict_errors if error != expected_transient]
    validation = {
        "overall_mismatch_count_is_one": len(strict_errors) == 1,
        "transient_path_is_exact": transient_errors == [expected_transient],
        "durable_mismatch_count_is_zero": len(durable_errors) == 0,
    }
    return {
        "run_id": manifest["run_id"],
        "runtime_path": str(frozen_runtime_root),
        "manifest_path": str(frozen_manifest_path),
        "manifest_sha256": manifest_sha256,
        "expected_manifest_sha256": expected_manifest_sha256,
        "artifact_files_checked": len(manifest["artifacts"]),
        "artifact_total_bytes": manifest["artifact_total_bytes"],
        "prior_verification_sha256": sha256_file(prior_verification_path),
        "strict_errors": strict_errors,
        "transient_sqlite_errors": transient_errors,
        "transient_sqlite_role": (
            "SQLite shared-memory WAL index and locking state; non-durable runtime state"
        ),
        "durable_evidence_errors": durable_errors,
        "strict_byte_identity": not strict_errors,
        "durable_evidence_identity": not durable_errors,
        "validation": validation,
        "valid": all(validation.values()),
    }


def _cached_frozen_run(
    *,
    cache_path: Path,
    frozen_runtime_root: Path,
    frozen_manifest_path: Path,
) -> dict[str, Any]:
    cached = _json(cache_path)
    manifest = _json(frozen_manifest_path)
    if (
        cached.get("manifest_sha256") != sha256_file(frozen_manifest_path)
        or int(cached.get("artifact_files_checked", -1)) != len(manifest["artifacts"])
        or cached.get("runtime_path") != str(frozen_runtime_root)
    ):
        raise ValueError("frozen verification cache does not match the manifest")
    strict_errors = cast(list[str], cached.get("strict_errors", cached.get("errors", [])))
    expected_transient = "sha256:layerzero/worker.sqlite-shm"
    transient_errors = [error for error in strict_errors if error == expected_transient]
    durable_errors = [error for error in strict_errors if error != expected_transient]
    validation = {
        "overall_mismatch_count_is_one": len(strict_errors) == 1,
        "transient_path_is_exact": transient_errors == [expected_transient],
        "durable_mismatch_count_is_zero": len(durable_errors) == 0,
    }
    return {
        **cached,
        "verification_cache_path": str(cache_path),
        "verification_cache_sha256": sha256_file(cache_path),
        "verified_at": datetime.fromtimestamp(cache_path.stat().st_mtime, UTC).isoformat(),
        "strict_errors": strict_errors,
        "transient_sqlite_errors": transient_errors,
        "transient_sqlite_role": (
            "SQLite shared-memory WAL index and locking state; non-durable runtime state"
        ),
        "durable_evidence_errors": durable_errors,
        "strict_byte_identity": not strict_errors,
        "durable_evidence_identity": not durable_errors,
        "validation": validation,
        "valid": all(validation.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualified-preflight", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--component-provenance", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--repository-revision")
    parser.add_argument("--campaign-version", choices=sorted(SECURITY_SOURCE_FILES), default="v1")
    parser.add_argument("--campaign-pid-file", type=Path)
    parser.add_argument("--frozen-runtime-root", type=Path, required=True)
    parser.add_argument("--frozen-manifest", type=Path, required=True)
    parser.add_argument("--frozen-verification-cache", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    qualified = _json(args.qualified_preflight)
    validator_names = [str(item["name"]) for item in qualified["validators"]]
    validators = _validator_status(validator_names)
    component_provenance = _json(args.component_provenance)
    docker_root = _docker_root()
    runtime_disk = _disk(args.runtime_root)
    docker_disk = _disk(docker_root)
    memory = _memory()
    host_fingerprint = _host_fingerprint()
    source_provenance = _source_provenance(
        args.repository_root,
        args.repository_revision,
        SECURITY_SOURCE_FILES[args.campaign_version],
    )
    protocol_agents = [
        _pid_status("hyperlane-relayer", args.runtime_root / "hyperlane/agents/pids/relayer.pid"),
        _pid_status("layerzero-worker", args.runtime_root / "pids/layerzero-worker.pid"),
    ]
    campaign_runner = (
        _pid_status("security-campaign-runner", args.campaign_pid_file)
        if args.campaign_pid_file is not None
        else None
    )
    if args.frozen_verification_cache is None:
        frozen = _verify_frozen_run(
            frozen_runtime_root=args.frozen_runtime_root,
            frozen_manifest_path=args.frozen_manifest,
        )
    else:
        frozen = _cached_frozen_run(
            cache_path=args.frozen_verification_cache,
            frozen_runtime_root=args.frozen_runtime_root,
            frozen_manifest_path=args.frozen_manifest,
        )
    frozen_checkpoint = args.output.with_suffix(".run003-check.json")
    frozen_checkpoint.parent.mkdir(parents=True, exist_ok=True)
    frozen_checkpoint.write_text(
        json.dumps(frozen, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    errors: list[str] = []
    if qualified.get("valid") is not True:
        errors.append("initial qualified preflight is invalid")
    if len(validators) != 12 or not all(item["valid"] for item in validators):
        errors.append("twelve healthy validators were not observed")
    if not frozen["valid"]:
        errors.append("frozen run-003 manifest verification failed")
    if not all(
        item.get("clean") is True and item.get("build_complete") is True
        for item in component_provenance["components"]
    ):
        errors.append("component provenance is not clean and complete")
    if not all(item["valid"] for item in protocol_agents):
        errors.append("native protocol agent is not alive")
    if campaign_runner is not None and campaign_runner["valid"] is not True:
        errors.append("security campaign runner is not alive")

    document = {
        "schema_version": f"xir-lab-native-security-{args.campaign_version}-remote-preflight-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "host_fingerprint": host_fingerprint,
        "runtime_path": str(args.runtime_root),
        "deployment": {
            "namespace": args.deployment.parent.name,
            "path": str(args.deployment),
            "sha256": sha256_file(args.deployment),
        },
        "initial_qualified_preflight": {
            "path": str(args.qualified_preflight),
            "sha256": sha256_file(args.qualified_preflight),
            "observed_at": qualified.get("observed_at"),
            "valid": qualified.get("valid"),
        },
        "capacity": {
            "runtime_filesystem": runtime_disk,
            "docker_filesystem": docker_disk,
            "memory": memory,
        },
        "validators": validators,
        "validator_count": len(validators),
        "healthy_validator_count": sum(item["valid"] for item in validators),
        "protocol_agents": protocol_agents,
        "campaign_runner": campaign_runner,
        "component_provenance": {
            "path": str(args.component_provenance),
            "sha256": sha256_file(args.component_provenance),
            "lock_sha256": component_provenance.get("lock_sha256"),
            "components": [
                {
                    "component_id": item["component_id"],
                    "commit": item["commit"],
                    "clean": item["clean"],
                    "build_complete": item["build_complete"],
                }
                for item in component_provenance["components"]
            ],
        },
        "source_provenance": source_provenance,
        "frozen_run_003_untouched_check": frozen,
        "credentials_included": False,
        "errors": errors,
        "valid": not errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        validate_publishable_file(args.output.parent, args.output)
    except PublicationError as exc:
        document["errors"].append(f"secret scan: {exc}")
        document["valid"] = False
        args.output.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    report = [
        f"# native-security-{args.campaign_version} remote preflight",
        "",
        f"- Runtime: `{document['runtime_path']}`",
        f"- Healthy validators: {document['healthy_validator_count']}/12",
        f"- Frozen run-003 artifacts rechecked: {frozen['artifact_files_checked']}",
        f"- Frozen run-003 strict byte identity: {frozen['strict_byte_identity']}",
        f"- Frozen run-003 durable evidence identity: {frozen['durable_evidence_identity']}",
        f"- Secret-free: {document['credentials_included'] is False}",
        f"- Valid: {document['valid']}",
    ]
    report_path = args.output.with_suffix(".md")
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(document, indent=2, sort_keys=True))
    if not document["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
