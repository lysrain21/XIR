"""Clean-state admission helpers for native-stack replications."""

from __future__ import annotations

import re
from pathlib import Path

from xir_lab.localnet.topology import LocalTopologyError


def expected_validator_names() -> set[str]:
    return {
        f"xir-local-scale-local-{role}-v{validator}-1"
        for role in ("source", "intermediate", "destination")
        for validator in range(1, 5)
    }


def validate_replication_paths(
    runtime_root: Path,
    prior_runtime_root: Path,
    *,
    require_empty: bool = True,
) -> None:
    runtime = runtime_root.resolve()
    prior = prior_runtime_root.resolve()
    if runtime == prior or runtime in prior.parents or prior in runtime.parents:
        raise LocalTopologyError("replication and prior runtime paths overlap")
    runtime_match = re.fullmatch(r"native-stack-run-(\d{3})", runtime.name)
    prior_match = re.fullmatch(r"native-stack-run-(\d{3})", prior.name)
    if runtime_match is None or prior_match is None:
        raise LocalTopologyError(
            "replication runtimes must use numbered native-stack-run paths"
        )
    if int(runtime_match.group(1)) <= int(prior_match.group(1)):
        raise LocalTopologyError("replication run number must follow the prior run")
    if not prior.is_dir():
        raise LocalTopologyError("prior runtime is unavailable")
    if require_empty and runtime.exists() and any(runtime.iterdir()):
        raise LocalTopologyError("replication runtime is not empty")


def validate_validator_inventory(rows: list[dict[str, str]]) -> None:
    observed = {row["name"] for row in rows}
    expected = expected_validator_names()
    if observed != expected:
        raise LocalTopologyError("replication validator inventory is not exact")
    unhealthy = sorted(
        row["name"] for row in rows if "(healthy)" not in row["status"].lower()
    )
    if unhealthy:
        raise LocalTopologyError(
            "replication validators are unhealthy: " + ", ".join(unhealthy)
        )


def validate_distinct_role_identities(
    current_roles: dict[str, str], prior_roles: dict[str, str]
) -> None:
    if not prior_roles or not set(prior_roles).issubset(current_roles):
        raise LocalTopologyError("replication is missing a prior role identity class")
    normalized_current = [value.lower() for value in current_roles.values()]
    if len(normalized_current) != len(set(normalized_current)):
        raise LocalTopologyError("replication role identities are not distinct")
    overlap = {value.lower() for value in current_roles.values()} & {
        value.lower() for value in prior_roles.values()
    }
    if overlap:
        raise LocalTopologyError(
            f"replication reuses {len(overlap)} prior role identities"
        )


def validate_capacity(
    *,
    docker_free_bytes: int,
    gpfs_free_bytes: int,
    minimum_docker_free_bytes: int,
    minimum_gpfs_free_bytes: int,
) -> None:
    if docker_free_bytes < minimum_docker_free_bytes:
        raise LocalTopologyError("Docker filesystem reserve is insufficient")
    if gpfs_free_bytes < minimum_gpfs_free_bytes:
        raise LocalTopologyError("GPFS filesystem reserve is insufficient")
