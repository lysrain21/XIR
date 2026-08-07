from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.replication import (
    expected_validator_names,
    validate_capacity,
    validate_distinct_role_identities,
    validate_replication_paths,
    validate_validator_inventory,
)


def test_clean_replication_paths_require_empty_successor_run(tmp_path: Path) -> None:
    prior = tmp_path / "native-stack-run-001"
    prior.mkdir()
    current = tmp_path / "native-stack-run-002"
    validate_replication_paths(current, prior)
    current.mkdir()
    (current / "stale").write_text("x", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="not empty"):
        validate_replication_paths(current, prior)
    next_run = tmp_path / "native-stack-run-003"
    validate_replication_paths(next_run, current)
    with pytest.raises(LocalTopologyError, match="must follow"):
        validate_replication_paths(prior, current)


def test_validator_inventory_is_exact_and_healthy() -> None:
    rows = [
        {"name": name, "status": "Up 1 minute (healthy)"}
        for name in expected_validator_names()
    ]
    validate_validator_inventory(rows)
    rows[0]["status"] = "Up 1 minute (unhealthy)"
    with pytest.raises(LocalTopologyError, match="unhealthy"):
        validate_validator_inventory(rows)


def test_replication_role_identities_must_not_be_reused() -> None:
    prior = {"runner": "0x" + "11" * 20}
    current = {"runner": "0x" + "22" * 20}
    validate_distinct_role_identities(current, prior)
    validate_distinct_role_identities(
        {**current, "root-signer": "0x" + "33" * 20}, prior
    )
    with pytest.raises(LocalTopologyError, match="reuses"):
        validate_distinct_role_identities(prior, prior)
    with pytest.raises(LocalTopologyError, match="not distinct"):
        validate_distinct_role_identities(
            {"runner": "0x" + "22" * 20, "root-signer": "0x" + "22" * 20},
            prior,
        )


def test_replication_capacity_enforces_both_reserves() -> None:
    validate_capacity(
        docker_free_bytes=28,
        gpfs_free_bytes=40,
        minimum_docker_free_bytes=28,
        minimum_gpfs_free_bytes=40,
    )
    with pytest.raises(LocalTopologyError, match="Docker"):
        validate_capacity(
            docker_free_bytes=27,
            gpfs_free_bytes=40,
            minimum_docker_free_bytes=28,
            minimum_gpfs_free_bytes=40,
        )
