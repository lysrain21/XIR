from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import LocalIdentityError, initialize_local_identities
from xir_lab.localnet.preflight import (
    HostSnapshot,
    NodeObservation,
    build_local_preflight,
)
from xir_lab.localnet.topology import (
    LocalTopologyError,
    load_identity_manifest,
    load_topology,
)

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "configs" / "local" / "topology-v1.json"
REMOTE_TOPOLOGY = ROOT / "configs" / "local" / "topology-remote-v1.json"


def _initialized(tmp_path: Path) -> tuple[Any, Any, Path]:
    topology = load_topology(TOPOLOGY)
    runtime = tmp_path / "runtime"
    manifest_path = initialize_local_identities(
        topology,
        runtime_root=runtime,
        repository_root=ROOT,
        created_at=datetime(2026, 7, 29, tzinfo=UTC),
    )
    return topology, load_identity_manifest(manifest_path, topology=topology), runtime


def _observations() -> tuple[NodeObservation, ...]:
    return tuple(
        NodeObservation(
            network_id=network_id,
            validator_id=f"v{validator}",
            chain_id=chain_id,
            reachable=True,
            peer_count=3,
            head_block=20,
            checkpoint_block=19,
            checkpoint_hash=f"0x{chain_id:064x}",
            block_advanced=True,
        )
        for network_id, chain_id in (
            ("local-source", 3133701),
            ("local-intermediate", 3133702),
            ("local-destination", 3133703),
        )
        for validator in range(1, 5)
    )


def test_topology_is_exact_and_denies_public_chain_ids() -> None:
    topology = load_topology(TOPOLOGY)
    assert [item.route_role for item in topology.networks] == [
        "source",
        "intermediate",
        "destination",
    ]
    assert [item.chain_id for item in topology.networks] == [
        3133701,
        3133702,
        3133703,
    ]
    assert sum(item.validator_count for item in topology.networks) == 12
    assert "@sha256:" in topology.besu_image


def test_public_chain_id_collision_is_rejected(tmp_path: Path) -> None:
    document = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
    document["networks"][0]["chain_id"] = 11155420
    path = tmp_path / "topology.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="denied public chain ID"):
        load_topology(path)


def test_external_identity_initialization_and_deterministic_compose(
    tmp_path: Path,
) -> None:
    topology, manifest, runtime = _initialized(tmp_path)
    assert manifest.deployer != manifest.runner
    assert len({item.address for network in manifest.networks for item in network.validators}) == 12
    assert not (ROOT / "private").exists()
    private_paths = [
        runtime / item.private_key_path
        for network in manifest.networks
        for item in network.validators
    ]
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in private_paths)
    manifest_text = manifest.source_path.read_text(encoding="utf-8")
    assert "private_bytes" not in manifest_text

    first, first_digest = render_compose(topology, manifest)
    second, second_digest = render_compose(topology, manifest)
    assert first == second
    assert first_digest == second_digest
    compose = yaml.safe_load(first)
    assert len(compose["services"]) == 12
    assert "volumes" not in compose
    assert len(compose["networks"]) == 3
    assert sum("ports" in service for service in compose["services"].values()) == 3
    assert {
        service["image"] for service in compose["services"].values()
    } == {topology.besu_image}
    data_mounts = [
        mount
        for service in compose["services"].values()
        for mount in service["volumes"]
        if mount.endswith(":/data")
    ]
    assert len(data_mounts) == 12
    assert len(set(data_mounts)) == 12
    assert all(
        mount.startswith("${XIR_LOCAL_RUNTIME_ROOT:?set runtime root}/data/")
        for mount in data_mounts
    )
    assert all((runtime / "data" / network / validator).is_dir()
               for network in ("local-source", "local-intermediate", "local-destination")
               for validator in ("v1", "v2", "v3", "v4"))


def test_identity_initialization_refuses_repository_path() -> None:
    topology = load_topology(TOPOLOGY)
    with pytest.raises(LocalIdentityError, match="outside the repository"):
        initialize_local_identities(
            topology,
            runtime_root=ROOT / "unsafe-runtime",
            repository_root=ROOT,
        )


def test_remote_topology_renders_twelve_isolated_named_volumes(
    tmp_path: Path,
) -> None:
    topology = load_topology(REMOTE_TOPOLOGY)
    runtime = tmp_path / "remote-runtime"
    manifest_path = initialize_local_identities(
        topology,
        runtime_root=runtime,
        repository_root=ROOT,
        created_at=datetime(2026, 7, 29, tzinfo=UTC),
    )
    manifest = load_identity_manifest(manifest_path, topology=topology)
    rendered, _ = render_compose(topology, manifest)
    compose = yaml.safe_load(rendered)
    assert topology.validator_data_storage == "docker-volume"
    assert len(compose["volumes"]) == 12
    assert {
        mount["source"]
        for service in compose["services"].values()
        for mount in service["volumes"]
        if mount["target"] == "/data"
    } == {
        f"{network}-v{validator}-data"
        for network in ("local-source", "local-intermediate", "local-destination")
        for validator in range(1, 5)
    }
    assert all(
        service["command"][0] == "--genesis-file=/data/bootstrap/genesis.json"
        and service["command"][2] == "--node-private-key-file=/data/bootstrap/key"
        and len(service["volumes"]) == 1
        for service in compose["services"].values()
    )


def test_host_and_network_preflight_pass_and_fail_closed(
    tmp_path: Path,
) -> None:
    topology, manifest, _ = _initialized(tmp_path)
    passing = build_local_preflight(
        topology=topology,
        manifest=manifest,
        mode="scale",
        host=HostSnapshot(
            logical_cpus=16,
            memory_bytes=32 * 1024**3,
            disk_available_bytes=100 * 1024**3,
            storage_filesystem_path=str(tmp_path),
        ),
        observations=_observations(),
    )
    assert passing["eligible"] is True

    failing = build_local_preflight(
        topology=topology,
        manifest=manifest,
        mode="scale",
        host=HostSnapshot(
            logical_cpus=2,
            memory_bytes=8 * 1024**3,
            disk_available_bytes=100 * 1024**3,
            storage_filesystem_path=str(tmp_path),
        ),
    )
    assert failing["eligible"] is False
    failed = {
        item["check_id"] for item in failing["checks"] if item["status"] == "fail"
    }
    assert {"logical_cpus", "memory_bytes", "twelve_node_observations"} <= failed
