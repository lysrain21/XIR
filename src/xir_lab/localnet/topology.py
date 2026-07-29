"""Strict loading for the controlled local QBFT topology."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

import jsonschema
import rfc8785

PUBLIC_TESTNET_CHAIN_IDS = frozenset({11_155_420, 421_614, 84_532})
ROUTE_ROLES = ("source", "intermediate", "destination")


class LocalTopologyError(ValueError):
    """Raised when local identities could overlap public-network state."""


@dataclass(frozen=True)
class ResourceThresholds:
    minimum_logical_cpus: int
    minimum_memory_bytes: int
    minimum_disk_available_bytes: int


@dataclass(frozen=True)
class ResourcePolicy:
    render: ResourceThresholds
    smoke: ResourceThresholds
    scale: ResourceThresholds
    validator_memory_bytes: int
    validator_cpu_limit: float


@dataclass(frozen=True)
class LocalNetwork:
    network_id: str
    route_role: str
    chain_id: int
    host_rpc_port: int
    subnet: str
    validator_count: int
    block_period_seconds: int
    request_timeout_seconds: int
    gas_limit: str


@dataclass(frozen=True)
class LocalTopology:
    source_path: Path
    source_sha256: str
    topology_id: str
    project_name: str
    besu_image: str
    validator_data_storage: str
    runtime_root_environment_variable: str
    allowed_rpc_hosts: tuple[str, ...]
    public_chain_id_denylist: frozenset[int]
    networks: tuple[LocalNetwork, ...]
    resource_policy: ResourcePolicy


@dataclass(frozen=True)
class ValidatorIdentity:
    validator_id: str
    address: str
    public_key: str
    enode: str
    private_key_path: str


@dataclass(frozen=True)
class NetworkIdentity:
    network_id: str
    chain_id: int
    genesis_path: str
    genesis_sha256: str
    validators: tuple[ValidatorIdentity, ...]


@dataclass(frozen=True)
class LocalIdentityManifest:
    source_path: Path
    source_sha256: str
    payload_sha256: str
    topology_sha256: str
    created_at: str
    deployer: str
    runner: str
    networks: tuple[NetworkIdentity, ...]


def _schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _document(path: Path, schema_name: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read local document: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("local document root must be an object")
    validator = jsonschema.Draft202012Validator(
        _schema(schema_name),
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise LocalTopologyError(
            f"{schema_name} violation at {location}: {first.message}"
        )
    return cast(dict[str, Any], document), raw


def _thresholds(value: dict[str, Any]) -> ResourceThresholds:
    return ResourceThresholds(
        minimum_logical_cpus=cast(int, value["minimum_logical_cpus"]),
        minimum_memory_bytes=cast(int, value["minimum_memory_bytes"]),
        minimum_disk_available_bytes=cast(int, value["minimum_disk_available_bytes"]),
    )


def load_topology(path: Path) -> LocalTopology:
    """Load a topology and enforce identities that JSON Schema cannot compare."""

    document, raw = _document(path, "local-topology-v1.schema.json")
    network_values = cast(list[dict[str, Any]], document["networks"])
    networks = tuple(LocalNetwork(**item) for item in network_values)
    if tuple(item.route_role for item in networks) != ROUTE_ROLES:
        raise LocalTopologyError("local route roles must be source/intermediate/destination")
    chain_ids = [item.chain_id for item in networks]
    if len(set(chain_ids)) != 3:
        raise LocalTopologyError("local chain IDs must be unique")
    denylist = frozenset(cast(list[int], document["public_chain_id_denylist"]))
    if not PUBLIC_TESTNET_CHAIN_IDS <= denylist:
        raise LocalTopologyError("public testnet denylist is incomplete")
    if set(chain_ids) & denylist:
        raise LocalTopologyError("local topology uses a denied public chain ID")
    identities = [item.network_id for item in networks]
    ports = [item.host_rpc_port for item in networks]
    subnets = [item.subnet for item in networks]
    if len(set(identities)) != 3 or len(set(ports)) != 3 or len(set(subnets)) != 3:
        raise LocalTopologyError("local network IDs, RPC ports, and subnets must be unique")
    policy = cast(dict[str, Any], document["resource_policy"])
    return LocalTopology(
        source_path=path.resolve(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        topology_id=cast(str, document["topology_id"]),
        project_name=cast(str, document["project_name"]),
        besu_image=cast(str, document["besu_image"]),
        validator_data_storage=cast(str, document["validator_data_storage"]),
        runtime_root_environment_variable=cast(
            str, document["runtime_root_environment_variable"]
        ),
        allowed_rpc_hosts=tuple(cast(list[str], document["allowed_rpc_hosts"])),
        public_chain_id_denylist=denylist,
        networks=networks,
        resource_policy=ResourcePolicy(
            render=_thresholds(cast(dict[str, Any], policy["render"])),
            smoke=_thresholds(cast(dict[str, Any], policy["smoke"])),
            scale=_thresholds(cast(dict[str, Any], policy["scale"])),
            validator_memory_bytes=cast(int, policy["validator_memory_bytes"]),
            validator_cpu_limit=float(policy["validator_cpu_limit"]),
        ),
    )


def _safe_relative(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise LocalTopologyError(f"{label} must stay below the runtime root")


def load_identity_manifest(
    path: Path,
    *,
    topology: LocalTopology,
) -> LocalIdentityManifest:
    """Load a public manifest and bind it to the exact topology."""

    document, raw = _document(path, "local-identity-manifest-v1.schema.json")
    payload = cast(dict[str, Any], document["payload"])
    payload_sha256 = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    if payload_sha256 != document["payload_sha256"]:
        raise LocalTopologyError("local identity payload digest mismatch")
    if payload["topology_sha256"] != topology.source_sha256:
        raise LocalTopologyError("local identity manifest references another topology")
    network_values = cast(list[dict[str, Any]], payload["networks"])
    if [item["network_id"] for item in network_values] != [
        item.network_id for item in topology.networks
    ]:
        raise LocalTopologyError("local identity network order differs from topology")
    if [item["chain_id"] for item in network_values] != [
        item.chain_id for item in topology.networks
    ]:
        raise LocalTopologyError("local identity chain IDs differ from topology")
    networks: list[NetworkIdentity] = []
    addresses: list[str] = []
    public_keys: list[str] = []
    enodes: list[str] = []
    for network in network_values:
        _safe_relative(cast(str, network["genesis_path"]), "genesis path")
        validators: list[ValidatorIdentity] = []
        for item in cast(list[dict[str, Any]], network["validators"]):
            _safe_relative(cast(str, item["private_key_path"]), "private key path")
            validator = ValidatorIdentity(**item)
            validators.append(validator)
            addresses.append(validator.address.lower())
            public_keys.append(validator.public_key)
            enodes.append(validator.enode)
        networks.append(
            NetworkIdentity(
                network_id=cast(str, network["network_id"]),
                chain_id=cast(int, network["chain_id"]),
                genesis_path=cast(str, network["genesis_path"]),
                genesis_sha256=cast(str, network["genesis_sha256"]),
                validators=tuple(validators),
            )
        )
    if len(set(addresses)) != 12 or len(set(public_keys)) != 12 or len(set(enodes)) != 12:
        raise LocalTopologyError("validator identities must be unique across all chains")
    accounts = cast(dict[str, str], payload["accounts"])
    if accounts["deployer"].lower() == accounts["runner"].lower():
        raise LocalTopologyError("local deployer and runner must be distinct")
    return LocalIdentityManifest(
        source_path=path.resolve(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        payload_sha256=payload_sha256,
        topology_sha256=cast(str, payload["topology_sha256"]),
        created_at=cast(str, payload["created_at"]),
        deployer=accounts["deployer"],
        runner=accounts["runner"],
        networks=tuple(networks),
    )
