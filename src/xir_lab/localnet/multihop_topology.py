"""Fail-closed loading for the versioned five-chain QBFT topology."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, cast

import jsonschema
import rfc8785

from xir_lab.localnet.topology import (
    PUBLIC_TESTNET_CHAIN_IDS,
    LocalIdentityManifest,
    LocalNetwork,
    LocalTopology,
    LocalTopologyError,
    NetworkIdentity,
    ResourcePolicy,
    ResourceThresholds,
    ValidatorIdentity,
)

MULTIHOP_ROUTE_ROLES = ("chain_a", "chain_b", "chain_c", "chain_d", "chain_e")


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _document(path: Path, schema_name: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read multihop topology document: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("multihop topology document root must be an object")
    schema = json.loads((_root() / "schemas" / schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).iter_errors(document),
        key=lambda error: [str(part) for part in error.path],
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise LocalTopologyError(f"{schema_name} violation at {location}: {first.message}")
    return cast(dict[str, Any], document), raw


def _thresholds(value: dict[str, Any]) -> ResourceThresholds:
    return ResourceThresholds(
        minimum_logical_cpus=int(value["minimum_logical_cpus"]),
        minimum_memory_bytes=int(value["minimum_memory_bytes"]),
        minimum_disk_available_bytes=int(value["minimum_disk_available_bytes"]),
    )


def load_multihop_topology(path: Path) -> LocalTopology:
    document, raw = _document(path, "native-multihop-local-topology-v1.schema.json")
    networks = tuple(
        LocalNetwork(**item) for item in cast(list[dict[str, Any]], document["networks"])
    )
    if tuple(network.route_role for network in networks) != MULTIHOP_ROUTE_ROLES:
        raise LocalTopologyError("multihop route roles must be chain_a through chain_e")
    denylist = frozenset(cast(list[int], document["public_chain_id_denylist"]))
    if not PUBLIC_TESTNET_CHAIN_IDS <= denylist:
        raise LocalTopologyError("public testnet denylist is incomplete")
    uniqueness_fields: dict[str, list[object]] = {
        "chain ID": [network.chain_id for network in networks],
        "network ID": [network.network_id for network in networks],
        "RPC port": [network.host_rpc_port for network in networks],
        "subnet": [network.subnet for network in networks],
    }
    for field, values in uniqueness_fields.items():
        if len(values) != len(set(values)):
            raise LocalTopologyError(f"multihop topology has duplicate {field}")
    if {network.chain_id for network in networks} & denylist:
        raise LocalTopologyError("multihop topology uses a denied public chain ID")
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
            validator_memory_bytes=int(policy["validator_memory_bytes"]),
            validator_cpu_limit=float(policy["validator_cpu_limit"]),
        ),
        rpc_http_apis=tuple(cast(list[str], document["rpc_http_apis"])),
        validator_runtime_user=cast(str, document["validator_runtime_user"]),
    )


def _safe_relative(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise LocalTopologyError(f"{label} must stay below the runtime root")


def load_multihop_identity_manifest(
    path: Path, *, topology: LocalTopology
) -> LocalIdentityManifest:
    document, raw = _document(
        path, "native-multihop-identity-manifest-v1.schema.json"
    )
    payload = cast(dict[str, Any], document["payload"])
    if hashlib.sha256(rfc8785.dumps(payload)).hexdigest() != document["payload_sha256"]:
        raise LocalTopologyError("multihop identity payload digest mismatch")
    if payload["topology_sha256"] != topology.source_sha256:
        raise LocalTopologyError("multihop identity manifest references another topology")
    values = cast(list[dict[str, Any]], payload["networks"])
    if [value["network_id"] for value in values] != [
        network.network_id for network in topology.networks
    ]:
        raise LocalTopologyError("multihop identity network order differs from topology")
    networks: list[NetworkIdentity] = []
    addresses: list[str] = []
    public_keys: list[str] = []
    enodes: list[str] = []
    for value in values:
        _safe_relative(cast(str, value["genesis_path"]), "genesis path")
        validators: list[ValidatorIdentity] = []
        for row in cast(list[dict[str, Any]], value["validators"]):
            _safe_relative(cast(str, row["private_key_path"]), "private key path")
            validator = ValidatorIdentity(**row)
            validators.append(validator)
            addresses.append(validator.address.lower())
            public_keys.append(validator.public_key)
            enodes.append(validator.enode)
        networks.append(
            NetworkIdentity(
                network_id=cast(str, value["network_id"]),
                chain_id=int(value["chain_id"]),
                genesis_path=cast(str, value["genesis_path"]),
                genesis_sha256=cast(str, value["genesis_sha256"]),
                validators=tuple(validators),
            )
        )
    if len(set(addresses)) != 20 or len(set(public_keys)) != 20 or len(set(enodes)) != 20:
        raise LocalTopologyError("20 validator identities must be globally unique")
    accounts = cast(dict[str, str], payload["accounts"])
    if accounts["deployer"].lower() == accounts["runner"].lower():
        raise LocalTopologyError("multihop deployer and runner must be distinct")
    return LocalIdentityManifest(
        source_path=path.resolve(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        payload_sha256=cast(str, document["payload_sha256"]),
        topology_sha256=cast(str, payload["topology_sha256"]),
        created_at=cast(str, payload["created_at"]),
        deployer=accounts["deployer"],
        runner=accounts["runner"],
        networks=tuple(networks),
    )
