"""Schema-backed typed loaders for XIR Testnet Lab durable inputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785

NetworkId = Literal["op-sepolia", "arbitrum-sepolia", "base-sepolia"]
RouteRole = Literal["source", "intermediate", "destination"]
Protocol = Literal["hyperlane", "layerzero-v2"]
SignerRole = Literal["deployer", "runner", "approval-authority"]
OperationType = Literal["deployment", "configuration", "pilot", "primary", "scale", "closeout"]
FinalityKind = Literal["confirmations", "l2-safe", "l2-finalized", "l1-settlement"]

EXPECTED_NETWORKS: dict[NetworkId, tuple[int, RouteRole]] = {
    "op-sepolia": (11_155_420, "source"),
    "arbitrum-sepolia": (421_614, "intermediate"),
    "base-sepolia": (84_532, "destination"),
}
EXPECTED_OPERATIONS = frozenset(
    {"deployment", "configuration", "pilot", "primary", "scale", "closeout"}
)
EXPECTED_CARRIER_EDGES = frozenset(
    {
        ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
        ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
        ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
        ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
    }
)


class ConfigError(ValueError):
    """Raised when a durable configuration is malformed or semantically unsafe."""


@dataclass(frozen=True)
class Checkpoint:
    kind: str
    block_number: int
    block_hash: str


@dataclass(frozen=True)
class Network:
    network_id: NetworkId
    chain_id: int
    route_role: RouteRole
    read_rpc_ref: str
    write_rpc_ref: str
    checkpoint: Checkpoint


@dataclass(frozen=True)
class ContractIdentity:
    contract_id: str
    network_id: NetworkId
    kind: str
    address: str
    runtime_code_sha256: str
    administrator: str
    runner: str


@dataclass(frozen=True)
class CarrierEndpoint:
    endpoint_id: str
    protocol: Protocol
    local_network: NetworkId
    remote_network: NetworkId
    endpoint_address: str
    remote_selector: int
    peer_address: str
    security_config_sha256: str


@dataclass(frozen=True)
class Deployment:
    deployment_id: str
    deployment_version: int
    compiler_version: str
    contracts: tuple[ContractIdentity, ...]
    carrier_endpoints: tuple[CarrierEndpoint, ...]


@dataclass(frozen=True)
class PayloadEffect:
    payload_id: str
    payload_hex: str
    payload_sha256: str
    destination_effect_id: str
    effect_definition_sha256: str


@dataclass(frozen=True)
class SignerReference:
    signer_id: str
    role: SignerRole
    kind: str
    reference: str
    public_identity: str


@dataclass(frozen=True)
class ApprovalRequirement:
    operation_type: OperationType
    approval_schema: str
    expected_pre_state_sha256: str
    authorized_transition_sha256: str


@dataclass(frozen=True)
class ChainBudget:
    chain_id: int
    max_transaction_wei: int
    max_batch_wei: int
    max_run_wei: int
    minimum_runner_balance_wei: int


@dataclass(frozen=True)
class StopPolicy:
    consecutive_failures: int
    rolling_window: int
    rolling_failure_rate: float
    max_quote_age_seconds: int
    max_quote_movement_bps: int
    timeout_count: int
    collector_backlog: int
    collector_heartbeat_seconds: int
    disk_floor_bytes: int
    nonce_gap_action: str
    rpc_disagreement_action: str
    reorganization_action: str
    allow_partial_conditions: bool


@dataclass(frozen=True)
class FinalityPolicy:
    chain_id: int
    kind: FinalityKind
    confirmation_count: int | None


@dataclass(frozen=True)
class LabConfig:
    config_id: str
    networks: tuple[Network, ...]
    deployment: Deployment
    payload_effect: PayloadEffect
    signers: tuple[SignerReference, ...]
    approval_requirements: tuple[ApprovalRequirement, ...]
    budgets: tuple[ChainBudget, ...]
    stop_policy: StopPolicy
    finality_policies: tuple[FinalityPolicy, ...]
    source_sha256: str


@dataclass(frozen=True)
class ApprovalEnvelope:
    operation_type: OperationType
    operation_id: str
    approval_id: str
    issuer_id: str
    issuer_sequence: int
    payload_sha256: str
    signature: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class RunManifest:
    manifest_id: str
    run_id: str
    profile_id: str
    config_sha256: str
    generated_at: str
    document: dict[str, Any]


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read JSON document: {path}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"JSON document root must be an object: {path}")
    return cast(dict[str, Any], value), raw


def _validate_schema(document: dict[str, Any], schema_path: Path) -> None:
    schema, _ = _read_json(schema_path)
    try:
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(document)
    except jsonschema.ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path)
        raise ConfigError(f"schema violation at {location or '<root>'}: {exc.message}") from exc


def _dict(value: Any) -> dict[str, Any]:
    return cast(dict[str, Any], value)


def _network(value: dict[str, Any]) -> Network:
    checkpoint = _dict(value["checkpoint"])
    return Network(
        network_id=cast(NetworkId, value["network_id"]),
        chain_id=cast(int, value["chain_id"]),
        route_role=cast(RouteRole, value["route_role"]),
        read_rpc_ref=cast(str, value["read_rpc_ref"]),
        write_rpc_ref=cast(str, value["write_rpc_ref"]),
        checkpoint=Checkpoint(
            kind=cast(str, checkpoint["kind"]),
            block_number=cast(int, checkpoint["block_number"]),
            block_hash=cast(str, checkpoint["block_hash"]),
        ),
    )


def _contract(value: dict[str, Any]) -> ContractIdentity:
    return ContractIdentity(
        contract_id=cast(str, value["contract_id"]),
        network_id=cast(NetworkId, value["network_id"]),
        kind=cast(str, value["kind"]),
        address=cast(str, value["address"]),
        runtime_code_sha256=cast(str, value["runtime_code_sha256"]),
        administrator=cast(str, value["administrator"]),
        runner=cast(str, value["runner"]),
    )


def _carrier(value: dict[str, Any]) -> CarrierEndpoint:
    return CarrierEndpoint(
        endpoint_id=cast(str, value["endpoint_id"]),
        protocol=cast(Protocol, value["protocol"]),
        local_network=cast(NetworkId, value["local_network"]),
        remote_network=cast(NetworkId, value["remote_network"]),
        endpoint_address=cast(str, value["endpoint_address"]),
        remote_selector=cast(int, value["remote_selector"]),
        peer_address=cast(str, value["peer_address"]),
        security_config_sha256=cast(str, value["security_config_sha256"]),
    )


def _deployment(value: dict[str, Any]) -> Deployment:
    return Deployment(
        deployment_id=cast(str, value["deployment_id"]),
        deployment_version=cast(int, value["deployment_version"]),
        compiler_version=cast(str, value["compiler_version"]),
        contracts=tuple(_contract(_dict(item)) for item in cast(list[Any], value["contracts"])),
        carrier_endpoints=tuple(
            _carrier(_dict(item)) for item in cast(list[Any], value["carrier_endpoints"])
        ),
    )


def _payload_effect(value: dict[str, Any]) -> PayloadEffect:
    return PayloadEffect(
        payload_id=cast(str, value["payload_id"]),
        payload_hex=cast(str, value["payload_hex"]),
        payload_sha256=cast(str, value["payload_sha256"]),
        destination_effect_id=cast(str, value["destination_effect_id"]),
        effect_definition_sha256=cast(str, value["effect_definition_sha256"]),
    )


def _signer(value: dict[str, Any]) -> SignerReference:
    return SignerReference(
        signer_id=cast(str, value["signer_id"]),
        role=cast(SignerRole, value["role"]),
        kind=cast(str, value["kind"]),
        reference=cast(str, value["reference"]),
        public_identity=cast(str, value["public_identity"]),
    )


def _approval_requirement(value: dict[str, Any]) -> ApprovalRequirement:
    return ApprovalRequirement(
        operation_type=cast(OperationType, value["operation_type"]),
        approval_schema=cast(str, value["approval_schema"]),
        expected_pre_state_sha256=cast(str, value["expected_pre_state_sha256"]),
        authorized_transition_sha256=cast(str, value["authorized_transition_sha256"]),
    )


def _budget(value: dict[str, Any]) -> ChainBudget:
    return ChainBudget(
        chain_id=cast(int, value["chain_id"]),
        max_transaction_wei=cast(int, value["max_transaction_wei"]),
        max_batch_wei=cast(int, value["max_batch_wei"]),
        max_run_wei=cast(int, value["max_run_wei"]),
        minimum_runner_balance_wei=cast(int, value["minimum_runner_balance_wei"]),
    )


def _stop_policy(value: dict[str, Any]) -> StopPolicy:
    return StopPolicy(
        consecutive_failures=cast(int, value["consecutive_failures"]),
        rolling_window=cast(int, value["rolling_window"]),
        rolling_failure_rate=cast(float, value["rolling_failure_rate"]),
        max_quote_age_seconds=cast(int, value["max_quote_age_seconds"]),
        max_quote_movement_bps=cast(int, value["max_quote_movement_bps"]),
        timeout_count=cast(int, value["timeout_count"]),
        collector_backlog=cast(int, value["collector_backlog"]),
        collector_heartbeat_seconds=cast(int, value["collector_heartbeat_seconds"]),
        disk_floor_bytes=cast(int, value["disk_floor_bytes"]),
        nonce_gap_action=cast(str, value["nonce_gap_action"]),
        rpc_disagreement_action=cast(str, value["rpc_disagreement_action"]),
        reorganization_action=cast(str, value["reorganization_action"]),
        allow_partial_conditions=cast(bool, value["allow_partial_conditions"]),
    )


def _finality(value: dict[str, Any]) -> FinalityPolicy:
    return FinalityPolicy(
        chain_id=cast(int, value["chain_id"]),
        kind=cast(FinalityKind, value["kind"]),
        confirmation_count=cast(int | None, value["confirmation_count"]),
    )


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ConfigError(f"{label} must be unique")


def _semantic_lab_validation(config: LabConfig) -> None:
    network_map = {network.network_id: network for network in config.networks}
    if set(network_map) != set(EXPECTED_NETWORKS):
        raise ConfigError("networks must be exactly OP, Arbitrum, and Base Sepolia")
    for network_id, (chain_id, role) in EXPECTED_NETWORKS.items():
        network = network_map[network_id]
        if network.chain_id != chain_id or network.route_role != role:
            raise ConfigError(f"network identity or route role mismatch: {network_id}")
        if network.read_rpc_ref == network.write_rpc_ref:
            raise ConfigError(f"read and write RPC references must be distinct: {network_id}")

    _unique([item.contract_id for item in config.deployment.contracts], "contract_id")
    _unique([item.endpoint_id for item in config.deployment.carrier_endpoints], "endpoint_id")
    for contract in config.deployment.contracts:
        if int(contract.address, 16) == 0:
            raise ConfigError(f"zero contract address is not an identity: {contract.contract_id}")

    carrier_edges = {
        (item.local_network, item.remote_network, item.protocol)
        for item in config.deployment.carrier_endpoints
    }
    if carrier_edges != EXPECTED_CARRIER_EDGES:
        raise ConfigError("carrier endpoints must cover H and L on both fixed route legs")

    try:
        payload = bytes.fromhex(config.payload_effect.payload_hex)
    except ValueError as exc:
        raise ConfigError("payload_hex is invalid") from exc
    if hashlib.sha256(payload).hexdigest() != config.payload_effect.payload_sha256:
        raise ConfigError("payload_sha256 does not match payload_hex")

    _unique([item.signer_id for item in config.signers], "signer_id")
    signer_map = {item.role: item for item in config.signers}
    if set(signer_map) != {"deployer", "runner", "approval-authority"}:
        raise ConfigError("signers must define deployer, runner, and approval-authority")
    deployer = signer_map["deployer"]
    runner = signer_map["runner"]
    if deployer.public_identity.lower() == runner.public_identity.lower():
        raise ConfigError("deployer and runner identities must be distinct")
    if deployer.kind == "ed25519-approval-authority" or runner.kind == "ed25519-approval-authority":
        raise ConfigError("deployer and runner must use EVM signer kinds")
    if signer_map["approval-authority"].kind != "ed25519-approval-authority":
        raise ConfigError("approval-authority must use the Ed25519 authority kind")

    operations = {item.operation_type for item in config.approval_requirements}
    if operations != EXPECTED_OPERATIONS:
        raise ConfigError("approval requirements must cover all six operation types")

    expected_chain_ids = {item[0] for item in EXPECTED_NETWORKS.values()}
    budgets = {item.chain_id: item for item in config.budgets}
    if set(budgets) != expected_chain_ids:
        raise ConfigError("budgets must cover all three chain IDs")
    for budget in budgets.values():
        if not (budget.max_transaction_wei <= budget.max_batch_wei <= budget.max_run_wei):
            raise ConfigError(f"budget limits are not monotonic for chain {budget.chain_id}")

    finality_chain_ids = {item.chain_id for item in config.finality_policies}
    if finality_chain_ids != expected_chain_ids:
        raise ConfigError("finality policies must cover all three chain IDs")


def load_lab_config(path: Path, *, schema_path: Path) -> LabConfig:
    """Load, schema-check, type, and semantically validate a lab configuration."""

    document, raw = _read_json(path)
    _validate_schema(document, schema_path)
    config = LabConfig(
        config_id=cast(str, document["config_id"]),
        networks=tuple(_network(_dict(item)) for item in cast(list[Any], document["networks"])),
        deployment=_deployment(_dict(document["deployment"])),
        payload_effect=_payload_effect(_dict(document["payload_effect"])),
        signers=tuple(_signer(_dict(item)) for item in cast(list[Any], document["signers"])),
        approval_requirements=tuple(
            _approval_requirement(_dict(item))
            for item in cast(list[Any], document["approval_requirements"])
        ),
        budgets=tuple(_budget(_dict(item)) for item in cast(list[Any], document["budgets"])),
        stop_policy=_stop_policy(_dict(document["stop_policy"])),
        finality_policies=tuple(
            _finality(_dict(item)) for item in cast(list[Any], document["finality_policies"])
        ),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )
    _semantic_lab_validation(config)
    return config


def _parse_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be a date-time")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"{label} must be an ISO date-time") from exc


def load_approval_envelope(path: Path, *, schema_path: Path) -> ApprovalEnvelope:
    """Load a generic operation approval and verify its canonical payload digest."""

    document, _ = _read_json(path)
    _validate_schema(document, schema_path)
    payload = _dict(document["payload"])
    actual_digest = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    expected_digest = cast(str, document["payload_sha256"])
    if actual_digest != expected_digest:
        raise ConfigError("approval payload_sha256 does not match RFC 8785 canonical payload")
    valid_from = _parse_datetime(payload["valid_from"], "valid_from")
    valid_until = _parse_datetime(payload["valid_until"], "valid_until")
    issued_at = _parse_datetime(payload["issued_at"], "issued_at")
    if not (issued_at <= valid_from < valid_until):
        raise ConfigError("approval times must satisfy issued_at <= valid_from < valid_until")
    return ApprovalEnvelope(
        operation_type=cast(OperationType, payload["operation_type"]),
        operation_id=cast(str, payload["operation_id"]),
        approval_id=cast(str, payload["approval_id"]),
        issuer_id=cast(str, payload["issuer_id"]),
        issuer_sequence=cast(int, payload["issuer_sequence"]),
        payload_sha256=expected_digest,
        signature=cast(str, document["signature"]),
        payload=payload,
    )


def load_run_manifest(path: Path, *, schema_path: Path) -> RunManifest:
    """Load and type a formal run manifest."""

    document, _ = _read_json(path)
    _validate_schema(document, schema_path)
    _parse_datetime(document["generated_at"], "generated_at")
    conditions = cast(list[str], document["conditions"])
    if set(conditions) != {"HH", "HL", "LH", "LL"}:
        raise ConfigError("run manifest must contain all four conditions")
    return RunManifest(
        manifest_id=cast(str, document["manifest_id"]),
        run_id=cast(str, document["run_id"]),
        profile_id=cast(str, document["profile_id"]),
        config_sha256=cast(str, document["config_sha256"]),
        generated_at=cast(str, document["generated_at"]),
        document=document,
    )
