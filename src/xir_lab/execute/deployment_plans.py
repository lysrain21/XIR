"""Deterministic unsigned deployment plans for the external signer boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

import rfc8785
import rlp  # type: ignore[import-untyped]
from eth_abi import encode  # type: ignore[attr-defined]
from eth_utils import keccak, to_checksum_address  # type: ignore[attr-defined]

from xir_lab.execute.signer import SignerRequest
from xir_lab.execute.signer_socket import unsigned_transaction_digest


class DeploymentPlanError(ValueError):
    """Raised when creation inputs or dry-run results are incomplete."""


@dataclass(frozen=True)
class AddressReference:
    contract_id: str


@dataclass(frozen=True)
class ContractCreationSpec:
    contract_id: str
    artifact_path: Path
    constructor_types: tuple[str, ...]
    constructor_values: tuple[Any, ...]
    gas_limit: int
    value_wei: int = 0
    factory_address: str | None = None


@dataclass(frozen=True)
class PlannedCreation:
    contract_id: str
    chain_id: int
    nonce: int
    predicted_address: str
    factory_address: str | None
    creation_bytecode_sha256: str
    constructor_args_sha256: str
    runtime_code_sha256: str
    gas_limit: int
    max_fee_per_gas_wei: int
    max_priority_fee_per_gas_wei: int
    value_wei: int
    unsigned_transaction_sha256: str
    data_hex: str


@dataclass(frozen=True)
class DeploymentPlan:
    plan_id: str
    chain_id: int
    deployer_address: str
    starting_nonce: int
    compiler_version: str
    toolchain_sha256: str
    creations: tuple[PlannedCreation, ...]
    plan_sha256: str


@dataclass(frozen=True)
class ThreeChainDeploymentPlan:
    plans: tuple[DeploymentPlan, DeploymentPlan, DeploymentPlan]
    route_order: tuple[str, str, str]
    plan_sha256: str


@dataclass(frozen=True)
class DeploymentSimulation:
    contract_id: str
    success: bool
    predicted_address: str
    runtime_code_sha256: str
    gas_used: int
    reason_code: str


class DeploymentSimulationProvider(Protocol):
    def simulate(self, creation: PlannedCreation) -> DeploymentSimulation:
        """Simulate an unsigned creation without signing or broadcasting."""


def _create_address(deployer: str, nonce: int) -> str:
    try:
        sender = bytes.fromhex(deployer.removeprefix("0x"))
    except ValueError as exc:
        raise DeploymentPlanError("deployer address is invalid") from exc
    if len(sender) != 20 or nonce < 0:
        raise DeploymentPlanError("deployer address or nonce is invalid")
    return to_checksum_address(keccak(rlp.encode([sender, nonce]))[-20:])


def _artifact(path: Path) -> tuple[bytes, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        creation_hex = cast(str, document["bytecode"]["object"])
        runtime_hex = cast(str, document["deployedBytecode"]["object"])
        creation = bytes.fromhex(creation_hex.removeprefix("0x"))
        runtime = bytes.fromhex(runtime_hex.removeprefix("0x"))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentPlanError(f"invalid Foundry artifact: {path}") from exc
    if not creation or not runtime:
        raise DeploymentPlanError("artifact bytecode cannot be empty")
    return creation, hashlib.sha256(runtime).hexdigest()


def _resolve(value: Any, addresses: dict[str, str]) -> Any:
    if isinstance(value, AddressReference):
        try:
            return addresses[value.contract_id]
        except KeyError as exc:
            raise DeploymentPlanError(
                f"unknown constructor address reference: {value.contract_id}"
            ) from exc
    if isinstance(value, tuple):
        return tuple(_resolve(item, addresses) for item in value)
    if isinstance(value, list):
        return [_resolve(item, addresses) for item in value]
    return value


def build_deployment_plan(
    *,
    plan_id: str,
    chain_id: int,
    deployer_address: str,
    starting_nonce: int,
    compiler_version: str,
    toolchain_sha256: str,
    max_fee_per_gas_wei: int,
    max_priority_fee_per_gas_wei: int,
    specs: tuple[ContractCreationSpec, ...],
) -> DeploymentPlan:
    if not specs or len({item.contract_id for item in specs}) != len(specs):
        raise DeploymentPlanError("deployment specs must be nonempty and uniquely identified")
    if min(
        chain_id,
        starting_nonce,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
    ) < 0:
        raise DeploymentPlanError("deployment numeric inputs cannot be negative")
    if len(toolchain_sha256) != 64:
        raise DeploymentPlanError("toolchain digest is invalid")
    addresses = {
        spec.contract_id: _create_address(deployer_address, starting_nonce + index)
        for index, spec in enumerate(specs)
    }
    creations: list[PlannedCreation] = []
    for index, spec in enumerate(specs):
        if spec.factory_address is not None:
            raise DeploymentPlanError("factory deployment is not implemented for this pilot")
        if spec.gas_limit <= 0 or spec.value_wei < 0:
            raise DeploymentPlanError("creation gas/value bounds are invalid")
        bytecode, runtime_sha256 = _artifact(spec.artifact_path)
        values = tuple(_resolve(item, addresses) for item in spec.constructor_values)
        try:
            arguments = encode(list(spec.constructor_types), list(values))
        except Exception as exc:
            raise DeploymentPlanError(
                f"constructor encoding failed: {spec.contract_id}"
            ) from exc
        data = bytecode + arguments
        nonce = starting_nonce + index
        unsigned: dict[str, Any] = {
            "chainId": chain_id,
            "nonce": nonce,
            "to": None,
            "value": spec.value_wei,
            "data": "0x" + data.hex(),
            "gas": spec.gas_limit,
            "maxFeePerGas": max_fee_per_gas_wei,
            "maxPriorityFeePerGas": max_priority_fee_per_gas_wei,
            "type": 2,
        }
        creations.append(
            PlannedCreation(
                contract_id=spec.contract_id,
                chain_id=chain_id,
                nonce=nonce,
                predicted_address=addresses[spec.contract_id],
                factory_address=None,
                creation_bytecode_sha256=hashlib.sha256(bytecode).hexdigest(),
                constructor_args_sha256=hashlib.sha256(arguments).hexdigest(),
                runtime_code_sha256=runtime_sha256,
                gas_limit=spec.gas_limit,
                max_fee_per_gas_wei=max_fee_per_gas_wei,
                max_priority_fee_per_gas_wei=max_priority_fee_per_gas_wei,
                value_wei=spec.value_wei,
                unsigned_transaction_sha256=hashlib.sha256(
                    rfc8785.dumps(unsigned)
                ).hexdigest(),
                data_hex=data.hex(),
            )
        )
    plan_body: dict[str, Any] = {
        "plan_id": plan_id,
        "chain_id": chain_id,
        "deployer_address": deployer_address.lower(),
        "starting_nonce": starting_nonce,
        "compiler_version": compiler_version,
        "toolchain_sha256": toolchain_sha256,
        "creations": [
            {
                key: value
                for key, value in creation.__dict__.items()
                if key != "data_hex"
            }
            for creation in creations
        ],
    }
    return DeploymentPlan(
        plan_id=plan_id,
        chain_id=chain_id,
        deployer_address=deployer_address,
        starting_nonce=starting_nonce,
        compiler_version=compiler_version,
        toolchain_sha256=toolchain_sha256,
        creations=tuple(creations),
        plan_sha256=hashlib.sha256(rfc8785.dumps(plan_body)).hexdigest(),
    )


def dry_run_deployment_plan(
    plan: DeploymentPlan,
    provider: DeploymentSimulationProvider,
) -> tuple[DeploymentSimulation, ...]:
    results: list[DeploymentSimulation] = []
    for creation in plan.creations:
        result = provider.simulate(creation)
        if (
            result.contract_id != creation.contract_id
            or result.predicted_address.lower() != creation.predicted_address.lower()
            or result.runtime_code_sha256 != creation.runtime_code_sha256
            or result.gas_used > creation.gas_limit
            or not result.success
        ):
            raise DeploymentPlanError(
                f"deployment simulation mismatch: {creation.contract_id}"
            )
        results.append(result)
    return tuple(results)


def deployment_signer_requests(
    plan: DeploymentPlan,
    *,
    network_id: str,
    signer_id: str,
    config_sha256: str,
    code_sha256: str,
) -> tuple[SignerRequest, ...]:
    expected_networks = {
        11_155_420: "op-sepolia",
        421_614: "arbitrum-sepolia",
        84_532: "base-sepolia",
    }
    if expected_networks.get(plan.chain_id) != network_id:
        raise DeploymentPlanError("deployment signer request changed network identity")
    for value, label in (
        (config_sha256, "configuration digest"),
        (code_sha256, "code digest"),
    ):
        if len(value) != 64:
            raise DeploymentPlanError(f"{label} is invalid")
    requests: list[SignerRequest] = []
    for creation in plan.creations:
        calldata = bytes.fromhex(creation.data_hex)
        request = SignerRequest(
            network_id=network_id,
            chain_id=plan.chain_id,
            signer_id=signer_id,
            intent_id=f"{plan.plan_id}:{creation.contract_id}",
            nonce=creation.nonce,
            destination=None,
            value_wei=creation.value_wei,
            calldata_sha256=hashlib.sha256(calldata).hexdigest(),
            calldata_length=len(calldata),
            fee_limit_wei=(
                creation.gas_limit * creation.max_fee_per_gas_wei
            ),
            role="deployer",
            config_sha256=config_sha256,
            code_sha256=code_sha256,
            gas_limit=creation.gas_limit,
            max_fee_per_gas_wei=creation.max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei=(
                creation.max_priority_fee_per_gas_wei
            ),
            calldata_hex=creation.data_hex,
            unsigned_transaction_sha256=creation.unsigned_transaction_sha256,
        )
        if unsigned_transaction_digest(request) != creation.unsigned_transaction_sha256:
            raise DeploymentPlanError("deployment signer transaction digest changed")
        requests.append(request)
    return tuple(requests)


def build_three_chain_deployment_plan(
    plans: tuple[DeploymentPlan, DeploymentPlan, DeploymentPlan],
) -> ThreeChainDeploymentPlan:
    expected = (11_155_420, 421_614, 84_532)
    if tuple(item.chain_id for item in plans) != expected:
        raise DeploymentPlanError(
            "deployment plans must follow OP, Arbitrum, Base Sepolia order"
        )
    digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "xir-lab-three-chain-deployment-v1",
                "route_order": [
                    "op-sepolia",
                    "arbitrum-sepolia",
                    "base-sepolia",
                ],
                "plan_sha256": [item.plan_sha256 for item in plans],
            }
        )
    ).hexdigest()
    return ThreeChainDeploymentPlan(
        plans=plans,
        route_order=("op-sepolia", "arbitrum-sepolia", "base-sepolia"),
        plan_sha256=digest,
    )
