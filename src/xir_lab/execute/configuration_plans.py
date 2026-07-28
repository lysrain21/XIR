"""Deployment identity recollection and exact configuration transition plans."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.signer import SignerRequest
from xir_lab.execute.signer_socket import unsigned_transaction_digest

ConfigurationCategory = Literal[
    "endpoint",
    "peer",
    "selector",
    "security",
    "runner",
    "pause-drain",
    "xir-route-profile",
    "receiver-isolation",
]

REQUIRED_CONFIGURATION_CATEGORIES = frozenset(
    {
        "endpoint",
        "peer",
        "selector",
        "security",
        "runner",
        "pause-drain",
        "xir-route-profile",
        "receiver-isolation",
    }
)
FIXED_NETWORKS = frozenset(
    {"op-sepolia", "arbitrum-sepolia", "base-sepolia"}
)


class ConfigurationPlanError(ValueError):
    """Raised when deployment identity or configuration transitions diverge."""


@dataclass(frozen=True)
class ContractIdentityExpectation:
    contract_id: str
    network_id: str
    chain_id: int
    address: str
    runtime_code_sha256: str
    administrator: str | None
    runner: str | None
    expected_control_state_sha256: str


@dataclass(frozen=True)
class ContractIdentityObservation:
    contract_id: str
    network_id: str
    chain_id: int
    address: str
    runtime_code_sha256: str
    administrator: str | None
    runner: str | None
    control_state_sha256: str
    observation_block: int
    status: str
    reason_codes: tuple[str, ...]


class DeploymentStateProvider(Protocol):
    def observe(
        self, expectation: ContractIdentityExpectation
    ) -> ContractIdentityObservation:
        """Read runtime, authorities, controls, and block from public state."""


@dataclass(frozen=True)
class DeploymentIdentity:
    observations: tuple[ContractIdentityObservation, ...]
    outcome: str
    deployment_sha256: str


@dataclass(frozen=True)
class ConfigurationTransition:
    transition_id: str
    category: ConfigurationCategory
    network_id: str
    chain_id: int
    contract_id: str
    destination: str
    sender: str
    nonce: int
    value_wei: int
    calldata: bytes
    gas_limit: int
    max_fee_per_gas_wei: int
    max_priority_fee_per_gas_wei: int
    expected_pre_state_sha256: str
    expected_post_state_sha256: str


@dataclass(frozen=True)
class ConfigurationPlan:
    plan_id: str
    deployment_sha256: str
    transitions: tuple[ConfigurationTransition, ...]
    plan_sha256: str


@dataclass(frozen=True)
class ConfigurationSimulation:
    transition_id: str
    success: bool
    gas_used: int
    observed_post_state_sha256: str
    reason_code: str


class ConfigurationSimulationProvider(Protocol):
    def simulate(
        self, transition: ConfigurationTransition
    ) -> ConfigurationSimulation:
        """Simulate the exact transition without signing or broadcasting."""


def _digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ConfigurationPlanError(f"{label} is not a lowercase SHA-256 digest")


def _address(value: str, label: str) -> None:
    try:
        valid = len(value) == 42 and value.startswith("0x") and int(value, 16) != 0
    except ValueError:
        valid = False
    if not valid:
        raise ConfigurationPlanError(f"{label} is not a nonzero EVM address")


def recollect_deployment_identity(
    expectations: tuple[ContractIdentityExpectation, ...],
    provider: DeploymentStateProvider,
) -> DeploymentIdentity:
    if not expectations or len({item.contract_id for item in expectations}) != len(
        expectations
    ):
        raise ConfigurationPlanError("deployment expectations are empty or duplicated")
    if {item.network_id for item in expectations} != FIXED_NETWORKS:
        raise ConfigurationPlanError("deployment identity must cover all fixed networks")
    observations: list[ContractIdentityObservation] = []
    for expected in sorted(expectations, key=lambda item: item.contract_id):
        _address(expected.address, "expected contract")
        _digest(expected.runtime_code_sha256, "expected runtime")
        _digest(expected.expected_control_state_sha256, "expected control state")
        observed = provider.observe(expected)
        reasons: list[str] = []
        if (
            observed.contract_id != expected.contract_id
            or observed.network_id != expected.network_id
            or observed.chain_id != expected.chain_id
            or observed.address.lower() != expected.address.lower()
        ):
            reasons.append("deployment_identity_coordinates_mismatch")
        if observed.runtime_code_sha256 != expected.runtime_code_sha256:
            reasons.append("deployment_runtime_mismatch")
        if observed.administrator != expected.administrator:
            reasons.append("deployment_administrator_mismatch")
        if observed.runner != expected.runner:
            reasons.append("deployment_runner_mismatch")
        if observed.control_state_sha256 != expected.expected_control_state_sha256:
            reasons.append("deployment_control_state_mismatch")
        if observed.observation_block < 0:
            reasons.append("deployment_observation_block_invalid")
        observations.append(
            ContractIdentityObservation(
                contract_id=observed.contract_id,
                network_id=observed.network_id,
                chain_id=observed.chain_id,
                address=observed.address,
                runtime_code_sha256=observed.runtime_code_sha256,
                administrator=observed.administrator,
                runner=observed.runner,
                control_state_sha256=observed.control_state_sha256,
                observation_block=observed.observation_block,
                status="pass" if not reasons else "fail",
                reason_codes=tuple(sorted(reasons)) or ("deployment_identity_ready",),
            )
        )
    body = [
        {
            **item.__dict__,
            "reason_codes": list(item.reason_codes),
        }
        for item in observations
    ]
    digest = hashlib.sha256(rfc8785.dumps(body)).hexdigest()
    return DeploymentIdentity(
        observations=tuple(observations),
        outcome=(
            "pass" if all(item.status == "pass" for item in observations) else "blocked"
        ),
        deployment_sha256=digest,
    )


def freeze_deployment_identity(
    identity: DeploymentIdentity,
    *,
    observed_at: datetime,
    store: EvidenceStore | None = None,
) -> tuple[dict[str, Any], str]:
    document: dict[str, Any] = {
        "schema_version": "xir-lab-deployment-identity-v1",
        "observed_at": observed_at.astimezone(UTC).isoformat(),
        "outcome": identity.outcome,
        "deployment_sha256": identity.deployment_sha256,
        "contracts": [
            {
                **item.__dict__,
                "reason_codes": list(item.reason_codes),
            }
            for item in identity.observations
        ],
        "effects": {
            "signing_operations": 0,
            "configurations": 0,
            "broadcasts": 0,
        },
    }
    raw = rfc8785.dumps(document)
    digest = hashlib.sha256(raw).hexdigest()
    if store is not None:
        stored = store.put_raw(
            raw,
            media_type="application/json",
            metadata={"kind": "deployment-identity", "public_facts_only": True},
        )
        if stored != digest:
            raise ConfigurationPlanError("deployment identity changed during storage")
    return document, digest


def build_configuration_plan(
    *,
    plan_id: str,
    deployment_sha256: str,
    transitions: tuple[ConfigurationTransition, ...],
) -> ConfigurationPlan:
    _digest(deployment_sha256, "deployment identity")
    if not transitions or len({item.transition_id for item in transitions}) != len(
        transitions
    ):
        raise ConfigurationPlanError("configuration transitions are empty or duplicated")
    if {item.network_id for item in transitions} != FIXED_NETWORKS:
        raise ConfigurationPlanError("configuration plan must cover all fixed networks")
    if {item.category for item in transitions} != REQUIRED_CONFIGURATION_CATEGORIES:
        raise ConfigurationPlanError("configuration plan lacks a required transition category")
    for item in transitions:
        _address(item.destination, "configuration destination")
        _address(item.sender, "configuration sender")
        _digest(item.expected_pre_state_sha256, "expected pre-state")
        _digest(item.expected_post_state_sha256, "expected post-state")
        if (
            item.nonce < 0
            or item.value_wei < 0
            or item.gas_limit <= 0
            or item.max_fee_per_gas_wei < item.max_priority_fee_per_gas_wei
            or not item.calldata
        ):
            raise ConfigurationPlanError("configuration transaction bounds are invalid")
    ordered = tuple(
        sorted(transitions, key=lambda item: (item.chain_id, item.nonce, item.transition_id))
    )
    body: dict[str, Any] = {
        "plan_id": plan_id,
        "deployment_sha256": deployment_sha256,
        "transitions": [
            {
                **item.__dict__,
                "calldata": item.calldata.hex(),
            }
            for item in ordered
        ],
    }
    return ConfigurationPlan(
        plan_id=plan_id,
        deployment_sha256=deployment_sha256,
        transitions=ordered,
        plan_sha256=hashlib.sha256(rfc8785.dumps(body)).hexdigest(),
    )


def simulate_configuration_plan(
    plan: ConfigurationPlan,
    provider: ConfigurationSimulationProvider,
) -> tuple[ConfigurationSimulation, ...]:
    results: list[ConfigurationSimulation] = []
    for transition in plan.transitions:
        result = provider.simulate(transition)
        if (
            result.transition_id != transition.transition_id
            or not result.success
            or result.gas_used > transition.gas_limit
            or result.observed_post_state_sha256
            != transition.expected_post_state_sha256
        ):
            raise ConfigurationPlanError(
                f"configuration simulation mismatch: {transition.transition_id}"
            )
        results.append(result)
    return tuple(results)


def configuration_signer_requests(
    plan: ConfigurationPlan,
    *,
    signer_id: str,
    config_sha256: str,
    code_sha256: str,
) -> tuple[SignerRequest, ...]:
    requests: list[SignerRequest] = []
    for transition in plan.transitions:
        request = SignerRequest(
            network_id=transition.network_id,
            chain_id=transition.chain_id,
            signer_id=signer_id,
            intent_id=f"{plan.plan_id}:{transition.transition_id}",
            nonce=transition.nonce,
            destination=transition.destination,
            value_wei=transition.value_wei,
            calldata_sha256=hashlib.sha256(transition.calldata).hexdigest(),
            calldata_length=len(transition.calldata),
            fee_limit_wei=(
                transition.gas_limit * transition.max_fee_per_gas_wei
            ),
            role="deployer",
            config_sha256=config_sha256,
            code_sha256=code_sha256,
            gas_limit=transition.gas_limit,
            max_fee_per_gas_wei=transition.max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei=(
                transition.max_priority_fee_per_gas_wei
            ),
            calldata_hex=transition.calldata.hex(),
        )
        requests.append(
            SignerRequest(
                **{
                    **request.__dict__,
                    "unsigned_transaction_sha256": unsigned_transaction_digest(request),
                }
            )
        )
    return tuple(requests)
