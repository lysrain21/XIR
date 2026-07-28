from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.configuration_plans import (
    ConfigurationPlanError,
    ConfigurationSimulation,
    ConfigurationTransition,
    ContractIdentityExpectation,
    ContractIdentityObservation,
    build_configuration_plan,
    configuration_signer_requests,
    freeze_deployment_identity,
    recollect_deployment_identity,
    simulate_configuration_plan,
)

DIGEST = "11" * 32
NETWORKS = (
    ("op-sepolia", 11_155_420),
    ("arbitrum-sepolia", 421_614),
    ("base-sepolia", 84_532),
)


def _expectations() -> tuple[ContractIdentityExpectation, ...]:
    return tuple(
        ContractIdentityExpectation(
            contract_id=f"gateway-{network}",
            network_id=network,
            chain_id=chain_id,
            address=f"0x{index + 1:040x}",
            runtime_code_sha256="22" * 32,
            administrator="0x" + "aa" * 20,
            runner="0x" + "bb" * 20,
            expected_control_state_sha256="33" * 32,
        )
        for index, (network, chain_id) in enumerate(NETWORKS)
    )


class IdentityFixture:
    def __init__(self, mismatch: str | None = None) -> None:
        self.mismatch = mismatch

    def observe(
        self, expectation: ContractIdentityExpectation
    ) -> ContractIdentityObservation:
        return ContractIdentityObservation(
            contract_id=expectation.contract_id,
            network_id=expectation.network_id,
            chain_id=expectation.chain_id,
            address=expectation.address,
            runtime_code_sha256=(
                "ff" * 32
                if self.mismatch == expectation.contract_id
                else expectation.runtime_code_sha256
            ),
            administrator=expectation.administrator,
            runner=expectation.runner,
            control_state_sha256=expectation.expected_control_state_sha256,
            observation_block=100,
            status="unvalidated",
            reason_codes=(),
        )


def test_deployment_identity_recollects_and_freezes_exact_public_state(
    tmp_path: Path,
) -> None:
    identity = recollect_deployment_identity(_expectations(), IdentityFixture())
    assert identity.outcome == "pass"
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    document, digest = freeze_deployment_identity(
        identity,
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
        store=store,
    )
    assert document["deployment_sha256"] == identity.deployment_sha256
    assert store.read_raw(digest)

    blocked = recollect_deployment_identity(
        _expectations(),
        IdentityFixture("gateway-op-sepolia"),
    )
    assert blocked.outcome == "blocked"


def _transitions() -> tuple[ConfigurationTransition, ...]:
    categories = (
        "endpoint",
        "peer",
        "selector",
        "security",
        "runner",
        "pause-drain",
        "xir-route-profile",
        "receiver-isolation",
    )
    return tuple(
        ConfigurationTransition(
            transition_id=f"configure-{category}",
            category=category,  # type: ignore[arg-type]
            network_id=NETWORKS[index % 3][0],
            chain_id=NETWORKS[index % 3][1],
            contract_id=f"contract-{index}",
            destination=f"0x{index + 11:040x}",
            sender="0x" + "aa" * 20,
            nonce=index,
            value_wei=0,
            calldata=bytes([index + 1]) * 4,
            gas_limit=100_000,
            max_fee_per_gas_wei=100,
            max_priority_fee_per_gas_wei=2,
            expected_pre_state_sha256="33" * 32,
            expected_post_state_sha256=f"{index + 40:02x}" * 32,
        )
        for index, category in enumerate(categories)
    )


class SimulationFixture:
    def __init__(self, changed: str | None = None) -> None:
        self.changed = changed

    def simulate(
        self, transition: ConfigurationTransition
    ) -> ConfigurationSimulation:
        return ConfigurationSimulation(
            transition_id=transition.transition_id,
            success=self.changed != transition.transition_id,
            gas_used=50_000,
            observed_post_state_sha256=transition.expected_post_state_sha256,
            reason_code="fixture",
        )


def test_configuration_plan_binds_all_categories_simulation_and_signer_requests() -> None:
    plan = build_configuration_plan(
        plan_id="configuration-1",
        deployment_sha256=DIGEST,
        transitions=_transitions(),
    )
    assert len(simulate_configuration_plan(plan, SimulationFixture())) == 8
    requests = configuration_signer_requests(
        plan,
        signer_id="deployer",
        config_sha256="44" * 32,
        code_sha256="55" * 32,
    )
    assert len(requests) == 8
    assert all(item.role == "deployer" for item in requests)
    assert all(len(item.unsigned_transaction_sha256) == 64 for item in requests)

    with pytest.raises(ConfigurationPlanError, match="simulation mismatch"):
        simulate_configuration_plan(
            plan,
            SimulationFixture(plan.transitions[0].transition_id),
        )
    with pytest.raises(ConfigurationPlanError, match="category"):
        build_configuration_plan(
            plan_id="incomplete",
            deployment_sha256=DIGEST,
            transitions=_transitions()[:-1],
        )


def test_changed_deployment_digest_changes_configuration_plan() -> None:
    first = build_configuration_plan(
        plan_id="configuration-1",
        deployment_sha256=DIGEST,
        transitions=_transitions(),
    )
    second = build_configuration_plan(
        plan_id="configuration-1",
        deployment_sha256="12" * 32,
        transitions=tuple(
            replace(item, nonce=item.nonce + 10) for item in _transitions()
        ),
    )
    assert first.plan_sha256 != second.plan_sha256
