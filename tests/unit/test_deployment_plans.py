from __future__ import annotations

from pathlib import Path

import pytest

from xir_lab.execute.deployment_plans import (
    AddressReference,
    ContractCreationSpec,
    DeploymentPlanError,
    DeploymentSimulation,
    PlannedCreation,
    build_deployment_plan,
    build_three_chain_deployment_plan,
    dry_run_deployment_plan,
)

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "out"


def _specs() -> tuple[ContractCreationSpec, ...]:
    return (
        ContractCreationSpec(
            "registry",
            OUT / "XIRRegistry.sol" / "XIRRegistry.json",
            ("address",),
            ("0x" + "aa" * 20,),
            2_000_000,
        ),
        ContractCreationSpec(
            "gateway",
            OUT / "XIRGateway.sol" / "XIRGateway.json",
            ("address", "(uint8,bytes)"),
            (
                AddressReference("registry"),
                (1, bytes.fromhex("bb" * 20)),
            ),
            3_000_000,
        ),
    )


def _plan():
    return build_deployment_plan(
        plan_id="op-deployment-1",
        chain_id=11_155_420,
        deployer_address="0x" + "12" * 20,
        starting_nonce=7,
        compiler_version="0.8.28",
        toolchain_sha256="11" * 32,
        max_fee_per_gas_wei=100,
        max_priority_fee_per_gas_wei=2,
        specs=_specs(),
    )


def _chain_plan(chain_id: int):
    return build_deployment_plan(
        plan_id=f"deployment-{chain_id}",
        chain_id=chain_id,
        deployer_address="0x" + "12" * 20,
        starting_nonce=7,
        compiler_version="0.8.28",
        toolchain_sha256="11" * 32,
        max_fee_per_gas_wei=100,
        max_priority_fee_per_gas_wei=2,
        specs=_specs(),
    )


def test_plan_binds_bytecode_constructor_nonce_predicted_addresses_and_fees() -> None:
    first = _plan()
    second = _plan()
    assert first == second
    assert [item.nonce for item in first.creations] == [7, 8]
    assert len({item.predicted_address for item in first.creations}) == 2
    assert all(item.data_hex for item in first.creations)
    assert all(len(item.unsigned_transaction_sha256) == 64 for item in first.creations)
    assert len(first.plan_sha256) == 64


class FixtureSimulator:
    def __init__(self, changed: str | None = None) -> None:
        self.changed = changed

    def simulate(self, creation: PlannedCreation) -> DeploymentSimulation:
        return DeploymentSimulation(
            contract_id=creation.contract_id,
            success=self.changed != "revert",
            predicted_address=(
                "0x" + "ff" * 20
                if self.changed == "address"
                else creation.predicted_address
            ),
            runtime_code_sha256=(
                "ff" * 32
                if self.changed == "runtime"
                else creation.runtime_code_sha256
            ),
            gas_used=(
                creation.gas_limit + 1
                if self.changed == "gas"
                else creation.gas_limit
            ),
            reason_code="fixture",
        )


def test_every_creation_dry_run_must_match_exact_plan() -> None:
    plan = _plan()
    results = dry_run_deployment_plan(plan, FixtureSimulator())
    assert [item.contract_id for item in results] == ["registry", "gateway"]
    for change in ("revert", "address", "runtime", "gas"):
        with pytest.raises(DeploymentPlanError, match="simulation mismatch"):
            dry_run_deployment_plan(plan, FixtureSimulator(change))


def test_unknown_constructor_reference_and_factory_fail_closed() -> None:
    bad = (
        ContractCreationSpec(
            "gateway",
            OUT / "XIRGateway.sol" / "XIRGateway.json",
            ("address", "(uint8,bytes)"),
            (AddressReference("missing"), (1, bytes.fromhex("bb" * 20))),
            3_000_000,
        ),
    )
    with pytest.raises(DeploymentPlanError, match="unknown"):
        build_deployment_plan(
            plan_id="bad",
            chain_id=11_155_420,
            deployer_address="0x" + "12" * 20,
            starting_nonce=0,
            compiler_version="0.8.28",
            toolchain_sha256="11" * 32,
            max_fee_per_gas_wei=1,
            max_priority_fee_per_gas_wei=1,
            specs=bad,
        )


def test_three_chain_plan_order_is_fixed_and_digest_bound() -> None:
    plans = (
        _chain_plan(11_155_420),
        _chain_plan(421_614),
        _chain_plan(84_532),
    )
    combined = build_three_chain_deployment_plan(plans)
    assert combined.route_order == (
        "op-sepolia",
        "arbitrum-sepolia",
        "base-sepolia",
    )
    with pytest.raises(DeploymentPlanError, match="order"):
        build_three_chain_deployment_plan((plans[1], plans[0], plans[2]))
