from __future__ import annotations

from dataclasses import replace

import pytest

from xir_lab.preflight.estimator import (
    CHAIN_NAMES,
    CapacityState,
    ChainEstimateState,
    CostItem,
    EstimatorError,
    FrozenMeasurementReference,
    FundingTarget,
    estimate_preflight,
)


def _chains() -> tuple[ChainEstimateState, ...]:
    return tuple(
        ChainEstimateState(
            chain_id=chain_id,
            deployer_address=f"0x{index + 1:040x}",
            runner_address=f"0x{index + 11:040x}",
            deployer_nonce=5,
            runner_nonce=10,
            deployer_balance_wei=100,
            runner_balance_wei=100,
            deployer_budget_wei=1_000,
            runner_budget_wei=1_000,
            deployer_balance_floor_wei=50,
            runner_balance_floor_wei=50,
            read_rpc_reachable=True,
            write_endpoint_identity_verified=True,
        )
        for index, chain_id in enumerate(CHAIN_NAMES)
    )


def _costs() -> tuple[CostItem, ...]:
    items = []
    for chain_id in CHAIN_NAMES:
        items.extend(
            (
                CostItem(
                    item_id=f"deploy-{chain_id}",
                    chain_id=chain_id,
                    role="deployer",
                    operation_type="deployment",
                    physical_transactions=1,
                    gas_limit=100,
                    max_fee_per_gas_wei=2,
                    carrier_payment_wei=0,
                    transaction_value_wei=0,
                    seconds_per_transaction=10,
                    evidence_bytes_per_transaction=100,
                ),
                CostItem(
                    item_id=f"primary-{chain_id}",
                    chain_id=chain_id,
                    role="runner",
                    operation_type="primary",
                    physical_transactions=2,
                    gas_limit=100,
                    max_fee_per_gas_wei=2,
                    carrier_payment_wei=10,
                    transaction_value_wei=0,
                    seconds_per_transaction=10,
                    evidence_bytes_per_transaction=100,
                ),
            )
        )
    return tuple(items)


def _targets(
    chains: tuple[ChainEstimateState, ...],
) -> tuple[FundingTarget, ...]:
    targets = []
    for chain in chains:
        targets.extend(
            (
                FundingTarget(
                    chain.chain_id,
                    "deployer",
                    chain.deployer_address,
                    500,
                ),
                FundingTarget(
                    chain.chain_id,
                    "runner",
                    chain.runner_address,
                    500,
                ),
            )
        )
    return tuple(targets)


def _capacity() -> CapacityState:
    return CapacityState(
        collector_healthy=True,
        backup_writable=True,
        disk_available_bytes=10_000,
        backup_reserve_bytes=1_000,
        clock_skew_seconds=1,
        maximum_clock_skew_seconds=2,
        maximum_physical_transactions=9,
        maximum_duration_seconds=30,
        maximum_storage_bytes=900,
        max_concurrency=3,
    )


def test_estimates_all_resources_and_emits_only_manual_role_funding() -> None:
    chains = _chains()
    report = estimate_preflight(
        chains=chains,
        costs=_costs(),
        funding_targets=_targets(chains),
        capacity=_capacity(),
        funding_margin_bps=1_000,
    )
    assert report.passed
    assert report.estimated_physical_transactions == 9
    assert report.estimated_duration_seconds == 30
    assert report.estimated_storage_bytes == 900
    assert report.projected_nonces == {
        **{f"{chain_id}:deployer": 6 for chain_id in CHAIN_NAMES},
        **{f"{chain_id}:runner": 12 for chain_id in CHAIN_NAMES},
    }
    assert len(report.funding_instructions) == 6
    assert {item.role for item in report.funding_instructions} == {
        "deployer",
        "runner",
    }
    assert all(
        item.action == "manual_external_funding_checkpoint"
        for item in report.funding_instructions
    )
    assert report.effects == {
        "wallets_created": 0,
        "funding_operations": 0,
        "signing_operations": 0,
        "broadcasts": 0,
    }


def test_capacity_rpc_clock_count_duration_storage_and_budget_failures_are_named() -> None:
    chains = list(_chains())
    chains[0] = replace(
        chains[0],
        read_rpc_reachable=False,
        write_endpoint_identity_verified=False,
        runner_budget_wei=100,
    )
    capacity = replace(
        _capacity(),
        collector_healthy=False,
        backup_writable=False,
        disk_available_bytes=100,
        clock_skew_seconds=3,
        maximum_physical_transactions=8,
        maximum_duration_seconds=29,
        maximum_storage_bytes=899,
    )
    report = estimate_preflight(
        chains=tuple(chains),
        costs=_costs(),
        funding_targets=_targets(tuple(chains)),
        capacity=capacity,
        funding_margin_bps=1_000,
    )
    failures = {
        check.reason_code for check in report.checks if check.status == "fail"
    }
    assert {
        "collector_unhealthy",
        "backup_unwritable",
        "disk_capacity_insufficient",
        "clock_skew_exceeded",
        "physical_transaction_limit",
        "duration_limit",
        "storage_limit",
        "read_rpc_unreachable",
        "write_endpoint_identity_mismatch",
        "budget_insufficient",
    } <= failures


def test_balance_and_maximum_deposit_estimation_can_fail_without_transferring() -> None:
    chains = _chains()
    targets = list(_targets(chains))
    runner_index = next(
        index
        for index, target in enumerate(targets)
        if target.chain_id == 11_155_420 and target.role == "runner"
    )
    targets[runner_index] = replace(targets[runner_index], maximum_deposit_wei=411)
    report = estimate_preflight(
        chains=chains,
        costs=_costs(),
        funding_targets=tuple(targets),
        capacity=_capacity(),
        funding_margin_bps=1_000,
    )
    instruction = next(
        item
        for item in report.funding_instructions
        if item.chain_id == 11_155_420 and item.role == "runner"
    )
    assert instruction.required_manual_deposit_wei == 412
    assert any(
        check.reason_code == "maximum_deposit_exceeded"
        for check in report.checks
    )
    assert report.effects["funding_operations"] == 0


def test_contract_receiver_collector_and_arbitrary_targets_are_rejected() -> None:
    chains = _chains()
    targets = list(_targets(chains))
    targets[0] = replace(targets[0], role="collector")
    with pytest.raises(EstimatorError, match="exactly deployer and runner"):
        estimate_preflight(
            chains=chains,
            costs=_costs(),
            funding_targets=tuple(targets),
            capacity=_capacity(),
            funding_margin_bps=1_000,
        )


def test_scale_estimator_requires_frozen_measurements_and_bounds_rpc_quota() -> None:
    chains = _chains()
    costs = tuple(
        replace(
            item,
            operation_type="scale",
            rpc_requests_per_transaction=5,
        )
        if item.role == "runner"
        else item
        for item in _costs()
    )
    missing = estimate_preflight(
        chains=chains,
        costs=costs,
        funding_targets=_targets(chains),
        capacity=replace(_capacity(), maximum_rpc_requests=100),
        funding_margin_bps=1_000,
    )
    assert any(
        check.reason_code == "scale_requires_frozen_pilot_and_primary_measurements"
        for check in missing.checks
    )
    measured = estimate_preflight(
        chains=chains,
        costs=costs,
        funding_targets=_targets(chains),
        capacity=replace(_capacity(), maximum_rpc_requests=29),
        funding_margin_bps=1_000,
        scale_measurements=(
            FrozenMeasurementReference("pilot", "11" * 32, True),
            FrozenMeasurementReference("primary", "22" * 32, True),
        ),
    )
    assert measured.estimated_rpc_requests == 30
    assert any(
        check.reason_code == "rpc_quota_limit" for check in measured.checks
    )
    assert measured.effects["broadcasts"] == 0

    targets = list(_targets(chains))
    targets[0] = replace(targets[0], address="0x" + "ff" * 20)
    with pytest.raises(EstimatorError, match="arbitrary funding target"):
        estimate_preflight(
            chains=chains,
            costs=_costs(),
            funding_targets=tuple(targets),
            capacity=_capacity(),
            funding_margin_bps=1_000,
        )


def test_deployer_and_runner_cost_roles_cannot_be_swapped() -> None:
    chains = _chains()
    costs = list(_costs())
    costs[0] = replace(costs[0], role="runner")
    with pytest.raises(EstimatorError, match="wrong role"):
        estimate_preflight(
            chains=chains,
            costs=tuple(costs),
            funding_targets=_targets(chains),
            capacity=_capacity(),
            funding_margin_bps=1_000,
        )
