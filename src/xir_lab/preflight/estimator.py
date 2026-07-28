"""Zero-write workload, capacity, and role-specific funding estimator."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

Role = Literal["deployer", "runner"]

CHAIN_NAMES = {
    11_155_420: "OP Sepolia",
    421_614: "Arbitrum Sepolia",
    84_532: "Base Sepolia",
}
ROLE_OPERATIONS = {
    "deployer": frozenset({"deployment", "configuration", "closeout"}),
    "runner": frozenset({"pilot", "primary", "scale"}),
}


class EstimatorError(ValueError):
    """Raised when an estimator input or funding target is unsafe."""


@dataclass(frozen=True)
class ChainEstimateState:
    chain_id: int
    deployer_address: str
    runner_address: str
    deployer_nonce: int
    runner_nonce: int
    deployer_balance_wei: int
    runner_balance_wei: int
    deployer_budget_wei: int
    runner_budget_wei: int
    deployer_balance_floor_wei: int
    runner_balance_floor_wei: int
    read_rpc_reachable: bool
    write_endpoint_identity_verified: bool


@dataclass(frozen=True)
class CostItem:
    item_id: str
    chain_id: int
    role: Role
    operation_type: str
    physical_transactions: int
    gas_limit: int
    max_fee_per_gas_wei: int
    carrier_payment_wei: int
    transaction_value_wei: int
    seconds_per_transaction: int
    evidence_bytes_per_transaction: int
    rpc_requests_per_transaction: int = 0

    @property
    def per_transaction_wei(self) -> int:
        return (
            self.gas_limit * self.max_fee_per_gas_wei
            + self.carrier_payment_wei
            + self.transaction_value_wei
        )

    @property
    def total_wei(self) -> int:
        return self.per_transaction_wei * self.physical_transactions


@dataclass(frozen=True)
class FundingTarget:
    chain_id: int
    role: str
    address: str
    maximum_deposit_wei: int


@dataclass(frozen=True)
class CapacityState:
    collector_healthy: bool
    backup_writable: bool
    disk_available_bytes: int
    backup_reserve_bytes: int
    clock_skew_seconds: int
    maximum_clock_skew_seconds: int
    maximum_physical_transactions: int
    maximum_duration_seconds: int
    maximum_storage_bytes: int
    max_concurrency: int
    maximum_rpc_requests: int = 0


@dataclass(frozen=True)
class FrozenMeasurementReference:
    profile_kind: Literal["pilot", "primary"]
    freeze_sha256: str
    validated: bool


@dataclass(frozen=True)
class EstimateCheck:
    check_id: str
    status: str
    reason_code: str
    observed: int | bool
    limit: int | bool


@dataclass(frozen=True)
class FundingInstruction:
    chain_id: int
    network_name: str
    native_test_token: str
    role: Role
    recipient_address: str
    estimated_spend_wei: int
    margin_wei: int
    balance_floor_wei: int
    observed_balance_wei: int
    required_manual_deposit_wei: int
    maximum_deposit_wei: int
    action: str = "manual_external_funding_checkpoint"


@dataclass(frozen=True)
class EstimateReport:
    checks: tuple[EstimateCheck, ...]
    funding_instructions: tuple[FundingInstruction, ...]
    projected_nonces: dict[str, int]
    estimated_physical_transactions: int
    estimated_duration_seconds: int
    estimated_storage_bytes: int
    estimated_rpc_requests: int
    effects: dict[str, int]

    @property
    def passed(self) -> bool:
        return all(check.status == "pass" for check in self.checks)


def estimate_preflight(
    *,
    chains: tuple[ChainEstimateState, ...],
    costs: tuple[CostItem, ...],
    funding_targets: tuple[FundingTarget, ...],
    capacity: CapacityState,
    funding_margin_bps: int,
    scale_measurements: tuple[FrozenMeasurementReference, ...] = (),
) -> EstimateReport:
    _validate_inputs(chains, costs, funding_targets, capacity, funding_margin_bps)
    chain_map = {chain.chain_id: chain for chain in chains}
    target_map = {
        (target.chain_id, target.role): target for target in funding_targets
    }
    totals: dict[tuple[int, str], int] = defaultdict(int)
    tx_counts: dict[tuple[int, str], int] = defaultdict(int)
    total_transactions = 0
    serial_seconds = 0
    storage_bytes = 0
    rpc_requests = 0
    for item in costs:
        key = (item.chain_id, item.role)
        totals[key] += item.total_wei
        tx_counts[key] += item.physical_transactions
        total_transactions += item.physical_transactions
        serial_seconds += item.physical_transactions * item.seconds_per_transaction
        storage_bytes += (
            item.physical_transactions * item.evidence_bytes_per_transaction
        )
        rpc_requests += (
            item.physical_transactions * item.rpc_requests_per_transaction
        )
    duration_seconds = (
        serial_seconds + capacity.max_concurrency - 1
    ) // capacity.max_concurrency
    checks: list[EstimateCheck] = [
        _check(
            "collector_health",
            capacity.collector_healthy,
            True,
            "collector_unhealthy",
        ),
        _check(
            "backup_writable",
            capacity.backup_writable,
            True,
            "backup_unwritable",
        ),
        _upper_check(
            "clock_skew",
            abs(capacity.clock_skew_seconds),
            capacity.maximum_clock_skew_seconds,
            "clock_skew_exceeded",
        ),
        _upper_check(
            "physical_transactions",
            total_transactions,
            capacity.maximum_physical_transactions,
            "physical_transaction_limit",
        ),
        _upper_check(
            "duration",
            duration_seconds,
            capacity.maximum_duration_seconds,
            "duration_limit",
        ),
        _upper_check(
            "storage",
            storage_bytes,
            capacity.maximum_storage_bytes,
            "storage_limit",
        ),
        _upper_check(
            "rpc_requests",
            rpc_requests,
            capacity.maximum_rpc_requests,
            "rpc_quota_limit",
        ),
        _lower_check(
            "disk_capacity",
            capacity.disk_available_bytes,
            storage_bytes + capacity.backup_reserve_bytes,
            "disk_capacity_insufficient",
        ),
    ]
    if any(item.operation_type == "scale" for item in costs):
        measurement_kinds = {
            item.profile_kind
            for item in scale_measurements
            if item.validated and len(item.freeze_sha256) == 64
        }
        checks.append(
            _check(
                "scale_frozen_measurements",
                measurement_kinds == {"pilot", "primary"},
                True,
                "scale_requires_frozen_pilot_and_primary_measurements",
            )
        )
    instructions: list[FundingInstruction] = []
    projected_nonces: dict[str, int] = {}
    for chain_id in sorted(chain_map):
        chain = chain_map[chain_id]
        checks.extend(
            (
                _check(
                    f"read_rpc:{chain_id}",
                    chain.read_rpc_reachable,
                    True,
                    "read_rpc_unreachable",
                ),
                _check(
                    f"write_endpoint_identity:{chain_id}",
                    chain.write_endpoint_identity_verified,
                    True,
                    "write_endpoint_identity_mismatch",
                ),
            )
        )
        for role in ("deployer", "runner"):
            typed_role: Role = role
            key = (chain_id, role)
            estimated = totals[key]
            margin = (estimated * funding_margin_bps + 9_999) // 10_000
            planned = estimated + margin
            if role == "deployer":
                nonce = chain.deployer_nonce
                balance = chain.deployer_balance_wei
                budget = chain.deployer_budget_wei
                floor = chain.deployer_balance_floor_wei
                address = chain.deployer_address
            else:
                nonce = chain.runner_nonce
                balance = chain.runner_balance_wei
                budget = chain.runner_budget_wei
                floor = chain.runner_balance_floor_wei
                address = chain.runner_address
            projected_nonces[f"{chain_id}:{role}"] = nonce + tx_counts[key]
            checks.append(
                _upper_check(
                    f"budget:{chain_id}:{role}",
                    planned,
                    budget,
                    "budget_insufficient",
                )
            )
            required_deposit = max(0, planned + floor - balance)
            target = target_map[key]
            checks.append(
                _upper_check(
                    f"maximum_deposit:{chain_id}:{role}",
                    required_deposit,
                    target.maximum_deposit_wei,
                    "maximum_deposit_exceeded",
                )
            )
            instructions.append(
                FundingInstruction(
                    chain_id=chain_id,
                    network_name=CHAIN_NAMES[chain_id],
                    native_test_token=f"{CHAIN_NAMES[chain_id]} native test ETH",
                    role=typed_role,
                    recipient_address=address,
                    estimated_spend_wei=estimated,
                    margin_wei=margin,
                    balance_floor_wei=floor,
                    observed_balance_wei=balance,
                    required_manual_deposit_wei=required_deposit,
                    maximum_deposit_wei=target.maximum_deposit_wei,
                )
            )
    return EstimateReport(
        checks=tuple(checks),
        funding_instructions=tuple(instructions),
        projected_nonces=projected_nonces,
        estimated_physical_transactions=total_transactions,
        estimated_duration_seconds=duration_seconds,
        estimated_storage_bytes=storage_bytes,
        estimated_rpc_requests=rpc_requests,
        effects={
            "wallets_created": 0,
            "funding_operations": 0,
            "signing_operations": 0,
            "broadcasts": 0,
        },
    )


def _validate_inputs(
    chains: tuple[ChainEstimateState, ...],
    costs: tuple[CostItem, ...],
    funding_targets: tuple[FundingTarget, ...],
    capacity: CapacityState,
    margin_bps: int,
) -> None:
    if {chain.chain_id for chain in chains} != set(CHAIN_NAMES):
        raise EstimatorError("chain estimates must cover exactly the fixed three networks")
    if len(chains) != len(CHAIN_NAMES):
        raise EstimatorError("chain estimate identities must be unique")
    if margin_bps < 0:
        raise EstimatorError("funding margin cannot be negative")
    capacity_values = (
        capacity.disk_available_bytes,
        capacity.backup_reserve_bytes,
        capacity.maximum_clock_skew_seconds,
        capacity.maximum_physical_transactions,
        capacity.maximum_duration_seconds,
        capacity.maximum_storage_bytes,
        capacity.maximum_rpc_requests,
    )
    if min(capacity_values) < 0 or capacity.max_concurrency < 1:
        raise EstimatorError("capacity limits are invalid")
    chain_map = {chain.chain_id: chain for chain in chains}
    for chain in chains:
        numeric = (
            chain.deployer_nonce,
            chain.runner_nonce,
            chain.deployer_balance_wei,
            chain.runner_balance_wei,
            chain.deployer_budget_wei,
            chain.runner_budget_wei,
            chain.deployer_balance_floor_wei,
            chain.runner_balance_floor_wei,
        )
        if min(numeric) < 0:
            raise EstimatorError("nonce, balance, budget, and floor cannot be negative")
        if (
            not _address(chain.deployer_address)
            or not _address(chain.runner_address)
            or chain.deployer_address.lower() == chain.runner_address.lower()
        ):
            raise EstimatorError("deployer and runner must be distinct nonzero addresses")
    for item in costs:
        values = (
            item.physical_transactions,
            item.gas_limit,
            item.max_fee_per_gas_wei,
            item.carrier_payment_wei,
            item.transaction_value_wei,
            item.seconds_per_transaction,
            item.evidence_bytes_per_transaction,
            item.rpc_requests_per_transaction,
        )
        if item.chain_id not in chain_map or min(values) < 0:
            raise EstimatorError("cost item has an invalid chain or negative value")
        if item.operation_type not in ROLE_OPERATIONS[item.role]:
            raise EstimatorError("cost item operation is assigned to the wrong role")
    expected_targets = {
        (chain_id, role)
        for chain_id in CHAIN_NAMES
        for role in ("deployer", "runner")
    }
    actual_targets = {(target.chain_id, target.role) for target in funding_targets}
    if len(funding_targets) != 6 or actual_targets != expected_targets:
        raise EstimatorError(
            "funding targets must be exactly deployer and runner on each chain"
        )
    for target in funding_targets:
        chain = chain_map[target.chain_id]
        expected_address = (
            chain.deployer_address if target.role == "deployer" else chain.runner_address
        )
        if (
            target.maximum_deposit_wei < 0
            or target.address.lower() != expected_address.lower()
        ):
            raise EstimatorError(
                "contract, receiver, collector, or arbitrary funding target rejected"
            )


def _address(value: str) -> bool:
    try:
        return len(value) == 42 and value.startswith("0x") and int(value, 16) != 0
    except ValueError:
        return False


def _check(
    check_id: str,
    observed: bool,
    limit: bool,
    failure: str,
) -> EstimateCheck:
    return EstimateCheck(
        check_id,
        "pass" if observed == limit else "fail",
        "within_limit" if observed == limit else failure,
        observed,
        limit,
    )


def _upper_check(
    check_id: str,
    observed: int,
    limit: int,
    failure: str,
) -> EstimateCheck:
    return EstimateCheck(
        check_id,
        "pass" if observed <= limit else "fail",
        "within_limit" if observed <= limit else failure,
        observed,
        limit,
    )


def _lower_check(
    check_id: str,
    observed: int,
    limit: int,
    failure: str,
) -> EstimateCheck:
    return EstimateCheck(
        check_id,
        "pass" if observed >= limit else "fail",
        "within_limit" if observed >= limit else failure,
        observed,
        limit,
    )
