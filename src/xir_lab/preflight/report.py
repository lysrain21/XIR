"""Machine-readable, fail-closed operation preflight aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

GateStatus = Literal["pass", "fail", "unknown", "not_applicable"]
GateScope = Literal["global", "path"]

CONDITIONS = ("HH", "HL", "LH", "LL")
ARMS = ("baseline", "xir")
COMMON_GATES = frozenset(
    {
        "approval",
        "network_identity",
        "nonce",
        "balance",
        "budget",
        "read_rpc",
        "write_endpoint_identity",
        "evidence_storage",
        "disk",
        "backup",
        "clock",
    }
)
REQUIRED_GATES: dict[str, frozenset[str]] = {
    "deployment": COMMON_GATES
    | {
        "creation_inputs",
        "deployer_identity",
        "deployer_nonce",
        "predicted_addresses",
    },
    "configuration": COMMON_GATES
    | {
        "runtime_snapshot",
        "administrator",
        "expected_state",
        "authorized_transition",
    },
    "experiment": COMMON_GATES
    | {
        "signer_identity",
        "deployment_snapshot",
        "permissions",
        "pause_state",
        "carrier_paths",
        "quotes",
        "simulations",
        "destination_isolation",
        "collector",
        "physical_transaction_estimate",
        "duration_estimate",
        "storage_estimate",
        "native_token_estimate",
    },
    "closeout": COMMON_GATES
    | {
        "runtime_snapshot",
        "administrator",
        "expected_state",
        "authorized_transition",
    },
}


class PreflightReportError(ValueError):
    """Raised when required gate evidence is missing or ambiguous."""


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    status: GateStatus
    reason_code: str
    required: bool
    scope: GateScope = "global"
    condition: str | None = None
    arm: str | None = None


@dataclass(frozen=True)
class ArmDecision:
    arm: str
    state: str


@dataclass(frozen=True)
class ConditionDecision:
    condition: str
    state: str
    arms: tuple[ArmDecision, ArmDecision]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class PreflightReport:
    operation_type: str
    outcome: str
    reason_code: str
    allow_partial_conditions: bool
    partial_policy_authenticated: bool
    gates: tuple[GateResult, ...]
    conditions: tuple[ConditionDecision, ...]
    eligible_for_separately_authorized_live_execution: bool
    effects: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "xir-lab-preflight-report-v1",
            "operation_type": self.operation_type,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "allow_partial_conditions": self.allow_partial_conditions,
            "partial_policy_authenticated": self.partial_policy_authenticated,
            "gates": [
                {
                    "gate_id": gate.gate_id,
                    "status": gate.status,
                    "reason_code": gate.reason_code,
                    "required": gate.required,
                    "scope": gate.scope,
                    "condition": gate.condition,
                    "arm": gate.arm,
                }
                for gate in self.gates
            ],
            "conditions": [
                {
                    "condition": condition.condition,
                    "state": condition.state,
                    "arms": [
                        {"arm": arm.arm, "state": arm.state}
                        for arm in condition.arms
                    ],
                    "reason_codes": list(condition.reason_codes),
                }
                for condition in self.conditions
            ],
            "eligible_for_separately_authorized_live_execution": (
                self.eligible_for_separately_authorized_live_execution
            ),
            "effects": self.effects,
        }


def build_preflight_report(
    *,
    operation_type: str,
    gates: tuple[GateResult, ...],
    allow_partial_conditions: bool = False,
    partial_policy_authenticated: bool = False,
    public_identity_queries: int = 0,
) -> PreflightReport:
    category = (
        "experiment"
        if operation_type in {"pilot", "primary", "scale"}
        else operation_type
    )
    required_ids = REQUIRED_GATES.get(category)
    if required_ids is None:
        raise PreflightReportError(f"unsupported operation type: {operation_type}")
    if public_identity_queries not in {0, 1}:
        raise PreflightReportError("preflight permits at most one public identity query")
    _validate_gates(gates, required_ids, experiment=category == "experiment")
    global_blockers = [
        gate
        for gate in gates
        if gate.required
        and gate.scope == "global"
        and gate.status in {"fail", "unknown"}
    ]
    effective_partial = allow_partial_conditions and partial_policy_authenticated
    conditions: tuple[ConditionDecision, ...] = ()
    outcome: str
    reason: str
    eligible: bool
    if category != "experiment":
        outcome = "blocked" if global_blockers else "pass"
        reason = "required_global_gate_failed" if global_blockers else "all_required_gates_pass"
        eligible = not global_blockers
    else:
        unavailable = _unavailable_conditions(gates)
        if global_blockers:
            outcome = "blocked"
            reason = "required_global_gate_failed"
            conditions = _condition_decisions(
                unavailable=set(CONDITIONS),
                reasons={
                    condition: ("global_preflight_block",)
                    for condition in CONDITIONS
                },
            )
            eligible = False
        elif unavailable and not effective_partial:
            outcome = "blocked"
            reason = (
                "partial_policy_not_authenticated"
                if allow_partial_conditions and not partial_policy_authenticated
                else "condition_unavailable_default_whole_run_block"
            )
            conditions = _condition_decisions(
                unavailable=set(CONDITIONS),
                reasons={
                    condition: (
                        tuple(unavailable.get(condition, ("whole_run_block",)))
                        if condition in unavailable
                        else ("whole_run_block",)
                    )
                    for condition in CONDITIONS
                },
            )
            eligible = False
        elif unavailable:
            outcome = "partial"
            reason = "authenticated_partial_conditions"
            conditions = _condition_decisions(
                unavailable=set(unavailable),
                reasons=unavailable,
            )
            eligible = True
        else:
            outcome = "pass"
            reason = "all_required_gates_pass"
            conditions = _condition_decisions(unavailable=set(), reasons={})
            eligible = True
    return PreflightReport(
        operation_type=operation_type,
        outcome=outcome,
        reason_code=reason,
        allow_partial_conditions=allow_partial_conditions,
        partial_policy_authenticated=partial_policy_authenticated,
        gates=tuple(sorted(gates, key=_gate_sort_key)),
        conditions=conditions,
        eligible_for_separately_authorized_live_execution=eligible,
        effects={
            "public_identity_queries": public_identity_queries,
            "signing_operations": 0,
            "broadcasts": 0,
            "deployments": 0,
            "funding_operations": 0,
        },
    )


def _validate_gates(
    gates: tuple[GateResult, ...],
    required_ids: frozenset[str],
    *,
    experiment: bool,
) -> None:
    if not gates:
        raise PreflightReportError("preflight requires explicit gate results")
    seen: set[tuple[str, str | None, str | None]] = set()
    for gate in gates:
        key = (gate.gate_id, gate.condition, gate.arm)
        if key in seen:
            raise PreflightReportError(f"duplicate gate result: {key}")
        seen.add(key)
        if gate.reason_code == "":
            raise PreflightReportError("every gate requires a reason code")
        if gate.required and gate.status == "not_applicable":
            raise PreflightReportError("required gate cannot be not_applicable")
        if gate.scope == "path":
            if not experiment:
                raise PreflightReportError("path gates apply only to experiment execution")
            if gate.condition not in CONDITIONS or gate.arm not in ARMS:
                raise PreflightReportError("path gate has invalid condition or arm")
        elif gate.condition is not None or gate.arm is not None:
            raise PreflightReportError("global gate cannot name a condition or arm")
    present_required_ids = {gate.gate_id for gate in gates if gate.required}
    missing = required_ids - present_required_ids
    if missing:
        raise PreflightReportError(
            f"missing required gate results: {sorted(missing)}"
        )
    if experiment:
        path_cells = {
            (gate.condition, gate.arm)
            for gate in gates
            if gate.required and gate.scope == "path"
        }
        expected_cells = {
            (condition, arm) for condition in CONDITIONS for arm in ARMS
        }
        if path_cells != expected_cells:
            raise PreflightReportError(
                "required path gates must cover all eight condition/arm cells"
            )


def _unavailable_conditions(
    gates: tuple[GateResult, ...],
) -> dict[str, tuple[str, ...]]:
    reasons: dict[str, set[str]] = {}
    for gate in gates:
        if (
            gate.required
            and gate.scope == "path"
            and gate.status in {"fail", "unknown"}
            and gate.condition is not None
        ):
            reasons.setdefault(gate.condition, set()).add(gate.reason_code)
    return {
        condition: tuple(sorted(values))
        for condition, values in reasons.items()
    }


def _condition_decisions(
    *,
    unavailable: set[str],
    reasons: dict[str, tuple[str, ...]],
) -> tuple[ConditionDecision, ...]:
    return tuple(
        ConditionDecision(
            condition=condition,
            state="not_executed" if condition in unavailable else "eligible",
            arms=(
                ArmDecision(
                    "baseline",
                    "not_submitted" if condition in unavailable else "eligible",
                ),
                ArmDecision(
                    "xir",
                    "not_submitted" if condition in unavailable else "eligible",
                ),
            ),
            reason_codes=reasons.get(condition, ()),
        )
        for condition in CONDITIONS
    )


def _gate_sort_key(gate: GateResult) -> tuple[str, str, str]:
    return (gate.gate_id, gate.condition or "", gate.arm or "")
