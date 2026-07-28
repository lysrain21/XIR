from __future__ import annotations

import pytest

from xir_lab.preflight.report import (
    ARMS,
    CONDITIONS,
    REQUIRED_GATES,
    GateResult,
    PreflightReportError,
    build_preflight_report,
)

PATH_GATES = {"carrier_paths", "quotes", "simulations"}


def _experiment_gates() -> list[GateResult]:
    gates = [
        GateResult(gate_id, "pass", "fixture_pass", True)
        for gate_id in sorted(REQUIRED_GATES["experiment"] - PATH_GATES)
    ]
    gates.extend(
        GateResult(
            gate_id,
            "pass",
            "fixture_path_pass",
            True,
            scope="path",
            condition=condition,
            arm=arm,
        )
        for gate_id in sorted(PATH_GATES)
        for condition in CONDITIONS
        for arm in ARMS
    )
    gates.append(
        GateResult(
            "optional_explorer",
            "not_applicable",
            "explorer_not_required",
            False,
        )
    )
    return gates


def _replace_gate(
    gates: list[GateResult],
    *,
    gate_id: str,
    status: str,
    reason: str,
    condition: str | None = None,
    arm: str | None = None,
) -> None:
    for index, gate in enumerate(gates):
        if (
            gate.gate_id == gate_id
            and gate.condition == condition
            and gate.arm == arm
        ):
            gates[index] = GateResult(
                gate.gate_id,
                status,  # type: ignore[arg-type]
                reason,
                gate.required,
                gate.scope,
                gate.condition,
                gate.arm,
            )
            return
    raise AssertionError("fixture gate not found")


def test_all_explicit_gates_pass_with_zero_write_effects() -> None:
    report = build_preflight_report(
        operation_type="primary",
        gates=tuple(_experiment_gates()),
        public_identity_queries=1,
    )
    assert report.outcome == "pass"
    assert report.eligible_for_separately_authorized_live_execution
    assert all(condition.state == "eligible" for condition in report.conditions)
    assert report.effects == {
        "public_identity_queries": 1,
        "signing_operations": 0,
        "broadcasts": 0,
        "deployments": 0,
        "funding_operations": 0,
    }
    document = report.as_dict()
    assert any(
        gate["status"] == "not_applicable" for gate in document["gates"]
    )


def test_default_condition_failure_blocks_whole_run_and_both_arms() -> None:
    gates = _experiment_gates()
    _replace_gate(
        gates,
        gate_id="quotes",
        condition="HL",
        arm="xir",
        status="unknown",
        reason="quote_unavailable",
    )
    report = build_preflight_report(
        operation_type="primary",
        gates=tuple(gates),
    )
    assert report.outcome == "blocked"
    assert report.reason_code == "condition_unavailable_default_whole_run_block"
    assert not report.eligible_for_separately_authorized_live_execution
    assert all(condition.state == "not_executed" for condition in report.conditions)
    hl = next(item for item in report.conditions if item.condition == "HL")
    assert {arm.state for arm in hl.arms} == {"not_submitted"}


def test_authenticated_partial_policy_marks_exact_condition_not_executed() -> None:
    gates = _experiment_gates()
    _replace_gate(
        gates,
        gate_id="simulations",
        condition="LL",
        arm="baseline",
        status="fail",
        reason="simulation_revert",
    )
    report = build_preflight_report(
        operation_type="pilot",
        gates=tuple(gates),
        allow_partial_conditions=True,
        partial_policy_authenticated=True,
    )
    assert report.outcome == "partial"
    assert report.eligible_for_separately_authorized_live_execution
    unavailable = [item for item in report.conditions if item.state == "not_executed"]
    assert [item.condition for item in unavailable] == ["LL"]
    assert {arm.state for arm in unavailable[0].arms} == {"not_submitted"}
    assert all(
        item.state == "eligible"
        for item in report.conditions
        if item.condition != "LL"
    )


def test_unauthenticated_partial_flag_remains_whole_run_blocked() -> None:
    gates = _experiment_gates()
    _replace_gate(
        gates,
        gate_id="carrier_paths",
        condition="HH",
        arm="baseline",
        status="fail",
        reason="peer_mismatch",
    )
    report = build_preflight_report(
        operation_type="scale",
        gates=tuple(gates),
        allow_partial_conditions=True,
        partial_policy_authenticated=False,
    )
    assert report.outcome == "blocked"
    assert report.reason_code == "partial_policy_not_authenticated"
    assert all(item.state == "not_executed" for item in report.conditions)


def test_global_unknown_blocks_even_authenticated_partial_execution() -> None:
    gates = _experiment_gates()
    _replace_gate(
        gates,
        gate_id="approval",
        status="unknown",
        reason="revocation_record_unavailable",
    )
    report = build_preflight_report(
        operation_type="primary",
        gates=tuple(gates),
        allow_partial_conditions=True,
        partial_policy_authenticated=True,
    )
    assert report.outcome == "blocked"
    assert report.reason_code == "required_global_gate_failed"
    assert not report.eligible_for_separately_authorized_live_execution


def test_missing_or_not_applicable_required_gate_is_rejected() -> None:
    gates = _experiment_gates()
    gates = [gate for gate in gates if gate.gate_id != "approval"]
    with pytest.raises(PreflightReportError, match="missing required"):
        build_preflight_report(operation_type="primary", gates=tuple(gates))

    deployment = [
        GateResult(gate_id, "pass", "fixture_pass", True)
        for gate_id in REQUIRED_GATES["deployment"]
    ]
    deployment[0] = GateResult(
        deployment[0].gate_id,
        "not_applicable",
        "incorrect_na",
        True,
    )
    with pytest.raises(PreflightReportError, match="cannot be not_applicable"):
        build_preflight_report(
            operation_type="deployment",
            gates=tuple(deployment),
        )


def test_non_experiment_operation_uses_only_its_scoped_required_gates() -> None:
    gates = tuple(
        GateResult(gate_id, "pass", "fixture_pass", True)
        for gate_id in REQUIRED_GATES["closeout"]
    )
    report = build_preflight_report(
        operation_type="closeout",
        gates=gates,
    )
    assert report.outcome == "pass"
    assert report.conditions == ()
