"""Local capacity and observation-window gates for live preflight."""

from __future__ import annotations

from dataclasses import dataclass


class ReadinessError(ValueError):
    """Raised when readiness limits are incomplete or nonsensical."""


@dataclass(frozen=True)
class ReadinessFacts:
    clock_skew_seconds: int | None
    disk_available_bytes: int | None
    backup_writable: bool | None
    raw_store_writable: bool | None
    database_integrity_ok: bool | None
    rpc_quota_remaining: int | None
    observation_window_seconds: int | None


@dataclass(frozen=True)
class ReadinessLimits:
    maximum_clock_skew_seconds: int
    minimum_disk_available_bytes: int
    minimum_rpc_quota_remaining: int
    minimum_observation_window_seconds: int


@dataclass(frozen=True)
class ReadinessGate:
    gate_id: str
    status: str
    reason_code: str


@dataclass(frozen=True)
class HostReadinessReport:
    gates: tuple[ReadinessGate, ...]
    outcome: str
    effects: dict[str, int]


def assess_host_readiness(
    facts: ReadinessFacts,
    limits: ReadinessLimits,
) -> HostReadinessReport:
    """Evaluate injected local facts without opening a signer or network writer."""

    if min(
        limits.maximum_clock_skew_seconds,
        limits.minimum_disk_available_bytes,
        limits.minimum_rpc_quota_remaining,
        limits.minimum_observation_window_seconds,
    ) < 0:
        raise ReadinessError("readiness limits cannot be negative")
    gates = (
        _maximum_gate(
            "clock",
            facts.clock_skew_seconds,
            limits.maximum_clock_skew_seconds,
            "clock_skew_exceeded",
        ),
        _minimum_gate(
            "disk",
            facts.disk_available_bytes,
            limits.minimum_disk_available_bytes,
            "disk_floor_not_met",
        ),
        _boolean_gate("backup", facts.backup_writable, "backup_not_writable"),
        _boolean_gate(
            "evidence_storage",
            facts.raw_store_writable,
            "raw_store_not_writable",
        ),
        _boolean_gate(
            "database",
            facts.database_integrity_ok,
            "database_integrity_failed",
        ),
        _minimum_gate(
            "rpc_quota",
            facts.rpc_quota_remaining,
            limits.minimum_rpc_quota_remaining,
            "rpc_quota_exhausted",
        ),
        _minimum_gate(
            "observation_window",
            facts.observation_window_seconds,
            limits.minimum_observation_window_seconds,
            "observation_window_too_short",
        ),
    )
    return HostReadinessReport(
        gates=gates,
        outcome="pass" if all(item.status == "pass" for item in gates) else "blocked",
        effects={
            "signing_operations": 0,
            "funding_operations": 0,
            "deployments": 0,
            "broadcasts": 0,
        },
    )


def _maximum_gate(
    gate_id: str,
    value: int | None,
    maximum: int,
    failure: str,
) -> ReadinessGate:
    if value is None:
        return ReadinessGate(gate_id, "unknown", f"{gate_id}_unknown")
    if abs(value) > maximum:
        return ReadinessGate(gate_id, "fail", failure)
    return ReadinessGate(gate_id, "pass", f"{gate_id}_ready")


def _minimum_gate(
    gate_id: str,
    value: int | None,
    minimum: int,
    failure: str,
) -> ReadinessGate:
    if value is None:
        return ReadinessGate(gate_id, "unknown", f"{gate_id}_unknown")
    if value < minimum:
        return ReadinessGate(gate_id, "fail", failure)
    return ReadinessGate(gate_id, "pass", f"{gate_id}_ready")


def _boolean_gate(
    gate_id: str,
    value: bool | None,
    failure: str,
) -> ReadinessGate:
    if value is None:
        return ReadinessGate(gate_id, "unknown", f"{gate_id}_unknown")
    if not value:
        return ReadinessGate(gate_id, "fail", failure)
    return ReadinessGate(gate_id, "pass", f"{gate_id}_ready")
