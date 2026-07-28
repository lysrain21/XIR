from __future__ import annotations

import pytest

from xir_lab.preflight.readiness import (
    ReadinessFacts,
    ReadinessLimits,
    assess_host_readiness,
)


def _facts() -> ReadinessFacts:
    return ReadinessFacts(
        clock_skew_seconds=1,
        disk_available_bytes=10_000,
        backup_writable=True,
        raw_store_writable=True,
        database_integrity_ok=True,
        rpc_quota_remaining=1_000,
        observation_window_seconds=3_600,
    )


def _limits() -> ReadinessLimits:
    return ReadinessLimits(
        maximum_clock_skew_seconds=5,
        minimum_disk_available_bytes=1_000,
        minimum_rpc_quota_remaining=100,
        minimum_observation_window_seconds=600,
    )


def test_all_host_capacity_facts_must_be_concrete_and_pass() -> None:
    report = assess_host_readiness(_facts(), _limits())
    assert report.outcome == "pass"
    assert all(item.status == "pass" for item in report.gates)
    assert set(report.effects.values()) == {0}


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("clock_skew_seconds", "clock_skew_exceeded"),
        ("disk_available_bytes", "disk_floor_not_met"),
        ("backup_writable", "backup_not_writable"),
        ("raw_store_writable", "raw_store_not_writable"),
        ("database_integrity_ok", "database_integrity_failed"),
        ("rpc_quota_remaining", "rpc_quota_exhausted"),
        ("observation_window_seconds", "observation_window_too_short"),
    ),
)
def test_each_host_gate_fails_closed(field: str, reason: str) -> None:
    values = _facts().__dict__.copy()
    values[field] = (
        999_999
        if field == "clock_skew_seconds"
        else False
        if field.endswith("writable") or field == "database_integrity_ok"
        else 0
    )
    report = assess_host_readiness(ReadinessFacts(**values), _limits())
    assert report.outcome == "blocked"
    assert reason in {item.reason_code for item in report.gates}


def test_unknown_quota_or_clock_is_blocking() -> None:
    values = _facts().__dict__.copy()
    values["rpc_quota_remaining"] = None
    report = assess_host_readiness(ReadinessFacts(**values), _limits())
    assert report.outcome == "blocked"
    assert next(item for item in report.gates if item.gate_id == "rpc_quota").status == "unknown"
