from __future__ import annotations

from pathlib import Path

import pytest

from xir_lab.localnet.report import (
    build_local_scale_report,
    validate_local_scale_report,
)
from xir_lab.localnet.scale import build_local_scale_plan
from xir_lab.localnet.topology import LocalTopologyError, load_topology
from xir_lab.localnet.workload import build_local_attempts

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "configs" / "local" / "topology-v1.json"
PROFILE = ROOT / "configs" / "profiles" / "local-paper-scale-v2.json"
DIGEST = "ab" * 32


@pytest.mark.parametrize(
    ("phase", "expected"),
    (("smoke", 40), ("rehearsal", 1000), ("scale", 40000)),
)
def test_local_workload_schedule_is_exact_and_balanced(
    phase: str,
    expected: int,
) -> None:
    attempts = build_local_attempts(profile_path=PROFILE, phase=phase)  # type: ignore[arg-type]
    assert len(attempts) == expected
    assert len({item.attempt_id for item in attempts}) == expected
    assert {
        route: sum(
            item.route == route for item in attempts
        )
        for route in ("HH", "HL", "LH", "LL")
    } == {
        route: expected // 4
        for route in ("HH", "HL", "LH", "LL")
    }
    assert all(item.xir == (item.route in {"HL", "LH"}) for item in attempts)
    assert all(
        item.execution_class
        == ("heterogeneous-xir" if item.xir else "homogeneous-native")
        for item in attempts
    )
    payload_distributions = {
        route: sorted(item.payload_bytes for item in attempts if item.route == route)
        for route in ("HH", "HL", "LH", "LL")
    }
    assert len({tuple(values) for values in payload_distributions.values()}) == 1


def test_local_scale_plan_has_exact_balanced_counts_and_progression_gate() -> None:
    topology = load_topology(TOPOLOGY)
    planned = build_local_scale_plan(
        profile_path=PROFILE,
        topology_sha256=topology.source_sha256,
    )
    assert planned["eligible"] is False
    assert planned["counts"] == {
        "designated_attempts": 40000,
        "source_transactions": 40000,
        "intermediate_transactions": 40000,
        "destination_transactions": 40000,
        "physical_transactions": 120000,
        "xir_transitions": 20000,
    }
    assert planned["route_counts"] == {
        "HH": 10000,
        "HL": 10000,
        "LH": 10000,
        "LL": 10000,
    }
    assert set(planned["reason_codes"]) == {
        "smoke_freeze_sha256",
        "rehearsal_freeze_sha256",
        "measured_limits_sha256",
    }

    eligible = build_local_scale_plan(
        profile_path=PROFILE,
        topology_sha256=topology.source_sha256,
        smoke_freeze_sha256=DIGEST,
        rehearsal_freeze_sha256=DIGEST,
        measured_limits_sha256=DIGEST,
    )
    assert eligible["eligible"] is True
    assert eligible["reason_codes"] == []


def test_local_report_requires_complete_reconciliation_and_claim_exclusions() -> None:
    metrics = {
        "gas_used": 1,
        "calldata_bytes": 2,
        "controlled_latency_ms": 3,
        "completion_invocation_rpc_requests": 4,
        "storage_bytes": 5,
        "peak_cpu_percent": 6.0,
        "peak_memory_bytes": 7,
        "restart_outcomes": ["runner_recovered", "validator_caught_up"],
    }
    document = build_local_scale_report(
        topology_sha256=DIGEST,
        identity_manifest_sha256=DIGEST,
        plan_sha256=DIGEST,
        terminal_attempts=40000,
        physical_transactions=120000,
        retries=0,
        metrics=metrics,
        offline_rebuild_digests=(DIGEST, DIGEST),
    )
    validate_local_scale_report(document)

    incomplete = {
        **document,
        "counts": {**document["counts"], "terminal_attempts": 39999},
    }
    with pytest.raises(LocalTopologyError, match="incomplete terminal"):
        validate_local_scale_report(incomplete)

    mismatched = {
        **document,
        "offline_rebuild_digests": [DIGEST, "cd" * 32],
    }
    with pytest.raises(LocalTopologyError, match="digests differ"):
        validate_local_scale_report(mismatched)
