from __future__ import annotations

from pathlib import Path

from xir_lab.localnet.native_profile import (
    NATIVE_ROUTES,
    build_native_attempts,
    build_native_plan,
    load_native_profile,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs" / "profiles" / "native-protocol-stack-v1.json"
DIGEST = "ab" * 32


def test_native_profile_binds_component_lock_and_unique_network_ids() -> None:
    profile, digest = load_native_profile(PROFILE)
    assert len(digest) == 64
    assert profile["protocol"]["hyperlane"]["ism"] == "messageIdMultisigIsm"
    assert profile["protocol"]["layerzero_v2"]["send_library"] == "SendUln302"
    assert profile["protocol"]["layerzero_v2"]["receive_library"] == "ReceiveUln302"


def test_native_progression_is_deterministic_balanced_and_route_exact() -> None:
    expected_counts = {"smoke": 40, "rehearsal": 1000, "scale": 40000}
    for phase, expected in expected_counts.items():
        first = build_native_attempts(profile_path=PROFILE, phase=phase)  # type: ignore[arg-type]
        second = build_native_attempts(profile_path=PROFILE, phase=phase)  # type: ignore[arg-type]
        assert first == second
        assert len(first) == expected
        assert len({attempt.attempt_id for attempt in first}) == expected
        assert {
            route: sum(attempt.route == route for attempt in first)
            for route in NATIVE_ROUTES
        } == {route: expected // 4 for route in NATIVE_ROUTES}
        assert all(attempt.xir == (attempt.route in {"HL", "LH"}) for attempt in first)
        distributions = {
            route: sorted(
                attempt.payload_bytes for attempt in first if attempt.route == route
            )
            for route in NATIVE_ROUTES
        }
        assert len({tuple(value) for value in distributions.values()}) == 1
        for sequence in range(expected // 4):
            matched = [
                attempt.payload_sha256
                for attempt in first
                if attempt.route_sequence == sequence
            ]
            assert len(set(matched)) == 1


def test_native_plan_gates_scale_without_fixing_physical_transaction_count() -> None:
    smoke = build_native_plan(
        profile_path=PROFILE,
        topology_sha256=DIGEST,
        phase="smoke",
    )
    assert smoke["eligible"] is True
    assert smoke["logical_attempts"] == 40
    assert smoke["physical_transaction_accounting"] == (
        "derived-from-complete-protocol-evidence"
    )

    scale = build_native_plan(
        profile_path=PROFILE,
        topology_sha256=DIGEST,
        phase="scale",
    )
    assert scale["eligible"] is False
    assert scale["route_counts"] == {route: 10000 for route in NATIVE_ROUTES}
    assert scale["expected_xir_transitions"] == 20000
    assert scale["expected_application_effects"] == 40000

    qualified = build_native_plan(
        profile_path=PROFILE,
        topology_sha256=DIGEST,
        phase="scale",
        smoke_reconciliation_sha256=DIGEST,
        rehearsal_reconciliation_sha256=DIGEST,
        measured_limits_sha256=DIGEST,
    )
    assert qualified["eligible"] is True
    assert qualified["reason_codes"] == []
