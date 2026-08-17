from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_scalability import (
    CHAIN_LABELS,
    ROUTE_ORDER,
    build_multihop_attempt,
    build_multihop_attempts,
    build_multihop_plan,
    expected_coordinator_transactions,
    expected_physical_transactions,
    expected_stage_sequence,
    load_multihop_config,
    load_multihop_plan,
    load_multihop_profile,
    switch_count,
    write_multihop_plan,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "native" / "native-multihop-switching-v1.json"
PROFILE = ROOT / "configs" / "profiles" / "native-multihop-five-chain-v1.json"


def test_five_chain_profile_and_preregistration_are_source_bound() -> None:
    profile, profile_sha = load_multihop_profile(PROFILE)
    config, config_sha = load_multihop_config(CONFIG)
    assert len(profile_sha) == len(config_sha) == 64
    assert [chain["label"] for chain in profile["chains"]] == list(CHAIN_LABELS)
    assert tuple(config["route_order"]) == ROUTE_ORDER
    assert config["attempts_per_route"]["scale"] == 10_000


def test_frozen_overrides_do_not_read_current_tree(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    frozen_config = tmp_path / "config.json"
    frozen_profile = tmp_path / "profile.json"
    frozen_component = tmp_path / "component-lock.json"
    source_root = tmp_path / "source-locks"
    frozen_config.write_text(json.dumps(config) + "\n", encoding="utf-8")
    frozen_profile.write_text(json.dumps(profile) + "\n", encoding="utf-8")
    shutil.copyfile(
        ROOT / profile["component_lock"]["relative_path"], frozen_component
    )
    for relative in config["source_sha256"]:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    loaded, _ = load_multihop_config(
        frozen_config,
        profile_path_override=frozen_profile,
        component_lock_path_override=frozen_component,
        source_root_override=source_root,
    )
    assert loaded["namespace"] == "native-multihop-switching-v1"
    (source_root / next(iter(config["source_sha256"]))).write_text(
        "drift\n", encoding="utf-8"
    )
    with pytest.raises(LocalTopologyError, match="source digest mismatch"):
        load_multihop_config(
            frozen_config,
            profile_path_override=frozen_profile,
            component_lock_path_override=frozen_component,
            source_root_override=source_root,
        )


@pytest.mark.parametrize(
    ("route", "switches", "coordinator", "physical"),
    [
        ("H", 0, 3, 4),
        ("L", 0, 3, 6),
        ("HH", 0, 4, 6),
        ("HL", 1, 5, 9),
        ("HLH", 2, 7, 12),
        ("HLHL", 3, 9, 17),
        ("LHLH", 3, 9, 17),
        ("HHL", 1, 6, 11),
        ("HHHL", 1, 7, 13),
    ],
)
def test_transaction_theory_and_stage_multiset(
    route: str, switches: int, coordinator: int, physical: int
) -> None:
    assert switch_count(route) == switches
    assert expected_coordinator_transactions(route) == coordinator
    assert expected_physical_transactions(route) == physical
    assert len(expected_stage_sequence(route)) == physical


def test_smoke_plan_is_matched_balanced_and_deterministic(tmp_path: Path) -> None:
    first = build_multihop_plan(config_path=CONFIG, phase="smoke")
    second = build_multihop_plan(config_path=CONFIG, phase="smoke")
    assert first == second
    assert first["logical_attempts"] == 11
    assert first["route_counts"] == {route: 1 for route in ROUTE_ORDER}
    attempts = build_multihop_attempts(config_path=CONFIG, phase="smoke")
    assert len({attempt.payload_sha256 for attempt in attempts}) == 1
    assert {attempt.chain_labels for attempt in attempts if attempt.hop_count == 4} == {
        CHAIN_LABELS
    }
    output = tmp_path / "smoke-plan.json"
    one = write_multihop_plan(output, first)
    two = write_multihop_plan(output, second)
    assert one == two
    assert json.loads(output.read_text(encoding="utf-8"))["plan_sha256"] == first[
        "plan_sha256"
    ]
    loaded, file_digest = load_multihop_plan(
        path=output, config_path=CONFIG, phase="smoke"
    )
    assert loaded == first
    assert file_digest == one
    tampered = dict(first)
    tampered["logical_attempts"] = 22
    output.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="differs from config"):
        load_multihop_plan(path=output, config_path=CONFIG, phase="smoke")


def test_publication_smoke_rotates_route_order_without_breaking_matching() -> None:
    attempts = build_multihop_attempts(config_path=CONFIG, phase="publication_smoke")
    assert [attempt.route for attempt in attempts[:11]] == list(ROUTE_ORDER)
    assert [attempt.route for attempt in attempts[11:22]] == [
        *ROUTE_ORDER[1:],
        ROUTE_ORDER[0],
    ]
    assert len({attempt.payload_sha256 for attempt in attempts[:11]}) == 1
    assert len({attempt.payload_sha256 for attempt in attempts[11:22]}) == 1


def test_scale_plan_has_exact_preregistered_denominator() -> None:
    plan = build_multihop_plan(config_path=CONFIG, phase="scale")
    assert plan["logical_attempts"] == 110_000
    assert plan["expected_application_effects"] == 110_000
    assert set(plan["route_counts"].values()) == {10_000}
    assert sum(
        int(plan["route_counts"][route]) * expected_physical_transactions(route)
        for route in ROUTE_ORDER
    ) == 1_130_000
    config, _ = load_multihop_config(CONFIG)
    first = build_multihop_attempt(
        config=config, phase="scale", route_sequence=0, route="H"
    )
    last = build_multihop_attempt(
        config=config, phase="scale", route_sequence=9_999, route="HHHL"
    )
    assert first.route_sequence == 0
    assert last.route_sequence == 9_999
    assert first.attempt_id != last.attempt_id


def test_invalid_route_fails_closed() -> None:
    with pytest.raises(LocalTopologyError, match="invalid multihop route"):
        switch_count("HX")
