from __future__ import annotations

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_deployer import (
    adapter_key,
    classify_multihop_deployment_costs,
    multihop_profile_hash,
)
from xir_lab.native.multihop_scalability import ROUTE_ORDER


def test_route_specific_profiles_and_adapter_keys_do_not_alias() -> None:
    profiles = {
        multihop_profile_hash(route, hop)
        for route in ROUTE_ORDER
        for hop in range(1, len(route) + 1)
    }
    adapters = {
        adapter_key(route, hop, direction)
        for route in ROUTE_ORDER
        for hop in range(1, len(route) + 1)
        for direction in ("out", "in")
    }
    assert len(profiles) == sum(map(len, ROUTE_ORDER)) == 31
    assert len(adapters) == 62


def test_shared_prefix_profiles_remain_route_specific_for_verifier_binding() -> None:
    assert multihop_profile_hash("HHH", 1) != multihop_profile_hash("HLH", 1)
    assert adapter_key("HHH", 2, "out") != adapter_key("HLH", 2, "out")


def test_deployment_costs_exclude_reused_native_carriers() -> None:
    rows = [
        {"action": "deploy:a:gateway", "gas_used": 101},
        {"action": "configure:a:profile", "gas_used": 29},
    ]
    components, classes = classify_multihop_deployment_costs(rows)
    assert components == {"gateway": [101], "configuration_call": [29]}
    assert classes == {
        "xir_only_contract_deployment": [101],
        "xir_profile_root_peer_binding_initialization": [29],
    }
    assert {row["cost_classification"] for row in rows} == set(classes)
    with pytest.raises(LocalTopologyError, match="classes are incomplete"):
        classify_multihop_deployment_costs(
            [{"action": "deploy:a:gateway", "gas_used": 101}]
        )
