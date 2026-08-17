from __future__ import annotations

import hashlib
import json
from collections import deque
from itertools import combinations
from pathlib import Path

import pytest
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.gateway_deployment import (
    PROTOCOLS,
    GatewayReachability,
    _measured_deployment_gas,
    _validate_gateway_reference_replay,
    compare_gateway_publications,
    component_obligations,
    greedy_gateway_placement,
    protocol_expansion_curves,
    publish_gateway_deployment_document,
)


def test_gateway_semantics_keep_homogeneous_paths_without_gateways() -> None:
    nodes = ["a", "b", "c"]
    edges = [
        {"src": "a", "dst": "b", "carrier": "hyperlane"},
        {"src": "b", "dst": "a", "carrier": "hyperlane"},
        {"src": "b", "dst": "c", "carrier": "layerzero"},
        {"src": "c", "dst": "b", "carrier": "layerzero"},
    ]
    model = GatewayReachability(nodes, edges)
    assert model.reachable_pairs(model.base_closure) == 4
    assert model.reachable_pairs(model.closure({"b"})) == 6
    result = greedy_gateway_placement(model, all_compatible_pairs=6)
    assert result["selected_nodes"] == ["b"]
    assert result["equals_all_compatible"] is True
    pair = next(
        row for row in result["pair_evidence"] if row["source"] == "a" and row["destination"] == "c"
    )
    assert pair == {
        "source": "a",
        "destination": "c",
        "baseline_reachable": False,
        "terminal_reachable": True,
        "newly_enabled_by_gateway": True,
        "route_state_path": "hyperlane:a>hyperlane:b>layerzero:b>layerzero:c",
        "carrier_sequence": "hyperlane>layerzero",
        "gateway_switch_nodes": "b",
        "native_hop_count": 2,
        "switch_count": 1,
    }


def _oracle_pairs(nodes: list[str], edges: list[dict[str, str]], gateways: set[str]) -> int:
    states = [(protocol, node) for protocol in PROTOCOLS for node in nodes]
    adjacency = {state: set() for state in states}
    for edge in edges:
        adjacency[(edge["carrier"], edge["src"])].add((edge["carrier"], edge["dst"]))
    for node in gateways:
        for source_protocol in PROTOCOLS:
            for destination_protocol in PROTOCOLS:
                if source_protocol != destination_protocol:
                    adjacency[(source_protocol, node)].add((destination_protocol, node))
    total = 0
    for source in nodes:
        visited = {(protocol, source) for protocol in PROTOCOLS}
        queue = deque(sorted(visited))
        while queue:
            state = queue.popleft()
            for destination in sorted(adjacency[state]):
                if destination not in visited:
                    visited.add(destination)
                    queue.append(destination)
        total += len({node for _, node in visited}) - 1
    return total


def test_gateway_fixed_point_matches_expanded_graph_for_every_subset() -> None:
    nodes = ["a", "m", "z", "d"]
    edges = [
        {"src": "a", "dst": "z", "carrier": "hyperlane"},
        {"src": "z", "dst": "m", "carrier": "layerzero"},
        {"src": "m", "dst": "d", "carrier": "hyperlane"},
    ]
    model = GatewayReachability(nodes, edges)
    for size in range(len(nodes) + 1):
        for subset in combinations(nodes, size):
            gateways = set(subset)
            closure = model.closure(gateways)
            assert model.reachable_pairs(closure) == _oracle_pairs(nodes, edges, gateways)
    closure = model.closure({"m", "z"})
    assert model.reachable_pairs(closure) == _oracle_pairs(nodes, edges, {"m", "z"})
    evidence = model.pair_evidence(closure, gateways={"m", "z"})
    witness = next(row for row in evidence if row["source"] == "a" and row["destination"] == "d")
    assert witness["gateway_switch_nodes"] == "z>m"
    assert witness["carrier_sequence"] == "hyperlane>layerzero>hyperlane"


def test_gateway_tie_break_is_canonical_and_zero_gain_stops() -> None:
    nodes = ["a", "b"]
    edges = [
        {"src": "a", "dst": "b", "carrier": "hyperlane"},
        {"src": "b", "dst": "a", "carrier": "hyperlane"},
    ]
    model = GatewayReachability(nodes, edges)
    result = greedy_gateway_placement(model, all_compatible_pairs=2)
    assert result["terminal_k"] == 0
    assert result["terminal_reason"] == "all_compatible_reached"


def test_protocol_counterfactual_scenarios_are_explicit_and_deterministic() -> None:
    nodes = ["a", "b", "c"]
    edges = []
    for protocol in PROTOCOLS:
        edges.extend(
            [
                {
                    "src": "a",
                    "dst": "b",
                    "carrier": protocol,
                    "event_count": 10,
                },
                {
                    "src": "b",
                    "dst": "a",
                    "carrier": protocol,
                    "event_count": 10,
                },
            ]
        )
    first = protocol_expansion_curves(nodes, edges)
    second = protocol_expansion_curves(nodes, list(reversed(edges)))
    assert first == second
    assert {row["scenario"] for row in first} == {
        "optimistic",
        "central",
        "conservative",
    }
    final = {
        (row["protocol"], row["scenario"]): row["reachable_pairs"]
        for row in first
        if row["added_nodes"] == 1
    }
    for protocol in PROTOCOLS:
        assert final[(protocol, "optimistic")] >= final[(protocol, "central")]
        assert final[(protocol, "central")] >= final[(protocol, "conservative")]


def _reference_replay_fixture() -> tuple[dict[str, object], list[str], list[dict[str, object]]]:
    nodes = ["a", "b", "c", "d"]
    edges: list[dict[str, object]] = [
        {"src": "a", "dst": "b", "carrier": "hyperlane", "event_count": 10},
        {"src": "b", "dst": "c", "carrier": "layerzero", "event_count": 9},
    ]
    edges.extend(
        {"src": "d", "dst": "d", "carrier": protocol, "event_count": 1}
        for protocol in PROTOCOLS
        if protocol not in {"hyperlane", "layerzero"}
    )
    model = GatewayReachability(nodes, edges)
    all_compatible = model.reachable_pairs(model.closure(set(nodes)))
    document: dict[str, object] = {
        "gateway_placement": greedy_gateway_placement(model, all_compatible_pairs=all_compatible),
        "protocol_expansion": protocol_expansion_curves(nodes, edges),
    }
    return document, nodes, edges


def test_reference_replay_recomputes_candidate_gains_and_protocol_prefixes() -> None:
    document, nodes, edges = _reference_replay_fixture()
    result = _validate_gateway_reference_replay(document=document, nodes=nodes, edges=edges)
    assert result["valid"] is True
    assert result["candidate_row_count"] > 0
    assert result["protocol_prefix_row_count"] == len(document["protocol_expansion"])


def test_reference_replay_rejects_self_consistent_candidate_gain_tamper() -> None:
    document, nodes, edges = _reference_replay_fixture()
    placement = document["gateway_placement"]
    assert isinstance(placement, dict)
    rounds = placement["rounds"]
    assert isinstance(rounds, list)
    candidate = rounds[1]["candidate_gains"][0]
    candidate["marginal_pair_gain"] += 1
    with pytest.raises(LocalTopologyError, match="candidate gain"):
        _validate_gateway_reference_replay(document=document, nodes=nodes, edges=edges)


def test_reference_replay_rejects_protocol_prefix_tamper() -> None:
    document, nodes, edges = _reference_replay_fixture()
    curves = document["protocol_expansion"]
    assert isinstance(curves, list)
    curves[-1]["reachable_pairs"] += 1
    with pytest.raises(LocalTopologyError, match="protocol expansion curve"):
        _validate_gateway_reference_replay(document=document, nodes=nodes, edges=edges)


def test_xir_deployment_gas_keeps_contract_and_initialization_costs_separate(
    tmp_path: Path,
) -> None:
    receipts = [
        {
            "role": "a",
            "chain_id": 31_337,
            "action": "deploy:Gateway",
            "action_id": "deploy-gateway-a",
            "nonce": 0,
            "transaction_hash": "0x" + "11" * 32,
            "raw_sha256": "22" * 32,
            "target_or_created_address": "0x" + "33" * 20,
            "calldata_sha256": "44" * 32,
            "status": 1,
            "gas_used": 101,
            "block_number": 1,
            "block_timestamp_utc_seconds": 1_700_000_000,
            "receipt_sha256": "55" * 32,
            "runtime_code_sha256": "66" * 32,
            "compiled_artifact_sha256": "77" * 32,
            "cost_classification": "xir_only_contract_deployment",
        },
        {
            "role": "a",
            "chain_id": 31_337,
            "action": "configure:profile",
            "action_id": "configure-profile-a",
            "nonce": 1,
            "transaction_hash": "0x" + "88" * 32,
            "raw_sha256": "99" * 32,
            "target_or_created_address": "0x" + "33" * 20,
            "calldata_sha256": "aa" * 32,
            "status": 1,
            "gas_used": 29,
            "block_number": 2,
            "block_timestamp_utc_seconds": 1_700_000_001,
            "receipt_sha256": "bb" * 32,
            "runtime_code_sha256": "66" * 32,
            "compiled_artifact_sha256": None,
            "cost_classification": "xir_profile_root_peer_binding_initialization",
        },
    ]
    deployment = tmp_path / "deployment.json"
    deployment.write_text(
        json.dumps(
            {
                "namespace": "native-multihop-switching-v1",
                "deployment_gas": {
                    "gas_used": 130,
                    "transaction_count": 2,
                    "scope": "experiment_route_isolation_total_not_single_gateway_cost",
                    "reused_native_carrier_gas_included": False,
                    "classified_totals": [
                        {
                            "classification": "xir_only_contract_deployment",
                            "transaction_count": 1,
                            "gas_used": 101,
                        },
                        {
                            "classification": "xir_profile_root_peer_binding_initialization",
                            "transaction_count": 1,
                            "gas_used": 29,
                        },
                    ],
                    "component_unit_observations": [],
                    "receipts": receipts,
                },
            }
        ),
        encoding="utf-8",
    )
    result = _measured_deployment_gas(
        multihop_deployment_path=deployment,
        hyperlane_evidence_path=None,
        layerzero_evidence_path=None,
    )
    assert result["xir"]["xir_only_contract_deployment_gas"] == 101
    assert result["xir"]["profile_root_peer_binding_initialization_gas"] == 29
    assert result["xir"]["reused_native_carrier_gas_included"] is False


def test_component_table_has_all_six_non_monetized_obligation_classes() -> None:
    rows = component_obligations()
    expected_classes = {
        "on_chain_contracts",
        "verification_network_roles",
        "relayer_executor_roles",
        "peer_configuration_operations",
        "heterogeneous_vm_engineering",
        "ongoing_operations",
    }
    assert len(rows) == 7 * len(expected_classes)
    for approach in {str(row["approach"]) for row in rows}:
        selected = [row for row in rows if row["approach"] == approach]
        assert {row["component_class"] for row in selected} == expected_classes
        assert all(
            {
                "incremental",
                "reusable",
                "chain_specific",
                "off_chain",
                "measured",
                "evidence_kind",
                "monetized",
            }.issubset(row)
            for row in selected
        )
        assert all(row["monetized"] is False for row in selected)


def test_gateway_publication_rebuilds_are_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair_rows = [
        {
            "source": f"s{index // 285}",
            "destination": f"d{index}",
            "baseline_reachable": index < 46_187,
            "terminal_reachable": index < 46_187,
            "newly_enabled_by_gateway": False,
            "route_state_path": "hyperlane:s>hyperlane:d" if index < 46_187 else None,
            "carrier_sequence": "hyperlane" if index < 46_187 else None,
            "gateway_switch_nodes": "" if index < 46_187 else None,
            "native_hop_count": 1 if index < 46_187 else None,
            "switch_count": 0 if index < 46_187 else None,
        }
        for index in range(81_510)
    ]
    curves = [
        {
            "protocol": protocol,
            "scenario": scenario,
            "added_nodes": 0,
            "reachable_pairs": reachable,
            "reachability_rate": reachable / 81_510,
            "added_node_order_sha256": "11" * 32,
            "original_coverage_sha256": "22" * 32,
            "added_node_prefix_json": "[]",
            "last_added_node": None,
        }
        for protocol in PROTOCOLS
        for scenario, reachable in (
            ("optimistic", 100),
            ("central", 90),
            ("conservative", 80),
        )
    ]
    placement = {
        "rounds": [
            {
                "step": 0,
                "selected_node": None,
                "reachable_pairs": 46_187,
                "reachability_rate": 46_187 / 81_510,
                "candidate_gains": [],
            }
        ],
        "selected_nodes": [],
        "terminal_k": 0,
        "terminal_pairs": 46_187,
        "pair_evidence": pair_rows,
    }
    document = {
        "schema_version": "xir-lab-gateway-deployment-analysis-v1",
        "claim_boundary": "structural_upper_bound_not_observed_xir_delivery",
        "source_sha256": {},
        "frozen": {
            "node_count": 286,
            "protocol_edge_count": 15_965,
            "ordered_pair_denominator": 81_510,
            "homogeneous_pairs": 46_187,
            "all_compatible_pairs": 78_953,
        },
        "gateway_placement": placement,
        "protocol_expansion": curves,
        "independent_replay": {
            "valid": True,
            "semantic_sha256": "33" * 32,
        },
        "component_obligations": [],
        "measured_deployment_gas": {},
        "public_protocol_deployment_gas": [
            {
                "protocol": protocol,
                "gas": None,
                "status": "not_observed",
                "provenance": None,
            }
            for protocol in PROTOCOLS
        ],
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.setattr(
        "xir_lab.native.gateway_deployment.load_frozen_connectivity",
        lambda **_: (["unused"], [], document["frozen"]),
    )
    monkeypatch.setattr(
        "xir_lab.native.gateway_deployment._validate_gateway_reference_replay",
        lambda **_: document["independent_replay"],
    )
    source = tmp_path / "source.json"
    source.write_text("{}\n", encoding="utf-8")
    publish_gateway_deployment_document(
        document=document,
        output_root=first,
        topology_path=source,
        mainnet_path=source,
        semantic_path=source,
        multihop_deployment_path=source,
        hyperlane_evidence_path=source,
        layerzero_evidence_path=source,
    )
    publish_gateway_deployment_document(
        document=document,
        output_root=second,
        topology_path=source,
        mainnet_path=source,
        semantic_path=source,
        multihop_deployment_path=source,
        hyperlane_evidence_path=source,
        layerzero_evidence_path=source,
    )
    comparison = compare_gateway_publications(
        publication_a=first,
        publication_b=second,
        output_path=tmp_path / "comparison.json",
    )
    assert comparison["valid"] is True
    assert json.loads((first / "validation.json").read_text())["valid"] is True
    assert {path.name for path in (first / "provenance").iterdir() if path.is_file()} == {
        "topology.json",
        "mainnet-only.json",
        "semantic-aggregates.json",
        "multihop-deployment.json",
        "hyperlane-deployment-evidence.json",
        "layerzero-deployment-evidence.json",
    }
    tampered = json.loads((first / "analysis.json").read_text(encoding="utf-8"))
    tampered["gateway_placement"]["terminal_k"] += 1
    unsigned = dict(tampered)
    unsigned.pop("semantic_sha256")
    tampered["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest()
    (first / "analysis.json").write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(LocalTopologyError, match="replay|selected-node|semantic"):
        compare_gateway_publications(
            publication_a=first,
            publication_b=second,
            output_path=tmp_path / "tampered-comparison.json",
        )
