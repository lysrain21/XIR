"""Frozen-graph compatible-Gateway placement and protocol counterfactuals."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import tempfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, cast

import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_freeze_v2 import secret_scan

PROTOCOLS = ("axelar", "ccip", "hyperlane", "layerzero", "relay", "wormhole")
EXPECTED_INPUTS = {
    "topology.json": "37de12d3a6d01a23efd16c3b2fda75f8c9d54e92cb85be6236b55c2640a0bb2b",
    "mainnet-only.json": "050cb2d1229a76e86ba860d642cbb10da9b1eb31846ff88c868018ecde8c0eb2",
    "semantic-aggregates.json": "d591aea76ee6e4251081bf9c8b9ceb236c24e12f2ad00bff17609c47008a4c3a",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_frozen_connectivity(
    *, topology_path: Path, mainnet_path: Path, semantic_path: Path
) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
    for path in (topology_path, mainnet_path, semantic_path):
        expected = EXPECTED_INPUTS[path.name]
        if _sha256(path) != expected:
            raise LocalTopologyError(f"frozen connectivity digest drift: {path.name}")
    topology = cast(dict[str, Any], json.loads(topology_path.read_text(encoding="utf-8")))
    mainnet = cast(dict[str, Any], json.loads(mainnet_path.read_text(encoding="utf-8")))
    semantic = cast(dict[str, Any], json.loads(semantic_path.read_text(encoding="utf-8")))
    nodes = sorted(cast(list[str], topology["nodes"]))
    edges = cast(list[dict[str, Any]], topology["edges"])
    metrics = cast(dict[str, Any], mainnet["cumulative_reference"]["metrics"])
    frozen = {
        "node_count": len(nodes),
        "protocol_edge_count": len(edges),
        "ordered_pair_denominator": len(nodes) * (len(nodes) - 1),
        "direct_pairs": metrics["strategy"]["direct"]["reachable_pairs"],
        "homogeneous_pairs": metrics["strategy"]["homogeneous"]["reachable_pairs"],
        "all_compatible_pairs": metrics["strategy"]["carrier_switching"]["reachable_pairs"],
        "all_compatible_rate": metrics["strategy"]["carrier_switching"]["reachability_rate"],
        "semantic_protocol_edges": semantic["daily_metadata"]["cumulative_protocol_edge_keys"],
    }
    if frozen != {
        "node_count": 286,
        "protocol_edge_count": 15965,
        "ordered_pair_denominator": 81510,
        "direct_pairs": 11935,
        "homogeneous_pairs": 46187,
        "all_compatible_pairs": 78953,
        "all_compatible_rate": 0.9686296159980371,
        "semantic_protocol_edges": 15965,
    }:
        raise LocalTopologyError("frozen connectivity cardinalities changed")
    if any(
        edge["src"] not in set(nodes)
        or edge["dst"] not in set(nodes)
        or edge["carrier"] not in PROTOCOLS
        for edge in edges
    ):
        raise LocalTopologyError("frozen connectivity edge is outside admitted universe")
    return nodes, edges, frozen


class GatewayReachability:
    """Bitset transitive closure over (carrier, network) states."""

    def __init__(self, nodes: list[str], edges: list[dict[str, Any]]) -> None:
        self.nodes = tuple(nodes)
        self.node_index = {node: index for index, node in enumerate(nodes)}
        self.node_count = len(nodes)
        self.state_count = self.node_count * len(PROTOCOLS)
        adjacency: list[list[int]] = [[] for _ in range(self.state_count)]
        for edge in edges:
            protocol = PROTOCOLS.index(str(edge["carrier"]))
            source = protocol * self.node_count + self.node_index[str(edge["src"])]
            destination = protocol * self.node_count + self.node_index[str(edge["dst"])]
            adjacency[source].append(destination)
        self.native_adjacency = tuple(
            tuple(sorted(set(destinations))) for destinations in adjacency
        )
        self.base_closure = [0] * self.state_count
        for source in range(self.state_count):
            visited = 1 << source
            queue = deque([source])
            while queue:
                current = queue.popleft()
                for destination in self.native_adjacency[current]:
                    bit = 1 << destination
                    if visited & bit:
                        continue
                    visited |= bit
                    queue.append(destination)
            self.base_closure[source] = visited
        self.network_mask = (1 << self.node_count) - 1

    def add_gateway(self, closure: list[int], node_index: int) -> bool:
        """Relax one compatible-Gateway clique and report whether closure grew."""

        state_mask = 0
        successor_union = 0
        for protocol in range(len(PROTOCOLS)):
            state = protocol * self.node_count + node_index
            state_mask |= 1 << state
            successor_union |= closure[state]
        changed = False
        for source, reachable in enumerate(closure):
            if reachable & state_mask:
                updated = reachable | successor_union
                if updated != reachable:
                    closure[source] = updated
                    changed = True
        return changed

    def _close_gateways(self, closure: list[int], gateway_indices: tuple[int, ...]) -> None:
        """Reach a fixed point across all selected Gateway switching cliques."""

        changed = True
        while changed:
            changed = False
            for node_index in gateway_indices:
                changed = self.add_gateway(closure, node_index) or changed

    def closure(self, gateways: set[str]) -> list[int]:
        closure = self.base_closure.copy()
        gateway_indices = tuple(self.node_index[node] for node in sorted(gateways))
        self._close_gateways(closure, gateway_indices)
        return closure

    def reachable_pairs(self, closure: list[int]) -> int:
        total = 0
        for node in range(self.node_count):
            states = 0
            for protocol in range(len(PROTOCOLS)):
                states |= closure[protocol * self.node_count + node]
            networks = 0
            for protocol in range(len(PROTOCOLS)):
                networks |= (states >> (protocol * self.node_count)) & self.network_mask
            total += networks.bit_count() - 1
        return total

    def _expanded_adjacency(self, gateways: set[str]) -> tuple[tuple[tuple[int, str], ...], ...]:
        gateway_indices = {self.node_index[node] for node in gateways}
        rows: list[list[tuple[int, str]]] = [
            [(destination, "native_hop") for destination in destinations]
            for destinations in self.native_adjacency
        ]
        for node_index in sorted(gateway_indices):
            states = [protocol * self.node_count + node_index for protocol in range(len(PROTOCOLS))]
            for source in states:
                rows[source].extend(
                    (destination, "gateway_switch")
                    for destination in states
                    if destination != source
                )
        return tuple(tuple(sorted(set(row), key=lambda edge: (edge[0], edge[1]))) for row in rows)

    def _source_witnesses(
        self,
        source_index: int,
        adjacency: tuple[tuple[tuple[int, str], ...], ...],
    ) -> dict[int, dict[str, Any]]:
        roots = [protocol * self.node_count + source_index for protocol in range(len(PROTOCOLS))]
        parent: dict[int, tuple[int | None, str | None]] = {state: (None, None) for state in roots}
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for destination, edge_kind in adjacency[current]:
                if destination in parent:
                    continue
                parent[destination] = (current, edge_kind)
                queue.append(destination)

        witnesses: dict[int, dict[str, Any]] = {}
        for destination_state in parent:
            destination_index = destination_state % self.node_count
            if destination_index in witnesses:
                continue
            reversed_states: list[int] = []
            reversed_kinds: list[str] = []
            cursor: int | None = destination_state
            while cursor is not None:
                reversed_states.append(cursor)
                previous, parent_edge_kind = parent[cursor]
                if parent_edge_kind is not None:
                    reversed_kinds.append(parent_edge_kind)
                cursor = previous
            states = list(reversed(reversed_states))
            edge_kinds = list(reversed(reversed_kinds))
            switch_nodes = [
                self.nodes[states[index] % self.node_count]
                for index, kind in enumerate(edge_kinds)
                if kind == "gateway_switch"
            ]
            carrier_sequence: list[str] = []
            for state in states:
                carrier = PROTOCOLS[state // self.node_count]
                if not carrier_sequence or carrier_sequence[-1] != carrier:
                    carrier_sequence.append(carrier)
            witnesses[destination_index] = {
                "route_state_path": ">".join(
                    f"{PROTOCOLS[state // self.node_count]}:{self.nodes[state % self.node_count]}"
                    for state in states
                ),
                "carrier_sequence": ">".join(carrier_sequence),
                "gateway_switch_nodes": ">".join(switch_nodes),
                "native_hop_count": edge_kinds.count("native_hop"),
                "switch_count": edge_kinds.count("gateway_switch"),
            }
        return witnesses

    def pair_evidence(self, closure: list[int], *, gateways: set[str]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        adjacency = self._expanded_adjacency(gateways)
        for source_index, source in enumerate(self.nodes):
            states = 0
            for protocol in range(len(PROTOCOLS)):
                states |= closure[protocol * self.node_count + source_index]
            networks = 0
            for protocol in range(len(PROTOCOLS)):
                networks |= (states >> (protocol * self.node_count)) & self.network_mask
            baseline_states = 0
            for protocol in range(len(PROTOCOLS)):
                baseline_states |= self.base_closure[protocol * self.node_count + source_index]
            baseline_networks = 0
            for protocol in range(len(PROTOCOLS)):
                baseline_networks |= (
                    baseline_states >> (protocol * self.node_count)
                ) & self.network_mask
            witnesses = self._source_witnesses(source_index, adjacency)
            for destination_index, destination in enumerate(self.nodes):
                if source_index != destination_index:
                    baseline_reachable = bool(baseline_networks & (1 << destination_index))
                    reachable = bool(networks & (1 << destination_index))
                    if reachable != (destination_index in witnesses):
                        raise LocalTopologyError("bitset closure and route witness disagree")
                    witness = witnesses.get(destination_index, {}) if reachable else {}
                    rows.append(
                        {
                            "source": source,
                            "destination": destination,
                            "baseline_reachable": baseline_reachable,
                            "terminal_reachable": reachable,
                            "newly_enabled_by_gateway": reachable and not baseline_reachable,
                            "route_state_path": witness.get("route_state_path"),
                            "carrier_sequence": witness.get("carrier_sequence"),
                            "gateway_switch_nodes": witness.get("gateway_switch_nodes"),
                            "native_hop_count": witness.get("native_hop_count"),
                            "switch_count": witness.get("switch_count"),
                        }
                    )
        return rows


def greedy_gateway_placement(
    model: GatewayReachability, *, all_compatible_pairs: int
) -> dict[str, Any]:
    closure = model.base_closure.copy()
    current = model.reachable_pairs(closure)
    selected: set[str] = set()
    rounds: list[dict[str, Any]] = [
        {
            "step": 0,
            "selected_node": None,
            "reachable_pairs": current,
            "reachability_rate": current / (model.node_count * (model.node_count - 1)),
            "candidate_gains": [],
        }
    ]
    while current < all_compatible_pairs:
        candidates: list[tuple[int, str, int, list[int]]] = []
        for node in model.nodes:
            if node in selected:
                continue
            candidate_closure = closure.copy()
            candidate_gateway_indices = tuple(
                model.node_index[selected_node] for selected_node in sorted(selected | {node})
            )
            model._close_gateways(candidate_closure, candidate_gateway_indices)
            candidate_pairs = model.reachable_pairs(candidate_closure)
            candidates.append((candidate_pairs - current, node, candidate_pairs, candidate_closure))
        candidates.sort(key=lambda row: (-row[0], row[1]))
        if not candidates:
            break
        best_gain, best_node, best_pairs, best_closure = candidates[0]
        candidate_rows = [
            {"node": node, "marginal_pair_gain": gain, "reachable_pairs": pairs}
            for gain, node, pairs, _ in sorted(candidates, key=lambda row: row[1])
        ]
        round_document: dict[str, Any] = {
            "step": len(selected) + 1,
            "selected_node": best_node if best_gain > 0 else None,
            "tie_break": best_node if best_gain > 0 else None,
            "marginal_pair_gain": best_gain,
            "reachable_pairs": best_pairs if best_gain > 0 else current,
            "reachability_rate": (best_pairs if best_gain > 0 else current)
            / (model.node_count * (model.node_count - 1)),
            "candidate_gains": candidate_rows,
        }
        round_document["round_sha256"] = hashlib.sha256(rfc8785.dumps(round_document)).hexdigest()
        rounds.append(round_document)
        if best_gain <= 0:
            break
        selected.add(best_node)
        closure = best_closure
        current = best_pairs
    return {
        "rounds": rounds,
        "selected_nodes": sorted(selected),
        "terminal_k": len(selected),
        "terminal_pairs": current,
        "terminal_rate": current / (model.node_count * (model.node_count - 1)),
        "equals_all_compatible": current == all_compatible_pairs,
        "terminal_reason": (
            "all_compatible_reached"
            if current == all_compatible_pairs
            else "no_positive_marginal_gain"
        ),
        "pair_evidence": model.pair_evidence(closure, gateways=selected),
    }


def _protocol_closure(
    nodes: list[str], edges: set[tuple[str, str]]
) -> tuple[dict[str, int], list[int]]:
    indices = {node: index for index, node in enumerate(nodes)}
    adjacency: list[list[int]] = [[] for _ in nodes]
    for source, destination in edges:
        adjacency[indices[source]].append(indices[destination])
    closure: list[int] = []
    for source_index in range(len(nodes)):
        reachable = 1 << source_index
        queue = deque([source_index])
        while queue:
            current = queue.popleft()
            for destination_index in adjacency[current]:
                bit = 1 << destination_index
                if reachable & bit:
                    continue
                reachable |= bit
                queue.append(destination_index)
        closure.append(reachable)
    return indices, closure


def _add_protocol_edge(closure: list[int], source: int, destination: int) -> None:
    if closure[source] & (1 << destination):
        return
    successors = closure[destination]
    source_bit = 1 << source
    for origin, reachable in enumerate(closure):
        if reachable & source_bit:
            closure[origin] = reachable | successors


def _closure_pairs(closure: list[int]) -> int:
    return sum(reachable.bit_count() - 1 for reachable in closure)


def _reference_gateway_pairs(
    nodes: list[str], edges: list[dict[str, Any]], gateways: set[str]
) -> int:
    """Independent explicit-state BFS oracle; it does not use bitset closure code."""

    adjacency: dict[tuple[str, str], set[tuple[str, str]]] = {
        (protocol, node): set() for protocol in PROTOCOLS for node in nodes
    }
    for edge in edges:
        carrier = str(edge["carrier"])
        adjacency[(carrier, str(edge["src"]))].add((carrier, str(edge["dst"])))
    for node in gateways:
        for source_protocol in PROTOCOLS:
            adjacency[(source_protocol, node)].update(
                (destination_protocol, node)
                for destination_protocol in PROTOCOLS
                if destination_protocol != source_protocol
            )
    total = 0
    for source in nodes:
        visited = {(protocol, source) for protocol in PROTOCOLS}
        queue = deque(sorted(visited))
        while queue:
            current = queue.popleft()
            for destination in sorted(adjacency[current]):
                if destination not in visited:
                    visited.add(destination)
                    queue.append(destination)
        total += len({node for _, node in visited}) - 1
    return total


def _reference_protocol_pairs(nodes: list[str], edges: set[tuple[str, str]]) -> int:
    """Independent node-level BFS oracle for one protocol expansion prefix."""

    adjacency: dict[str, set[str]] = {node: set() for node in nodes}
    for source, destination in edges:
        adjacency[source].add(destination)
    total = 0
    for source in nodes:
        visited = {source}
        queue = deque([source])
        while queue:
            current = queue.popleft()
            for destination in sorted(adjacency[current]):
                if destination not in visited:
                    visited.add(destination)
                    queue.append(destination)
        total += len(visited) - 1
    return total


def _reference_carrier_reachability(
    nodes: list[str], edges: list[dict[str, Any]]
) -> dict[str, dict[str, frozenset[str]]]:
    """Build a plain-set reachability oracle without production bitsets."""

    result: dict[str, dict[str, frozenset[str]]] = {}
    for protocol in PROTOCOLS:
        adjacency: dict[str, set[str]] = {node: set() for node in nodes}
        for edge in edges:
            if str(edge["carrier"]) == protocol:
                adjacency[str(edge["src"])].add(str(edge["dst"]))
        protocol_rows: dict[str, frozenset[str]] = {}
        for source in nodes:
            visited = {source}
            queue = deque([source])
            while queue:
                current = queue.popleft()
                for destination in sorted(adjacency[current]):
                    if destination not in visited:
                        visited.add(destination)
                        queue.append(destination)
            protocol_rows[source] = frozenset(visited)
        result[protocol] = protocol_rows
    return result


def _reference_gateway_pair_set(
    nodes: list[str],
    carrier_reachability: dict[str, dict[str, frozenset[str]]],
    gateways: set[str],
) -> set[tuple[str, str]]:
    """Reference Gateway closure by carrier seed propagation over plain sets."""

    pairs: set[tuple[str, str]] = set()
    for source in nodes:
        reached = {protocol: set(carrier_reachability[protocol][source]) for protocol in PROTOCOLS}
        changed = True
        while changed:
            changed = False
            for gateway in sorted(gateways):
                if not any(gateway in reached[protocol] for protocol in PROTOCOLS):
                    continue
                for protocol in PROTOCOLS:
                    updated = reached[protocol] | set(carrier_reachability[protocol][gateway])
                    if updated != reached[protocol]:
                        reached[protocol] = updated
                        changed = True
        destinations = set().union(*(reached[protocol] for protocol in PROTOCOLS))
        pairs.update((source, destination) for destination in destinations if destination != source)
    return pairs


def _reference_protocol_curve_counts(
    nodes: list[str], edges: list[dict[str, Any]]
) -> dict[tuple[str, str, int], int]:
    """Closed-form prefix oracle derived from a plain BFS of each frozen protocol."""

    activity: dict[str, int] = defaultdict(int)
    for edge in edges:
        activity[str(edge["src"])] += int(edge.get("event_count", 0))
        activity[str(edge["dst"])] += int(edge.get("event_count", 0))
    expected: dict[tuple[str, str, int], int] = {}
    for protocol in PROTOCOLS:
        original_edges = {
            (str(edge["src"]), str(edge["dst"]))
            for edge in edges
            if str(edge["carrier"]) == protocol
        }
        covered = {node for edge in original_edges for node in edge}
        order = sorted(set(nodes) - covered, key=lambda node: (-activity[node], node))
        component = _largest_scc(covered, original_edges)
        anchor = min(component, key=lambda node: (-activity[node], node))
        adjacency: dict[str, set[str]] = {node: set() for node in nodes}
        reverse: dict[str, set[str]] = {node: set() for node in nodes}
        for source, destination in original_edges:
            adjacency[source].add(destination)
            reverse[destination].add(source)

        def visit(graph: dict[str, set[str]], source: str) -> set[str]:
            reached = {source}
            queue = deque([source])
            while queue:
                current = queue.popleft()
                for destination in sorted(graph[current]):
                    if destination not in reached:
                        reached.add(destination)
                        queue.append(destination)
            return reached

        base_pairs = _reference_protocol_pairs(nodes, original_edges)
        reaches_anchor = len(visit(reverse, anchor))
        reachable_from_anchor = len(visit(adjacency, anchor))
        for step in range(len(order) + 1):
            joined_pairs = (
                base_pairs
                + step * reaches_anchor
                + step * reachable_from_anchor
                + step * (step - 1)
            )
            conservative_pairs = base_pairs + step * reachable_from_anchor
            expected[(protocol, "optimistic", step)] = joined_pairs
            expected[(protocol, "central", step)] = joined_pairs
            expected[(protocol, "conservative", step)] = conservative_pairs
    return expected


def _validate_reference_route_witness(
    *,
    row: dict[str, Any],
    native_edges: set[tuple[str, str, str]],
    gateways: set[str],
) -> None:
    path = str(row.get("route_state_path") or "")
    states = [tuple(value.split(":", 1)) for value in path.split(">") if value]
    if not states or states[0][1] != str(row["source"]) or states[-1][1] != str(row["destination"]):
        raise LocalTopologyError("Gateway route witness endpoints are invalid")
    switch_nodes: list[str] = []
    native_hops = 0
    carrier_sequence: list[str] = []
    for carrier, _ in states:
        if carrier not in PROTOCOLS:
            raise LocalTopologyError("Gateway route witness carrier is invalid")
        if not carrier_sequence or carrier_sequence[-1] != carrier:
            carrier_sequence.append(carrier)
    for (carrier_a, node_a), (carrier_b, node_b) in zip(states, states[1:], strict=False):
        if carrier_a == carrier_b:
            if (carrier_a, node_a, node_b) not in native_edges:
                raise LocalTopologyError("Gateway route witness uses a missing native edge")
            native_hops += 1
        elif node_a == node_b and node_a in gateways:
            switch_nodes.append(node_a)
        else:
            raise LocalTopologyError("Gateway route witness uses an unauthorized switch")
    if (
        int(row.get("native_hop_count", -1)) != native_hops
        or int(row.get("switch_count", -1)) != len(switch_nodes)
        or str(row.get("gateway_switch_nodes") or "") != ">".join(switch_nodes)
        or str(row.get("carrier_sequence") or "") != ">".join(carrier_sequence)
    ):
        raise LocalTopologyError("Gateway route witness accounting is invalid")


def _validate_gateway_reference_replay(
    *,
    document: dict[str, Any],
    nodes: list[str],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Recompute every reported graph row with algorithms separate from production."""

    placement = cast(dict[str, Any], document["gateway_placement"])
    rounds = cast(list[dict[str, Any]], placement["rounds"])
    carrier_reachability = _reference_carrier_reachability(nodes, edges)
    baseline_pairs = _reference_gateway_pair_set(nodes, carrier_reachability, set())
    if int(rounds[0]["reachable_pairs"]) != len(baseline_pairs):
        raise LocalTopologyError("Gateway round zero differs from reference BFS")
    selected: set[str] = set()
    candidate_row_count = 0
    for row in rounds[1:]:
        candidates = cast(list[dict[str, Any]], row["candidate_gains"])
        candidate_map = {str(candidate["node"]): candidate for candidate in candidates}
        expected_nodes = set(nodes) - selected
        if set(candidate_map) != expected_nodes:
            raise LocalTopologyError("Gateway reference candidate universe is incomplete")
        current_pairs = _reference_gateway_pair_set(nodes, carrier_reachability, selected)
        reference_rows: list[tuple[int, str, int]] = []
        for node in sorted(expected_nodes):
            pairs = _reference_gateway_pair_set(nodes, carrier_reachability, selected | {node})
            pair_count = len(pairs)
            gain = pair_count - len(current_pairs)
            candidate = candidate_map[node]
            if (
                int(candidate["reachable_pairs"]) != pair_count
                or int(candidate["marginal_pair_gain"]) != gain
            ):
                raise LocalTopologyError("Gateway candidate gain differs from reference BFS")
            reference_rows.append((gain, node, pair_count))
        candidate_row_count += len(reference_rows)
        best_gain, best_node, best_pairs = min(reference_rows, key=lambda item: (-item[0], item[1]))
        expected_selected = best_node if best_gain > 0 else None
        if (
            row.get("selected_node") != expected_selected
            or int(row["marginal_pair_gain"]) != best_gain
            or int(row["reachable_pairs"]) != (best_pairs if best_gain > 0 else len(current_pairs))
        ):
            raise LocalTopologyError("Gateway selected round differs from reference BFS")
        if expected_selected is not None:
            selected.add(expected_selected)

    terminal_pairs = _reference_gateway_pair_set(nodes, carrier_reachability, selected)
    pair_rows = cast(list[dict[str, Any]], placement["pair_evidence"])
    by_pair = {(str(row["source"]), str(row["destination"])): row for row in pair_rows}
    expected_pair_universe = {
        (source, destination) for source in nodes for destination in nodes if source != destination
    }
    if set(by_pair) != expected_pair_universe:
        raise LocalTopologyError("Gateway pair evidence universe differs from frozen graph")
    native_edges = {(str(edge["carrier"]), str(edge["src"]), str(edge["dst"])) for edge in edges}
    for pair, row in by_pair.items():
        baseline = pair in baseline_pairs
        terminal = pair in terminal_pairs
        if (
            bool(row["baseline_reachable"]) != baseline
            or bool(row["terminal_reachable"]) != terminal
            or bool(row["newly_enabled_by_gateway"]) != (terminal and not baseline)
        ):
            raise LocalTopologyError("Gateway pair evidence differs from reference BFS")
        if terminal:
            _validate_reference_route_witness(row=row, native_edges=native_edges, gateways=selected)
        elif any(
            row.get(field) is not None
            for field in (
                "route_state_path",
                "carrier_sequence",
                "gateway_switch_nodes",
                "native_hop_count",
                "switch_count",
            )
        ):
            raise LocalTopologyError("unreachable Gateway pair contains a route witness")

    expected_curves = _reference_protocol_curve_counts(nodes, edges)
    curves = cast(list[dict[str, Any]], document["protocol_expansion"])
    observed_curves = {
        (str(row["protocol"]), str(row["scenario"]), int(row["added_nodes"])): int(
            row["reachable_pairs"]
        )
        for row in curves
    }
    if observed_curves != expected_curves:
        raise LocalTopologyError("protocol expansion curve differs from reference BFS")
    summary: dict[str, Any] = {
        "valid": True,
        "algorithm": "plain_set_carrier_seed_bfs_and_closed_form_prefix_oracle",
        "baseline_pair_count": len(baseline_pairs),
        "terminal_pair_count": len(terminal_pairs),
        "selected_nodes": sorted(selected),
        "candidate_row_count": candidate_row_count,
        "pair_row_count": len(pair_rows),
        "protocol_prefix_row_count": len(expected_curves),
        "terminal_pair_set_sha256": hashlib.sha256(
            rfc8785.dumps([list(pair) for pair in sorted(terminal_pairs)])
        ).hexdigest(),
        "protocol_curve_counts_sha256": hashlib.sha256(
            rfc8785.dumps(
                [
                    [protocol, scenario, step, count]
                    for (protocol, scenario, step), count in sorted(expected_curves.items())
                ]
            )
        ).hexdigest(),
    }
    summary["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(summary)).hexdigest()
    return summary


def _largest_scc(nodes: set[str], edges: set[tuple[str, str]]) -> set[str]:
    forward: dict[str, list[str]] = defaultdict(list)
    reverse: dict[str, list[str]] = defaultdict(list)
    for source, destination in edges:
        forward[source].append(destination)
        reverse[destination].append(source)
    order: list[str] = []
    visited: set[str] = set()
    for origin in sorted(nodes):
        if origin in visited:
            continue
        stack: list[tuple[str, bool]] = [(origin, False)]
        while stack:
            current, exiting = stack.pop()
            if exiting:
                order.append(current)
                continue
            if current in visited:
                continue
            visited.add(current)
            stack.append((current, True))
            stack.extend(
                (neighbor, False) for neighbor in forward[current] if neighbor not in visited
            )
    components: list[set[str]] = []
    visited.clear()
    for origin in reversed(order):
        if origin in visited:
            continue
        component: set[str] = set()
        queue = [origin]
        visited.add(origin)
        while queue:
            current = queue.pop()
            component.add(current)
            for neighbor in reverse[current]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        components.append(component)
    return min(
        (component for component in components if component),
        key=lambda component: (-len(component), sorted(component)[0]),
    )


def protocol_expansion_curves(
    nodes: list[str], edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    activity: dict[str, int] = defaultdict(int)
    for edge in edges:
        activity[str(edge["src"])] += int(edge.get("event_count", 0))
        activity[str(edge["dst"])] += int(edge.get("event_count", 0))
    rows: list[dict[str, Any]] = []
    denominator = len(nodes) * (len(nodes) - 1)
    for protocol in PROTOCOLS:
        original_edges = {
            (str(edge["src"]), str(edge["dst"])) for edge in edges if edge["carrier"] == protocol
        }
        covered = {node for edge in original_edges for node in edge}
        order = sorted(set(nodes) - covered, key=lambda node: (-activity[node], node))
        component = _largest_scc(covered, original_edges)
        anchor = min(component, key=lambda node: (-activity[node], node))
        coverage_json = json.dumps(sorted(covered), separators=(",", ":"))
        coverage_sha256 = hashlib.sha256(rfc8785.dumps(sorted(covered))).hexdigest()
        order_sha256 = hashlib.sha256(rfc8785.dumps(order)).hexdigest()
        for scenario in ("optimistic", "central", "conservative"):
            indices, closure = _protocol_closure(nodes, original_edges)
            for step in range(len(order) + 1):
                pairs = _closure_pairs(closure)
                rows.append(
                    {
                        "protocol": protocol,
                        "scenario": scenario,
                        "counterfactual": True,
                        "original_coverage": len(covered),
                        "original_coverage_nodes_json": coverage_json,
                        "original_coverage_sha256": coverage_sha256,
                        "added_node_order_sha256": order_sha256,
                        "added_node_prefix_json": json.dumps(order[:step], separators=(",", ":")),
                        "added_nodes": step,
                        "last_added_node": None if step == 0 else order[step - 1],
                        "attachment_anchor": anchor,
                        "attachment_rule": {
                            "optimistic": "bidirectional_to_every_original_largest_scc_member",
                            "central": "bidirectional_to_highest_activity_original_scc_anchor",
                            "conservative": "new_endpoint_outbound_only_to_anchor",
                        }[scenario],
                        "reachable_pairs": pairs,
                        "reachability_rate": pairs / denominator,
                    }
                )
                if step == len(order):
                    continue
                node = order[step]
                if scenario == "optimistic":
                    for member in component:
                        _add_protocol_edge(closure, indices[node], indices[member])
                        _add_protocol_edge(closure, indices[member], indices[node])
                elif scenario == "central":
                    _add_protocol_edge(closure, indices[node], indices[anchor])
                    _add_protocol_edge(closure, indices[anchor], indices[node])
                else:
                    _add_protocol_edge(closure, indices[node], indices[anchor])
    return rows


def component_obligations() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    definitions = {
        "xir": {
            "on_chain_contracts": "Gateway + Registry + selected-carrier adapters + application receiver",
            "verification_network_roles": "reuse each selected carrier's existing verification network",
            "relayer_executor_roles": "reuse each selected carrier's existing relayer/executor path",
            "peer_configuration_operations": "root, profile, remote-peer, options, and approved-prior-ingress bindings",
            "heterogeneous_vm_engineering": "port Gateway/Registry/adapter/receiver contracts to each admitted VM",
            "ongoing_operations": "monitor XIR bindings plus reused carrier services",
        },
        "axelar": {
            "on_chain_contracts": "gateway and endpoint contracts",
            "verification_network_roles": "validator set integration",
            "relayer_executor_roles": "gateway relaying services",
            "peer_configuration_operations": "chain registration and gateway configuration",
            "heterogeneous_vm_engineering": "protocol endpoint port and audit for the target VM",
            "ongoing_operations": "validator, relayer, upgrade, and chain-support operations",
        },
        "ccip": {
            "on_chain_contracts": "router, on-ramp, and off-ramp contracts",
            "verification_network_roles": "decentralized oracle network integration",
            "relayer_executor_roles": "execution and risk-management services",
            "peer_configuration_operations": "lane and token-pool configuration",
            "heterogeneous_vm_engineering": "protocol endpoint port and audit for the target VM",
            "ongoing_operations": "DON, execution, risk, upgrade, and chain-support operations",
        },
        "hyperlane": {
            "on_chain_contracts": "Mailbox, hooks, and ISM contracts",
            "verification_network_roles": "validator and ISM configuration",
            "relayer_executor_roles": "relayer service",
            "peer_configuration_operations": "domain, mailbox, hook, and ISM enrollment",
            "heterogeneous_vm_engineering": "Mailbox and ISM port and audit for the target VM",
            "ongoing_operations": "validator, relayer, upgrade, and chain-support operations",
        },
        "layerzero": {
            "on_chain_contracts": "Endpoint and ULN library contracts",
            "verification_network_roles": "DVN configuration",
            "relayer_executor_roles": "Executor service",
            "peer_configuration_operations": "EID, peer, library, DVN, and options configuration",
            "heterogeneous_vm_engineering": "Endpoint and library port and audit for the target VM",
            "ongoing_operations": "DVN, Executor, upgrade, and chain-support operations",
        },
        "relay": {
            "on_chain_contracts": "relay endpoint contracts",
            "verification_network_roles": "relay verification roles",
            "relayer_executor_roles": "relay operator services",
            "peer_configuration_operations": "network and endpoint enrollment",
            "heterogeneous_vm_engineering": "endpoint port and audit for the target VM",
            "ongoing_operations": "relay, upgrade, and chain-support operations",
        },
        "wormhole": {
            "on_chain_contracts": "core bridge and message receiver contracts",
            "verification_network_roles": "guardian network integration",
            "relayer_executor_roles": "relayer service",
            "peer_configuration_operations": "chain, emitter, and receiver enrollment",
            "heterogeneous_vm_engineering": "core bridge port and audit for the target VM",
            "ongoing_operations": "guardian, relayer, upgrade, and chain-support operations",
        },
    }
    for approach, obligations in definitions.items():
        for component_class, obligation in obligations.items():
            reused_by_xir = approach == "xir" and component_class in {
                "verification_network_roles",
                "relayer_executor_roles",
            }
            measured = approach == "xir" and component_class in {
                "on_chain_contracts",
                "peer_configuration_operations",
            }
            rows.append(
                {
                    "approach": approach,
                    "component_class": component_class,
                    "obligation": obligation,
                    "incremental": not reused_by_xir,
                    "reusable": reused_by_xir,
                    "chain_specific": True,
                    "off_chain": component_class
                    in {
                        "verification_network_roles",
                        "relayer_executor_roles",
                        "heterogeneous_vm_engineering",
                        "ongoing_operations",
                    },
                    "measured": measured,
                    "evidence_kind": "measured_local" if measured else "qualitative_not_monetized",
                    "monetized": False,
                }
            )
    return rows


def _measured_deployment_gas(
    *,
    multihop_deployment_path: Path | None,
    hyperlane_evidence_path: Path | None,
    layerzero_evidence_path: Path | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "measurement_environment": "controlled_local_five_chain_qbft",
        "currency_conversion": "not_performed",
        "security_products_are_not_claimed_equivalent": True,
        "xir": {"status": "not_observed"},
        "hyperlane": {"status": "not_observed"},
        "layerzero": {"status": "not_observed"},
    }
    if multihop_deployment_path is not None:
        deployment = cast(
            dict[str, Any],
            json.loads(multihop_deployment_path.read_text(encoding="utf-8")),
        )
        if deployment.get("namespace") != "native-multihop-switching-v1":
            raise LocalTopologyError("deployment gas input uses another namespace")
        gas = cast(dict[str, Any], deployment["deployment_gas"])
        classified_totals = cast(list[dict[str, Any]], gas["classified_totals"])
        classification_map = {str(row["classification"]): row for row in classified_totals}
        if gas.get("reused_native_carrier_gas_included") is not False or set(
            classification_map
        ) != {
            "xir_only_contract_deployment",
            "xir_profile_root_peer_binding_initialization",
        }:
            raise LocalTopologyError("XIR deployment gas classification is incomplete")
        receipts = cast(list[dict[str, Any]], gas.get("receipts", []))
        if (
            len(receipts) != int(gas["transaction_count"])
            or sum(int(row.get("gas_used", -1)) for row in receipts) != int(gas["gas_used"])
            or any(
                str(row.get("role", "")) not in {"a", "b", "c", "d", "e"}
                or int(row.get("chain_id", -1)) <= 0
                or not str(row.get("action_id", ""))
                or int(row.get("nonce", -1)) < 0
                or len(str(row.get("transaction_hash", "")).removeprefix("0x")) != 64
                or len(str(row.get("raw_sha256", ""))) != 64
                or len(str(row.get("target_or_created_address", "")).removeprefix("0x")) != 40
                or len(str(row.get("calldata_sha256", ""))) != 64
                or int(row.get("status", 0)) != 1
                or int(row.get("gas_used", 0)) <= 0
                or int(row.get("block_number", -1)) < 0
                or int(row.get("block_timestamp_utc_seconds", 0)) <= 0
                or len(str(row.get("receipt_sha256", ""))) != 64
                or len(str(row.get("runtime_code_sha256", ""))) != 64
                or str(row.get("cost_classification", "")) not in classification_map
                or (
                    str(row.get("action", "")).startswith("deploy:")
                    and len(str(row.get("compiled_artifact_sha256", ""))) != 64
                )
                for row in receipts
            )
            or any(
                sum(
                    int(row["gas_used"])
                    for row in receipts
                    if row["cost_classification"] == classification
                )
                != int(total["gas_used"])
                or sum(row["cost_classification"] == classification for row in receipts)
                != int(total["transaction_count"])
                for classification, total in classification_map.items()
            )
        ):
            raise LocalTopologyError("XIR deployment receipt provenance is incomplete")
        result["xir"] = {
            "status": "observed_local",
            "source_sha256": _sha256(multihop_deployment_path),
            "experiment_matrix_total_gas": int(gas["gas_used"]),
            "experiment_matrix_transaction_count": int(gas["transaction_count"]),
            "scope": gas["scope"],
            "classified_totals": classified_totals,
            "xir_only_contract_deployment_gas": int(
                classification_map["xir_only_contract_deployment"]["gas_used"]
            ),
            "profile_root_peer_binding_initialization_gas": int(
                classification_map["xir_profile_root_peer_binding_initialization"]["gas_used"]
            ),
            "reused_native_carrier_gas_included": False,
            "component_unit_observations": gas["component_unit_observations"],
            "receipt_provenance": receipts,
            "single_chain_cost_not_collapsed_to_one_number": True,
        }
    for protocol, path in (
        ("hyperlane", hyperlane_evidence_path),
        ("layerzero", layerzero_evidence_path),
    ):
        if path is None:
            continue
        evidence = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        expected_schema = {
            "hyperlane": "xir-lab-multihop-hyperlane-deployment-evidence-v1",
            "layerzero": "xir-lab-layerzero-deployment-evidence-v1",
        }[protocol]
        chains = cast(list[dict[str, Any]], evidence["chains"])
        if (
            evidence.get("schema_version") != expected_schema
            or len(chains) != 5
            or (protocol == "layerzero" and evidence.get("official_chain_components") is not True)
        ):
            raise LocalTopologyError(f"{protocol} deployment-gas evidence identity is invalid")
        chain_rows: list[dict[str, Any]] = []
        for chain in chains:
            transactions = cast(
                list[dict[str, Any]],
                chain["transactions"] if protocol == "hyperlane" else chain["receipts"],
            )
            components = cast(
                list[dict[str, Any]],
                [
                    {"role": role, **value}
                    for role, value in cast(dict[str, dict[str, Any]], chain["addresses"]).items()
                ]
                if protocol == "hyperlane"
                else chain["components"],
            )
            if (
                not transactions
                or not components
                or any(
                    len(str(component.get("runtime_code_sha256", ""))) != 64
                    or not str(component.get("address", "")).startswith("0x")
                    for component in components
                )
                or any(
                    (
                        int(transaction.get("status", -1)) != 1
                        if protocol == "hyperlane"
                        else int(str(transaction.get("status", "0x0")), 16) != 1
                    )
                    for transaction in transactions
                )
            ):
                raise LocalTopologyError(
                    f"{protocol} receipt or runtime-bytecode evidence is incomplete"
                )
            gas_values = [
                int(row["gas_used"]) if "gas_used" in row else int(str(row["gasUsed"]), 16)
                for row in transactions
            ]
            chain_rows.append(
                {
                    "chain_id": int(chain["chain_id"]),
                    "transaction_count": len(gas_values),
                    "gas_used": sum(gas_values),
                    "transactions": transactions,
                    "components": components,
                    "component_runtime_code_sha256": {
                        str(component["role"]): component["runtime_code_sha256"]
                        for component in components
                    },
                }
            )
        result[protocol] = {
            "status": "observed_local_full_stack",
            "source_sha256": _sha256(path),
            "source_file": path.name,
            "chains": chain_rows,
            "mean_gas_per_chain": sum(row["gas_used"] for row in chain_rows) / len(chain_rows),
            "includes_protocol_specific_on_chain_stack": True,
            "locally_reproduced_runtime_bytecode_identified": True,
            "off_chain_operations_not_monetized": True,
        }
    return result


def analyze_gateway_deployment(
    *,
    topology_path: Path,
    mainnet_path: Path,
    semantic_path: Path,
    multihop_deployment_path: Path | None = None,
    hyperlane_evidence_path: Path | None = None,
    layerzero_evidence_path: Path | None = None,
) -> dict[str, Any]:
    nodes, edges, frozen = load_frozen_connectivity(
        topology_path=topology_path,
        mainnet_path=mainnet_path,
        semantic_path=semantic_path,
    )
    model = GatewayReachability(nodes, edges)
    homogeneous = model.reachable_pairs(model.base_closure)
    all_compatible = model.reachable_pairs(model.closure(set(nodes)))
    if (
        homogeneous != frozen["homogeneous_pairs"]
        or all_compatible != frozen["all_compatible_pairs"]
    ):
        raise LocalTopologyError("new Gateway semantics do not reproduce frozen endpoints")
    placement = greedy_gateway_placement(
        model, all_compatible_pairs=int(frozen["all_compatible_pairs"])
    )
    curves = protocol_expansion_curves(nodes, edges)
    document: dict[str, Any] = {
        "schema_version": "xir-lab-gateway-deployment-analysis-v1",
        "claim_boundary": "structural_upper_bound_not_observed_xir_delivery",
        "source_sha256": EXPECTED_INPUTS,
        "frozen": frozen,
        "gateway_placement": placement,
        "protocol_expansion": curves,
        "component_obligations": component_obligations(),
        "measured_deployment_gas": _measured_deployment_gas(
            multihop_deployment_path=multihop_deployment_path,
            hyperlane_evidence_path=hyperlane_evidence_path,
            layerzero_evidence_path=layerzero_evidence_path,
        ),
        "public_protocol_deployment_gas": [
            {"protocol": protocol, "gas": None, "status": "not_observed", "provenance": None}
            for protocol in PROTOCOLS
        ],
    }
    document["independent_replay"] = _validate_gateway_reference_replay(
        document=document, nodes=nodes, edges=edges
    )
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    return document


def _validate_gateway_rounds_and_curves(document: dict[str, Any]) -> dict[str, int]:
    placement = cast(dict[str, Any], document["gateway_placement"])
    rounds = cast(list[dict[str, Any]], placement["rounds"])
    if not rounds or int(rounds[0].get("step", -1)) != 0:
        raise LocalTopologyError("Gateway placement round zero is missing")
    selected: list[str] = []
    previous_pairs = int(rounds[0]["reachable_pairs"])
    for expected_step, row in enumerate(rounds[1:], start=1):
        candidates = cast(list[dict[str, Any]], row.get("candidate_gains", []))
        if int(row.get("step", -1)) != expected_step or not candidates:
            raise LocalTopologyError("Gateway candidate round inventory is incomplete")
        if [str(item["node"]) for item in candidates] != sorted(
            str(item["node"]) for item in candidates
        ):
            raise LocalTopologyError("Gateway candidate rows are not canonical")
        best = min(
            candidates,
            key=lambda item: (-int(item["marginal_pair_gain"]), str(item["node"])),
        )
        best_gain = int(best["marginal_pair_gain"])
        expected_node = str(best["node"]) if best_gain > 0 else None
        semantic = dict(row)
        round_sha = str(semantic.pop("round_sha256", ""))
        if (
            row.get("selected_node") != expected_node
            or row.get("tie_break") != expected_node
            or int(row.get("marginal_pair_gain", -1)) != best_gain
            or int(row.get("reachable_pairs", -1))
            != (previous_pairs + best_gain if best_gain > 0 else previous_pairs)
            or hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != round_sha
        ):
            raise LocalTopologyError("Gateway greedy round replay failed")
        if expected_node is not None:
            selected.append(expected_node)
            previous_pairs += best_gain
    if (
        sorted(selected) != cast(list[str], placement.get("selected_nodes", []))
        or len(selected) != int(placement["terminal_k"])
        or previous_pairs != int(placement["terminal_pairs"])
    ):
        raise LocalTopologyError("Gateway selected-node prefix does not reconcile")

    curves = cast(list[dict[str, Any]], document["protocol_expansion"])
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in curves:
        groups[(str(row["protocol"]), str(row["scenario"]))].append(row)
    expected_groups = {
        (protocol, scenario)
        for protocol in PROTOCOLS
        for scenario in ("optimistic", "central", "conservative")
    }
    if set(groups) != expected_groups:
        raise LocalTopologyError("six-protocol by three-scenario curves are incomplete")
    for key, rows in groups.items():
        rows.sort(key=lambda item: int(item["added_nodes"]))
        steps = [int(row["added_nodes"]) for row in rows]
        if steps != list(range(len(rows))):
            raise LocalTopologyError(f"protocol curve prefix is incomplete: {key}")
        order_hashes = {str(row["added_node_order_sha256"]) for row in rows}
        coverage_hashes = {str(row["original_coverage_sha256"]) for row in rows}
        if len(order_hashes) != 1 or len(coverage_hashes) != 1:
            raise LocalTopologyError("protocol curve source identity changes across prefixes")
        for step, row in enumerate(rows):
            prefix = cast(list[str], json.loads(str(row["added_node_prefix_json"])))
            if len(prefix) != step or (step and row["last_added_node"] != prefix[-1]):
                raise LocalTopologyError("protocol curve added-node prefix is invalid")
    for protocol in PROTOCOLS:
        by_scenario = {
            scenario: sorted(
                groups[(protocol, scenario)], key=lambda item: int(item["added_nodes"])
            )
            for scenario in ("optimistic", "central", "conservative")
        }
        if len({len(rows) for rows in by_scenario.values()}) != 1:
            raise LocalTopologyError("protocol scenario prefix lengths differ")
        if not all(
            int(optimistic["reachable_pairs"])
            >= int(central["reachable_pairs"])
            >= int(conservative["reachable_pairs"])
            for optimistic, central, conservative in zip(
                by_scenario["optimistic"],
                by_scenario["central"],
                by_scenario["conservative"],
                strict=True,
            )
        ):
            raise LocalTopologyError("protocol scenario ordering is invalid")
    return {"greedy_round_count": len(rounds), "curve_group_count": len(groups)}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = sorted({field for row in rows for field in row})
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def publish_gateway_deployment_document(
    *,
    document: dict[str, Any],
    output_root: Path,
    topology_path: Path,
    mainnet_path: Path,
    semantic_path: Path,
    multihop_deployment_path: Path,
    hyperlane_evidence_path: Path,
    layerzero_evidence_path: Path,
) -> dict[str, Any]:
    """Publish a complete, deterministic and secret-free graph-analysis tree."""

    if output_root.exists():
        raise LocalTopologyError("Gateway publication output already exists")
    semantic = dict(document)
    expected_semantic = str(semantic.pop("semantic_sha256", ""))
    if (
        document.get("schema_version") != "xir-lab-gateway-deployment-analysis-v1"
        or document.get("claim_boundary") != "structural_upper_bound_not_observed_xir_delivery"
        or hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != expected_semantic
    ):
        raise LocalTopologyError("Gateway publication input is invalid")
    replay_counts = _validate_gateway_rounds_and_curves(document)
    nodes, edges, frozen_reference = load_frozen_connectivity(
        topology_path=topology_path,
        mainnet_path=mainnet_path,
        semantic_path=semantic_path,
    )
    if document.get("frozen") != frozen_reference:
        raise LocalTopologyError("Gateway publication frozen summary differs from source graph")
    reference_replay = _validate_gateway_reference_replay(
        document=document, nodes=nodes, edges=edges
    )
    if document.get("independent_replay") != reference_replay:
        raise LocalTopologyError("Gateway independent replay summary is stale")
    output_root.mkdir(parents=True)
    provenance_root = output_root / "provenance"
    provenance_root.mkdir()
    provenance_sources = {
        "topology.json": topology_path,
        "mainnet-only.json": mainnet_path,
        "semantic-aggregates.json": semantic_path,
        "multihop-deployment.json": multihop_deployment_path,
        "hyperlane-deployment-evidence.json": hyperlane_evidence_path,
        "layerzero-deployment-evidence.json": layerzero_evidence_path,
    }
    for name, source in provenance_sources.items():
        if not source.is_file():
            raise LocalTopologyError(f"Gateway publication provenance is missing: {name}")
        shutil.copyfile(source, provenance_root / name)
    measured = cast(dict[str, dict[str, Any]], document["measured_deployment_gas"])
    measured_sources = {
        "xir": multihop_deployment_path,
        "hyperlane": hyperlane_evidence_path,
        "layerzero": layerzero_evidence_path,
    }
    for key, source in measured_sources.items():
        row = measured.get(key, {})
        if str(row.get("status", "")).startswith("observed") and row.get(
            "source_sha256"
        ) != _sha256(source):
            raise LocalTopologyError(f"Gateway measured {key} provenance digest drift")
    placement = cast(dict[str, Any], document["gateway_placement"])
    rounds = cast(list[dict[str, Any]], placement["rounds"])
    round_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    for row in rounds:
        candidates = cast(list[dict[str, Any]], row.get("candidate_gains", []))
        round_rows.append({key: value for key, value in row.items() if key != "candidate_gains"})
        candidate_rows.extend({"step": int(row["step"]), **candidate} for candidate in candidates)
    _write_json(output_root / "analysis.json", document)
    _write_csv(output_root / "gateway-rounds.csv", round_rows)
    _write_csv(output_root / "gateway-candidate-gains.csv", candidate_rows)
    _write_csv(
        output_root / "gateway-pair-evidence.csv",
        cast(list[dict[str, Any]], placement["pair_evidence"]),
    )
    _write_csv(
        output_root / "protocol-expansion-curves.csv",
        cast(list[dict[str, Any]], document["protocol_expansion"]),
    )
    _write_csv(
        output_root / "component-obligations.csv",
        cast(list[dict[str, Any]], document["component_obligations"]),
    )
    _write_json(
        output_root / "measured-deployment-gas.json",
        document["measured_deployment_gas"],
    )
    _write_json(
        output_root / "public-protocol-deployment-gas.json",
        document["public_protocol_deployment_gas"],
    )
    frozen = cast(dict[str, Any], document["frozen"])
    pair_evidence = cast(list[dict[str, Any]], placement["pair_evidence"])
    terminal_reachable_rows = sum(bool(row.get("terminal_reachable")) for row in pair_evidence)
    baseline_reachable_rows = sum(bool(row.get("baseline_reachable")) for row in pair_evidence)
    newly_enabled_rows = sum(bool(row.get("newly_enabled_by_gateway")) for row in pair_evidence)
    route_witness_rows = sum(bool(row.get("route_state_path")) for row in pair_evidence)
    validation: dict[str, Any] = {
        "schema_version": "xir-lab-gateway-deployment-validation-v1",
        "valid": (
            int(frozen["node_count"]) == 286
            and int(frozen["protocol_edge_count"]) == 15_965
            and int(frozen["ordered_pair_denominator"]) == 81_510
            and int(frozen["all_compatible_pairs"]) == 78_953
            and int(placement["terminal_pairs"]) <= 78_953
            and len(pair_evidence) == 81_510
            and terminal_reachable_rows == int(placement["terminal_pairs"])
            and baseline_reachable_rows == int(frozen.get("homogeneous_pairs", 46_187))
            and newly_enabled_rows == terminal_reachable_rows - baseline_reachable_rows
            and route_witness_rows == terminal_reachable_rows
            and all(
                row["gas"] is None and row["status"] == "not_observed" and row["provenance"] is None
                for row in cast(
                    list[dict[str, Any]],
                    document["public_protocol_deployment_gas"],
                )
            )
        ),
        "node_count": frozen["node_count"],
        "ordered_pair_count": len(pair_evidence),
        "baseline_reachable_pair_rows": baseline_reachable_rows,
        "terminal_reachable_pair_rows": terminal_reachable_rows,
        "newly_enabled_pair_rows": newly_enabled_rows,
        "route_witness_rows": route_witness_rows,
        "terminal_k": placement["terminal_k"],
        "terminal_pairs": placement["terminal_pairs"],
        "structural_upper_bound_pairs": frozen["all_compatible_pairs"],
        "counterfactual_scenarios": ["central", "conservative", "optimistic"],
        "unobserved_public_protocol_gas_cells": len(PROTOCOLS),
        "reference_replay_semantic_sha256": reference_replay["semantic_sha256"],
        **replay_counts,
    }
    if not validation["valid"]:
        raise LocalTopologyError("Gateway publication validation failed")
    _write_json(output_root / "validation.json", validation)
    if secret_scan(output_root):
        raise LocalTopologyError("Gateway publication contains sensitive material")
    manifest: dict[str, Any] = {
        "schema_version": "xir-lab-gateway-deployment-manifest-v1",
        "analysis_semantic_sha256": expected_semantic,
        "files": [
            {
                "path": str(path.relative_to(output_root)),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in sorted(output_root.rglob("*"))
            if path.is_file()
        ],
    }
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write_json(output_root / "manifest.json", manifest)
    return manifest


def compare_gateway_publications(
    *, publication_a: Path, publication_b: Path, output_path: Path
) -> dict[str, Any]:
    def inventory(root: Path) -> dict[str, str]:
        return {
            str(path.relative_to(root)): _sha256(path)
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    verify_gateway_publication(publication_a)
    verify_gateway_publication(publication_b)
    first = inventory(publication_a)
    second = inventory(publication_b)
    if first != second:
        raise LocalTopologyError("Gateway publication rebuilds are not byte-identical")
    document = {
        "schema_version": "xir-lab-gateway-deployment-rebuild-comparison-v1",
        "valid": True,
        "byte_identical_files": first,
        "publication_a_manifest_sha256": _sha256(publication_a / "manifest.json"),
        "publication_b_manifest_sha256": _sha256(publication_b / "manifest.json"),
    }
    _write_json(output_path, document)
    return document


def verify_gateway_publication(root: Path) -> dict[str, Any]:
    """Replay graph semantics and reproduce every public byte from provenance."""

    document = cast(
        dict[str, Any], json.loads((root / "analysis.json").read_text(encoding="utf-8"))
    )
    provenance = root / "provenance"
    sources = {
        "topology_path": provenance / "topology.json",
        "mainnet_path": provenance / "mainnet-only.json",
        "semantic_path": provenance / "semantic-aggregates.json",
        "multihop_deployment_path": provenance / "multihop-deployment.json",
        "hyperlane_evidence_path": provenance / "hyperlane-deployment-evidence.json",
        "layerzero_evidence_path": provenance / "layerzero-deployment-evidence.json",
    }
    with tempfile.TemporaryDirectory(prefix="xir-gateway-reverify-") as temporary:
        rebuilt = Path(temporary) / "publication"
        publish_gateway_deployment_document(
            document=document,
            output_root=rebuilt,
            **sources,
        )
        expected = {
            path.relative_to(rebuilt).as_posix(): _sha256(path)
            for path in sorted(rebuilt.rglob("*"))
            if path.is_file()
        }
    observed = {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    if observed != expected:
        raise LocalTopologyError("Gateway publication differs from semantic replay")
    return document
