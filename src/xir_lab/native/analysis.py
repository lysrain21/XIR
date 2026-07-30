"""Fail-closed reconciliation and deterministic analysis for native-stack phases."""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from pathlib import Path
from statistics import mean, median
from typing import Any, cast

from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.native_profile import build_native_attempts
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.rpc import qbft_web3

EFFECT_TOPIC = "0x" + keccak(
    text=(
        "NativeEffectApplied(bytes32,bytes2,uint64,bytes32,bytes32,bytes32,"
        "bytes32,bytes32,uint256,bool)"
    )
).hex()
TRANSITION_TOPIC = "0x" + keccak(
    text=(
        "NativeXIRTransitionRecorded(bytes32,bytes2,uint64,bytes32,bytes32,"
        "bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)"
    )
).hex()
HYPERLANE_DISPATCH_TOPIC = "0x" + keccak(
    text="HyperlaneDispatched(bytes32,uint32,bytes32,uint256)"
).hex()
LAYERZERO_BASELINE_TOPIC = "0x" + keccak(
    text="BaselineDispatched(bytes32,uint64,uint256)"
).hex()
LAYERZERO_XIR_TOPIC = "0x" + keccak(
    text="VerifiedEvidenceForwarded(bytes32,uint64,uint256)"
).hex()
HYPERLANE_PROCESS_ID_TOPIC = "0x" + keccak(text="ProcessId(bytes32)").hex()
HYPERLANE_DISPATCH_ID_TOPIC = "0x" + keccak(text="DispatchId(bytes32)").hex()
LOG_QUERY_BLOCKS = 2_000


def _logs(
    client: Web3,
    address: str,
    topic: str,
    first_block: int,
    *,
    chunk_blocks: int = LOG_QUERY_BLOCKS,
) -> list[Any]:
    if chunk_blocks <= 0:
        raise LocalTopologyError("log query chunk size must be positive")
    last_block = int(client.eth.block_number)
    logs: list[Any] = []
    for chunk_first in range(first_block, last_block + 1, chunk_blocks):
        chunk_last = min(chunk_first + chunk_blocks - 1, last_block)
        logs.extend(
            client.eth.get_logs(
                {
                    "fromBlock": chunk_first,
                    "toBlock": chunk_last,
                    "address": Web3.to_checksum_address(address),
                    "topics": [topic],
                }
            )
        )
    return logs


def _expected_cumulative_per_route(profile: dict[str, Any], phase: str) -> int:
    progression = profile["progression"]
    if phase == "smoke":
        return int(progression["smoke_attempts_per_route"])
    if phase == "rehearsal":
        return int(progression["smoke_attempts_per_route"]) + int(
            progression["rehearsal_attempts_per_route"]
        )
    return (
        int(progression["smoke_attempts_per_route"])
        + int(progression["rehearsal_attempts_per_route"])
        + int(progression["scale_attempts_per_route"])
    )


def _install_guid_scope(
    connection: sqlite3.Connection, guids: list[str]
) -> None:
    connection.execute(
        """
        CREATE TEMP TABLE native_scoped_guids(
          guid TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    connection.executemany(
        "INSERT INTO native_scoped_guids(guid) VALUES (?)",
        ((guid.lower(),) for guid in guids),
    )


def reconcile_native_phase(
    *,
    phase: str,
    profile_path: Path,
    deployment_path: Path,
    runner_state_path: Path,
    layerzero_state_path: Path,
) -> dict[str, Any]:
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
    expected = build_native_attempts(
        profile_path=profile_path, phase=cast(Any, phase)
    )
    expected_by_id = {attempt.attempt_id: attempt for attempt in expected}
    runner = sqlite3.connect(runner_state_path)
    runner.row_factory = sqlite3.Row
    attempts = runner.execute("SELECT * FROM attempts").fetchall()
    actual_by_id = {str(row["attempt_id"]): row for row in attempts}
    missing_attempts = sorted(set(expected_by_id) - set(actual_by_id))
    unexpected_attempts = sorted(set(actual_by_id) - set(expected_by_id))
    incomplete_attempts = sorted(
        attempt_id
        for attempt_id, row in actual_by_id.items()
        if str(row["status"]) != "succeeded"
    )
    required_stages = {
        "HH": {"source_dispatch", "destination_effect"},
        "LL": {"source_dispatch", "destination_effect"},
        "HL": {
            "xir_root_record",
            "first_protocol_dispatch",
            "xir_transition",
            "second_protocol_dispatch",
            "destination_deliver",
        },
        "LH": {
            "xir_root_record",
            "first_protocol_dispatch",
            "xir_transition",
            "second_protocol_dispatch",
            "destination_deliver",
        },
    }
    missing_stages: list[dict[str, Any]] = []
    failed_stages: list[dict[str, Any]] = []
    for attempt_id, attempt in expected_by_id.items():
        rows = runner.execute(
            "SELECT stage, state FROM stages WHERE attempt_id=?", (attempt_id,)
        ).fetchall()
        observed = {str(row["stage"]): str(row["state"]) for row in rows}
        absent = sorted(required_stages[attempt.route] - set(observed))
        if absent:
            missing_stages.append({"attempt_id": attempt_id, "stages": absent})
        for stage, state in observed.items():
            if state == "failed":
                failed_stages.append(
                    {"attempt_id": attempt_id, "stage": stage}
                )
    destination_chain = next(
        item for item in profile["chains"] if item["route_role"] == "destination"
    )
    intermediate_chain = next(
        item for item in profile["chains"] if item["route_role"] == "intermediate"
    )
    clients = {
        "destination": qbft_web3(destination_chain["rpc_url"]),
        "intermediate": qbft_web3(intermediate_chain["rpc_url"]),
    }
    bounds = deployment["deployment_block_bounds"]
    effects = _logs(
        clients["destination"],
        deployment["chains"]["destination"]["receiver"],
        EFFECT_TOPIC,
        int(bounds["destination"]["first"]),
    )
    effect_attempts = {"0x" + bytes(log["topics"][1]).hex() for log in effects}
    expected_effect_attempts = {
        "0x" + keccak(text=attempt.attempt_id).hex() for attempt in expected
    }
    missing_effects = sorted(expected_effect_attempts - effect_attempts)
    transitions = _logs(
        clients["intermediate"],
        deployment["chains"]["intermediate"]["xir_transition_recorder"],
        TRANSITION_TOPIC,
        int(bounds["intermediate"]["first"]),
    )
    transition_attempts = {
        "0x" + bytes(log["topics"][1]).hex() for log in transitions
    }
    expected_transition_attempts = {
        "0x" + keccak(text=attempt.attempt_id).hex()
        for attempt in expected
        if attempt.xir
    }
    missing_transitions = sorted(
        expected_transition_attempts - transition_attempts
    )
    cumulative = _expected_cumulative_per_route(profile, phase)
    protocol_counts: dict[str, int] = {}
    hyperlane_count = 0
    hyperlane_adapter_ids: set[str] = set()
    for role, adapter in (
        ("source", "h_source"),
        ("intermediate", "h_hom_out"),
        ("intermediate", "h_xir_out"),
    ):
        chain = next(
            item for item in profile["chains"] if item["route_role"] == role
        )
        client = qbft_web3(chain["rpc_url"])
        adapter_logs = _logs(
            client,
            deployment["chains"][role][adapter],
            HYPERLANE_DISPATCH_TOPIC,
            int(bounds[role]["first"]),
        )
        hyperlane_count += len(adapter_logs)
        hyperlane_adapter_ids.update(
            "0x" + bytes(log["topics"][1]).hex() for log in adapter_logs
        )
    layerzero_count = 0
    layerzero_adapter_guids: set[str] = set()
    for role, adapter in (
        ("source", "l_source"),
        ("intermediate", "l_hom_out"),
        ("intermediate", "l_xir_out"),
    ):
        chain = next(
            item for item in profile["chains"] if item["route_role"] == role
        )
        client = qbft_web3(chain["rpc_url"])
        for topic in (LAYERZERO_BASELINE_TOPIC, LAYERZERO_XIR_TOPIC):
            adapter_logs = _logs(
                client,
                deployment["chains"][role][adapter],
                topic,
                int(bounds[role]["first"]),
            )
            layerzero_count += len(adapter_logs)
            layerzero_adapter_guids.update(
                "0x" + bytes(log["topics"][1]).hex() for log in adapter_logs
            )
    protocol_counts["hyperlane"] = hyperlane_count
    protocol_counts["layerzero_v2"] = layerzero_count
    worker = sqlite3.connect(layerzero_state_path)
    worker.row_factory = sqlite3.Row
    if not layerzero_adapter_guids:
        raise LocalTopologyError("native phase has no LayerZero adapter GUIDs")
    scoped_guids = sorted(layerzero_adapter_guids)
    _install_guid_scope(worker, scoped_guids)
    delivered_packets = int(
        worker.execute(
            """
            SELECT COUNT(*)
            FROM packets AS packet
            JOIN native_scoped_guids AS scope
              ON lower(packet.guid)=scope.guid
            WHERE packet.status='delivered'
            """,
        ).fetchone()[0]
    )
    failed_worker_actions = int(
        worker.execute(
            """
            SELECT COUNT(*)
            FROM actions AS action
            JOIN native_scoped_guids AS scope
              ON lower(action.guid)=scope.guid
            WHERE action.status='failed'
            """,
        ).fetchone()[0]
    )
    worker_packet_guids = {
        str(row[0]).lower()
        for row in worker.execute(
            """
            SELECT packet.guid
            FROM packets AS packet
            JOIN native_scoped_guids AS scope
              ON lower(packet.guid)=scope.guid
            """
        ).fetchall()
    }
    incomplete_worker_lineages = [
        str(row[0])
        for row in worker.execute(
            """
            SELECT packet.guid
            FROM packets AS packet
            JOIN native_scoped_guids AS scope
              ON lower(packet.guid)=scope.guid
            LEFT JOIN actions AS action ON action.guid=packet.guid
            GROUP BY packet.guid
            HAVING packet.status != 'delivered'
               OR COUNT(action.action_id) != 3
               OR SUM(CASE WHEN action.status='succeeded' THEN 1 ELSE 0 END) != 3
               OR COUNT(DISTINCT action.stage) != 3
            """,
        ).fetchall()
    ]
    phases = ("smoke", "rehearsal", "scale")
    included_phases = phases[: phases.index(phase) + 1]
    runner_transaction_coordinates: set[str] = set()
    nonce_coordinates: list[str] = []
    runner_raw_replacements = 0
    runner_transient_rpc_retries = 0
    run_root = runner_state_path.parents[1]
    for included_phase in included_phases:
        phase_db = run_root / included_phase / "runner.sqlite"
        if not phase_db.is_file():
            raise LocalTopologyError(
                f"cumulative runner state is missing: {phase_db}"
            )
        phase_connection = sqlite3.connect(phase_db)
        phase_connection.row_factory = sqlite3.Row
        for row in phase_connection.execute(
            """
            SELECT transaction_hash, detail_json FROM stages
            WHERE transaction_hash IS NOT NULL AND state='succeeded'
            """
        ).fetchall():
            detail = json.loads(row["detail_json"])
            role = str(detail["role"])
            runner_transaction_coordinates.add(
                f"{role}:{str(row['transaction_hash']).lower()}"
            )
            nonce_coordinates.append(
                f"{role}:{int(detail.get('transaction_nonce', detail['nonce']))}"
            )
        history_exists = phase_connection.execute(
            """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='stage_history'
            """
        ).fetchone()[0]
        if history_exists:
            runner_raw_replacements += int(
                phase_connection.execute(
                    "SELECT COUNT(*) FROM stage_history WHERE state='superseded'"
                ).fetchone()[0]
            )
        errors_exist = phase_connection.execute(
            """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='attempt_errors'
            """
        ).fetchone()[0]
        if errors_exist:
            runner_transient_rpc_retries += int(
                phase_connection.execute(
                    "SELECT COUNT(*) FROM attempt_errors"
                ).fetchone()[0]
            )
        phase_connection.close()
    worker_transaction_coordinates = {
        f"{int(row['destination_chain_id'])}:{str(row['transaction_hash']).lower()}"
        for row in worker.execute(
            """
            SELECT action.destination_chain_id, action.transaction_hash
            FROM actions AS action
            JOIN native_scoped_guids AS scope
              ON lower(action.guid)=scope.guid
            WHERE action.status='succeeded'
              AND action.transaction_hash IS NOT NULL
            """,
        ).fetchall()
    }
    worker_rebroadcasts = int(
        worker.execute(
            """
            SELECT COUNT(*) FROM observations
            JOIN actions AS action USING(action_id)
            JOIN native_scoped_guids AS scope
              ON lower(action.guid)=scope.guid
            WHERE observations.state='submitted'
            """,
        ).fetchone()[0]
    ) - int(
        worker.execute(
            """
            SELECT COUNT(*)
            FROM actions AS action
            JOIN native_scoped_guids AS scope
              ON lower(action.guid)=scope.guid
            """,
        ).fetchone()[0]
    )
    hyperlane_process_coordinates: set[str] = set()
    hyperlane_process_ids: set[str] = set()
    hyperlane_dispatch_ids: set[str] = set()
    for role in ("source", "intermediate"):
        chain = next(
            item for item in profile["chains"] if item["route_role"] == role
        )
        client = qbft_web3(chain["rpc_url"])
        dispatch_logs = _logs(
            client,
            deployment["infrastructure"][role]["mailbox"],
            HYPERLANE_DISPATCH_ID_TOPIC,
            int(bounds[role]["first"]),
        )
        hyperlane_dispatch_ids.update(
            "0x" + bytes(log["topics"][1]).hex() for log in dispatch_logs
        )
    for role in ("intermediate", "destination"):
        chain = next(
            item for item in profile["chains"] if item["route_role"] == role
        )
        client = qbft_web3(chain["rpc_url"])
        process_logs = _logs(
            client,
            deployment["infrastructure"][role]["mailbox"],
            HYPERLANE_PROCESS_ID_TOPIC,
            int(bounds[role]["first"]),
        )
        hyperlane_process_coordinates.update(
            f"{role}:0x{bytes(log['transactionHash']).hex()}"
            for log in process_logs
        )
        hyperlane_process_ids.update(
            "0x" + bytes(log["topics"][1]).hex() for log in process_logs
        )
    physical_transaction_coordinates = (
        runner_transaction_coordinates
        | worker_transaction_coordinates
        | hyperlane_process_coordinates
    )
    expected_each_protocol = cumulative * 4
    invariant_results = {
        "logical_attempts_exact": (
            not missing_attempts
            and not unexpected_attempts
            and not incomplete_attempts
        ),
        "required_stages_exact": not missing_stages and not failed_stages,
        "application_effects_exact": not missing_effects
        and len(effect_attempts) == cumulative * 4,
        "xir_transitions_exact": not missing_transitions
        and len(transition_attempts) == cumulative * 2,
        "hyperlane_messages_exact": hyperlane_count == expected_each_protocol,
        "hyperlane_dispatch_lineage_exact": hyperlane_adapter_ids
        == hyperlane_dispatch_ids,
        "hyperlane_process_lineage_exact": hyperlane_dispatch_ids
        == hyperlane_process_ids,
        "layerzero_messages_exact": layerzero_count == expected_each_protocol,
        "layerzero_deliveries_exact": delivered_packets
        == expected_each_protocol,
        "layerzero_packet_lineage_exact": layerzero_adapter_guids
        == worker_packet_guids,
        "layerzero_worker_stages_exact": not incomplete_worker_lineages,
        "worker_has_no_failed_actions": failed_worker_actions == 0,
        "nonce_coordinates_unique": len(nonce_coordinates)
        == len(set(nonce_coordinates)),
        "physical_transactions_evidenced": bool(physical_transaction_coordinates),
    }
    valid = all(invariant_results.values())
    return {
        "schema_version": "xir-lab-native-reconciliation-v1",
        "phase": phase,
        "valid": valid,
        "denominator": {
            "per_route": len(expected) // 4,
            "logical_attempts": len(expected),
            "cumulative_per_route": cumulative,
        },
        "invariants": invariant_results,
        "missing_attempts": missing_attempts,
        "unexpected_attempts": unexpected_attempts,
        "incomplete_attempts": incomplete_attempts,
        "missing_stages": missing_stages,
        "failed_stages": failed_stages,
        "missing_effects": missing_effects,
        "missing_transitions": missing_transitions,
        "incomplete_layerzero_worker_lineages": incomplete_worker_lineages,
        "observed": {
            "cumulative_effects": len(effect_attempts),
            "cumulative_xir_transitions": len(transition_attempts),
            "protocol_messages": protocol_counts,
            "layerzero_delivered_packets": delivered_packets,
            "layerzero_failed_actions": failed_worker_actions,
            "hyperlane_dispatch_ids": len(hyperlane_dispatch_ids),
            "hyperlane_process_ids": len(hyperlane_process_ids),
            "layerzero_packet_guids": len(worker_packet_guids),
            "physical_transactions": {
                "cumulative_unique": len(physical_transaction_coordinates),
                "coordinator": len(runner_transaction_coordinates),
                "layerzero_worker": len(worker_transaction_coordinates),
                "hyperlane_process": len(hyperlane_process_coordinates),
            },
            "retries": {
                "layerzero_raw_rebroadcasts": max(worker_rebroadcasts, 0),
                "runner_raw_replacements": runner_raw_replacements,
                "runner_transient_rpc_retries": runner_transient_rpc_retries,
                "semantic_retry_attempts": 0,
            },
            "nonce_coordinates": len(nonce_coordinates),
        },
    }


def analyze_native_phase(
    *,
    phase: str,
    runner_state_path: Path,
    reconciliation: dict[str, Any],
    resource_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not reconciliation["valid"]:
        raise LocalTopologyError("native analysis requires exact reconciliation")
    connection = sqlite3.connect(runner_state_path)
    connection.row_factory = sqlite3.Row
    per_route: list[dict[str, Any]] = []
    phase_started: list[float] = []
    phase_finished: list[float] = []

    def percentile(values: list[float], proportion: float) -> float:
        ordered = sorted(values)
        index = max(0, min(len(ordered) - 1, int(proportion * len(ordered) + 0.999999) - 1))
        return ordered[index]

    for route in ("HH", "LL", "HL", "LH"):
        rows = connection.execute(
            "SELECT started_at, finished_at FROM attempts WHERE route=? AND status='succeeded'",
            (route,),
        ).fetchall()
        latencies = [
            float(row["finished_at"]) - float(row["started_at"]) for row in rows
        ]
        phase_started.extend(float(row["started_at"]) for row in rows)
        phase_finished.extend(float(row["finished_at"]) for row in rows)
        stage_rows = connection.execute(
            """
            SELECT stage.detail_json
            FROM stages AS stage
            JOIN attempts AS attempt ON attempt.attempt_id=stage.attempt_id
            WHERE attempt.route=? AND stage.state='succeeded'
              AND stage.transaction_hash IS NOT NULL
            """,
            (route,),
        ).fetchall()
        gas = [
            int(json.loads(row["detail_json"])["gas_used"])
            for row in stage_rows
            if "gas_used" in json.loads(row["detail_json"])
        ]
        per_route.append(
            {
                "route": route,
                "logical_attempts": len(rows),
                "success_rate": 1.0,
                "latency_seconds_mean": mean(latencies),
                "latency_seconds_median": median(latencies),
                "latency_seconds_p95": percentile(latencies, 0.95),
                "latency_seconds_p99": percentile(latencies, 0.99),
                "latency_seconds_min": min(latencies),
                "latency_seconds_max": max(latencies),
                "coordinator_transactions": len(gas),
                "coordinator_gas_used": sum(gas),
                "coordinator_gas_mean": mean(gas) if gas else 0,
                "xir": route in {"HL", "LH"},
            }
        )
    resource_samples = []
    if resource_path.is_file():
        resource_samples = [
            json.loads(line)
            for line in resource_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
    gaps = sum(len(sample.get("gaps", [])) for sample in resource_samples)
    restarts = sum(len(sample.get("restarts", [])) for sample in resource_samples)
    phase_wall_seconds = max(phase_finished) - min(phase_started)
    pools = []
    for name, routes in (
        ("homogeneous", {"HH", "LL"}),
        ("heterogeneous_xir", {"HL", "LH"}),
    ):
        selected = [row for row in per_route if row["route"] in routes]
        attempts = sum(int(row["logical_attempts"]) for row in selected)
        pools.append(
            {
                "pool": name,
                "routes": sorted(routes),
                "logical_attempts": attempts,
                "coordinator_transactions": sum(
                    int(row["coordinator_transactions"]) for row in selected
                ),
                "coordinator_gas_used": sum(
                    int(row["coordinator_gas_used"]) for row in selected
                ),
                "weighted_latency_seconds_mean": sum(
                    float(row["latency_seconds_mean"])
                    * int(row["logical_attempts"])
                    for row in selected
                )
                / attempts,
            }
        )
    host_samples = [
        sample["host"]
        for sample in resource_samples
        if isinstance(sample.get("host"), dict)
        and "memory_available_bytes" in sample["host"]
    ]
    result = {
        "schema_version": "xir-lab-native-analysis-v1",
        "phase": phase,
        "reconciled": True,
        "units": {
            "latency": "seconds per logical two-hop attempt",
            "gas": "gas used by coordinator-controlled transactions",
            "success_rate": "successful logical attempts / designated attempts",
        },
        "denominator": reconciliation["denominator"],
        "per_route": per_route,
        "pools": pools,
        "phase_wall_seconds": phase_wall_seconds,
        "throughput_logical_attempts_per_second": len(phase_finished)
        / phase_wall_seconds,
        "physical_transactions": reconciliation["observed"][
            "physical_transactions"
        ],
        "protocol_messages": reconciliation["observed"]["protocol_messages"],
        "xir_transitions": reconciliation["observed"][
            "cumulative_xir_transitions"
        ],
        "application_effects": reconciliation["observed"]["cumulative_effects"],
        "resource_samples": len(resource_samples),
        "resource_sampling_gaps": gaps,
        "observed_process_restarts": restarts,
        "resource_extrema": {
            "minimum_memory_available_bytes": min(
                (int(sample["memory_available_bytes"]) for sample in host_samples),
                default=None,
            ),
            "minimum_gpfs_free_bytes": min(
                (
                    int(sample["gpfs_free_bytes"])
                    for sample in host_samples
                    if sample.get("gpfs_free_bytes") is not None
                ),
                default=None,
            ),
            "minimum_docker_free_bytes": min(
                (
                    int(sample["docker_free_bytes"])
                    for sample in host_samples
                    if sample.get("docker_free_bytes") is not None
                ),
                default=None,
            ),
        },
        "confounds": [
            "Hyperlane uses official validator/relayer agents; LayerZero private-chain off-chain roles use the self-hosted research worker.",
            "Coordinator gas excludes protocol-agent transaction gas; complete physical transaction evidence remains in raw receipts and protocol databases.",
            "Results characterize this controlled three-chain four-validator-per-chain host, not public-network performance.",
        ],
        "claim_exclusions": [
            "No claim about LayerZero Labs managed DVN or Executor service performance.",
            "No claim that adapter-only earlier experiments are native protocol-stack comparisons.",
            "No causal claim beyond the matched local deployment and pinned component versions.",
        ],
    }
    result["semantic_sha256"] = hashlib.sha256(
        json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    return result, per_route


def write_analysis(
    *, output_json: Path, output_csv: Path, document: dict[str, Any], rows: list[dict[str, Any]]
) -> None:
    output_json.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with output_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
