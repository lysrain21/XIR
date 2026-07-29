#!/usr/bin/env python3
"""Compute bounded paper results from reconciled four-route evidence."""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

STAGES = {0: "source", 1: "intermediate", 2: "destination"}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def metrics(rows: list[sqlite3.Row]) -> dict[str, Any]:
    gas = [float(item["gas_used"]) for item in rows]
    calldata = [float(item["calldata_bytes"]) for item in rows]
    latency = [
        (float(item["finalized_at"]) - float(item["submitted_at"])) * 1000
        for item in rows
    ]
    blocks: dict[str, set[int]] = {
        str(item["network_id"]): set() for item in rows
    }
    for item in rows:
        blocks[str(item["network_id"])].add(int(item["block_number"]))
    return {
        "physical_transactions": len(rows),
        "gas_total": int(sum(gas)),
        "gas_mean": mean(gas),
        "gas_p50": percentile(gas, 0.50),
        "gas_p95": percentile(gas, 0.95),
        "calldata_bytes_total": int(sum(calldata)),
        "calldata_bytes_mean": mean(calldata),
        "calldata_bytes_p50": percentile(calldata, 0.50),
        "calldata_bytes_p95": percentile(calldata, 0.95),
        "runner_finalization_latency_ms_mean": mean(latency),
        "runner_finalization_latency_ms_p50": percentile(latency, 0.50),
        "runner_finalization_latency_ms_p95": percentile(latency, 0.95),
        "unique_blocks": {
            network: len(values) for network, values in sorted(blocks.items())
        },
    }


def attempt_metrics(rows: list[sqlite3.Row]) -> dict[str, Any]:
    grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[str(row["attempt_id"])].append(row)
    latencies = [
        (
            max(float(item["finalized_at"]) for item in items)
            - min(float(item["prepared_at"]) for item in items)
        )
        * 1000
        for items in grouped.values()
    ]
    return {
        "logical_attempts": len(grouped),
        "end_to_end_latency_ms_mean": mean(latencies),
        "end_to_end_latency_ms_p50": percentile(latencies, 0.50),
        "end_to_end_latency_ms_p95": percentile(latencies, 0.95),
    }


def flatten_csv(groups: dict[str, dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for dimension, values in groups.items():
        for group, value in values.items():
            output.append(
                {
                    "dimension": dimension,
                    "group": group,
                    **{
                        key: item
                        for key, item in value.items()
                        if not isinstance(item, dict)
                    },
                }
            )
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path)
    arguments = parser.parse_args()
    with sqlite3.connect(
        f"file:{arguments.database}?mode=ro",
        uri=True,
    ) as connection:
        connection.row_factory = sqlite3.Row
        rows = list(
            connection.execute(
                """
                SELECT attempt_id, route, execution_class, stage, gas_used,
                       calldata_bytes, prepared_at, submitted_at, finalized_at,
                       block_number, network_id, xir_event_count,
                       application_event_count, retry_generation
                FROM local_route_stages
                WHERE state = 'finalized'
                """
            )
        )
    if len(rows) != 120_000:
        raise RuntimeError("analysis requires exactly 120,000 finalized transactions")
    grouped_rows: dict[str, dict[str, list[sqlite3.Row]]] = {
        "by_route": defaultdict(list),
        "by_execution_class": defaultdict(list),
        "by_route_stage": defaultdict(list),
    }
    for row in rows:
        route = str(row["route"])
        execution_class = str(row["execution_class"])
        stage = STAGES[int(row["stage"])]
        grouped_rows["by_route"][route].append(row)
        grouped_rows["by_execution_class"][execution_class].append(row)
        grouped_rows["by_route_stage"][f"{route}/{stage}"].append(row)
    result_groups = {
        dimension: {
            key: {**metrics(items), **attempt_metrics(items)}
            for key, items in sorted(values.items())
        }
        for dimension, values in grouped_rows.items()
    }
    homogeneous_intermediate = [
        row
        for row in rows
        if row["execution_class"] == "homogeneous-native" and row["stage"] == 1
    ]
    heterogeneous_intermediate = [
        row
        for row in rows
        if row["execution_class"] == "heterogeneous-xir" and row["stage"] == 1
    ]
    homogeneous_gas = mean(float(item["gas_used"]) for item in homogeneous_intermediate)
    heterogeneous_gas = mean(
        float(item["gas_used"]) for item in heterogeneous_intermediate
    )
    homogeneous_calldata = mean(
        float(item["calldata_bytes"]) for item in homogeneous_intermediate
    )
    heterogeneous_calldata = mean(
        float(item["calldata_bytes"]) for item in heterogeneous_intermediate
    )
    first = min(float(item["prepared_at"]) for item in rows)
    last = max(float(item["finalized_at"]) for item in rows)
    document = {
        "schema_version": "xir-lab-local-paper-scale-analysis-v2",
        "environment": "controlled-local-qbft",
        "workload_model": "controlled-protocol-distinct-adapters",
        "sample": {
            "designated_attempts": 40_000,
            "attempts_per_route": 10_000,
            "physical_transactions": len(rows),
            "transactions_per_route": 30_000,
            "xir_transitions": sum(int(item["xir_event_count"]) for item in rows),
            "application_effects": sum(
                int(item["application_event_count"]) for item in rows
            ),
            "retry_generations": sum(int(item["retry_generation"]) for item in rows),
        },
        "elapsed_seconds": last - first,
        "controlled_physical_transactions_per_second": len(rows) / (last - first),
        "descriptive_results": result_groups,
        "pooled_descriptive_comparison": {
            "scope": "intermediate-stage only",
            "homogeneous_routes": ["HH", "LL"],
            "heterogeneous_routes": ["HL", "LH"],
            "sample_transactions_per_class": 20_000,
            "heterogeneous_minus_homogeneous_mean_gas": (
                heterogeneous_gas - homogeneous_gas
            ),
            "heterogeneous_gas_overhead_percent": (
                (heterogeneous_gas / homogeneous_gas) - 1
            )
            * 100,
            "heterogeneous_minus_homogeneous_mean_calldata_bytes": (
                heterogeneous_calldata - homogeneous_calldata
            ),
            "limitation": (
                "The pooled comparison is descriptive because route direction "
                "and carrier order are not separately randomized."
            ),
        },
        "claim_boundaries": [
            "Latency and throughput are observed on one controlled local QBFT host.",
            "Hyperlane and LayerZero are protocol-distinct controlled adapters, not vendor deployments.",
            "Gas is EVM execution gas and excludes public L1 or rollup data fees.",
            "Results do not establish public or production capacity, cost, security, or reliability.",
        ],
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if arguments.csv_output is not None:
        csv_rows = flatten_csv(result_groups)
        fields = sorted({key for row in csv_rows for key in row})
        with arguments.csv_output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=fields,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(csv_rows)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
