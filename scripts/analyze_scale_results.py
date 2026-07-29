#!/usr/bin/env python3
"""Compute claim-bounded descriptive results from reconciled scale evidence."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

STAGES = {0: "source", 1: "intermediate", 2: "destination"}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def metrics(rows: list[sqlite3.Row]) -> dict[str, Any]:
    gas = [int(item["gas_used"]) for item in rows]
    latency = [
        (float(item["finalized_at"]) - float(item["submitted_at"])) * 1000
        for item in rows
    ]
    return {
        "physical_transactions": len(rows),
        "gas_total": sum(gas),
        "gas_mean": sum(gas) / len(gas),
        "gas_p50": percentile([float(item) for item in gas], 0.50),
        "gas_p95": percentile([float(item) for item in gas], 0.95),
        "runner_finalization_latency_ms_mean": sum(latency) / len(latency),
        "runner_finalization_latency_ms_p50": percentile(latency, 0.50),
        "runner_finalization_latency_ms_p95": percentile(latency, 0.95),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    with sqlite3.connect(
        f"file:{arguments.database}?mode=ro",
        uri=True,
    ) as connection:
        connection.row_factory = sqlite3.Row
        rows = list(
            connection.execute(
                """
                SELECT condition, arm, stage, gas_used,
                       submitted_at, finalized_at
                FROM local_stages
                WHERE state = 'finalized'
                """
            )
        )
    groups: dict[str, dict[str, list[sqlite3.Row]]] = {
        "by_arm": defaultdict(list),
        "by_stage_arm": defaultdict(list),
        "by_condition_arm": defaultdict(list),
    }
    for row in rows:
        arm = str(row["arm"])
        groups["by_arm"][arm].append(row)
        groups["by_stage_arm"][f"{STAGES[int(row['stage'])]}/{arm}"].append(row)
        groups["by_condition_arm"][f"{row['condition']}/{arm}"].append(row)
    result_groups = {
        dimension: {
            key: metrics(items)
            for key, items in sorted(values.items())
        }
        for dimension, values in groups.items()
    }
    baseline_gas = result_groups["by_arm"]["baseline"]["gas_mean"]
    xir_gas = result_groups["by_arm"]["xir"]["gas_mean"]
    document = {
        "schema_version": "xir-lab-local-scale-analysis-v1",
        "environment": "controlled-local-qbft",
        "sample": {
            "designated_attempts": 10_000,
            "physical_transactions": len(rows),
            "balanced_condition_arm_stage_rows": 3_750,
        },
        "descriptive_results": result_groups,
        "comparisons": {
            "xir_minus_baseline_mean_gas": xir_gas - baseline_gas,
            "xir_gas_overhead_percent": (
                (xir_gas / baseline_gas) - 1
            ) * 100,
        },
        "claim_boundaries": [
            "Latency is runner-observed finalization time on controlled local QBFT.",
            "Gas is EVM execution gas and excludes public L1 or rollup data fees.",
            "The workload models three stages; it is not public carrier traffic.",
            "Results do not establish production capacity or reliability.",
        ],
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
