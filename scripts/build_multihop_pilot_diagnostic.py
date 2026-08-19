#!/usr/bin/env python3
"""Build a claim-ineligible pilot diagnostic when TRACE attribution is unavailable."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, cast

import rfc8785

from xir_lab.native.ablation_freeze_v2 import secret_scan
from xir_lab.native.multihop_scalability import (
    ROUTE_ORDER,
    expected_coordinator_transactions,
    expected_physical_transactions,
    switch_count,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(*, runtime: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError("pilot diagnostic output already exists")
    output.mkdir(parents=True)
    run = runtime / "runs/scale"
    with sqlite3.connect(f"file:{run / 'runner.sqlite'}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        attempts = db.execute(
            "SELECT attempt_id,route,route_sequence,status FROM attempts WHERE phase='scale'"
        ).fetchall()
        stages = db.execute(
            """
            SELECT a.route,a.attempt_id,s.stage,s.state,s.transaction_hash
            FROM attempts a JOIN stages s ON s.attempt_id=a.attempt_id
            WHERE a.phase='scale'
            """
        ).fetchall()
        errors = int(db.execute("SELECT COUNT(*) FROM attempt_errors").fetchone()[0])
    route_counts = Counter(str(row["route"]) for row in attempts if row["status"] == "succeeded")
    observed_by_attempt = Counter(str(row["attempt_id"]) for row in stages if row["state"] == "succeeded")
    stage_mismatches = []
    for attempt in attempts:
        expected = expected_coordinator_transactions(str(attempt["route"]))
        observed = observed_by_attempt[str(attempt["attempt_id"])]
        if observed != expected:
            stage_mismatches.append(
                {
                    "attempt_id": attempt["attempt_id"],
                    "route": attempt["route"],
                    "expected_coordinator_transactions": expected,
                    "observed_coordinator_transactions": observed,
                }
            )
    traces = run / "traces.sqlite"
    trace_count = trace_unavailable = 0
    if traces.is_file():
        with sqlite3.connect(f"file:{traces}?mode=ro", uri=True) as db:
            trace_count = int(db.execute("SELECT COUNT(*) FROM traces").fetchone()[0])
            trace_unavailable = int(
                db.execute(
                    "SELECT COUNT(*) FROM traces WHERE trace_json LIKE '%trace_unavailable%'"
                ).fetchone()[0]
            )
    rows = []
    for route in ROUTE_ORDER:
        rows.append(
            {
                "route": route,
                "hop_count": len(route),
                "switch_count": switch_count(route),
                "successful_attempts": route_counts[route],
                "expected_coordinator_transactions_per_attempt": expected_coordinator_transactions(route),
                "expected_physical_transactions_per_attempt": expected_physical_transactions(route),
            }
        )
    with (output / "route-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-pilot-diagnostic-v1",
        "namespace": "native-multihop-switching-pilot-v1",
        "role": "pilot_diagnostic_only",
        "claim_eligible": False,
        "run_id": runtime.name,
        "attempt_count": len(attempts),
        "successful_attempt_count": sum(route_counts.values()),
        "attempt_error_count": errors,
        "route_counts": dict(sorted(route_counts.items())),
        "coordinator_stage_mismatch_count": len(stage_mismatches),
        "coordinator_stage_mismatches": stage_mismatches,
        "trace_evidence": {
            "physical_transaction_expected_count": sum(
                route_counts[route] * expected_physical_transactions(route)
                for route in ROUTE_ORDER
            ),
            "trace_row_count": trace_count,
            "trace_unavailable_count": trace_unavailable,
            "internal_call_gas_attribution_status": "not_observed",
            "reason": "Besu trace_transaction returned empty for finalized successful transactions",
        },
        "experiment_1_status": "attempt_and_transaction_accounting_complete; internal_trace_gas_model_not_released",
        "experiment_2_status": "not_released_without_internal_trace_gas; latency/calldata remain diagnostic",
        "gateway_analysis_status": "run_separately_from_frozen_connectivity_inputs",
        "go_no_go": "NO_GO_FOR_FORMAL_110000_UNTIL_TRACE_ATTRIBUTION_IS_FIXED_OR_PREREGISTERED_AS_UNOBSERVED",
        "boundaries": [
            "100 attempts per route; 1100 attempts total",
            "pilot diagnostic only",
            "must not enter formal Figure 8 or manuscript claims",
            "run-003 and all prior evidence remain separate",
        ],
        "source_sha256": {
            "runner.sqlite": _sha(run / "runner.sqlite"),
            "root-signer-audit.jsonl": _sha(run / "root-signer-audit.jsonl"),
            "hyperlane-processes.json": _sha(run / "hyperlane-processes.json"),
            "resource-samples.jsonl": _sha(run / "resource-samples.jsonl"),
            "incidents.json": _sha(run / "incidents.json"),
            "config.json": _sha(Path(__file__).resolve().parents[1] / "configs/native/native-multihop-switching-pilot-v1.json"),
        },
    }
    report["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(report)).hexdigest()
    _write(output / "diagnostic.json", report)
    (output / "REPORT.md").write_text(
        "# Native multihop pilot diagnostic\n\n"
        f"- Run: `{runtime.name}`\n"
        f"- Attempts: {report['successful_attempt_count']}/1,100\n"
        f"- Route cells: 11 x 100\n"
        f"- Attempt errors: {errors}\n"
        f"- Coordinator stage mismatches: {len(stage_mismatches)}\n"
        f"- TRACE rows: {trace_count}; unavailable: {trace_unavailable}\n"
        "- Decision: **NO-GO** for the 110,000-attempt formal campaign until internal TRACE attribution is fixed or preregistered as unobserved.\n"
        "- Scope: pilot diagnostic only; not claim-eligible.\n",
        encoding="utf-8",
    )
    findings = secret_scan(output)
    if findings:
        raise RuntimeError("pilot diagnostic secret scan failed: " + ", ".join(findings))
    manifest = {
        "schema_version": "xir-lab-native-multihop-pilot-diagnostic-manifest-v1",
        "claim_eligible": False,
        "files": {
            path.relative_to(output).as_posix(): _sha(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    }
    manifest["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(cast(Any, manifest))
    ).hexdigest()
    _write(output / "manifest.json", manifest)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(runtime=args.runtime, output=args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
