#!/usr/bin/env python3
"""Build exact reconciliation evidence for the four-route scale database."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

ROUTES = ("HH", "HL", "LH", "LL")
EXPECTED_ATTEMPTS_PER_ROUTE = 10_000
EXPECTED_ATTEMPTS = 40_000
EXPECTED_TRANSACTIONS = 120_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--signed-spool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    with sqlite3.connect(
        f"file:{arguments.database}?mode=ro",
        uri=True,
    ) as connection:
        states = dict(
            connection.execute(
                "SELECT state, count(*) FROM local_route_stages GROUP BY state"
            ).fetchall()
        )
        stages = dict(
            connection.execute(
                "SELECT stage, count(*) FROM local_route_stages GROUP BY stage"
            ).fetchall()
        )
        route_stage_rows = {
            route: count
            for route, count in connection.execute(
                "SELECT route, count(*) FROM local_route_stages GROUP BY route"
            ).fetchall()
        }
        route_attempts = {
            route: count
            for route, count in connection.execute(
                """
                SELECT route, count(DISTINCT attempt_id)
                FROM local_route_stages GROUP BY route
                """
            ).fetchall()
        }
        row = connection.execute(
            """
            SELECT count(*), count(DISTINCT attempt_id),
                   count(DISTINCT transaction_hash),
                   coalesce(sum(gas_used), 0),
                   coalesce(sum(calldata_bytes), 0),
                   sum(block_number IS NULL OR block_hash IS NULL
                       OR block_timestamp IS NULL OR receipt_status IS NULL),
                   coalesce(sum(xir_event_count), 0),
                   coalesce(sum(application_event_count), 0),
                   coalesce(sum(route_event_count), 0),
                   count(DISTINCT network_id || ':' || nonce),
                   coalesce(sum(retry_generation), 0),
                   min(prepared_at), max(finalized_at)
            FROM local_route_stages
            """
        ).fetchone()
        semantic_errors = int(
            connection.execute(
                """
                SELECT count(*) FROM local_route_stages
                WHERE
                    (route = 'HH' AND (
                        first_carrier != 'hyperlane'
                        OR second_carrier != 'hyperlane'
                        OR xir != 0
                        OR execution_class != 'homogeneous-native'))
                    OR
                    (route = 'HL' AND (
                        first_carrier != 'hyperlane'
                        OR second_carrier != 'layerzero-v2'
                        OR xir != 1
                        OR execution_class != 'heterogeneous-xir'))
                    OR
                    (route = 'LH' AND (
                        first_carrier != 'layerzero-v2'
                        OR second_carrier != 'hyperlane'
                        OR xir != 1
                        OR execution_class != 'heterogeneous-xir'))
                    OR
                    (route = 'LL' AND (
                        first_carrier != 'layerzero-v2'
                        OR second_carrier != 'layerzero-v2'
                        OR xir != 0
                        OR execution_class != 'homogeneous-native'))
                    OR route_event_count != 1
                    OR (stage = 1 AND xir = 1 AND (
                        xir_event_count != 1
                        OR xir_transition_digest IS NULL))
                    OR (NOT (stage = 1 AND xir = 1) AND (
                        xir_event_count != 0
                        OR xir_transition_digest IS NOT NULL))
                    OR (stage = 2 AND application_event_count != 1)
                    OR (stage != 2 AND application_event_count != 0)
                    OR prior_envelope IS NULL
                    OR stage_envelope IS NULL
                    OR receipt_status != 1
                """
            ).fetchone()[0]
        )
        stage_dependency_errors = int(
            connection.execute(
                """
                SELECT count(*) FROM (
                    SELECT attempt_id
                    FROM local_route_stages
                    GROUP BY attempt_id
                    HAVING count(*) != 3
                       OR min(stage) != 0
                       OR max(stage) != 2
                       OR count(DISTINCT stage) != 3
                       OR count(DISTINCT route) != 1
                       OR count(DISTINCT payload_hash) != 1
                )
                """
            ).fetchone()[0]
        )
        envelope_link_errors = int(
            connection.execute(
                """
                SELECT count(*)
                FROM local_route_stages source
                JOIN local_route_stages intermediate
                  ON intermediate.attempt_id = source.attempt_id
                 AND intermediate.stage = 1
                JOIN local_route_stages destination
                  ON destination.attempt_id = source.attempt_id
                 AND destination.stage = 2
                WHERE source.stage = 0
                  AND (
                    source.stage_envelope != intermediate.prior_envelope
                    OR intermediate.stage_envelope
                       != destination.prior_envelope
                  )
                """
            ).fetchone()[0]
        )
        route_sequence_errors = int(
            connection.execute(
                """
                SELECT count(*) FROM (
                    SELECT route
                    FROM local_route_stages
                    WHERE stage = 0
                    GROUP BY route
                    HAVING count(DISTINCT route_sequence) != 10000
                       OR min(route_sequence) != 0
                       OR max(route_sequence) != 9999
                )
                """
            ).fetchone()[0]
        )
        payload_distributions = {
            route: list(
                connection.execute(
                    """
                    SELECT payload_bytes, count(DISTINCT attempt_id)
                    FROM local_route_stages
                    WHERE route = ? GROUP BY payload_bytes ORDER BY payload_bytes
                    """,
                    (route,),
                ).fetchall()
            )
            for route in ROUTES
        }
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    spool_files = sum(item.is_file() for item in arguments.signed_spool.rglob("*"))
    checks = {
        "sqlite_integrity": integrity == "ok",
        "all_finalized": states == {"finalized": EXPECTED_TRANSACTIONS},
        "stage_balance": stages == {0: 40_000, 1: 40_000, 2: 40_000},
        "route_stage_balance": route_stage_rows
        == {route: 30_000 for route in ROUTES},
        "route_attempt_balance": route_attempts
        == {route: EXPECTED_ATTEMPTS_PER_ROUTE for route in ROUTES},
        "attempt_identity_count": int(row[1]) == EXPECTED_ATTEMPTS,
        "transaction_hash_uniqueness": int(row[2]) == EXPECTED_TRANSACTIONS,
        "receipts_complete": int(row[5]) == 0,
        "xir_transition_count": int(row[6]) == 20_000,
        "application_effect_count": int(row[7]) == EXPECTED_ATTEMPTS,
        "route_event_count": int(row[8]) == EXPECTED_TRANSACTIONS,
        "nonce_uniqueness": int(row[9]) == EXPECTED_TRANSACTIONS,
        "route_semantics": semantic_errors == 0,
        "three_stage_dependencies": stage_dependency_errors == 0,
        "envelope_links": envelope_link_errors == 0,
        "route_sequence_coverage": route_sequence_errors == 0,
        "payload_balance": len(
            {
                tuple((int(size), int(count)) for size, count in values)
                for values in payload_distributions.values()
            }
        )
        == 1,
        "signed_spool_empty": spool_files == 0,
    }
    document = {
        "schema_version": "xir-lab-local-paper-scale-reconciliation-v2",
        "eligible": all(checks.values()),
        "checks": checks,
        "states": states,
        "stages": {str(key): value for key, value in stages.items()},
        "route_stage_rows": route_stage_rows,
        "route_attempts": route_attempts,
        "payload_distributions": {
            route: [
                {"payload_bytes": int(size), "attempts": int(count)}
                for size, count in values
            ]
            for route, values in payload_distributions.items()
        },
        "counts": {
            "physical_transactions": int(row[0]),
            "distinct_attempts": int(row[1]),
            "distinct_transaction_hashes": int(row[2]),
            "gas_used": int(row[3]),
            "calldata_bytes": int(row[4]),
            "xir_transitions": int(row[6]),
            "application_effects": int(row[7]),
            "route_events": int(row[8]),
            "retry_generations": int(row[10]),
            "signed_spool_files": spool_files,
        },
        "semantic_error_rows": semantic_errors,
        "stage_dependency_error_attempts": stage_dependency_errors,
        "envelope_link_error_attempts": envelope_link_errors,
        "observed_from_epoch_seconds": float(row[11]),
        "observed_through_epoch_seconds": float(row[12]),
        "evidence_sha256": hashlib.sha256(arguments.database.read_bytes()).hexdigest(),
    }
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
