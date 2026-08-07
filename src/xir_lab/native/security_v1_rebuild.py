"""Deterministic offline rebuild for native-security-v1 evidence.

The rebuild reads only frozen SQLite/JSON/receipt files.  It does not contact
an RPC endpoint and never reads private keys or signed-transaction spools.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, cast

from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import PROFILE_HASHES
from xir_lab.native.security_v1 import EXPECTED_ERROR, case_attempt, load_security_config
from xir_lab.native.security_v1_profile_evidence import (
    decode_set_profile,
    profile_event,
)
from xir_lab.publication import PublicationError, validate_publishable_file

SECURITY_CLASSIFICATION: dict[str, dict[str, Any]] = {
    "payload_tamper": {
        "input_class": "mutated_untrusted_payload",
        "target_guarantees": ["G1_AUTHENTICITY"],
        "primary_check_stage": "destination_payload_binding",
    },
    "context_tamper": {
        "input_class": "mutated_untrusted_context",
        "target_guarantees": ["G1_AUTHENTICITY", "G3_POLICY_COMPLIANCE"],
        "primary_check_stage": "source_root_verification",
    },
    "profile_substitution": {
        "input_class": "unregistered_profile_reference",
        "target_guarantees": ["G3_POLICY_COMPLIANCE"],
        "primary_check_stage": "profile_resolution",
    },
    "profile_inactive": {
        "input_class": "inactive_profile_reference",
        "target_guarantees": ["G3_POLICY_COMPLIANCE"],
        "primary_check_stage": "profile_activity_check",
    },
    "receipt_delete": {
        "input_class": "receipt_sequence_omission",
        "target_guarantees": ["G2_TRACE_INTEGRITY"],
        "primary_check_stage": "receipt_prefix_verification",
    },
    "receipt_reorder": {
        "input_class": "receipt_sequence_reordering",
        "target_guarantees": ["G2_TRACE_INTEGRITY"],
        "primary_check_stage": "receipt_prefix_verification",
    },
    "evidence_tamper": {
        "input_class": "mutated_native_evidence_reference",
        "target_guarantees": ["G1_AUTHENTICITY", "G2_TRACE_INTEGRITY"],
        "primary_check_stage": "native_evidence_verification",
    },
    "wrong_registry_version": {
        "input_class": "unbound_registry_version_reference",
        "target_guarantees": ["G1_AUTHENTICITY", "G3_POLICY_COMPLIANCE"],
        "primary_check_stage": "root_version_verification",
    },
    "cross_execution_splice": {
        "input_class": "cross_execution_tuple_splice",
        "target_guarantees": ["G2_TRACE_INTEGRITY"],
        "primary_check_stage": "ordered_final_bundle_verification",
    },
    "sequential_replay": {
        "input_class": "duplicate_valid_envelope_sequential",
        "target_guarantees": ["G4_AT_MOST_ONCE_EFFECT"],
        "primary_check_stage": "atomic_message_consumption",
    },
    "concurrent_replay": {
        "input_class": "duplicate_valid_envelope_concurrent",
        "target_guarantees": ["G4_AT_MOST_ONCE_EFFECT"],
        "primary_check_stage": "atomic_message_consumption",
    },
    "fake_verifier": {
        "input_class": "runner_selected_unapproved_verifier",
        "target_guarantees": ["G1_AUTHENTICITY", "G2_TRACE_INTEGRITY"],
        "primary_check_stage": "prior_verifier_binding",
    },
    "wrong_endpoint": {
        "input_class": "profile_endpoint_mismatch",
        "target_guarantees": ["G1_AUTHENTICITY", "G2_TRACE_INTEGRITY"],
        "primary_check_stage": "prior_verifier_binding",
    },
}
TRUSTED_ASSUMPTION_STATUS = "none (A1-A4 hold)"
AUTHORITY_CASES = frozenset({"fake_verifier", "wrong_endpoint"})


def _campaign_version(config: dict[str, Any]) -> str:
    return "v2" if config.get("campaign_id") == "native-security-v2" else "v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_case_rows(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT * FROM cases ORDER BY route, case_name, repetition"
        ).fetchall()
    finally:
        connection.close()
    output: list[dict[str, Any]] = []
    for row in rows:
        value = dict(row)
        value["result"] = (
            json.loads(value.pop("result_json")) if value["result_json"] is not None else None
        )
        value["planned"] = json.loads(value.pop("planned_json"))
        output.append(value)
    return output


def _runner_attempts(
    path: Path,
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        attempts = {
            str(attempt_id): str(status)
            for attempt_id, status in connection.execute(
                "SELECT attempt_id, status FROM attempts"
            ).fetchall()
        }
        succeeded_stages: dict[str, set[str]] = {}
        failed_stages: dict[str, set[str]] = {}
        for attempt_id, stage, state in connection.execute(
            "SELECT attempt_id, stage, state FROM stages"
        ).fetchall():
            if str(state) == "succeeded":
                succeeded_stages.setdefault(str(attempt_id), set()).add(str(stage))
            elif str(state) == "failed":
                failed_stages.setdefault(str(attempt_id), set()).add(str(stage))
    finally:
        connection.close()
    return attempts, succeeded_stages, failed_stages


def _audit_rows(path: Path) -> list[dict[str, Any]]:
    return [
        cast(dict[str, Any], json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _profile_inactive_lineage(
    *,
    rows: list[dict[str, Any]],
    owner_receipts: list[Path],
    evidence_root: Path,
    registry_address: str,
    config_sha256: str,
    deployment_sha256: str,
    campaign_version: str,
) -> dict[str, Any]:
    """Reconstruct disable -> reject -> restore for all profile-inactive cases."""

    errors: list[str] = []
    capture_path = evidence_root / "profile-transaction-capture.json"
    capture: dict[str, Any] = {}
    if not capture_path.is_file():
        errors.append("profile transaction capture is missing")
    else:
        try:
            capture = cast(dict[str, Any], json.loads(capture_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"profile transaction capture is unreadable: {exc}")
    if capture:
        if capture.get("valid") is not True:
            errors.append("profile transaction capture is not valid")
        if capture.get("config_sha256") != config_sha256:
            errors.append("profile transaction capture config digest mismatch")
        if capture.get("deployment_sha256") != deployment_sha256:
            errors.append("profile transaction capture deployment digest mismatch")
        if str(capture.get("registry_address", "")).lower() != registry_address:
            errors.append("profile transaction capture registry mismatch")

    capture_rows = {
        str(item.get("transaction_hash", "")).lower(): item
        for item in cast(list[dict[str, Any]], capture.get("transactions", []))
    }
    mutations: list[dict[str, Any]] = []
    for receipt_path in owner_receipts:
        tx_hash = receipt_path.stem.lower()
        try:
            receipt = cast(dict[str, Any], json.loads(receipt_path.read_text(encoding="utf-8")))
            event = profile_event(receipt, registry_address)
            transaction_path = evidence_root / "raw-profile-transactions" / f"{tx_hash}.json"
            if not transaction_path.is_file():
                raise LocalTopologyError("captured profile transaction is missing")
            transaction = cast(
                dict[str, Any],
                json.loads(transaction_path.read_text(encoding="utf-8")),
            )
            decoded = decode_set_profile(transaction)
            captured = capture_rows.get(tx_hash)
            if captured is None:
                raise LocalTopologyError("transaction is absent from capture inventory")
            receipt_digest = _sha256(receipt_path)
            transaction_digest = _sha256(transaction_path)
            if (
                captured.get("receipt_sha256") != receipt_digest
                or captured.get("transaction_sha256") != transaction_digest
            ):
                raise LocalTopologyError("capture inventory digest mismatch")
            if (
                str(transaction.get("transaction_hash", "")).lower() != tx_hash
                or str(transaction.get("to", "")).lower() != registry_address
                or int(transaction.get("block_number", -1)) != int(receipt["blockNumber"])
                or int(transaction.get("transaction_index", -1)) != int(receipt["transactionIndex"])
                or decoded["profile_hash"] != event["profile_hash"]
                or decoded["src_hash"] != event["src_hash"]
                or decoded["dst_hash"] != event["dst_hash"]
            ):
                raise LocalTopologyError("profile calldata/event/receipt mismatch")
            mutations.append(
                {
                    "transaction_hash": tx_hash,
                    "block_number": int(receipt["blockNumber"]),
                    "transaction_index": int(receipt["transactionIndex"]),
                    "receipt_sha256": receipt_digest,
                    "transaction_sha256": transaction_digest,
                    **decoded,
                    "event": event,
                }
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            OSError,
            json.JSONDecodeError,
            LocalTopologyError,
        ) as exc:
            errors.append(f"profile mutation evidence {tx_hash}: {exc}")

    mutations.sort(key=lambda item: (item["block_number"], item["transaction_index"]))
    if set(capture_rows) != {item["transaction_hash"] for item in mutations}:
        errors.append("profile capture inventory does not equal decoded mutation set")
    if len(mutations) % 2:
        errors.append("profile mutation sequence has an odd length")

    inactive_rows: list[dict[str, Any]] = []
    for row in rows:
        if row["case_name"] != "profile_inactive" or row["result"] is None:
            continue
        result = cast(dict[str, Any], row["result"])
        transactions = cast(list[dict[str, Any]], result.get("transactions", []))
        if len(transactions) != 1:
            errors.append(f"profile inactive delivery count: {row['route']}/{row['repetition']}")
            continue
        transaction = transactions[0]
        inactive_rows.append(
            {
                "row": row,
                "result": result,
                "delivery": transaction,
                "position": (
                    int(transaction.get("block_number", -1)),
                    int(transaction.get("transaction_index", 0)),
                ),
            }
        )
    inactive_rows.sort(key=lambda item: item["position"])

    cases: list[dict[str, Any]] = []
    pairs = [mutations[index : index + 2] for index in range(0, len(mutations), 2)]
    if len(pairs) != len(inactive_rows):
        errors.append(
            "profile state/case denominator mismatch: "
            f"pairs={len(pairs)}, cases={len(inactive_rows)}"
        )
    for pair_index, (pair, case_item) in enumerate(zip(pairs, inactive_rows, strict=False)):
        if len(pair) != 2:
            continue
        disable, restore = pair
        row = cast(dict[str, Any], case_item["row"])
        result = cast(dict[str, Any], case_item["result"])
        delivery = cast(dict[str, Any], case_item["delivery"])
        route = str(row["route"])
        expected_profile = "0x" + PROFILE_HASHES[f"{route[0]}_AB"].hex()
        disable_position = (
            int(disable["block_number"]),
            int(disable["transaction_index"]),
        )
        restore_position = (
            int(restore["block_number"]),
            int(restore["transaction_index"]),
        )
        delivery_position = cast(tuple[int, int], case_item["position"])
        same_snapshot = all(
            disable[field] == restore[field]
            for field in (
                "profile_hash",
                "src_hash",
                "dst_hash",
                "adapter",
                "security_level",
                "valid_after",
                "valid_until",
            )
        )
        checks = {
            "ordered": disable_position < delivery_position < restore_position,
            "disabled": disable["enabled"] is False,
            "restored": restore["enabled"] is True,
            "same_snapshot": same_snapshot,
            "expected_profile": disable["profile_hash"] == expected_profile,
            "event_profile": (
                disable["event"]["profile_hash"] == expected_profile
                and restore["event"]["profile_hash"] == expected_profile
            ),
            "delivery_rejected": int(delivery.get("status", -1)) == 0,
            "rejection_stage": delivery.get("revert_error") == "ProfileInactive",
            "no_rejection_effect": (
                result.get("rejection_application_effect_delta") == 0
                and result.get("application_effect_delta") == 0
            ),
            "gateway_unconsumed": result.get("after", {}).get("gateway_consumed") is False,
            "receiver_unconsumed": result.get("after", {}).get("receiver_attempt_consumed")
            is False,
        }
        if not all(checks.values()):
            failed = ",".join(name for name, passed in checks.items() if not passed)
            errors.append(f"profile inactive lineage {route}/{row['repetition']}: {failed}")
        cases.append(
            {
                "route": route,
                "case": "profile_inactive",
                "repetition": int(row["repetition"]),
                "attempt_id": str(row["attempt_id"]),
                "profile_hash": expected_profile,
                "disable": disable,
                "rejected_delivery": {
                    "transaction_hash": str(delivery["transaction_hash"]).lower(),
                    "block_number": delivery_position[0],
                    "transaction_index": delivery_position[1],
                    "status": int(delivery["status"]),
                    "revert_error": delivery.get("revert_error"),
                    "receipt_sha256": delivery.get("receipt_sha256"),
                    "application_effect_delta": result.get("application_effect_delta"),
                    "gateway_consumed_after": result.get("after", {}).get("gateway_consumed"),
                    "receiver_attempt_consumed_after": result.get("after", {}).get(
                        "receiver_attempt_consumed"
                    ),
                },
                "restore": restore,
                "checks": checks,
                "valid": all(checks.values()),
                "sequence_index": pair_index,
            }
        )

    cases.sort(key=lambda item: (item["route"], item["repetition"]))
    return {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-profile-lineage-v1"),
        "capture_sha256": _sha256(capture_path) if capture_path.is_file() else None,
        "expected_cases": len(inactive_rows),
        "observed_cases": len(cases),
        "profile_mutations": len(mutations),
        "cases": cases,
        "errors": errors,
        "valid": not errors and len(cases) == len(inactive_rows),
    }


def _validate(
    *,
    rows: list[dict[str, Any]],
    config: dict[str, Any],
    config_sha256: str,
    deployment: dict[str, Any],
    deployment_sha256: str,
    evidence_root: Path,
    runner_state_path: Path,
    root_audit_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    campaign_version = _campaign_version(config)
    routes = cast(list[str], config["routes"])
    cases = cast(list[str], config["cases"])
    repetitions = int(config["repetitions_per_route_case"])
    expected_count = len(routes) * len(cases) * repetitions
    expected_coordinates = {
        (route, case, repetition)
        for route in routes
        for case in cases
        for repetition in range(repetitions)
    }
    observed_coordinates: set[tuple[str, str, int]] = set()
    primary_attempt_ids: set[str] = set()
    transaction_hashes: set[str] = set()
    expected_raw_receipt_hashes: set[str] = set()
    raw_receipts_checked = 0
    authority_receipts_checked = 0
    authority_receipt_root = (evidence_root / "native-preparation-receipts").resolve()
    fixture_address = str(
        deployment.get("security_v2_fixtures", {}).get("always_true_prior_verifier", "")
    ).lower()
    intermediate = cast(dict[str, Any], deployment.get("chains", {}).get("intermediate", {}))

    for row in rows:
        route = str(row["route"])
        case = str(row["case_name"])
        repetition = int(row["repetition"])
        coordinate = (route, case, repetition)
        if coordinate in observed_coordinates:
            errors.append(f"duplicate coordinate: {route}/{case}/{repetition}")
        observed_coordinates.add(coordinate)
        expected_attempt = case_attempt(
            campaign_id=str(config["campaign_id"]),
            route=route,
            case=case,
            repetition=repetition,
        )
        primary_attempt_ids.add(expected_attempt.attempt_id)
        if row["attempt_id"] != expected_attempt.attempt_id:
            errors.append(f"attempt identity mismatch: {route}/{case}/{repetition}")
        if row["planned"] != expected_attempt.__dict__:
            errors.append(f"planned attempt mismatch: {route}/{case}/{repetition}")
        if row["status"] != "validated" or row["result"] is None:
            errors.append(f"case not validated: {route}/{case}/{repetition}")
            continue

        result = cast(dict[str, Any], row["result"])
        authority_case = case in AUTHORITY_CASES
        expected_error = EXPECTED_ERROR[case]
        expected_effects = int(config["expected_application_effects"][case])
        attempt_topic = "0x" + keccak(text=expected_attempt.attempt_id).hex()
        checks = {
            "result coordinate": (
                result.get("route") == route
                and result.get("case") == case
                and int(result.get("repetition", -1)) == repetition
                and result.get("attempt_id") == expected_attempt.attempt_id
            ),
            "expected rejection": result.get("expected_rejection") == expected_error,
            "actual rejection": result.get("actual_rejections") == [expected_error],
            "expected effects": result.get("expected_application_effects") == expected_effects,
            "observed effects": result.get("application_effect_delta") == expected_effects,
            "rejection effects": result.get("rejection_application_effect_delta") == 0,
            "effect identities": result.get("effect_attempt_ids")
            == ([attempt_topic] if expected_effects else []),
            "root signer separated": result.get("root_signer_separated") is True,
            "before gateway": (
                authority_case or result.get("before", {}).get("gateway_consumed") is False
            ),
            "before receiver": (
                authority_case or result.get("before", {}).get("receiver_attempt_consumed") is False
            ),
            "after gateway": result.get("after", {}).get("gateway_consumed")
            is bool(expected_effects),
            "after receiver": (
                (
                    result.get("before", {}).get("receiver_delivery_count")
                    == result.get("after", {}).get("receiver_delivery_count")
                    and result.get("before", {}).get("receiver_state_hash")
                    == result.get("after", {}).get("receiver_state_hash")
                )
                if authority_case
                else result.get("after", {}).get("receiver_attempt_consumed")
                is bool(expected_effects)
            ),
            "result valid": result.get("valid") is True,
        }
        for name, passed in checks.items():
            if not passed:
                errors.append(f"{name}: {route}/{case}/{repetition}")

        transactions = cast(list[dict[str, Any]], result.get("transactions", []))
        expected_transactions = 2 if case in {"sequential_replay", "concurrent_replay"} else 1
        if len(transactions) != expected_transactions:
            errors.append(f"transaction count: {route}/{case}/{repetition}")
        statuses = sorted(int(item.get("status", -1)) for item in transactions)
        expected_statuses = [0, 1] if expected_effects else [0]
        if statuses != expected_statuses:
            errors.append(f"transaction statuses: {route}/{case}/{repetition}")
        rejected = [item for item in transactions if int(item.get("status", -1)) == 0]
        if len(rejected) != 1 or rejected[0].get("revert_error") != expected_error:
            errors.append(f"rejected transaction: {route}/{case}/{repetition}")
        for item in transactions:
            tx_hash = str(item.get("transaction_hash", "")).lower()
            normalized_tx_hash = tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}"
            if normalized_tx_hash in transaction_hashes or len(normalized_tx_hash) != 66:
                errors.append(f"transaction hash uniqueness: {route}/{case}/{repetition}")
            transaction_hashes.add(normalized_tx_hash)
            expected_topics = [attempt_topic] if int(item.get("status", -1)) == 1 else []
            if item.get("native_effect_attempt_ids") != expected_topics:
                errors.append(f"transaction effect topics: {route}/{case}/{repetition}")
            recorded_receipt = item.get("receipt")
            receipt_path = (
                Path(str(recorded_receipt))
                if authority_case and recorded_receipt
                else evidence_root / "raw-receipts" / f"{normalized_tx_hash}.json"
            )
            if authority_case:
                expected_submitted = (
                    fixture_address
                    if case == "fake_verifier"
                    else str(intermediate["l_in" if route == "HL" else "h_in"]).lower()
                )
                try:
                    receipt_path.resolve().relative_to(authority_receipt_root)
                    authority_path_valid = (
                        receipt_path.stem.lower() == normalized_tx_hash.removeprefix("0x")
                    )
                except ValueError:
                    authority_path_valid = False
                if (
                    item.get("stage") != "second_protocol_dispatch"
                    or item.get("revert_selector") != "0x819d4ecb"
                    or str(item.get("submitted_prior_verifier", "")).lower()
                    != expected_submitted
                    or not authority_path_valid
                ):
                    errors.append(f"authority rejection metadata: {route}/{case}/{repetition}")
            if not receipt_path.is_file() or _sha256(receipt_path) != item.get("receipt_sha256"):
                errors.append(f"raw receipt digest: {normalized_tx_hash}")
            else:
                raw_receipts_checked += 1
                if authority_case:
                    authority_receipts_checked += 1
                    receipt = cast(
                        dict[str, Any],
                        json.loads(receipt_path.read_text(encoding="utf-8")),
                    )
                    receipt_status = receipt.get("status", -1)
                    if isinstance(receipt_status, str):
                        receipt_status = int(receipt_status, 0)
                    if (
                        int(receipt_status) != 0
                        or item.get("revert_error") != "UnapprovedPriorVerifier"
                        or result.get("after", {}).get("gateway_consumed") is not False
                        or result.get("application_effect_delta") != 0
                    ):
                        errors.append(f"authority rejection evidence: {route}/{case}/{repetition}")
                else:
                    expected_raw_receipt_hashes.add(normalized_tx_hash)

    if observed_coordinates != expected_coordinates:
        missing = len(expected_coordinates - observed_coordinates)
        extra = len(observed_coordinates - expected_coordinates)
        errors.append(f"coordinate denominator mismatch: missing={missing}, extra={extra}")

    runner_attempts, runner_stages, runner_failed_stages = _runner_attempts(runner_state_path)
    alternate_attempt_ids = {
        case_attempt(
            campaign_id=str(config["campaign_id"]),
            route=route,
            case="cross_execution_splice",
            repetition=repetition,
        ).attempt_id
        + "_alternate"
        for route in routes
        for repetition in range(repetitions)
    }
    expected_runner_attempts = primary_attempt_ids | alternate_attempt_ids
    if set(runner_attempts) != expected_runner_attempts:
        errors.append(
            "runner attempt denominator mismatch: "
            f"observed={len(runner_attempts)}, expected={len(expected_runner_attempts)}"
        )
    required_stages = {
        "xir_root_record",
        "first_protocol_dispatch",
        "xir_transition",
        "second_protocol_dispatch",
    }
    for attempt_id in primary_attempt_ids:
        if runner_attempts.get(attempt_id) != "succeeded":
            errors.append(f"runner attempt not succeeded: {attempt_id}")
        attempt_row = next(row for row in rows if str(row["attempt_id"]) == attempt_id)
        if str(attempt_row["case_name"]) in AUTHORITY_CASES:
            if runner_stages.get(attempt_id, set()) != {
                "xir_root_record",
                "first_protocol_dispatch",
                "xir_transition",
            } or runner_failed_stages.get(attempt_id, set()) != {"second_protocol_dispatch"}:
                errors.append(f"authority runner stage lineage differs: {attempt_id}")
        elif not required_stages <= runner_stages.get(attempt_id, set()):
            errors.append(f"runner stage lineage incomplete: {attempt_id}")
    for attempt_id in alternate_attempt_ids:
        if runner_attempts.get(attempt_id) != "succeeded":
            errors.append(f"alternate runner attempt not succeeded: {attempt_id}")
        if runner_stages.get(attempt_id, set()) != {
            "first_protocol_dispatch",
            "second_protocol_dispatch",
        }:
            errors.append(f"alternate runner stage lineage differs: {attempt_id}")

    raw_receipt_paths = sorted((evidence_root / "raw-receipts").glob("0x*.json"))
    referenced_hashes = {
        path.stem.lower() for path in raw_receipt_paths
    } & expected_raw_receipt_hashes
    if referenced_hashes != expected_raw_receipt_hashes:
        errors.append("listed delivery receipt set is incomplete")
    owner_receipts = [
        path for path in raw_receipt_paths if path.stem.lower() not in expected_raw_receipt_hashes
    ]
    expected_owner_receipts = len(routes) * repetitions * 2
    if len(owner_receipts) != expected_owner_receipts:
        errors.append(
            f"profile toggle receipt count: {len(owner_receipts)} != {expected_owner_receipts}"
        )
    registry_address = str(deployment["chains"]["destination"]["registry"]).lower()
    for path in owner_receipts:
        receipt = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        if (
            int(receipt.get("status", -1)) != 1
            or str(receipt.get("to", "")).lower() != registry_address
        ):
            errors.append(f"unexpected unreferenced security receipt: {path.name}")
    profile_lineage = _profile_inactive_lineage(
        rows=rows,
        owner_receipts=owner_receipts,
        evidence_root=evidence_root,
        registry_address=registry_address,
        config_sha256=config_sha256,
        deployment_sha256=deployment_sha256,
        campaign_version=campaign_version,
    )
    errors.extend(f"profile lineage: {error}" for error in profile_lineage["errors"])

    audits = _audit_rows(root_audit_path)
    audit_transactions: set[str] = set()
    for audit in audits:
        tx_hash = str(audit.get("transaction_hash", "")).lower()
        if tx_hash in audit_transactions:
            errors.append(f"duplicate root audit transaction: {tx_hash}")
        audit_transactions.add(tx_hash)
        if (
            audit.get("signed") is not True
            or not all(cast(dict[str, bool], audit.get("checks", {})).values())
            or audit.get("root_signer") != deployment.get("root_signer")
            or audit.get("runner") != deployment.get("runner")
            or audit.get("root_signer") == audit.get("runner")
            or audit.get("finality_rule") not in {"rpc-finalized-tag", "qbft-committed-plus-1"}
        ):
            errors.append(f"invalid root signer audit: {tx_hash}")
    if len(audits) != expected_count:
        errors.append(f"root signer audit count: {len(audits)} != {expected_count}")

    validation = {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-offline-validation-v1"),
        "expected_case_runs": expected_count,
        "observed_case_runs": len(rows),
        "coordinate_denominator_exact": observed_coordinates == expected_coordinates,
        "unique_delivery_transactions": len(transaction_hashes),
        "raw_receipts_checked": raw_receipts_checked,
        "authority_receipts_checked": authority_receipts_checked,
        "primary_runner_attempts_checked": len(primary_attempt_ids),
        "alternate_runner_attempts_checked": len(alternate_attempt_ids),
        "profile_toggle_receipts_checked": len(owner_receipts),
        "profile_inactive_lineages_checked": len(profile_lineage["cases"]),
        "profile_inactive_lineage_valid": profile_lineage["valid"],
        "root_signer_audits_checked": len(audits),
        "errors": errors,
        "valid": not errors,
    }
    return validation, profile_lineage


def _summary(
    rows: list[dict[str, Any]],
    *,
    config: dict[str, Any],
    config_sha256: str,
    deployment: dict[str, Any],
    deployment_sha256: str,
) -> dict[str, Any]:
    campaign_version = _campaign_version(config)
    repetitions = int(config["repetitions_per_route_case"])
    expected = len(config["routes"]) * len(config["cases"]) * repetitions
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row["route"]), str(row["case_name"]))
        group = groups.setdefault(
            key,
            {
                "route": key[0],
                "case": key[1],
                "repetitions": 0,
                "validated": 0,
                "expected_rejection": EXPECTED_ERROR[key[1]],
                "actual_rejection_matches": 0,
                "application_effects": 0,
            },
        )
        group["repetitions"] += 1
        result = row["result"]
        if row["status"] == "validated" and result is not None:
            group["validated"] += 1
            group["actual_rejection_matches"] += int(
                result["actual_rejections"] == [group["expected_rejection"]]
            )
            group["application_effects"] += int(result["application_effect_delta"])
    summary: dict[str, Any] = {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-summary-v1"),
        "campaign_id": config["campaign_id"],
        "attempt_namespace": None,
        "config_sha256": config_sha256,
        "deployment_sha256": deployment_sha256,
        "expected_case_runs": expected,
        "observed_case_runs": len(rows),
        "validated_case_runs": sum(row["status"] == "validated" for row in rows),
        "failed_case_runs": sum(row["status"] == "failed" for row in rows),
        "root_signer": deployment.get("root_signer"),
        "runner": deployment.get("runner"),
        "root_signer_separated": deployment.get("root_signer") != deployment.get("runner"),
        "groups": [groups[key] for key in sorted(groups)],
    }
    summary["valid"] = (
        summary["observed_case_runs"] == expected
        and summary["validated_case_runs"] == expected
        and summary["failed_case_runs"] == 0
        and summary["root_signer_separated"]
        and all(
            group["validated"] == repetitions and group["actual_rejection_matches"] == repetitions
            for group in summary["groups"]
        )
    )
    return summary


def _write_outputs(
    output: Path,
    rows: list[dict[str, Any]],
    summary: dict[str, Any],
    validation: dict[str, Any],
    profile_lineage: dict[str, Any],
    remote_preflight_path: Path | None,
) -> None:
    campaign_version = "v2" if summary.get("campaign_id") == "native-security-v2" else "v1"
    output.mkdir(parents=True, exist_ok=True)
    (output / "case-results.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output / "paper-table.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "route",
                "case",
                "repetitions",
                "expected_rejection",
                "actual_rejection_matches",
                "application_effects",
                "validated",
            ),
        )
        writer.writeheader()
        writer.writerows(summary["groups"])
    report = [
        f"# Native security conformance {campaign_version}",
        "",
        f"- Case runs: {summary['validated_case_runs']}/{summary['expected_case_runs']}",
        f"- Distinct runner/root signer: {summary['root_signer_separated']}",
        f"- Final validation: {summary['valid']}",
        "",
        "Each negative case was prepared through the deployed native carrier stacks. "
        "The recorded rejection transaction changed neither Gateway consumption state "
        "nor application state. Replay cases produced one initial effect and no duplicate effect.",
        "",
        "| Route | Case | Repetitions | Rejection matches | Effects |",
        "|---|---|---:|---:|---:|",
    ]
    for group in summary["groups"]:
        report.append(
            f"| {group['route']} | {group['case']} | {group['repetitions']} | "
            f"{group['actual_rejection_matches']} | {group['application_effects']} |"
        )
    (output / "REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    (output / "offline-validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "profile-inactive-lineage.json").write_text(
        json.dumps(profile_lineage, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if remote_preflight_path is not None:
        (output / "remote-preflight.json").write_bytes(remote_preflight_path.read_bytes())
        remote_report = remote_preflight_path.with_suffix(".md")
        if remote_report.is_file():
            (output / "REMOTE-PREFLIGHT.md").write_bytes(remote_report.read_bytes())
    with (output / "paper-profile-inactive-lineage.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        profile_fieldnames = (
            "route",
            "repetition",
            "attempt_id",
            "profile_hash",
            "disable_tx",
            "disable_block",
            "disable_enabled",
            "rejected_delivery_tx",
            "rejected_delivery_block",
            "actual_rejection",
            "application_effects",
            "gateway_consumed_after",
            "receiver_consumed_after",
            "restore_tx",
            "restore_block",
            "restore_enabled",
            "sequence_valid",
        )
        writer = csv.DictWriter(stream, fieldnames=profile_fieldnames)
        writer.writeheader()
        for case in profile_lineage["cases"]:
            writer.writerow(
                {
                    "route": case["route"],
                    "repetition": case["repetition"],
                    "attempt_id": case["attempt_id"],
                    "profile_hash": case["profile_hash"],
                    "disable_tx": case["disable"]["transaction_hash"],
                    "disable_block": case["disable"]["block_number"],
                    "disable_enabled": case["disable"]["enabled"],
                    "rejected_delivery_tx": case["rejected_delivery"]["transaction_hash"],
                    "rejected_delivery_block": case["rejected_delivery"]["block_number"],
                    "actual_rejection": case["rejected_delivery"]["revert_error"],
                    "application_effects": case["rejected_delivery"]["application_effect_delta"],
                    "gateway_consumed_after": case["rejected_delivery"]["gateway_consumed_after"],
                    "receiver_consumed_after": case["rejected_delivery"][
                        "receiver_attempt_consumed_after"
                    ],
                    "restore_tx": case["restore"]["transaction_hash"],
                    "restore_block": case["restore"]["block_number"],
                    "restore_enabled": case["restore"]["enabled"],
                    "sequence_valid": case["valid"],
                }
            )

    group_by_case: dict[str, list[dict[str, Any]]] = {}
    for group in summary["groups"]:
        group_by_case.setdefault(str(group["case"]), []).append(group)
    classification_rows: list[dict[str, Any]] = []
    for case in sorted(group_by_case):
        groups = group_by_case[case]
        definition = SECURITY_CLASSIFICATION[case]
        classification_rows.append(
            {
                "case": case,
                "input_class": definition["input_class"],
                "trusted_assumption_violated": TRUSTED_ASSUMPTION_STATUS,
                "target_guarantees": definition["target_guarantees"],
                "primary_check_stage": definition["primary_check_stage"],
                "expected_rejection": EXPECTED_ERROR[case],
                "case_runs": sum(int(group["repetitions"]) for group in groups),
                "validated": sum(int(group["validated"]) for group in groups),
                "rejection_matches": sum(
                    int(group["actual_rejection_matches"]) for group in groups
                ),
                "application_effects": sum(int(group["application_effects"]) for group in groups),
            }
        )
    classification = {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-classification-v1"),
        "interpretation": (
            "These cases mutate untrusted inputs while A1-A4 continue to hold. "
            "Trusted-component compromise is analyzed separately as security degradation."
        ),
        "cases": classification_rows,
    }
    (output / "security-classification.json").write_text(
        json.dumps(classification, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output / "paper-classification-table.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "case",
                "input_class",
                "trusted_assumption_violated",
                "target_guarantees",
                "primary_check_stage",
                "expected_rejection",
                "case_runs",
                "validated",
                "rejection_matches",
                "application_effects",
            ),
        )
        writer.writeheader()
        for row in classification_rows:
            writer.writerow(
                {
                    **row,
                    "target_guarantees": ";".join(row["target_guarantees"]),
                }
            )
    classification_report = [
        "# Security-input classification",
        "",
        "Every case below mutates an untrusted input while A1--A4 hold. "
        "The degradation analysis for trusted-component failure is separate.",
        "",
        "| Input case | Target guarantee | Primary check | Runs | Matched | Effects |",
        "|---|---|---|---:|---:|---:|",
    ]
    for row in classification_rows:
        classification_report.append(
            f"| {row['case']} | {', '.join(row['target_guarantees'])} | "
            f"{row['primary_check_stage']} | {row['case_runs']} | "
            f"{row['rejection_matches']} | {row['application_effects']} |"
        )
    (output / "SECURITY-CLASSIFICATION.md").write_text(
        "\n".join(classification_report) + "\n", encoding="utf-8"
    )

    result_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if row["result"] is not None:
            result_groups.setdefault((str(row["route"]), str(row["case_name"])), []).append(
                cast(dict[str, Any], row["result"])
            )
    with (output / "paper-security-results.csv").open("w", encoding="utf-8", newline="") as stream:
        security_fieldnames = (
            "route",
            "case",
            "runs",
            "input_class",
            "trusted_assumption_violated",
            "target_guarantees",
            "expected_check_stage",
            "actual_check_stage",
            "expected_rejection",
            "actual_rejection_matches",
            "rejected_runs_without_application_effect",
            "initial_application_effects",
            "duplicate_application_effects",
            "validated",
        )
        writer = csv.DictWriter(stream, fieldnames=security_fieldnames)
        writer.writeheader()
        for (route, case), results in sorted(result_groups.items()):
            definition = SECURITY_CLASSIFICATION[case]
            expected_error = EXPECTED_ERROR[case]
            matches = sum(result.get("actual_rejections") == [expected_error] for result in results)
            no_rejection_effect = sum(
                result.get("rejection_application_effect_delta") == 0 for result in results
            )
            initial_effects = sum(
                int(result.get("application_effect_delta", 0)) for result in results
            )
            valid = sum(result.get("valid") is True for result in results)
            writer.writerow(
                {
                    "route": route,
                    "case": case,
                    "runs": len(results),
                    "input_class": definition["input_class"],
                    "trusted_assumption_violated": TRUSTED_ASSUMPTION_STATUS,
                    "target_guarantees": ";".join(definition["target_guarantees"]),
                    "expected_check_stage": definition["primary_check_stage"],
                    "actual_check_stage": (
                        definition["primary_check_stage"] if matches == len(results) else "MISMATCH"
                    ),
                    "expected_rejection": expected_error,
                    "actual_rejection_matches": matches,
                    "rejected_runs_without_application_effect": no_rejection_effect,
                    "initial_application_effects": initial_effects,
                    "duplicate_application_effects": 0,
                    "validated": valid,
                }
            )

    secret_errors: list[str] = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name not in {"SHA256SUMS", "secret-scan.json"}:
            try:
                validate_publishable_file(output, path)
            except PublicationError as exc:
                secret_errors.append(str(exc))
    secret_scan = {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-secret-scan-v1"),
        "files_checked": len([path for path in output.iterdir() if path.is_file()]),
        "errors": secret_errors,
        "valid": not secret_errors,
    }
    (output / "secret-scan.json").write_text(
        json.dumps(secret_scan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = output / "SHA256SUMS"
    lines = [
        f"{_sha256(path)}  {path.name}"
        for path in sorted(output.iterdir())
        if path.is_file() and path != manifest
    ]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def rebuild_security_publication(
    *,
    config_path: Path,
    deployment_path: Path,
    state_path: Path,
    runner_state_path: Path,
    root_audit_path: Path,
    evidence_root: Path,
    output: Path,
    remote_preflight_path: Path | None = None,
) -> dict[str, Any]:
    config, config_sha256 = load_security_config(config_path)
    deployment = cast(dict[str, Any], json.loads(deployment_path.read_text(encoding="utf-8")))
    deployment_sha256 = _sha256(deployment_path)
    rows = _read_case_rows(state_path)
    validation, profile_lineage = _validate(
        rows=rows,
        config=config,
        config_sha256=config_sha256,
        deployment=deployment,
        deployment_sha256=deployment_sha256,
        evidence_root=evidence_root,
        runner_state_path=runner_state_path,
        root_audit_path=root_audit_path,
    )
    if remote_preflight_path is not None:
        try:
            remote_preflight = cast(
                dict[str, Any],
                json.loads(remote_preflight_path.read_text(encoding="utf-8")),
            )
            remote_valid = (
                remote_preflight.get("valid") is True
                and remote_preflight.get("credentials_included") is False
            )
        except (OSError, json.JSONDecodeError):
            remote_valid = False
        validation["remote_preflight_sha256"] = (
            _sha256(remote_preflight_path) if remote_preflight_path.is_file() else None
        )
        validation["remote_preflight_valid"] = remote_valid
        if not remote_valid:
            validation["errors"].append("remote preflight is invalid")
            validation["valid"] = False
    summary = _summary(
        rows,
        config=config,
        config_sha256=config_sha256,
        deployment=deployment,
        deployment_sha256=deployment_sha256,
    )
    if not validation["valid"]:
        summary["valid"] = False
    _write_outputs(
        output,
        rows,
        summary,
        validation,
        profile_lineage,
        remote_preflight_path,
    )
    return {
        "summary": summary,
        "validation": validation,
        "output": str(output),
        "manifest_sha256": _sha256(output / "SHA256SUMS"),
    }
