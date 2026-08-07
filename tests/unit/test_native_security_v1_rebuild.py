from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.native.deployer import PROFILE_HASHES
from xir_lab.native.security_v1 import (
    EXPECTED_ERROR,
    case_attempt,
    load_security_config,
)
from xir_lab.native.security_v1_profile_evidence import (
    PROFILE_SET_TOPIC,
    SET_PROFILE_SELECTOR,
)
from xir_lab.native.security_v1_rebuild import rebuild_security_publication


def _write_receipt(root: Path, tx_hash: str, document: dict[str, object]) -> str:
    path = root / "raw-receipts" / f"{tx_hash}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _set_profile_input(
    *,
    profile_hash: bytes,
    src_hash: bytes,
    dst_hash: bytes,
    adapter: str,
    enabled: bool,
) -> str:
    encoded = b"".join(
        (
            profile_hash,
            src_hash,
            dst_hash,
            bytes.fromhex(adapter[2:]).rjust(32, b"\x00"),
            _word(1),
            _word(0),
            _word(0),
            _word(int(enabled)),
        )
    )
    return SET_PROFILE_SELECTOR + encoded.hex()


def test_offline_rebuild_reconciles_exact_frozen_denominator(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    config_path = repository / "configs/native/native-security-v1.json"
    config, config_sha256 = load_security_config(config_path)
    evidence = tmp_path / "evidence"
    state_path = evidence / "campaign.sqlite"
    runner_path = evidence / "runner.sqlite"
    audit_path = evidence / "root-signer-audit.jsonl"
    deployment_path = evidence / "deployment.json"
    remote_preflight_path = evidence / "remote-preflight.json"
    runner = "0x" + "11" * 20
    signer = "0x" + "22" * 20
    registry = "0x" + "33" * 20
    deployment = {
        "runner": runner,
        "root_signer": signer,
        "chains": {"destination": {"registry": registry}},
    }
    evidence.mkdir(parents=True)
    deployment_path.write_text(json.dumps(deployment, sort_keys=True) + "\n", encoding="utf-8")
    remote_preflight_path.write_text(
        json.dumps({"valid": True, "credentials_included": False}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    remote_preflight_path.with_suffix(".md").write_text(
        "# Remote preflight\n\n- Valid: True\n", encoding="utf-8"
    )

    cases = sqlite3.connect(state_path)
    cases.execute(
        """
        CREATE TABLE cases(
          case_key TEXT, attempt_id TEXT, route TEXT, case_name TEXT,
          repetition INTEGER, status TEXT, planned_json TEXT,
          result_json TEXT, started_at REAL, finished_at REAL
        )
        """
    )
    runner_db = sqlite3.connect(runner_path)
    runner_db.execute("CREATE TABLE attempts(attempt_id TEXT, status TEXT)")
    runner_db.execute("CREATE TABLE stages(attempt_id TEXT, stage TEXT, state TEXT)")
    audit_lines: list[str] = []
    tx_counter = 1
    profile_cases: list[dict[str, object]] = []

    for route in config["routes"]:
        for case in config["cases"]:
            for repetition in range(config["repetitions_per_route_case"]):
                attempt = case_attempt(
                    campaign_id=config["campaign_id"],
                    route=route,
                    case=case,
                    repetition=repetition,
                )
                expected_effects = config["expected_application_effects"][case]
                attempt_topic = "0x" + keccak(text=attempt.attempt_id).hex()
                transactions = []
                statuses = [1, 0] if expected_effects else [0]
                for status in statuses:
                    tx_hash = f"0x{tx_counter:064x}"
                    block_number = tx_counter * 10
                    tx_counter += 1
                    receipt_sha = _write_receipt(
                        evidence,
                        tx_hash,
                        {
                            "status": status,
                            "to": "0x" + "44" * 20,
                            "blockNumber": block_number,
                            "transactionIndex": 0,
                            "logs": [],
                        },
                    )
                    transactions.append(
                        {
                            "transaction_hash": tx_hash,
                            "status": status,
                            "block_number": block_number,
                            "transaction_index": 0,
                            "revert_error": EXPECTED_ERROR[case] if status == 0 else None,
                            "native_effect_attempt_ids": [attempt_topic] if status == 1 else [],
                            "receipt_sha256": receipt_sha,
                        }
                    )
                result = {
                    "route": route,
                    "case": case,
                    "repetition": repetition,
                    "attempt_id": attempt.attempt_id,
                    "expected_rejection": EXPECTED_ERROR[case],
                    "actual_rejections": [EXPECTED_ERROR[case]],
                    "expected_application_effects": expected_effects,
                    "application_effect_delta": expected_effects,
                    "rejection_application_effect_delta": 0,
                    "effect_attempt_ids": [attempt_topic] if expected_effects else [],
                    "root_signer_separated": True,
                    "before": {
                        "gateway_consumed": False,
                        "receiver_attempt_consumed": False,
                    },
                    "after": {
                        "gateway_consumed": bool(expected_effects),
                        "receiver_attempt_consumed": bool(expected_effects),
                    },
                    "transactions": transactions,
                    "valid": True,
                }
                if case == "profile_inactive":
                    profile_cases.append(
                        {
                            "route": route,
                            "profile_hash": PROFILE_HASHES[f"{route[0]}_AB"],
                            "delivery_block": transactions[0]["block_number"],
                        }
                    )
                cases.execute(
                    "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        f"{route}:{case}:{repetition}",
                        attempt.attempt_id,
                        route,
                        case,
                        repetition,
                        "validated",
                        json.dumps(asdict(attempt), sort_keys=True),
                        json.dumps(result, sort_keys=True),
                        1.0,
                        2.0,
                    ),
                )
                runner_db.execute(
                    "INSERT INTO attempts VALUES(?, 'succeeded')", (attempt.attempt_id,)
                )
                for stage in (
                    "xir_root_record",
                    "first_protocol_dispatch",
                    "xir_transition",
                    "second_protocol_dispatch",
                ):
                    runner_db.execute(
                        "INSERT INTO stages VALUES(?, ?, 'succeeded')",
                        (attempt.attempt_id, stage),
                    )
                if case == "cross_execution_splice":
                    alternate = attempt.attempt_id + "_alternate"
                    runner_db.execute("INSERT INTO attempts VALUES(?, 'succeeded')", (alternate,))
                    for stage in ("first_protocol_dispatch", "second_protocol_dispatch"):
                        runner_db.execute(
                            "INSERT INTO stages VALUES(?, ?, 'succeeded')",
                            (alternate, stage),
                        )
                audit_lines.append(
                    json.dumps(
                        {
                            "transaction_hash": f"root-{attempt.attempt_id}",
                            "signed": True,
                            "checks": {"finalized": True, "rid": True},
                            "root_signer": signer,
                            "runner": runner,
                            "finality_rule": "qbft-committed-plus-1",
                        },
                        sort_keys=True,
                    )
                )

    src_hash = keccak(text="synthetic-profile-src")
    dst_hash = keccak(text="synthetic-profile-dst")
    adapter = "0x" + "55" * 20
    capture_rows: list[dict[str, object]] = []
    transaction_root = evidence / "raw-profile-transactions"
    transaction_root.mkdir(parents=True)
    for profile_case in profile_cases:
        profile_hash = bytes(profile_case["profile_hash"])
        delivery_block = int(profile_case["delivery_block"])
        for enabled, block_number in ((False, delivery_block - 1), (True, delivery_block + 1)):
            tx_hash = f"0x{tx_counter:064x}"
            tx_counter += 1
            block_hash = "0x" + f"{block_number:064x}"
            receipt_sha = _write_receipt(
                evidence,
                tx_hash,
                {
                    "status": 1,
                    "from": runner,
                    "to": registry,
                    "blockHash": block_hash,
                    "blockNumber": block_number,
                    "transactionHash": tx_hash,
                    "transactionIndex": 0,
                    "logs": [
                        {
                            "address": registry,
                            "topics": [PROFILE_SET_TOPIC, "0x" + profile_hash.hex()],
                            "data": "0x" + src_hash.hex() + dst_hash.hex(),
                        }
                    ],
                },
            )
            transaction = {
                "schema_version": ("xir-lab-native-security-v1-profile-transaction-v1"),
                "transaction_hash": tx_hash,
                "block_hash": block_hash,
                "block_number": block_number,
                "transaction_index": 0,
                "from": runner,
                "to": registry,
                "input": _set_profile_input(
                    profile_hash=profile_hash,
                    src_hash=src_hash,
                    dst_hash=dst_hash,
                    adapter=adapter,
                    enabled=enabled,
                ),
                "nonce": tx_counter,
                "chain_id": 3133703,
                "type": 2,
            }
            transaction_path = transaction_root / f"{tx_hash}.json"
            transaction_path.write_text(
                json.dumps(transaction, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            capture_rows.append(
                {
                    "transaction_hash": tx_hash,
                    "profile_hash": "0x" + profile_hash.hex(),
                    "enabled": enabled,
                    "block_number": block_number,
                    "transaction_index": 0,
                    "receipt_sha256": receipt_sha,
                    "transaction_sha256": hashlib.sha256(transaction_path.read_bytes()).hexdigest(),
                }
            )
    capture_rows.sort(key=lambda item: (item["block_number"], item["transaction_index"]))
    (evidence / "profile-transaction-capture.json").write_text(
        json.dumps(
            {
                "schema_version": "xir-lab-native-security-v1-profile-capture-v1",
                "config_sha256": config_sha256,
                "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
                "chain_id": 3133703,
                "registry_address": registry,
                "rpc_url_included": False,
                "expected_transactions": len(profile_cases) * 2,
                "captured_transactions": len(capture_rows),
                "transactions": capture_rows,
                "errors": [],
                "valid": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    cases.commit()
    cases.close()
    runner_db.commit()
    runner_db.close()
    audit_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    rebuilt = rebuild_security_publication(
        config_path=config_path,
        deployment_path=deployment_path,
        state_path=state_path,
        runner_state_path=runner_path,
        root_audit_path=audit_path,
        evidence_root=evidence,
        output=tmp_path / "rebuilt",
        remote_preflight_path=remote_preflight_path,
    )

    assert rebuilt["summary"]["valid"] is True
    assert rebuilt["validation"]["valid"] is True
    assert rebuilt["validation"]["observed_case_runs"] == 660
    assert rebuilt["validation"]["unique_delivery_transactions"] == 780
    assert rebuilt["validation"]["profile_toggle_receipts_checked"] == 120
    assert rebuilt["validation"]["profile_inactive_lineages_checked"] == 60
    assert rebuilt["validation"]["profile_inactive_lineage_valid"] is True
    assert rebuilt["validation"]["remote_preflight_valid"] is True
    assert (tmp_path / "rebuilt/remote-preflight.json").is_file()
    assert (tmp_path / "rebuilt/REMOTE-PREFLIGHT.md").is_file()
    lineage = json.loads(
        (tmp_path / "rebuilt/profile-inactive-lineage.json").read_text(encoding="utf-8")
    )
    assert lineage["valid"] is True
    assert len(lineage["cases"]) == 60
    assert all(case["disable"]["enabled"] is False for case in lineage["cases"])
    assert all(case["restore"]["enabled"] is True for case in lineage["cases"])
    classification = json.loads(
        (tmp_path / "rebuilt/security-classification.json").read_text(encoding="utf-8")
    )
    assert len(classification["cases"]) == 11
    assert {item["trusted_assumption_violated"] for item in classification["cases"]} == {
        "none (A1-A4 hold)"
    }
