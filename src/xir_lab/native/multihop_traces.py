"""Durable Besu TRACE capture for the five-chain multihop campaign."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import rfc8785
from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction
from eth_account._utils.signing import extract_chain_id
from eth_account.typed_transactions import TypedTransaction  # type: ignore[attr-defined]
from eth_utils.exceptions import ValidationError
from hexbytes import HexBytes
from rlp.exceptions import RLPException  # type: ignore[import-untyped]
from web3 import Web3

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_analysis import reconstruct_attempt_metrics
from xir_lab.native.multihop_scalability import MultihopPhase
from xir_lab.native.rpc import (
    BESU_RAW_TRANSACTION_RPC_METHOD,
    decode_besu_raw_transaction_result,
)

OPTIONAL_RECIPIENT_ISM_SELECTOR = "0xde523cf3"
HYPERLANE_PROCESS_SELECTOR = "0x7c39d130"
HYPERLANE_VERIFY_SELECTOR = "0xf7e83aee"
HYPERLANE_HANDLE_SELECTOR = "0x56d5d475"


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            document = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"Besu trace RPC failed: {method}") from exc
    if not isinstance(document, dict) or document.get("error") is not None:
        raise LocalTopologyError(f"Besu trace RPC returned an error: {method}")
    return document.get("result")


def _trace_with_retry(url: str, transaction_hash: str, *, attempts: int = 8) -> Any:
    """Retry only an empty Besu TRACE result from a finalized receipt."""

    for attempt in range(attempts):
        result = _rpc(url, "trace_transaction", [transaction_hash])
        if isinstance(result, list) and result:
            return result
        if attempt + 1 < attempts:
            time.sleep(min(2.0 ** attempt, 15.0))
    return None


def _quantity(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    raise LocalTopologyError("trace gas quantity is invalid")


def _canonical_hash(value: str) -> str:
    normalized = value.lower().removeprefix("0x")
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise LocalTopologyError("trace transaction hash is invalid")
    return "0x" + normalized


def _canonical_address(value: str) -> str:
    normalized = value.lower().removeprefix("0x")
    if len(normalized) != 40 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise LocalTopologyError("trace address is invalid")
    return "0x" + normalized


def _hyperlane_process_bindings(
    path: Path,
) -> dict[tuple[str, str], tuple[str, str]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError("Hyperlane process evidence is unavailable") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version")
        != "xir-lab-native-multihop-hyperlane-processes-v1"
        or not isinstance(document.get("messages"), dict)
    ):
        raise LocalTopologyError("Hyperlane process evidence is invalid")
    semantic = dict(document)
    claimed_semantic = semantic.pop("semantic_sha256", None)
    if (
        not isinstance(claimed_semantic, str)
        or hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != claimed_semantic
    ):
        raise LocalTopologyError("Hyperlane process evidence semantic hash is invalid")
    bindings: dict[tuple[str, str], tuple[str, str]] = {}
    for message in cast(dict[str, Any], document["messages"]).values():
        if not isinstance(message, dict):
            raise LocalTopologyError("Hyperlane process message is invalid")
        role = str(message.get("chain_role", ""))
        if role not in {"b", "c", "d", "e"} or int(message.get("status", 0)) != 1:
            raise LocalTopologyError("Hyperlane process message identity is invalid")
        coordinate = (role, _canonical_hash(str(message.get("transaction_hash", ""))))
        mailbox = _canonical_address(str(message.get("mailbox", "")))
        default_ism = _canonical_address(str(message.get("default_ism", "")))
        if coordinate in bindings:
            raise LocalTopologyError("Hyperlane process transaction is duplicated")
        bindings[coordinate] = (mailbox, default_ism)
    return bindings


def _address_labels(deployment: dict[str, Any]) -> dict[tuple[str, str], str]:
    labels: dict[tuple[str, str], str] = {}
    for role, components in cast(dict[str, dict[str, str]], deployment["chains"]).items():
        for name, address in components.items():
            key = (role, str(address).lower())
            if key in labels:
                raise LocalTopologyError("deployment address label is ambiguous")
            labels[key] = name
    return labels


def normalize_transaction_trace(
    *,
    chain_role: str,
    transaction_hash: str,
    receipt_gas: int,
    receipt_status: int,
    expected_root_target: str,
    expected_hyperlane_mailbox: str | None,
    expected_hyperlane_default_ism: str | None,
    trace_result: Any,
    labels: dict[tuple[str, str], str],
) -> dict[str, Any]:
    if receipt_status != 1:
        raise LocalTopologyError("trace transaction receipt is not successful")
    if not isinstance(trace_result, list) or not trace_result:
        raise LocalTopologyError("trace_transaction result is empty")
    traces: list[dict[str, Any]] = []
    for raw in trace_result:
        if not isinstance(raw, dict):
            raise LocalTopologyError("trace_transaction row is invalid")
        action = raw.get("action")
        result = raw.get("result")
        trace_address = raw.get("traceAddress")
        if not isinstance(action, dict) or not isinstance(trace_address, list):
            raise LocalTopologyError("trace_transaction action is invalid")
        destination = str(action.get("to", "")).lower()
        component = labels.get((chain_role, destination), "external_or_native_component")
        row = {
            "trace_address": [int(value) for value in trace_address],
            "type": str(raw.get("type")),
            "call_type": action.get("callType"),
            "from": str(action.get("from", "")).lower(),
            "to": destination,
            "component": component,
            "input_bytes": max((len(str(action.get("input", ""))) - 2) // 2, 0),
            "input_selector": str(action.get("input", ""))[:10].lower()
            if len(str(action.get("input", ""))) >= 10
            else "0x",
            "gas_supplied": _quantity(action["gas"]) if "gas" in action else None,
            "gas_used": (
                _quantity(cast(dict[str, Any], result)["gasUsed"])
                if isinstance(result, dict) and "gasUsed" in result
                else None
            ),
            "result_present": "result" in raw,
            "result_is_object": isinstance(result, dict),
            "result_is_null": "result" in raw and result is None,
            # Keep the result shape and output only while classifying Besu's
            # parity-style representation.  Besu can encode an errored
            # internal call with an omitted result, JSON null, or an object;
            # all temporary output fields are removed before publication.
            "_result_output_present": isinstance(result, dict) and "output" in result,
            "_result_output": (
                str(cast(dict[str, Any], result).get("output", "")).lower()
                if isinstance(result, dict)
                else None
            ),
            "error": raw.get("error"),
            "error_classification": None,
        }
        traces.append(row)
    roots = [row for row in traces if row["trace_address"] == []]
    if len(roots) != 1 or roots[0]["gas_used"] is None:
        raise LocalTopologyError("trace_transaction lacks one top-level gas result")
    root = roots[0]
    expected_root = _canonical_address(expected_root_target)
    if root["to"] != expected_root:
        raise LocalTopologyError("trace root target does not match signed transaction target")
    direct_child_rows = [
        row for row in traces if len(row["trace_address"]) == 1
    ]
    direct_children = {
        tuple(row["trace_address"]): row
        for row in direct_child_rows
    }
    if len(direct_children) != len(direct_child_rows):
        raise LocalTopologyError("trace_transaction contains duplicate direct-child coordinates")
    direct_child_summary = {
        str(list(coordinate)): {
            "call_type": child["call_type"],
            "from": child["from"],
            "to": child["to"],
            "selector": child["input_selector"],
            "error": child["error"],
            "result_present": child["result_present"],
            "result_is_object": child["result_is_object"],
            "result_is_null": child["result_is_null"],
            "gas_used": child["gas_used"],
        }
        for coordinate, child in sorted(direct_children.items())
    }
    process_binding_present = (
        expected_hyperlane_mailbox is not None
        or expected_hyperlane_default_ism is not None
    )
    if process_binding_present and (
        expected_hyperlane_mailbox is None
        or expected_hyperlane_default_ism is None
    ):
        raise LocalTopologyError("Hyperlane process trace binding is incomplete")
    probe = direct_children.get((0,))
    verify = direct_children.get((1,))
    delivery = direct_children.get((2,))
    probe_falls_back_to_default_ism = (
        probe is not None
        and probe["call_type"] == "staticcall"
        and probe["from"] == root["to"]
        and probe["input_selector"] == OPTIONAL_RECIPIENT_ISM_SELECTOR
        and probe["component"].startswith("route_")
        and probe["component"].endswith(("_in", "_out"))
        and (
            probe["error"] == "Reverted"
            or (
                probe["error"] is None
                and probe["result_present"]
                and probe["gas_used"] is not None
                and probe["_result_output_present"]
                and probe["_result_output"] == "0x"
            )
        )
    )
    process_boundary_valid = (
        process_binding_present
        and receipt_status == 1
        and root["error"] is None
        and root["to"] == _canonical_address(cast(str, expected_hyperlane_mailbox))
        and root["type"] == "call"
        and root["call_type"] == "call"
        and root["input_selector"] == HYPERLANE_PROCESS_SELECTOR
        and set(direct_children) == {(0,), (1,), (2,)}
        and probe_falls_back_to_default_ism
        and probe is not None
        and verify is not None
        # Hyperlane declares IInterchainSecurityModule.verify without view
        # mutability, so Mailbox emits CALL even when the implementation is
        # observationally read-only.  Besu's diagnostic error/result shape is
        # not authoritative at this exact process-bound boundary.
        and verify["call_type"] == "call"
        and verify["from"] == root["to"]
        and verify["input_selector"] == HYPERLANE_VERIFY_SELECTOR
        and verify["to"]
        == _canonical_address(cast(str, expected_hyperlane_default_ism))
        and verify["error"] in {None, "Reverted"}
        and delivery is not None
        # Mailbox.process invokes recipient.handle as an uncaught high-level
        # call.  A status-one process receipt therefore proves that this
        # exact, registry-bound delivery returned successfully.  Besu's
        # parity-style trace can nevertheless retain the same diagnostic
        # Reverted/omitted-result representation observed for the direct ISM
        # verification row.  Treat that representation as non-authoritative
        # only after the complete process boundary below is bound.
        and (
            delivery["error"] == "Reverted"
            or (
                delivery["error"] is None
                and delivery["result_present"]
                and delivery["gas_used"] is not None
            )
        )
        and delivery["call_type"] == "call"
        and delivery["from"] == root["to"]
        and delivery["to"] == probe["to"]
        and delivery["component"] == probe["component"]
        and delivery["input_selector"] == HYPERLANE_HANDLE_SELECTOR
    )
    if process_binding_present and not process_boundary_valid:
        raise LocalTopologyError(
            "Hyperlane process trace does not preserve the bound "
            "probe/verify/delivery structure: "
            f"transaction={_canonical_hash(transaction_hash)} "
            f"expected_mailbox={expected_hyperlane_mailbox} "
            f"expected_default_ism={expected_hyperlane_default_ism} "
            f"direct_children={direct_child_summary}"
        )
    for row in traces:
        if row["error"] is None:
            continue
        expected_optional_ism_probe = (
            row["error"] == "Reverted"
            and row["trace_address"] != []
            and row["call_type"] == "staticcall"
            and row["input_selector"] == OPTIONAL_RECIPIENT_ISM_SELECTOR
            and row["component"].startswith("route_")
            and row["component"].endswith(("_in", "_out"))
        )
        successful_hyperlane_ism_boundary = (
            row["error"] == "Reverted"
            and process_boundary_valid
            and row["trace_address"] == [1]
        )
        successful_hyperlane_delivery_boundary = (
            row["error"] == "Reverted"
            and process_boundary_valid
            and row["trace_address"] == [2]
        )
        if expected_optional_ism_probe:
            # Hyperlane Mailbox.recipientIsm deliberately probes the optional
            # recipient interface with a low-level STATICCALL.  A recipient
            # without that interface reverts the subcall; Besu can omit the
            # result or encode it as JSON null. Mailbox catches the failure and
            # uses its default ISM.
            row["error_classification"] = "expected_optional_recipient_ism_probe"
        elif successful_hyperlane_ism_boundary:
            # Besu's parity-style trace can retain a Reverted marker and an
            # absent/null/object result on this direct ISM verification row
            # even though the successful root process call continued to the
            # same recipient's handle call. Preserve it only when the frozen
            # Mailbox and default ISM plus the complete sibling structure and
            # successful receipt prove that exact boundary.
            row["error_classification"] = (
                "successful_hyperlane_ism_verification_trace_boundary"
            )
        elif successful_hyperlane_delivery_boundary:
            # Hyperlane Mailbox.process does not catch recipient.handle
            # failures.  The successful root receipt plus the frozen Mailbox,
            # recipient, selector, and complete sibling structure therefore
            # prove this exact delivery succeeded even when Besu retains a
            # diagnostic Reverted marker and omits the child result.
            row["error_classification"] = (
                "successful_hyperlane_delivery_trace_boundary"
            )
        else:
            raise LocalTopologyError(
                "successful physical transaction has an unexpected errored trace: "
                f"transaction={_canonical_hash(transaction_hash)} "
                f"trace_address={row['trace_address']} component={row['component']} "
                f"from={row['from']} to={row['to']} "
                f"selector={row['input_selector']} error={row['error']} "
                f"expected_mailbox={expected_hyperlane_mailbox} "
                f"expected_default_ism={expected_hyperlane_default_ism} "
                f"direct_children={direct_child_summary}"
            )
    for row in traces:
        row.pop("_result_output_present", None)
        row.pop("_result_output", None)
    top_level_execution_gas = int(roots[0]["gas_used"])
    if top_level_execution_gas > receipt_gas:
        raise LocalTopologyError("trace execution gas exceeds receipt gas")
    document: dict[str, Any] = {
        "chain_role": chain_role,
        "transaction_hash": _canonical_hash(transaction_hash),
        "receipt_gas": receipt_gas,
        "top_level_execution_gas": top_level_execution_gas,
        "receipt_minus_trace_gas": receipt_gas - top_level_execution_gas,
        "internal_call_count": len(traces) - 1,
        "internal_gas_is_inclusive_non_additive": True,
        "traces": traces,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    return document


def normalize_raw_transaction(
    *, raw_hex: str, transaction_hash: str, expected_chain_id: int
) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(raw_hex.removeprefix("0x"))
        if not raw:
            raise ValueError("empty raw transaction")
        if raw[0] >= 0xC0:
            decoded = Transaction.from_bytes(raw).as_dict()
            chain_id, _ = extract_chain_id(int(decoded["v"]))
            if chain_id is None:
                raise ValueError("legacy transaction is not EIP-155 protected")
        else:
            decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            chain_id = int(decoded["chainId"])
        sender = Account.recover_transaction(raw).lower()
    except (TypeError, ValueError, KeyError, ValidationError, RLPException) as exc:
        raise LocalTopologyError("raw physical transaction is undecodable") from exc
    actual_hash = _canonical_hash(Web3.keccak(raw).hex())
    if actual_hash != _canonical_hash(transaction_hash) or chain_id != expected_chain_id:
        raise LocalTopologyError("raw physical transaction hash/chain mismatch")
    return {
        "raw_transaction_hex": "0x" + raw.hex(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "sender": sender,
        "nonce": int(decoded["nonce"]),
        "target": "0x" + bytes(decoded["to"]).hex(),
        "calldata_sha256": hashlib.sha256(bytes(decoded["data"])).hexdigest(),
        "chain_id": chain_id,
    }


class MultihopTraceState:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS traces(
              chain_role TEXT NOT NULL,
              transaction_hash TEXT NOT NULL,
              receipt_gas INTEGER NOT NULL,
              trace_json TEXT NOT NULL,
              semantic_sha256 TEXT NOT NULL,
              raw_transaction_hex TEXT,
              raw_sha256 TEXT,
              block_hash TEXT,
              PRIMARY KEY(chain_role, transaction_hash)
            ) STRICT;
            """
        )
        columns = {str(row[1]) for row in self.connection.execute("PRAGMA table_info(traces)")}
        if "raw_transaction_hex" not in columns:
            self.connection.execute("ALTER TABLE traces ADD COLUMN raw_transaction_hex TEXT")
        if "raw_sha256" not in columns:
            self.connection.execute("ALTER TABLE traces ADD COLUMN raw_sha256 TEXT")
        if "block_hash" not in columns:
            self.connection.execute("ALTER TABLE traces ADD COLUMN block_hash TEXT")
        self.connection.commit()

    def existing(self) -> set[tuple[str, str]]:
        return {
            (str(row["chain_role"]), str(row["transaction_hash"]))
            for row in self.connection.execute(
                "SELECT chain_role,transaction_hash FROM traces"
            )
        }

    def store(self, document: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO traces(
              chain_role,transaction_hash,receipt_gas,trace_json,semantic_sha256,
              raw_transaction_hex,raw_sha256,block_hash
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                document["chain_role"],
                document["transaction_hash"],
                document["receipt_gas"],
                json.dumps(document, sort_keys=True, separators=(",", ":")),
                document["semantic_sha256"],
                document["raw_transaction_hex"],
                document["raw_sha256"],
                document["block_hash"],
            ),
        )
        self.connection.commit()


def capture_multihop_traces(
    *,
    repository_root: Path,
    config_path: Path,
    deployment_path: Path,
    phase: MultihopPhase,
    runner_state_path: Path,
    worker_state_path: Path,
    hyperlane_process_path: Path,
    root_signer_audit_path: Path,
    trace_state_path: Path,
    concurrency: int = 8,
) -> dict[str, Any]:
    if concurrency <= 0:
        raise LocalTopologyError("trace capture concurrency must be positive")
    config = cast(dict[str, Any], json.loads(config_path.read_text(encoding="utf-8")))
    profile = cast(
        dict[str, Any],
        json.loads(
            (repository_root / str(config["profile"])).read_text(encoding="utf-8")
        ),
    )
    role_rpc = {
        role: str(chain["rpc_url"])
        for role, chain in zip(
            ("a", "b", "c", "d", "e"),
            cast(list[dict[str, Any]], profile["chains"]),
            strict=True,
        )
    }
    role_chain_id = {
        role: int(chain["chain_id"])
        for role, chain in zip(
            ("a", "b", "c", "d", "e"),
            cast(list[dict[str, Any]], profile["chains"]),
            strict=True,
        )
    }
    deployment = cast(
        dict[str, Any], json.loads(deployment_path.read_text(encoding="utf-8"))
    )
    labels = _address_labels(deployment)
    process_bindings = _hyperlane_process_bindings(hyperlane_process_path)
    _, physical_rows, _, _ = reconstruct_attempt_metrics(
        config_path=config_path,
        phase=phase,
        runner_state_path=runner_state_path,
        worker_state_path=worker_state_path,
        hyperlane_process_path=hyperlane_process_path,
        root_signer_audit_path=root_signer_audit_path,
        deployment_path=deployment_path,
        trace_state_path=None,
        allow_missing_traces_for_capture=True,
    )
    coordinates = {
        (str(row["chain_role"]), _canonical_hash(str(row["transaction_hash"]))): int(
            row["gas"]
        )
        for row in physical_rows
    }
    if len(coordinates) != len(physical_rows):
        raise LocalTopologyError("physical transactions are not unique for trace capture")
    if not set(process_bindings).issubset(coordinates):
        raise LocalTopologyError(
            "Hyperlane process evidence is not a subset of physical transactions"
        )
    state = MultihopTraceState(trace_state_path)
    pending = [
        (role, transaction_hash, receipt_gas)
        for (role, transaction_hash), receipt_gas in sorted(coordinates.items())
        if (role, transaction_hash) not in state.existing()
    ]

    config_document = json.loads(config_path.read_text(encoding="utf-8"))
    pilot_trace_fallback = (
        phase == "scale"
        and isinstance(config_document, dict)
        and config_document.get("result_roles", {}).get("scale") == "pilot_diagnostic_only"
    )

    def fetch(item: tuple[str, str, int]) -> dict[str, Any]:
        role, transaction_hash, receipt_gas = item
        receipt = _rpc(role_rpc[role], "eth_getTransactionReceipt", [transaction_hash])
        if (
            not isinstance(receipt, dict)
            or int(str(receipt.get("status", "0x0")), 16) != 1
            or int(str(receipt.get("gasUsed", "0x0")), 16) != receipt_gas
        ):
            raise LocalTopologyError("physical transaction receipt is unavailable/invalid")
        raw = decode_besu_raw_transaction_result(
            _rpc(role_rpc[role], BESU_RAW_TRANSACTION_RPC_METHOD, [transaction_hash])
        )
        raw_document = normalize_raw_transaction(
            raw_hex="0x" + raw.hex(),
            transaction_hash=transaction_hash,
            expected_chain_id=role_chain_id[role],
        )
        process_binding = process_bindings.get((role, transaction_hash))
        trace_result = _trace_with_retry(
            role_rpc[role],
            transaction_hash,
            attempts=8,
        )
        if trace_result is None and pilot_trace_fallback:
            trace = {
                "schema_version": "xir-lab-native-multihop-trace-unavailable-v1",
                "trace_unavailable": True,
                "trace_unavailable_reason": "besu_trace_transaction_empty_after_bounded_retries",
                "chain_role": role,
                "transaction_hash": transaction_hash,
                "receipt_gas": receipt_gas,
                "status": 1,
                "raw_transaction_hex": "0x" + raw.hex(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "sender": str(raw_document["sender"]),
                "target": str(raw_document["target"]),
                "nonce": int(raw_document["nonce"]),
                "chain_id": int(raw_document["chain_id"]),
                "calldata_sha256": str(raw_document["calldata_sha256"]),
                "block_number": int(str(receipt["blockNumber"]), 16),
                "block_hash": _canonical_hash(str(receipt["blockHash"])),
                "transaction_index": int(str(receipt["transactionIndex"]), 16),
                "traces": [],
                "top_level_execution_gas": None,
                "receipt_minus_trace_gas": None,
                "internal_call_count": None,
            }
        else:
            trace = normalize_transaction_trace(
            chain_role=role,
            transaction_hash=transaction_hash,
            receipt_gas=receipt_gas,
            receipt_status=1,
            expected_root_target=str(raw_document["target"]),
            expected_hyperlane_mailbox=(
                process_binding[0] if process_binding is not None else None
            ),
            expected_hyperlane_default_ism=(
                process_binding[1] if process_binding is not None else None
            ),
                trace_result=trace_result,
                labels=labels,
            )
        trace.update(raw_document)
        trace["status"] = 1
        trace["block_number"] = int(str(receipt["blockNumber"]), 16)
        trace["block_hash"] = _canonical_hash(str(receipt["blockHash"]))
        trace["transaction_index"] = int(str(receipt["transactionIndex"]), 16)
        semantic = dict(trace)
        semantic.pop("semantic_sha256", None)
        trace["semantic_sha256"] = hashlib.sha256(
            rfc8785.dumps(cast(Any, semantic))
        ).hexdigest()
        return trace

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for document in pool.map(fetch, pending):
            state.store(document)
    captured = state.existing()
    if captured != set(coordinates):
        raise LocalTopologyError("trace capture did not close over physical transactions")
    summary = {
        "schema_version": "xir-lab-native-multihop-trace-capture-v1",
        "phase": phase,
        "physical_transaction_count": len(coordinates),
        "captured_transaction_count": len(captured),
        "valid": True,
    }
    state.connection.close()
    return summary
