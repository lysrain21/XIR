"""Profile-state evidence capture and decoding for native-security-v1.

The security runner intentionally treats registry-owner transactions as setup
operations.  This module freezes the public transaction inputs for those
operations and decodes them together with ``ProfileSet`` logs.  The resulting
evidence lets the offline publication rebuild prove the per-case sequence

    enabled=false -> rejected delivery -> enabled=true

without reading a private key or contacting an RPC endpoint.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.security_v1 import load_security_config

PROFILE_SET_TOPIC = "0x" + keccak(text="ProfileSet(bytes32,bytes32,bytes32)").hex()
SET_PROFILE_SELECTOR = (
    "0x"
    + keccak(text="setProfile(bytes32,(bytes32,bytes32,address,uint8,uint64,uint64,bool))")[
        :4
    ].hex()
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return Web3.to_hex(bytes(value)).lower()
    return str(value).lower()


def _integer(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def profile_event(receipt: dict[str, Any], registry_address: str) -> dict[str, str]:
    """Decode and validate the unique ProfileSet log in ``receipt``."""

    matches: list[dict[str, Any]] = []
    for raw_log in cast(list[dict[str, Any]], receipt.get("logs", [])):
        topics = cast(list[Any], raw_log.get("topics", []))
        if (
            str(raw_log.get("address", "")).lower() == registry_address.lower()
            and len(topics) == 2
            and _hex(topics[0]) == PROFILE_SET_TOPIC
        ):
            matches.append(raw_log)
    if len(matches) != 1:
        raise LocalTopologyError(f"expected one ProfileSet log, observed {len(matches)}")
    event = matches[0]
    topics = cast(list[Any], event["topics"])
    data = bytes.fromhex(str(event["data"])[2:])
    if len(data) != 64:
        raise LocalTopologyError("ProfileSet event data must contain srcHash and dstHash")
    return {
        "profile_hash": _hex(topics[1]),
        "src_hash": "0x" + data[:32].hex(),
        "dst_hash": "0x" + data[32:].hex(),
    }


def decode_set_profile(transaction: dict[str, Any]) -> dict[str, Any]:
    """Decode the static setProfile calldata used by XIRRegistry."""

    calldata = str(transaction.get("input", "")).lower()
    if not calldata.startswith(SET_PROFILE_SELECTOR):
        raise LocalTopologyError("registry transaction is not setProfile")
    encoded = bytes.fromhex(calldata[10:])
    if len(encoded) != 8 * 32:
        raise LocalTopologyError("setProfile calldata has an unexpected length")
    words = [encoded[index : index + 32] for index in range(0, len(encoded), 32)]
    integers = [int.from_bytes(word, "big") for word in words]
    if integers[4] > 255 or integers[5] > 2**64 - 1 or integers[6] > 2**64 - 1:
        raise LocalTopologyError("setProfile integer exceeds the Solidity field width")
    if integers[7] not in {0, 1}:
        raise LocalTopologyError("setProfile enabled flag is not canonical")
    if any(words[3][:12]):
        raise LocalTopologyError("setProfile adapter address is not canonically encoded")
    return {
        "profile_hash": "0x" + words[0].hex(),
        "src_hash": "0x" + words[1].hex(),
        "dst_hash": "0x" + words[2].hex(),
        "adapter": "0x" + words[3][12:].hex(),
        "security_level": integers[4],
        "valid_after": integers[5],
        "valid_until": integers[6],
        "enabled": bool(integers[7]),
    }


def capture_profile_transactions(
    *,
    config_path: Path,
    deployment_path: Path,
    evidence_root: Path,
    rpc_url: str,
) -> dict[str, Any]:
    """Freeze public transaction inputs for every successful ProfileSet receipt."""

    config, config_sha256 = load_security_config(config_path)
    campaign_version = "v2" if config.get("campaign_id") == "native-security-v2" else "v1"
    deployment = cast(dict[str, Any], json.loads(deployment_path.read_text(encoding="utf-8")))
    deployment_sha256 = sha256_file(deployment_path)
    registry_address = str(deployment["chains"]["destination"]["registry"]).lower()
    expected_count = (
        len(cast(list[str], config["routes"])) * int(config["repetitions_per_route_case"]) * 2
    )
    client = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    if not client.is_connected():
        raise LocalTopologyError("destination RPC is unavailable")

    transaction_root = evidence_root / "raw-profile-transactions"
    transaction_root.mkdir(parents=True, exist_ok=True)
    captures: list[dict[str, Any]] = []
    for receipt_path in sorted((evidence_root / "raw-receipts").glob("0x*.json")):
        receipt = cast(dict[str, Any], json.loads(receipt_path.read_text(encoding="utf-8")))
        if (
            int(receipt.get("status", -1)) != 1
            or str(receipt.get("to", "")).lower() != registry_address
        ):
            continue
        try:
            event = profile_event(receipt, registry_address)
        except LocalTopologyError:
            continue
        tx_hash = str(receipt["transactionHash"]).lower()
        transaction = client.eth.get_transaction(HexStr(tx_hash))
        document = {
            "schema_version": (
                f"xir-lab-native-security-{campaign_version}-profile-transaction-v1"
            ),
            "transaction_hash": _hex(transaction["hash"]),
            "block_hash": _hex(transaction["blockHash"]),
            "block_number": _integer(transaction["blockNumber"]),
            "transaction_index": _integer(transaction["transactionIndex"]),
            "from": str(transaction["from"]).lower(),
            "to": str(transaction["to"]).lower(),
            "input": _hex(transaction["input"]),
            "nonce": _integer(transaction["nonce"]),
            "chain_id": _integer(transaction.get("chainId", client.eth.chain_id)),
            "type": _integer(transaction["type"]),
        }
        decoded = decode_set_profile(document)
        if (
            document["transaction_hash"] != tx_hash
            or document["block_hash"] != str(receipt["blockHash"]).lower()
            or document["block_number"] != int(receipt["blockNumber"])
            or document["transaction_index"] != int(receipt["transactionIndex"])
            or document["to"] != registry_address
            or decoded["profile_hash"] != event["profile_hash"]
            or decoded["src_hash"] != event["src_hash"]
            or decoded["dst_hash"] != event["dst_hash"]
        ):
            raise LocalTopologyError(f"profile transaction/receipt mismatch: {tx_hash}")
        target = transaction_root / f"{tx_hash}.json"
        rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if target.exists() and target.read_text(encoding="utf-8") != rendered:
            raise LocalTopologyError(f"profile transaction capture changed: {target}")
        target.write_text(rendered, encoding="utf-8")
        captures.append(
            {
                "transaction_hash": tx_hash,
                "profile_hash": decoded["profile_hash"],
                "enabled": decoded["enabled"],
                "block_number": document["block_number"],
                "transaction_index": document["transaction_index"],
                "receipt_sha256": sha256_file(receipt_path),
                "transaction_sha256": sha256_file(target),
            }
        )

    captures.sort(key=lambda item: (item["block_number"], item["transaction_index"]))
    errors: list[str] = []
    if len(captures) != expected_count:
        errors.append(
            f"profile transaction count: observed={len(captures)}, expected={expected_count}"
        )
    if len({item["transaction_hash"] for item in captures}) != len(captures):
        errors.append("profile transaction hashes are not unique")
    capture = {
        "schema_version": (f"xir-lab-native-security-{campaign_version}-profile-capture-v1"),
        "config_sha256": config_sha256,
        "deployment_sha256": deployment_sha256,
        "chain_id": int(client.eth.chain_id),
        "registry_address": registry_address,
        "rpc_url_included": False,
        "expected_transactions": expected_count,
        "captured_transactions": len(captures),
        "transactions": captures,
        "errors": errors,
        "valid": not errors,
    }
    capture_path = evidence_root / "profile-transaction-capture.json"
    capture_path.write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        raise LocalTopologyError(errors[0])
    return capture
