"""Finality-gated root signing for follow-up native security experiments.

The signer is deliberately separate from the transaction-submitting experiment
coordinator.  It signs only after independently reading a finalized
``RootCreated`` event and rebuilding the record and message identifiers from the
exact ``createRecord`` calldata.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_typing import HexStr
from web3 import Web3
from web3.exceptions import Web3RPCError
from web3.types import RPCEndpoint

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.xir_trace import XIRContext, XIRRecord, message_id, root_id


@dataclass(frozen=True)
class FinalizedRootCreation:
    """Public chain evidence needed to authorize one root signature."""

    transaction_hash: str
    block_number: int
    finalized_block_number: int
    gateway_address: str
    transaction_sender: str
    event_rid: bytes
    event_mid: bytes
    event_sender: str
    event_nonce: int
    destination_app: tuple[int, bytes]
    payload: bytes
    context: XIRContext
    registry_version: int
    gateway_id: tuple[int, bytes]
    finality_rule: str = "rpc-finalized-tag"


class RootCreationSource(Protocol):
    def read_finalized_creation(self, transaction_hash: str) -> FinalizedRootCreation: ...


class Web3RootCreationSource:
    """Read and decode one finalized ``XIRGateway.createRecord`` transaction."""

    def __init__(
        self,
        client: Web3,
        gateway: Any,
        *,
        qbft_confirmation_blocks: int = 1,
        timeout_seconds: int = 30,
    ) -> None:
        self.client = client
        self.gateway = gateway
        self.qbft_confirmation_blocks = qbft_confirmation_blocks
        self.timeout_seconds = timeout_seconds
        if qbft_confirmation_blocks < 0 or timeout_seconds <= 0:
            raise ValueError("invalid QBFT finality parameters")

    def read_finalized_creation(self, transaction_hash: str) -> FinalizedRootCreation:
        tx_hash = HexStr(transaction_hash)
        receipt = self.client.eth.get_transaction_receipt(tx_hash)
        if int(receipt["status"]) != 1:
            raise LocalTopologyError("root creation transaction did not succeed")
        gateway_address = Web3.to_checksum_address(self.gateway.address)
        if str(receipt["to"]).lower() != gateway_address.lower():
            raise LocalTopologyError("root creation receipt targets another contract")
        block_number = int(receipt["blockNumber"])
        finalized_number, finality_rule = self._finalized_number(
            block_number, bytes(receipt["blockHash"])
        )
        if block_number > finalized_number:
            raise LocalTopologyError("RootCreated event is not finalized")

        transaction = self.client.eth.get_transaction(tx_hash)
        if str(transaction["to"]).lower() != gateway_address.lower():
            raise LocalTopologyError("root creation transaction targets another contract")
        function, decoded = self.gateway.decode_function_input(transaction["input"])
        if function.fn_name != "createRecord":
            raise LocalTopologyError("root signer received a non-createRecord transaction")

        events = self.gateway.events.RootCreated().process_receipt(receipt)
        if len(events) != 1:
            raise LocalTopologyError("root creation receipt must contain exactly one event")
        event = events[0]["args"]
        destination = decoded["destinationApp"]
        context = decoded["context"]
        gateway_id = self.gateway.functions.selfId().call(
            block_identifier=block_number
        )
        return FinalizedRootCreation(
            transaction_hash=str(transaction_hash).lower(),
            block_number=block_number,
            finalized_block_number=finalized_number,
            gateway_address=gateway_address.lower(),
            transaction_sender=str(transaction["from"]).lower(),
            event_rid=bytes(event["rid"]),
            event_mid=bytes(event["mid"]),
            event_sender=str(event["sender"]).lower(),
            event_nonce=int(event["nonce"]),
            destination_app=(
                int(_struct_field(destination, "kind", 0)),
                bytes(_struct_field(destination, "value", 1)),
            ),
            payload=bytes(decoded["payload"]),
            context=XIRContext(
                int(_struct_field(context, "requiredSecurity", 0)),
                bytes(_struct_field(context, "policyHash", 1)),
            ),
            registry_version=int(decoded["registryVersion"]),
            gateway_id=(
                int(_struct_field(gateway_id, "kind", 0)),
                bytes(_struct_field(gateway_id, "value", 1)),
            ),
            finality_rule=finality_rule,
        )

    def _finalized_number(
        self, block_number: int, receipt_block_hash: bytes
    ) -> tuple[int, str]:
        try:
            finalized = self.client.eth.get_block("finalized")
        except Web3RPCError as exc:
            if "unknown block" not in str(exc).lower():
                raise
        else:
            return int(finalized["number"]), "rpc-finalized-tag"

        # Besu's private QBFT networks do not expose the Ethereum finalized
        # block tag.  A QBFT block is final once committed by the validator
        # quorum.  The experiment additionally waits for one successor block
        # and checks that the receipt block remains canonical.
        validators = self.client.provider.make_request(
            RPCEndpoint("qbft_getValidatorsByBlockNumber"), ["latest"]
        )
        validator_rows = validators.get("result")
        if not isinstance(validator_rows, list) or len(validator_rows) < 4:
            raise LocalTopologyError("QBFT validator quorum cannot be established")
        deadline = time.monotonic() + self.timeout_seconds
        required_height = block_number + self.qbft_confirmation_blocks
        latest_number = int(self.client.eth.block_number)
        while latest_number < required_height and time.monotonic() < deadline:
            time.sleep(0.25)
            latest_number = int(self.client.eth.block_number)
        if latest_number < required_height:
            raise LocalTopologyError("QBFT RootCreated block lacks the successor depth")
        canonical = self.client.eth.get_block(block_number)
        if bytes(canonical["hash"]) != receipt_block_hash:
            raise LocalTopologyError("RootCreated receipt is not in the canonical QBFT chain")
        return latest_number, f"qbft-committed-plus-{self.qbft_confirmation_blocks}"


def _struct_field(value: Any, name: str, index: int) -> Any:
    """Read one ABI struct component from Web3's mapping or tuple forms."""

    if isinstance(value, Mapping):
        try:
            return value[name]
        except KeyError as exc:
            raise LocalTopologyError(f"decoded ABI struct lacks {name}") from exc
    try:
        return value[index]
    except (IndexError, KeyError, TypeError) as exc:
        raise LocalTopologyError(f"decoded ABI struct lacks {name}") from exc


class FinalizedRootSigner:
    """Validate finalized chain evidence before signing a reconstructed ``rid``."""

    def __init__(
        self,
        *,
        source: RootCreationSource,
        private_key: str,
        audit_path: Path | None = None,
    ) -> None:
        self.source = source
        self.account = Account.from_key(private_key)
        self.audit_path = audit_path
        self.audit_lock = threading.Lock()
        self.audit_rows: dict[str, dict[str, Any]] = {}
        if audit_path is not None:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            if audit_path.is_file():
                for line in audit_path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    transaction_hash = str(row.get("transaction_hash", "")).lower()
                    if not transaction_hash or transaction_hash in self.audit_rows:
                        raise LocalTopologyError(
                            "root signer audit contains duplicate or invalid transactions"
                        )
                    self.audit_rows[transaction_hash] = row

    @property
    def address(self) -> str:
        return str(self.account.address)

    def sign(
        self,
        *,
        transaction_hash: str,
        record: XIRRecord,
        context: XIRContext,
        registry_version: int,
    ) -> bytes:
        observed = self.source.read_finalized_creation(transaction_hash)
        expected_rid = root_id(record, context, registry_version)
        expected_mid = message_id(expected_rid, record.destination_app)
        source_app = _evm_address(record.source_app)

        checks = {
            "gateway_id": observed.gateway_id == record.source_gateway,
            "transaction_sender": observed.transaction_sender == source_app,
            "event_sender": observed.event_sender == source_app,
            "event_nonce": observed.event_nonce == record.nonce,
            "destination_app": observed.destination_app == record.destination_app,
            "payload_hash": Web3.keccak(observed.payload) == record.payload_hash,
            "context": observed.context == context,
            "registry_version": observed.registry_version == registry_version,
            "rid": observed.event_rid == expected_rid,
            "mid": observed.event_mid == expected_mid,
            "finalized": observed.block_number <= observed.finalized_block_number,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        if failed:
            self._append_audit(observed, expected_rid, expected_mid, checks, signed=False)
            raise LocalTopologyError(
                "root signing evidence mismatch: " + ", ".join(failed)
            )

        signature = bytes(
            Account.sign_message(
                encode_defunct(primitive=expected_rid),
                private_key=self.account.key,
            ).signature
        )
        self._append_audit(observed, expected_rid, expected_mid, checks, signed=True)
        return signature

    def _append_audit(
        self,
        observed: FinalizedRootCreation,
        rid: bytes,
        mid: bytes,
        checks: dict[str, bool],
        *,
        signed: bool,
    ) -> None:
        if self.audit_path is None:
            return
        row: dict[str, Any] = {
            "schema_version": "xir-lab-finalized-root-signature-audit-v1",
            "transaction_hash": observed.transaction_hash,
            "block_number": observed.block_number,
            "finalized_block_number": observed.finalized_block_number,
            "gateway_address": observed.gateway_address,
            "runner": observed.transaction_sender,
            "root_signer": self.address.lower(),
            "finality_rule": observed.finality_rule,
            "rid": "0x" + rid.hex(),
            "mid": "0x" + mid.hex(),
            "checks": checks,
            "signed": signed,
        }
        with self.audit_lock:
            transaction_hash = observed.transaction_hash.lower()
            existing = self.audit_rows.get(transaction_hash)
            if existing == row:
                return
            if existing is not None:
                immutable_existing = dict(existing)
                immutable_row = dict(row)
                prior_finalized = int(immutable_existing.pop("finalized_block_number"))
                current_finalized = int(immutable_row.pop("finalized_block_number"))
                if immutable_existing == immutable_row and current_finalized >= prior_finalized:
                    return
                raise LocalTopologyError("root signer audit conflicts for an existing transaction")
            with self.audit_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            self.audit_rows[transaction_hash] = row


def _evm_address(identifier: tuple[int, bytes]) -> str:
    kind, value = identifier
    if kind != 1 or len(value) != 20:
        raise LocalTopologyError("root signer requires an EVM source application")
    return Web3.to_checksum_address(value).lower()


def audit_digest(path: Path) -> str:
    """Return a stable digest without exposing the signing key."""

    return hashlib.sha256(path.read_bytes()).hexdigest()
