"""Durable idempotent execution for separately approved operation batches."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.signer import (
    SignerCoordinator,
    SignerRequest,
    SpoolReference,
    signer_operation_id,
)
from xir_lab.execute.submission import Broadcaster, BroadcastResult
from xir_lab.faults import CrashInjector, NoCrashInjector

OperationKind = Literal["deployment", "configuration", "closeout"]


class ApprovedOperationError(RuntimeError):
    """Raised when an approved operation cannot advance without ambiguity."""


@dataclass(frozen=True)
class ApprovedTransaction:
    transaction_id: str
    request: SignerRequest
    expected_created_address: str | None = None


@dataclass(frozen=True)
class ApprovedOperationBatch:
    operation_id: str
    operation_type: OperationKind
    approval_id: str
    approval_payload_sha256: str
    transactions: tuple[ApprovedTransaction, ...]
    batch_sha256: str


@dataclass(frozen=True)
class PublicOperationReceipt:
    transaction_hash: str
    chain_id: int
    nonce: int
    status: int
    block_number: int
    block_hash: str
    contract_address: str | None
    raw_bytes: bytes
    finalized: bool


class OperationLookup(Protocol):
    def receipt(
        self, chain_id: int, transaction_hash: str
    ) -> PublicOperationReceipt | None:
        """Read a public receipt by the exact precomputed hash."""

    def account_nonce(self, chain_id: int, address: str) -> int | None:
        """Read the public latest nonce for ambiguity resolution."""


def _digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ApprovedOperationError(f"{label} is not a lowercase SHA-256 digest")


def build_approved_operation_batch(
    *,
    operation_id: str,
    operation_type: OperationKind,
    approval_id: str,
    approval_payload_sha256: str,
    transactions: tuple[ApprovedTransaction, ...],
) -> ApprovedOperationBatch:
    _digest(approval_payload_sha256, "approval payload")
    if (
        not operation_id
        or not approval_id
        or not transactions
        or len({item.transaction_id for item in transactions}) != len(transactions)
    ):
        raise ApprovedOperationError("approved operation identity is empty or duplicated")
    seen_coordinates: set[tuple[int, str, int]] = set()
    for item in transactions:
        coordinate = (
            item.request.chain_id,
            item.request.signer_id,
            item.request.nonce,
        )
        if coordinate in seen_coordinates:
            raise ApprovedOperationError("approved operation reuses a signer nonce")
        seen_coordinates.add(coordinate)
    body: dict[str, Any] = {
        "operation_id": operation_id,
        "operation_type": operation_type,
        "approval_id": approval_id,
        "approval_payload_sha256": approval_payload_sha256,
        "transactions": [
            {
                "transaction_id": item.transaction_id,
                "signer_operation_id": signer_operation_id(item.request),
                "unsigned_transaction_sha256": (
                    item.request.unsigned_transaction_sha256
                ),
                "expected_created_address": item.expected_created_address,
            }
            for item in transactions
        ],
    }
    return ApprovedOperationBatch(
        operation_id=operation_id,
        operation_type=operation_type,
        approval_id=approval_id,
        approval_payload_sha256=approval_payload_sha256,
        transactions=transactions,
        batch_sha256=hashlib.sha256(rfc8785.dumps(body)).hexdigest(),
    )


class ApprovedOperationExecutor:
    """Persist-before-sign/broadcast executor with exact-byte recovery."""

    def __init__(
        self,
        *,
        batch: ApprovedOperationBatch,
        journal_path: Path,
        store: EvidenceStore,
        signer: SignerCoordinator,
        broadcaster: Broadcaster,
        lookup: OperationLookup,
        crash_injector: CrashInjector | None = None,
    ) -> None:
        self.batch = batch
        self.journal_path = journal_path
        self.store = store
        self.signer = signer
        self.broadcaster = broadcaster
        self.lookup = lookup
        self.crash_injector = crash_injector or NoCrashInjector()

    def initialize(self) -> None:
        if self.journal_path.exists():
            existing = self._load()
            if existing["batch_sha256"] != self.batch.batch_sha256:
                raise ApprovedOperationError(
                    "operation journal is bound to another approved batch"
                )
            return
        document: dict[str, Any] = {
            "schema_version": "xir-lab-approved-operation-journal-v1",
            "operation_id": self.batch.operation_id,
            "operation_type": self.batch.operation_type,
            "approval_id": self.batch.approval_id,
            "approval_payload_sha256": self.batch.approval_payload_sha256,
            "batch_sha256": self.batch.batch_sha256,
            "transactions": [
                {
                    "transaction_id": item.transaction_id,
                    "state": "planned",
                    "signer_operation_id": signer_operation_id(item.request),
                    "chain_id": item.request.chain_id,
                    "nonce": item.request.nonce,
                    "transaction_hash": None,
                    "spool_reference": None,
                    "provider_reference": None,
                    "receipt_raw_sha256": None,
                    "block_number": None,
                    "block_hash": None,
                    "contract_address": None,
                    "reason_code": "planned",
                }
                for item in self.batch.transactions
            ],
            "updated_at": datetime.now(UTC).isoformat(),
        }
        self._persist(document)

    def advance(self, transaction_id: str) -> str:
        """Advance one transaction by at most sign and broadcast acknowledgement."""

        document = self._load()
        index, record, approved = self._record(document, transaction_id)
        if any(
            item["state"] != "finalized"
            for item in cast(list[dict[str, Any]], document["transactions"])[:index]
        ):
            raise ApprovedOperationError("approved transaction order would be skipped")
        state = cast(str, record["state"])
        if state == "planned":
            reference, transaction_hash = self.signer.sign_to_spool(approved.request)
            self.crash_injector.hit("after_signer_return")
            record["spool_reference"] = asdict(reference)
            record["transaction_hash"] = transaction_hash
            record["state"] = "signed_hash_persisted"
            record["reason_code"] = "signed_bytes_private"
            self._persist(document)
            self.crash_injector.hit("after_hash_reference_persistence")
            state = "signed_hash_persisted"
        if state not in {"signed_hash_persisted", "broadcast_unknown"}:
            return state
        reference = SpoolReference(**cast(dict[str, Any], record["spool_reference"]))
        signed_bytes = self.signer.spool.load(reference)
        expected_hash = cast(str, record["transaction_hash"])
        record["state"] = "broadcast_unknown"
        record["reason_code"] = "broadcast_started_ack_unknown"
        self._persist(document)
        result = self.broadcaster.broadcast(signed_bytes, expected_hash)
        self.crash_injector.hit("after_broadcast_before_acknowledgement")
        if result.accepted:
            record["state"] = "submitted"
            record["provider_reference"] = result.provider_reference
            record["reason_code"] = "rpc_acknowledged"
            self._persist(document)
        return cast(str, record["state"])

    def reconcile(self, transaction_id: str) -> str:
        document = self._load()
        _, record, approved = self._record(document, transaction_id)
        state = cast(str, record["state"])
        if state not in {"broadcast_unknown", "submitted", "included", "finalized"}:
            raise ApprovedOperationError("operation transaction is not publicly observable")
        if state == "finalized":
            return state
        transaction_hash = cast(str, record["transaction_hash"])
        receipt = self.lookup.receipt(approved.request.chain_id, transaction_hash)
        if receipt is None:
            if state != "broadcast_unknown":
                return state
            identity = self.signer.public_identity(approved.request.network_id)
            nonce = self.lookup.account_nonce(
                approved.request.chain_id, identity.address
            )
            if nonce is None:
                record["reason_code"] = "nonce_lookup_unavailable"
            elif nonce > approved.request.nonce:
                record["state"] = "blocked"
                record["reason_code"] = "nonce_consumed_without_exact_receipt"
            else:
                record["reason_code"] = "exact_hash_absent_exact_rebroadcast_allowed"
            self._persist(document)
            return cast(str, record["state"])
        if (
            receipt.transaction_hash.lower() != transaction_hash.lower()
            or receipt.chain_id != approved.request.chain_id
            or receipt.nonce != approved.request.nonce
            or receipt.status != 1
        ):
            record["state"] = "blocked"
            record["reason_code"] = "receipt_identity_or_status_mismatch"
            self._persist(document)
            return "blocked"
        if approved.expected_created_address is not None and (
            receipt.contract_address is None
            or receipt.contract_address.lower()
            != approved.expected_created_address.lower()
        ):
            record["state"] = "blocked"
            record["reason_code"] = "created_address_mismatch"
            self._persist(document)
            return "blocked"
        raw_sha256 = self.store.put_raw(
            receipt.raw_bytes,
            media_type="application/json",
            metadata={
                "kind": "approved-operation-receipt",
                "transaction_id": transaction_id,
                "chain_id": receipt.chain_id,
                "public_facts_only": True,
            },
        )
        record["receipt_raw_sha256"] = raw_sha256
        record["block_number"] = receipt.block_number
        record["block_hash"] = receipt.block_hash
        record["contract_address"] = receipt.contract_address
        record["state"] = "finalized" if receipt.finalized else "included"
        record["reason_code"] = (
            "canonical_receipt_finalized"
            if receipt.finalized
            else "canonical_receipt_included"
        )
        self._persist(document)
        return cast(str, record["state"])

    def repeat_exact_broadcast(self, transaction_id: str) -> BroadcastResult:
        document = self._load()
        _, record, _ = self._record(document, transaction_id)
        if (
            record["state"] != "broadcast_unknown"
            or record["reason_code"]
            != "exact_hash_absent_exact_rebroadcast_allowed"
        ):
            raise ApprovedOperationError("exact rebroadcast has not been proven safe")
        reference = SpoolReference(**cast(dict[str, Any], record["spool_reference"]))
        result = self.broadcaster.broadcast(
            self.signer.spool.load(reference),
            cast(str, record["transaction_hash"]),
        )
        if result.accepted:
            record["state"] = "submitted"
            record["provider_reference"] = result.provider_reference
            record["reason_code"] = "exact_bytes_rebroadcast_acknowledged"
            self._persist(document)
        return result

    def _record(
        self, document: dict[str, Any], transaction_id: str
    ) -> tuple[int, dict[str, Any], ApprovedTransaction]:
        records = cast(list[dict[str, Any]], document["transactions"])
        for index, (record, approved) in enumerate(
            zip(records, self.batch.transactions, strict=True)
        ):
            if approved.transaction_id == transaction_id:
                if record["transaction_id"] != transaction_id:
                    raise ApprovedOperationError("operation journal ordering changed")
                return index, record, approved
        raise ApprovedOperationError("unknown approved operation transaction")

    def _load(self) -> dict[str, Any]:
        if not self.journal_path.exists():
            self.initialize()
        try:
            document = json.loads(self.journal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovedOperationError("operation journal is unavailable or corrupt") from exc
        if not isinstance(document, dict):
            raise ApprovedOperationError("operation journal root is not an object")
        value = cast(dict[str, Any], document)
        if value.get("batch_sha256") != self.batch.batch_sha256:
            raise ApprovedOperationError("operation journal batch digest mismatch")
        return value

    def _persist(self, document: dict[str, Any]) -> None:
        document["updated_at"] = datetime.now(UTC).isoformat()
        self.journal_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary_path = self.journal_path.with_name(
            f".{self.journal_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary_path.open("wb") as handle:
                os.chmod(temporary_path, 0o600)
                handle.write(rfc8785.dumps(document) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.journal_path)
            os.chmod(self.journal_path, 0o600)
            directory = os.open(self.journal_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
