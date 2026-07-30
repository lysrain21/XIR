"""Independent XIR trace construction matching contracts/src/XIREncoding.sol."""

from __future__ import annotations

from dataclasses import dataclass

from eth_utils import keccak  # type: ignore[attr-defined]

TypedId = tuple[int, bytes]


@dataclass(frozen=True)
class XIRRecord:
    source_gateway: TypedId
    source_app: TypedId
    destination_app: TypedId
    nonce: int
    payload_hash: bytes


@dataclass(frozen=True)
class XIRContext:
    required_security: int
    policy_hash: bytes


@dataclass(frozen=True)
class XIRReceipt:
    source_gateway: TypedId
    destination_gateway: TypedId
    profile_hash: bytes
    evidence_hash: bytes
    transition_hash: bytes
    prior_prefix: bytes


def encode_typed_id(identifier: TypedId) -> bytes:
    kind, value = identifier
    expected = 20 if kind == 1 else 32 if kind == 2 else 0
    if len(value) != expected:
        raise ValueError("invalid XIR typed identifier")
    return bytes([kind, len(value)]) + value


def record_hash(record: XIRRecord) -> bytes:
    return keccak(
        b"XIR_RECORD_V1"
        + encode_typed_id(record.source_gateway)
        + encode_typed_id(record.source_app)
        + encode_typed_id(record.destination_app)
        + record.nonce.to_bytes(8, "big")
        + record.payload_hash
    )


def context_hash(context: XIRContext) -> bytes:
    return keccak(
        b"XIR_CONTEXT_V1"
        + context.required_security.to_bytes(1, "big")
        + context.policy_hash
    )


def root_id(record: XIRRecord, context: XIRContext, registry_version: int) -> bytes:
    return keccak(
        b"XIR_RID_V1"
        + encode_typed_id(record.source_gateway)
        + record_hash(record)
        + context_hash(context)
        + registry_version.to_bytes(4, "big")
    )


def message_id(rid: bytes, destination_app: TypedId) -> bytes:
    return keccak(b"XIR_MID_V1" + rid + encode_typed_id(destination_app))


def root_prefix(rid: bytes) -> bytes:
    return keccak(b"XIR_ROOT_V1" + rid)


def transition_hash(
    record: XIRRecord, context: XIRContext, source: TypedId, destination: TypedId
) -> bytes:
    return keccak(
        b"XIR_TRANSITION_V1"
        + record_hash(record)
        + context_hash(context)
        + encode_typed_id(source)
        + encode_typed_id(destination)
    )


def receipt_hash(receipt: XIRReceipt) -> bytes:
    return keccak(
        b"XIR_HOP_V1"
        + receipt.prior_prefix
        + encode_typed_id(receipt.source_gateway)
        + encode_typed_id(receipt.destination_gateway)
        + receipt.profile_hash
        + receipt.evidence_hash
        + receipt.transition_hash
    )


def next_prefix(receipt: XIRReceipt) -> bytes:
    return keccak(b"XIR_PREFIX_V1" + receipt.prior_prefix + receipt_hash(receipt))


def record_tuple(record: XIRRecord) -> tuple[TypedId, TypedId, TypedId, int, bytes]:
    return (
        record.source_gateway,
        record.source_app,
        record.destination_app,
        record.nonce,
        record.payload_hash,
    )


def receipt_tuple(
    receipt: XIRReceipt,
) -> tuple[TypedId, TypedId, bytes, bytes, bytes, bytes]:
    return (
        receipt.source_gateway,
        receipt.destination_gateway,
        receipt.profile_hash,
        receipt.evidence_hash,
        receipt.transition_hash,
        receipt.prior_prefix,
    )
