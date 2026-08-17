"""Web3 client construction for the retained Besu QBFT chains."""

from __future__ import annotations

import re

from requests import RequestException
from web3 import HTTPProvider, Web3
from web3.exceptions import Web3RPCError
from web3.middleware import ExtraDataToPOAMiddleware

from xir_lab.localnet.topology import LocalTopologyError

BESU_RAW_TRANSACTION_RPC_METHOD = "debug_getRawTransaction"
_RAW_TRANSACTION_RESULT = re.compile(r"0x(?:[0-9a-fA-F]{2})+").fullmatch


def _unwrap_besu_typed_transaction(raw: bytes) -> bytes:
    """Normalize Besu's block-body RLP wrapper around a typed transaction.

    Besu 26.4 implements ``debug_getRawTransaction`` with
    ``Transaction.writeTo``.  Legacy transactions are emitted as their opaque
    RLP list, but EIP-2718 transactions are emitted as an RLP byte string whose
    payload is the opaque ``type || rlp(payload)`` transaction.  The transaction
    hash is defined over that payload, not over the surrounding byte string.
    """

    prefix = raw[0]
    if prefix < 0x80 or prefix >= 0xC0:
        return raw
    if prefix <= 0xB7:
        payload_offset = 1
        payload_length = prefix - 0x80
    else:
        length_length = prefix - 0xB7
        if len(raw) <= length_length:
            raise LocalTopologyError("Besu raw transaction RLP wrapper is truncated")
        length_bytes = raw[1 : 1 + length_length]
        if length_bytes[0] == 0:
            raise LocalTopologyError("Besu raw transaction RLP length is non-canonical")
        payload_offset = 1 + length_length
        payload_length = int.from_bytes(length_bytes, byteorder="big")
        if payload_length < 56:
            raise LocalTopologyError("Besu raw transaction RLP length is non-canonical")
    if payload_offset + payload_length != len(raw):
        raise LocalTopologyError("Besu raw transaction RLP wrapper length mismatch")
    payload = raw[payload_offset:]
    if len(payload) < 2 or payload[0] > 0x7F or payload[1] < 0xC0:
        raise LocalTopologyError("Besu raw transaction RLP wrapper is not EIP-2718")
    return payload


def decode_besu_raw_transaction_result(value: object) -> bytes:
    """Validate, decode, and normalize Besu's DEBUG raw-transaction result."""

    if not isinstance(value, str) or _RAW_TRANSACTION_RESULT(value) is None:
        raise LocalTopologyError("Besu raw transaction result is unavailable")
    return _unwrap_besu_typed_transaction(bytes.fromhex(value[2:]))


def is_transient_rpc_error(error: BaseException) -> bool:
    """Return whether a transport/RPC failure is safe to retry unchanged."""

    if isinstance(error, RequestException):
        return True
    if not isinstance(error, Web3RPCError):
        return False
    message = str(error).lower()
    return (
        "transaction pool not enabled" in message
        and "node not yet in sync" in message
    )


def qbft_web3(rpc_url: str, *, timeout: int = 60) -> Web3:
    """Return a client that accepts QBFT consensus data in block headers."""

    client = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
    client.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return client
