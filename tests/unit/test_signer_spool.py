from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from xir_lab.execute.signer import (
    PrivateSpool,
    PublicSignerIdentity,
    SignedTransaction,
    SignerCoordinator,
    SignerError,
    SignerRequest,
    signer_operation_id,
)


class FixtureSigner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        return PublicSignerIdentity(
            signer_id="runner",
            network_id=network_id,
            address="0x" + "11" * 20,
            identity_sha256="22" * 32,
        )

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        self.calls.append(operation_id)
        signed = hashlib.sha256(
            (operation_id + request.intent_id).encode()
        ).digest()
        return SignedTransaction(
            operation_id=operation_id,
            transaction_hash="0x" + hashlib.sha256(signed).hexdigest(),
            signed_bytes=signed,
        )


def _request() -> SignerRequest:
    return SignerRequest(
        network_id="op-sepolia",
        chain_id=11155420,
        signer_id="runner",
        intent_id="intent-1",
        nonce=7,
        destination="0x" + "33" * 20,
        value_wei=10,
        calldata_sha256="44" * 32,
        calldata_length=32,
        fee_limit_wei=100,
    )


def test_operation_id_is_deterministic_and_binds_intent() -> None:
    request = _request()
    assert signer_operation_id(request) == signer_operation_id(request)
    changed = SignerRequest(**{**request.__dict__, "nonce": 8})
    assert signer_operation_id(request) != signer_operation_id(changed)


def test_signed_bytes_flow_only_to_private_spool(tmp_path: Path) -> None:
    signer = FixtureSigner()
    spool = PrivateSpool(tmp_path / "private-spool")
    coordinator = SignerCoordinator(signer, spool)
    reference, transaction_hash = coordinator.sign_to_spool(_request())
    assert transaction_hash.startswith("0x")
    assert not hasattr(reference, "signed_bytes")
    assert spool.load(reference) != b""
    assert os.stat(spool.root).st_mode & 0o777 == 0o700
    assert os.stat(spool.root / reference.relative_path).st_mode & 0o777 == 0o600


def test_operation_id_cannot_map_to_different_signed_bytes(tmp_path: Path) -> None:
    spool = PrivateSpool(tmp_path / "private-spool")
    first = SignedTransaction("signop_fixture", "0x1", b"first")
    spool.persist(first)
    with pytest.raises(SignerError, match="different signed bytes"):
        spool.persist(SignedTransaction("signop_fixture", "0x2", b"second"))


def test_spool_detects_truncation(tmp_path: Path) -> None:
    spool = PrivateSpool(tmp_path / "private-spool")
    reference = spool.persist(
        SignedTransaction("signop_fixture", "0x1", b"signed-transaction")
    )
    (spool.root / reference.relative_path).write_bytes(b"truncated")
    with pytest.raises(SignerError, match="integrity mismatch"):
        spool.load(reference)
