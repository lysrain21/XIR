from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from eth_account import Account

from xir_lab.execute.approval_authority import (
    ApprovalAuthorityError,
    DetachedApprovalAuthority,
    create_approval_keypair,
)
from xir_lab.execute.approvals import APPROVAL_DOMAIN, signature_message
from xir_lab.execute.signer import (
    PrivateSpool,
    SignerCoordinator,
    SignerError,
    SignerRequest,
    signer_operation_id,
)
from xir_lab.execute.signer_socket import (
    EncryptedKeystoreSigner,
    SignerSocketClient,
    SignerSocketServer,
    signer_request_document,
    unsigned_transaction_digest,
)


def _private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    os.chmod(path, 0o600)


def _request_sha256(request: SignerRequest) -> tuple[str, str]:
    operation_id = signer_operation_id(request)
    digest = hashlib.sha256(
        rfc8785.dumps(signer_request_document(operation_id, request))
    ).hexdigest()
    return operation_id, digest


def _backend(
    tmp_path: Path,
    request: SignerRequest | None = None,
) -> EncryptedKeystoreSigner:
    repository = tmp_path / "repo"
    repository.mkdir()
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    account = Account.create()
    password = b"fixture-password-only"
    keystore = custody / "runner.keystore"
    password_path = custody / "runner.password"
    _private_file(
        keystore,
        json.dumps(Account.encrypt(account.key, password)).encode(),
    )
    _private_file(password_path, password)
    active_request = request or _request()
    operation_id, digest = _request_sha256(active_request)
    return EncryptedKeystoreSigner(
        signer_id="runner",
        role="runner",
        keystore_path=keystore,
        password_path=password_path,
        state_root=custody / "state",
        allowed_requests={operation_id: digest},
        forbidden_roots=(repository,),
    )


def _request() -> SignerRequest:
    calldata = bytes.fromhex("12345678")
    request = SignerRequest(
        network_id="op-sepolia",
        chain_id=11_155_420,
        signer_id="runner",
        intent_id="intent-live-1",
        nonce=0,
        destination="0x" + "12" * 20,
        value_wei=0,
        calldata_sha256=hashlib.sha256(calldata).hexdigest(),
        calldata_length=len(calldata),
        fee_limit_wei=21_000 * 10,
        role="runner",
        config_sha256="34" * 32,
        code_sha256="56" * 32,
        gas_limit=21_000,
        max_fee_per_gas_wei=10,
        max_priority_fee_per_gas_wei=1,
        calldata_hex=calldata.hex(),
    )
    return replace(
        request,
        unsigned_transaction_sha256=unsigned_transaction_digest(request),
    )


def test_encrypted_backend_is_idempotent_and_signs_exact_request(
    tmp_path: Path,
) -> None:
    request = _request()
    backend = _backend(tmp_path, request)
    operation_id = signer_operation_id(request)
    first = backend.sign_transaction(operation_id, request)
    second = backend.sign_transaction(operation_id, request)
    assert first == second
    assert first.transaction_hash.startswith("0x")
    assert first.signed_bytes
    result_files = tuple(backend.state_root.glob("*.json"))
    assert len(result_files) == 1
    assert os.stat(result_files[0]).st_mode & 0o777 == 0o600
    restarted = EncryptedKeystoreSigner(
        signer_id="runner",
        role="runner",
        keystore_path=backend.keystore_path,
        password_path=backend.password_path,
        state_root=backend.state_root,
        allowed_requests=dict(backend.allowed_requests),
        forbidden_roots=(tmp_path / "repo",),
    )
    assert restarted.sign_transaction(operation_id, request) == first


def test_backend_rejects_role_digest_and_permission_failures(
    tmp_path: Path,
) -> None:
    request = _request()
    backend = _backend(tmp_path, request)
    with pytest.raises(SignerError, match="role or identity"):
        backend.sign_transaction(
            signer_operation_id(replace(request, role="deployer")),
            replace(request, role="deployer"),
        )
    changed = replace(request, unsigned_transaction_sha256="00" * 32)
    with pytest.raises(SignerError, match="unsigned transaction digest"):
        backend.sign_transaction(signer_operation_id(changed), changed)
    os.chmod(backend.password_path, 0o644)
    with pytest.raises(SignerError, match="private regular file"):
        EncryptedKeystoreSigner(
            signer_id="runner",
            role="runner",
            keystore_path=backend.keystore_path,
            password_path=backend.password_path,
            state_root=tmp_path / "state-two",
            allowed_requests=dict(backend.allowed_requests),
            forbidden_roots=(tmp_path / "repo",),
        )


def test_backend_rejects_unknown_or_tampered_operation(
    tmp_path: Path,
) -> None:
    request = _request()
    backend = _backend(tmp_path, request)
    changed = replace(request, nonce=1)
    changed = replace(
        changed,
        unsigned_transaction_sha256=unsigned_transaction_digest(changed),
    )
    with pytest.raises(SignerError, match="not allowlisted"):
        backend.sign_transaction(signer_operation_id(changed), changed)
    with pytest.raises(SignerError, match="does not bind"):
        backend.sign_transaction(signer_operation_id(request), changed)


def test_unix_socket_client_authenticates_and_routes_bytes_to_spool(
    tmp_path: Path,
) -> None:
    request = _request()
    backend = _backend(tmp_path, request)
    socket_path = tmp_path / "socket-root" / "signer.sock"
    server = SignerSocketServer(socket_path=socket_path, signer=backend)
    server.start()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve_once()
            server.serve_once()
        except BaseException as exc:  # pragma: no cover - assertion transport
            errors.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = SignerSocketClient(socket_path)
        identity = client.public_identity("op-sepolia")
        assert identity.address == backend.public_identity("op-sepolia").address
        coordinator = SignerCoordinator(
            client,
            PrivateSpool(tmp_path / "private-spool"),
        )
        reference, transaction_hash = coordinator.sign_to_spool(request)
        assert reference.signed_length > 0
        assert transaction_hash.startswith("0x")
        assert coordinator.spool.load(reference)
    finally:
        thread.join(timeout=5)
        server.close()
    assert not thread.is_alive()
    assert errors == []


def test_socket_client_rejects_unavailable_or_broad_socket(
    tmp_path: Path,
) -> None:
    missing = SignerSocketClient(tmp_path / "missing.sock")
    with pytest.raises(FileNotFoundError):
        missing.public_identity("op-sepolia")
    backend = _backend(tmp_path)
    socket_path = tmp_path / "socket-root" / "signer.sock"
    server = SignerSocketServer(socket_path=socket_path, signer=backend)
    server.start()
    try:
        os.chmod(socket_path, 0o622)
        with pytest.raises(SignerError, match="writable by other users"):
            SignerSocketClient(socket_path).public_identity("op-sepolia")
    finally:
        server.close()


def test_approval_authority_never_returns_private_material(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    custody = tmp_path / "approval-custody"
    private_path = custody / "authority.key"
    public_path = custody / "authority.pub"
    create_approval_keypair(
        private_path=private_path,
        public_path=public_path,
        forbidden_roots=(repository,),
    )
    assert os.stat(private_path).st_mode & 0o777 == 0o600
    authority = DetachedApprovalAuthority(
        private_path,
        forbidden_roots=(repository,),
    )
    payload = {"approval_id": "fixture", "issuer_sequence": 1}
    envelope = authority.sign_approval(payload)
    assert set(envelope) == {"payload", "payload_sha256", "signature"}
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(authority.public_key_hex())
    ).verify(
        bytes.fromhex(envelope["signature"]),
        signature_message(APPROVAL_DOMAIN, envelope["payload_sha256"]),
    )
    with pytest.raises(ApprovalAuthorityError, match="overwrite"):
        create_approval_keypair(
            private_path=private_path,
            public_path=public_path,
            forbidden_roots=(repository,),
        )


def test_approval_key_cannot_be_created_inside_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    with pytest.raises(ApprovalAuthorityError, match="forbidden root"):
        create_approval_keypair(
            private_path=repository / "authority.key",
            public_path=repository / "authority.pub",
            forbidden_roots=(repository,),
        )
