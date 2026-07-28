"""Authenticated Unix-socket signer transport and encrypted-keystore backend."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import struct
import tempfile
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import jsonschema
import rfc8785
from eth_account import Account

from xir_lab.execute.signer import (
    ExternalSigner,
    PublicSignerIdentity,
    SignedTransaction,
    SignerError,
    SignerRequest,
    signer_operation_id,
)

_MAX_MESSAGE_BYTES = 1_048_576
_CHAIN_NETWORKS = {
    11_155_420: "op-sepolia",
    421_614: "arbitrum-sepolia",
    84_532: "base-sepolia",
}


def unsigned_transaction_document(request: SignerRequest) -> dict[str, Any]:
    return {
        "chainId": request.chain_id,
        "nonce": request.nonce,
        "to": request.destination,
        "value": request.value_wei,
        "data": "0x" + request.calldata_hex,
        "gas": request.gas_limit,
        "maxFeePerGas": request.max_fee_per_gas_wei,
        "maxPriorityFeePerGas": request.max_priority_fee_per_gas_wei,
        "type": 2,
    }


def unsigned_transaction_digest(request: SignerRequest) -> str:
    return hashlib.sha256(
        rfc8785.dumps(unsigned_transaction_document(request))
    ).hexdigest()


def signer_request_document(
    operation_id: str,
    request: SignerRequest,
) -> dict[str, Any]:
    return {
        "schema_version": "xir-lab-signer-request-v1",
        "operation_id": operation_id,
        **asdict(request),
    }


def _schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _validate_schema(document: dict[str, Any], schema_name: str) -> None:
    errors = sorted(
        jsonschema.Draft202012Validator(_schema(schema_name)).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(value) for value in errors[0].path) or "<root>"
        raise SignerError(f"signer schema violation at {location}")


def validate_signer_request(operation_id: str, request: SignerRequest) -> str:
    document = signer_request_document(operation_id, request)
    _validate_schema(document, "signer-request-v1.schema.json")
    if signer_operation_id(request) != operation_id:
        raise SignerError("signer operation ID does not bind the request")
    if _CHAIN_NETWORKS.get(request.chain_id) != request.network_id:
        raise SignerError("signer request changed the fixed network identity")
    calldata = bytes.fromhex(request.calldata_hex)
    if (
        len(calldata) != request.calldata_length
        or hashlib.sha256(calldata).hexdigest() != request.calldata_sha256
    ):
        raise SignerError("signer calldata digest or length mismatch")
    if unsigned_transaction_digest(request) != request.unsigned_transaction_sha256:
        raise SignerError("unsigned transaction digest mismatch")
    if request.max_priority_fee_per_gas_wei > request.max_fee_per_gas_wei:
        raise SignerError("priority fee exceeds maximum fee")
    if request.gas_limit * request.max_fee_per_gas_wei > request.fee_limit_wei:
        raise SignerError("unsigned transaction exceeds fee limit")
    return hashlib.sha256(rfc8785.dumps(document)).hexdigest()


def _assert_private_file(path: Path, label: str) -> None:
    status = path.stat()
    if not stat.S_ISREG(status.st_mode) or status.st_mode & 0o077:
        raise SignerError(f"{label} must be a private regular file")


def _assert_external(path: Path, forbidden_roots: tuple[Path, ...]) -> None:
    resolved = path.resolve()
    for root in forbidden_roots:
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            continue
        raise SignerError("signer custody path enters a forbidden root")


class EncryptedKeystoreSigner(ExternalSigner):
    """Signs only validated EIP-1559 requests and caches exact results privately."""

    def __init__(
        self,
        *,
        signer_id: str,
        role: str,
        keystore_path: Path,
        password_path: Path,
        state_root: Path,
        allowed_requests: Mapping[str, str],
        forbidden_roots: tuple[Path, ...],
    ) -> None:
        if role not in {"deployer", "runner"}:
            raise SignerError("unsupported signer role")
        for path in (keystore_path, password_path, state_root):
            _assert_external(path, forbidden_roots)
        _assert_private_file(keystore_path, "keystore")
        _assert_private_file(password_path, "password")
        state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state_root, 0o700)
        if state_root.stat().st_mode & 0o077:
            raise SignerError("signer state root permissions are too broad")
        self.signer_id = signer_id
        self.role = role
        self.keystore_path = keystore_path
        self.password_path = password_path
        self.state_root = state_root
        self.allowed_requests = dict(allowed_requests)
        self._account = self._load_account()

    def _load_account(self) -> Any:
        encrypted = json.loads(self.keystore_path.read_text(encoding="utf-8"))
        password = self.password_path.read_text(encoding="utf-8").rstrip("\r\n")
        try:
            private_key = Account.decrypt(encrypted, password)
        except (ValueError, KeyError) as exc:
            raise SignerError("encrypted keystore could not be opened") from exc
        return Account.from_key(private_key)

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        if network_id not in _CHAIN_NETWORKS.values():
            raise SignerError("signer identity requested for unsupported network")
        digest = hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "xir-testnet-lab-signer-identity-v1",
                    "signer_id": self.signer_id,
                    "role": self.role,
                    "address": self._account.address,
                    "keystore_sha256": hashlib.sha256(
                        self.keystore_path.read_bytes()
                    ).hexdigest(),
                }
            )
        ).hexdigest()
        return PublicSignerIdentity(
            signer_id=self.signer_id,
            network_id=network_id,
            address=self._account.address,
            identity_sha256=digest,
        )

    def _result_path(self, operation_id: str) -> Path:
        return self.state_root / f"{hashlib.sha256(operation_id.encode()).hexdigest()}.json"

    def sign_transaction(
        self,
        operation_id: str,
        request: SignerRequest,
    ) -> SignedTransaction:
        if request.signer_id != self.signer_id or request.role != self.role:
            raise SignerError("signer request role or identity mismatch")
        request_sha256 = validate_signer_request(operation_id, request)
        expected_request = self.allowed_requests.get(operation_id)
        if expected_request is None:
            raise SignerError("signer operation is not allowlisted")
        if expected_request != request_sha256:
            raise SignerError("signer allowlist request digest mismatch")
        destination = self._result_path(operation_id)
        if destination.exists():
            document = json.loads(destination.read_text(encoding="utf-8"))
            if document.get("request_sha256") != request_sha256:
                raise SignerError("operation ID is already bound to another request")
            return SignedTransaction(
                operation_id=operation_id,
                transaction_hash=cast(str, document["transaction_hash"]),
                signed_bytes=bytes.fromhex(cast(str, document["signed_bytes_hex"])),
            )
        signed = self._account.sign_transaction(unsigned_transaction_document(request))
        raw = bytes(signed.raw_transaction)
        transaction_hash = "0x" + signed.hash.hex().removeprefix("0x")
        response = {
            "schema_version": "xir-lab-signer-response-v1",
            "operation_id": operation_id,
            "signer_id": self.signer_id,
            "role": self.role,
            "address": self._account.address,
            "request_sha256": request_sha256,
            "transaction_hash": transaction_hash,
            "signed_bytes_hex": raw.hex(),
        }
        _validate_schema(response, "signer-response-v1.schema.json")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{operation_id}.",
            suffix=".tmp",
            dir=self.state_root,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(rfc8785.dumps(response) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            directory = os.open(self.state_root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return SignedTransaction(operation_id, transaction_hash, raw)


def _send_message(connection: socket.socket, document: dict[str, Any]) -> None:
    data = rfc8785.dumps(document)
    if len(data) > _MAX_MESSAGE_BYTES:
        raise SignerError("signer message exceeds size bound")
    connection.sendall(struct.pack("!I", len(data)) + data)


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise SignerError("signer socket closed during message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_message(connection: socket.socket) -> dict[str, Any]:
    length = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if length == 0 or length > _MAX_MESSAGE_BYTES:
        raise SignerError("invalid signer message size")
    value = json.loads(_receive_exact(connection, length))
    if not isinstance(value, dict):
        raise SignerError("signer message root must be an object")
    return cast(dict[str, Any], value)


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise SignerError("peer credential authentication is unavailable")
    credentials = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    _, uid, _ = struct.unpack("3i", credentials)
    return int(uid)


class SignerSocketClient(ExternalSigner):
    def __init__(
        self,
        socket_path: Path,
        *,
        expected_uid: int | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid

    def _request(self, document: dict[str, Any]) -> dict[str, Any]:
        status = self.socket_path.stat()
        if not stat.S_ISSOCK(status.st_mode) or status.st_mode & 0o022:
            raise SignerError("signer socket is missing or writable by other users")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(self.socket_path))
            if _peer_uid(connection) != self.expected_uid:
                raise SignerError("signer socket peer UID mismatch")
            _send_message(connection, document)
            response = _receive_message(connection)
        if response.get("ok") is not True:
            raise SignerError(
                f"signer service rejected request: {response.get('error_code', 'unknown')}"
            )
        data = response.get("data")
        if not isinstance(data, dict):
            raise SignerError("signer service returned invalid data")
        return cast(dict[str, Any], data)

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        data = self._request(
            {
                "schema_version": "xir-lab-signer-rpc-v1",
                "method": "public_identity",
                "network_id": network_id,
            }
        )
        return PublicSignerIdentity(
            signer_id=cast(str, data["signer_id"]),
            network_id=cast(str, data["network_id"]),
            address=cast(str, data["address"]),
            identity_sha256=cast(str, data["identity_sha256"]),
        )

    def sign_transaction(
        self,
        operation_id: str,
        request: SignerRequest,
    ) -> SignedTransaction:
        data = self._request(
            {
                "schema_version": "xir-lab-signer-rpc-v1",
                "method": "sign_transaction",
                "request": signer_request_document(operation_id, request),
            }
        )
        _validate_schema(data, "signer-response-v1.schema.json")
        return SignedTransaction(
            operation_id=cast(str, data["operation_id"]),
            transaction_hash=cast(str, data["transaction_hash"]),
            signed_bytes=bytes.fromhex(cast(str, data["signed_bytes_hex"])),
        )


class SignerSocketServer:
    """Small authenticated signer service; callers own process supervision."""

    def __init__(
        self,
        *,
        socket_path: Path,
        signer: ExternalSigner,
        allowed_uid: int | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.signer = signer
        self.allowed_uid = os.getuid() if allowed_uid is None else allowed_uid
        self.listener: socket.socket | None = None

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.socket_path.parent, 0o700)
        if self.socket_path.exists():
            raise SignerError("refusing to replace an existing signer socket path")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        listener.listen(4)
        self.listener = listener

    def close(self) -> None:
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.socket_path.exists() and stat.S_ISSOCK(self.socket_path.stat().st_mode):
            self.socket_path.unlink()

    def serve_once(self) -> None:
        if self.listener is None:
            raise SignerError("signer server is not started")
        connection, _ = self.listener.accept()
        with connection:
            if _peer_uid(connection) != self.allowed_uid:
                _send_message(
                    connection,
                    {"ok": False, "error_code": "peer_uid_mismatch"},
                )
                return
            try:
                request = _receive_message(connection)
                data = self._dispatch(request)
            except (SignerError, KeyError, TypeError, ValueError):
                _send_message(
                    connection,
                    {"ok": False, "error_code": "signer_request_rejected"},
                )
                return
            _send_message(connection, {"ok": True, "data": data})

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("schema_version") != "xir-lab-signer-rpc-v1":
            raise SignerError("unsupported signer RPC schema")
        method = request.get("method")
        if method == "public_identity":
            identity = self.signer.public_identity(cast(str, request["network_id"]))
            return asdict(identity)
        if method != "sign_transaction":
            raise SignerError("unsupported signer RPC method")
        document = cast(dict[str, Any], request["request"])
        _validate_schema(document, "signer-request-v1.schema.json")
        fields = dict(document)
        fields.pop("schema_version")
        operation_id = cast(str, fields.pop("operation_id"))
        signer_request = SignerRequest(**fields)
        signed = self.signer.sign_transaction(operation_id, signer_request)
        identity = self.signer.public_identity(signer_request.network_id)
        response = {
            "schema_version": "xir-lab-signer-response-v1",
            "operation_id": signed.operation_id,
            "signer_id": identity.signer_id,
            "role": signer_request.role,
            "address": identity.address,
            "request_sha256": hashlib.sha256(
                rfc8785.dumps(document)
            ).hexdigest(),
            "transaction_hash": signed.transaction_hash,
            "signed_bytes_hex": signed.signed_bytes.hex(),
        }
        _validate_schema(response, "signer-response-v1.schema.json")
        return response
