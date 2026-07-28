"""External signer boundary and restrictive private signed-transaction spool."""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import rfc8785

from xir_lab.faults import CrashInjector, NoCrashInjector

ZERO_SHA256 = "0" * 64


class SignerError(RuntimeError):
    """Raised when signer identity or private spool guarantees fail."""


@dataclass(frozen=True)
class PublicSignerIdentity:
    signer_id: str
    network_id: str
    address: str
    identity_sha256: str


@dataclass(frozen=True)
class SignerRequest:
    network_id: str
    chain_id: int
    signer_id: str
    intent_id: str
    nonce: int
    destination: str
    value_wei: int
    calldata_sha256: str
    calldata_length: int
    fee_limit_wei: int
    role: str = "runner"
    config_sha256: str = ZERO_SHA256
    code_sha256: str = ZERO_SHA256
    gas_limit: int = 0
    max_fee_per_gas_wei: int = 0
    max_priority_fee_per_gas_wei: int = 0
    calldata_hex: str = ""
    unsigned_transaction_sha256: str = ZERO_SHA256


@dataclass(frozen=True)
class SignedTransaction:
    operation_id: str
    transaction_hash: str
    signed_bytes: bytes


@dataclass(frozen=True)
class SpoolReference:
    operation_id: str
    relative_path: str
    signed_sha256: str
    signed_length: int


class ExternalSigner(Protocol):
    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        """Return only public identity material."""

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        """Return the same signed bytes for every repeat of one operation ID."""


def signer_operation_id(request: SignerRequest) -> str:
    canonical = rfc8785.dumps(
        {
            "domain": "xir-testnet-lab-signer-operation-v1",
            "request": {
                "network_id": request.network_id,
                "chain_id": request.chain_id,
                "signer_id": request.signer_id,
                "intent_id": request.intent_id,
                "nonce": request.nonce,
                "destination": request.destination,
                "value_wei": request.value_wei,
                "calldata_sha256": request.calldata_sha256,
                "calldata_length": request.calldata_length,
                "fee_limit_wei": request.fee_limit_wei,
                "role": request.role,
                "config_sha256": request.config_sha256,
                "code_sha256": request.code_sha256,
                "gas_limit": request.gas_limit,
                "max_fee_per_gas_wei": request.max_fee_per_gas_wei,
                "max_priority_fee_per_gas_wei": (
                    request.max_priority_fee_per_gas_wei
                ),
                "calldata_hex": request.calldata_hex,
                "unsigned_transaction_sha256": (
                    request.unsigned_transaction_sha256
                ),
            },
        }
    )
    return "signop_" + hashlib.sha256(canonical).hexdigest()


class PrivateSpool:
    """Stores reusable signed bytes outside release roots with 0700/0600 modes."""

    def __init__(
        self,
        root: Path,
        *,
        crash_injector: CrashInjector | None = None,
    ) -> None:
        self.root = root
        self.crash_injector = crash_injector or NoCrashInjector()

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    @staticmethod
    def relative_path(operation_id: str) -> str:
        operation_digest = hashlib.sha256(operation_id.encode()).hexdigest()
        return (
            Path("signed")
            / operation_digest[:2]
            / f"{operation_id}.bin"
        ).as_posix()

    def persist(self, transaction: SignedTransaction) -> SpoolReference:
        self.initialize()
        if transaction.operation_id == "" or transaction.signed_bytes == b"":
            raise SignerError("signed transaction and operation ID must be non-empty")
        signed_sha256 = hashlib.sha256(transaction.signed_bytes).hexdigest()
        relative = Path(self.relative_path(transaction.operation_id))
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        if destination.exists():
            existing = destination.read_bytes()
            if hashlib.sha256(existing).hexdigest() != signed_sha256:
                raise SignerError("operation ID already maps to different signed bytes")
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{transaction.operation_id}.{secrets.token_hex(4)}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    midpoint = max(1, len(transaction.signed_bytes) // 2)
                    handle.write(transaction.signed_bytes[:midpoint])
                    self.crash_injector.hit("during_spool_temporary_write")
                    handle.write(transaction.signed_bytes[midpoint:])
                    handle.flush()
                    os.fsync(handle.fileno())
                self.crash_injector.hit("after_spool_file_fsync")
                os.replace(temporary_name, destination)
                os.chmod(destination, 0o600)
                self.crash_injector.hit(
                    "after_spool_rename_before_directory_fsync"
                )
                directory_fd = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                self.crash_injector.hit(
                    "after_spool_directory_fsync_before_database_reference"
                )
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
        return SpoolReference(
            operation_id=transaction.operation_id,
            relative_path=relative.as_posix(),
            signed_sha256=signed_sha256,
            signed_length=len(transaction.signed_bytes),
        )

    def load(self, reference: SpoolReference) -> bytes:
        candidate = (self.root / reference.relative_path).resolve()
        try:
            candidate.relative_to(self.root.resolve())
        except ValueError as exc:
            raise SignerError("spool reference escapes private root") from exc
        data = candidate.read_bytes()
        if (
            len(data) != reference.signed_length
            or hashlib.sha256(data).hexdigest() != reference.signed_sha256
        ):
            raise SignerError("private spool integrity mismatch")
        return data

    def destroy(self, reference: SpoolReference) -> None:
        """Verify and durably remove signed bytes after an authorized release."""
        self.load(reference)
        candidate = self.root / reference.relative_path
        candidate.unlink()
        directory_fd = os.open(candidate.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def quarantine_orphans(self, referenced_paths: Iterable[str]) -> tuple[str, ...]:
        """Move unreferenced signed or temporary files out of the usable spool."""
        self.initialize()
        referenced = set(referenced_paths)
        quarantine = self.root / "quarantine"
        quarantined: list[str] = []
        candidates = [
            path
            for path in (self.root / "signed").rglob("*")
            if path.is_file()
        ] if (self.root / "signed").is_dir() else []
        for candidate in sorted(candidates):
            relative = candidate.relative_to(self.root).as_posix()
            if relative in referenced:
                continue
            quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(quarantine, 0o700)
            digest = hashlib.sha256(relative.encode()).hexdigest()
            destination = quarantine / f"{digest}-{candidate.name}"
            os.replace(candidate, destination)
            os.chmod(destination, 0o600)
            quarantined.append(relative)
        if quarantined:
            directory_fd = os.open(quarantine, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return tuple(quarantined)


class SignerCoordinator:
    """Obtains public identity or routes signed bytes directly into the spool."""

    def __init__(self, signer: ExternalSigner, spool: PrivateSpool) -> None:
        self.signer = signer
        self.spool = spool

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        return self.signer.public_identity(network_id)

    def obtain_signed(self, request: SignerRequest) -> SignedTransaction:
        """Call the idempotent signer; callers must immediately route bytes to spool."""
        operation_id = signer_operation_id(request)
        signed = self.signer.sign_transaction(operation_id, request)
        if signed.operation_id != operation_id:
            raise SignerError("signer returned a different operation ID")
        return signed

    def persist_signed(self, transaction: SignedTransaction) -> SpoolReference:
        return self.spool.persist(transaction)

    def sign_to_spool(self, request: SignerRequest) -> tuple[SpoolReference, str]:
        signed = self.obtain_signed(request)
        reference = self.persist_signed(signed)
        return reference, signed.transaction_hash
