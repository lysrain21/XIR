"""Offline Ed25519 approval-authority utility kept outside the runner."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from xir_lab.execute.approvals import (
    APPROVAL_DOMAIN,
    REVOCATION_DOMAIN,
    canonical_payload_digest,
    signature_message,
)


class ApprovalAuthorityError(RuntimeError):
    """Raised when approval-authority custody or signing is unsafe."""


def _outside(path: Path, forbidden_roots: tuple[Path, ...]) -> None:
    resolved = path.resolve()
    for root in forbidden_roots:
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            continue
        raise ApprovalAuthorityError("approval key enters a forbidden root")


def create_approval_keypair(
    *,
    private_path: Path,
    public_path: Path,
    forbidden_roots: tuple[Path, ...],
) -> None:
    """Create a raw Ed25519 pair without returning or printing private bytes."""

    for path in (private_path, public_path):
        _outside(path, forbidden_roots)
        if path.exists():
            raise ApprovalAuthorityError("refusing to overwrite approval key material")
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private_path.parent, 0o700)
    public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    descriptor = os.open(
        private_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    public_path.write_text(public_bytes.hex() + "\n", encoding="ascii")
    os.chmod(public_path, 0o644)


class DetachedApprovalAuthority:
    def __init__(
        self,
        private_path: Path,
        *,
        forbidden_roots: tuple[Path, ...],
    ) -> None:
        _outside(private_path, forbidden_roots)
        status = private_path.stat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_mode & 0o077
            or status.st_size != 32
        ):
            raise ApprovalAuthorityError(
                "approval private key must be a private 32-byte file"
            )
        self.private_path = private_path

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key().public_key()

    def public_key_hex(self) -> str:
        return self.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

    def sign_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._sign(payload, APPROVAL_DOMAIN)

    def sign_revocation(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._sign(payload, REVOCATION_DOMAIN)

    def _private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.private_path.read_bytes())

    def _sign(self, payload: dict[str, Any], domain: bytes) -> dict[str, Any]:
        digest = canonical_payload_digest(payload)
        signature = self._private_key().sign(signature_message(domain, digest))
        return {
            "payload": payload,
            "payload_sha256": digest,
            "signature": signature.hex(),
        }
