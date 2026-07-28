"""RFC 8785 + Ed25519 operation approvals, revocations, and anti-replay ledger."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import jsonschema
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from xir_lab.evidence.store import EvidenceStore

APPROVAL_DOMAIN = b"xir-testnet-lab-approval-v1"
REVOCATION_DOMAIN = b"xir-testnet-lab-revocation-v1"


class ApprovalError(ValueError):
    """Raised when an approval is invalid, expired, revoked, or replayed."""


@dataclass(frozen=True)
class PinnedApprovalKey:
    issuer_id: str
    approval_key_id: str
    public_key_hex: str


@dataclass(frozen=True)
class VerifiedApproval:
    approval_id: str
    operation_type: str
    operation_id: str
    payload_sha256: str
    issuer_sequence: int


def canonical_payload_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def signature_message(domain: bytes, payload_sha256: str) -> bytes:
    return domain + b"\x00" + bytes.fromhex(payload_sha256)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ApprovalError("approval time must include a UTC offset")
    return parsed.astimezone(UTC)


class ApprovalVerifier:
    def __init__(
        self,
        *,
        store: EvidenceStore,
        pinned_keys: tuple[PinnedApprovalKey, ...],
    ) -> None:
        self.store = store
        self.keys = {key.approval_key_id: key for key in pinned_keys}

    def _validate_document(
        self, document: dict[str, Any], schema_name: str
    ) -> dict[str, Any]:
        schema_path = Path(__file__).resolve().parents[3] / "schemas" / schema_name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
        if errors:
            first = errors[0]
            location = ".".join(str(item) for item in first.path) or "<root>"
            raise ApprovalError(f"schema validation failed at {location}: {first.message}")
        return cast(dict[str, Any], document["payload"])

    def _verify_signature(
        self,
        *,
        payload: dict[str, Any],
        payload_sha256: str,
        signature_hex: str,
        domain: bytes,
    ) -> PinnedApprovalKey:
        computed = canonical_payload_digest(payload)
        if computed != payload_sha256:
            raise ApprovalError("canonical payload digest mismatch")
        key_id = cast(str, payload["approval_key_id"])
        key = self.keys.get(key_id)
        if key is None or key.issuer_id != payload["issuer_id"]:
            raise ApprovalError("approval key is not pinned for this issuer")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(key.public_key_hex)
            )
            public_key.verify(
                bytes.fromhex(signature_hex),
                signature_message(domain, payload_sha256),
            )
        except (ValueError, InvalidSignature) as exc:
            raise ApprovalError("invalid Ed25519 signature") from exc
        return key

    def verify_and_consume(
        self,
        document: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> VerifiedApproval:
        payload = self._validate_document(document, "approval-envelope-v1.schema.json")
        payload_sha256 = cast(str, document["payload_sha256"])
        self._verify_signature(
            payload=payload,
            payload_sha256=payload_sha256,
            signature_hex=cast(str, document["signature"]),
            domain=APPROVAL_DOMAIN,
        )
        issued_at = _parse_time(cast(str, payload["issued_at"]))
        valid_from = _parse_time(cast(str, payload["valid_from"]))
        valid_until = _parse_time(cast(str, payload["valid_until"]))
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if not issued_at <= valid_from < valid_until:
            raise ApprovalError("approval time ordering is invalid")
        if not valid_from <= current < valid_until:
            raise ApprovalError("approval is not currently valid")
        approval_id = cast(str, payload["approval_id"])
        issuer_id = cast(str, payload["issuer_id"])
        sequence = cast(int, payload["issuer_sequence"])
        with self.store.write() as connection:
            revoked = connection.execute(
                "SELECT 1 FROM approval_revocations WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if revoked is not None:
                raise ApprovalError("approval has been revoked")
            maximum = connection.execute(
                """
                SELECT max(issuer_sequence) FROM (
                    SELECT issuer_sequence FROM approval_consumptions WHERE issuer_id = ?
                    UNION ALL
                    SELECT issuer_sequence FROM approval_revocations WHERE issuer_id = ?
                )
                """,
                (issuer_id, issuer_id),
            ).fetchone()[0]
            if maximum is not None and sequence <= int(maximum):
                raise ApprovalError("issuer sequence is not monotonic")
            try:
                connection.execute(
                    """
                    INSERT INTO approval_consumptions(
                        approval_id, issuer_id, approval_key_id, issuer_sequence,
                        operation_type, operation_id, payload_sha256,
                        valid_from, valid_until, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        issuer_id,
                        payload["approval_key_id"],
                        sequence,
                        payload["operation_type"],
                        payload["operation_id"],
                        payload_sha256,
                        valid_from.isoformat(),
                        valid_until.isoformat(),
                        current.isoformat(),
                    ),
                )
            except Exception as exc:
                raise ApprovalError("approval replay rejected") from exc
        return VerifiedApproval(
            approval_id=approval_id,
            operation_type=cast(str, payload["operation_type"]),
            operation_id=cast(str, payload["operation_id"]),
            payload_sha256=payload_sha256,
            issuer_sequence=sequence,
        )

    def verify_and_record_revocation(self, document: dict[str, Any]) -> None:
        payload = self._validate_document(document, "revocation-record-v1.schema.json")
        payload_sha256 = cast(str, document["payload_sha256"])
        self._verify_signature(
            payload=payload,
            payload_sha256=payload_sha256,
            signature_hex=cast(str, document["signature"]),
            domain=REVOCATION_DOMAIN,
        )
        revoked_at = _parse_time(cast(str, payload["revoked_at"]))
        issuer_id = cast(str, payload["issuer_id"])
        sequence = cast(int, payload["issuer_sequence"])
        with self.store.write() as connection:
            maximum = connection.execute(
                """
                SELECT max(issuer_sequence) FROM (
                    SELECT issuer_sequence FROM approval_consumptions WHERE issuer_id = ?
                    UNION ALL
                    SELECT issuer_sequence FROM approval_revocations WHERE issuer_id = ?
                )
                """,
                (issuer_id, issuer_id),
            ).fetchone()[0]
            if maximum is not None and sequence <= int(maximum):
                raise ApprovalError("revocation sequence is not monotonic")
            connection.execute(
                """
                INSERT INTO approval_revocations(
                    revocation_id, approval_id, issuer_id, approval_key_id,
                    issuer_sequence, payload_sha256, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["revocation_id"],
                    payload["approval_id"],
                    issuer_id,
                    payload["approval_key_id"],
                    sequence,
                    payload_sha256,
                    revoked_at.isoformat(),
                ),
            )
