from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.approvals import (
    APPROVAL_DOMAIN,
    REVOCATION_DOMAIN,
    ApprovalError,
    ApprovalVerifier,
    PinnedApprovalKey,
    canonical_payload_digest,
    signature_message,
)


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    return store


def _key() -> tuple[Ed25519PrivateKey, PinnedApprovalKey]:
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return private, PinnedApprovalKey("issuer-1", "key-1", public_hex)


def _payload(sequence: int = 1) -> dict[str, Any]:
    digest = "11" * 32
    return {
        "approval_id": f"approval-{sequence}",
        "issuer_id": "issuer-1",
        "approval_key_id": "key-1",
        "issuer_sequence": sequence,
        "operation_type": "pilot",
        "operation_id": "pilot-run-1",
        "run_id": "run-1",
        "issued_at": "2026-07-25T00:00:00Z",
        "valid_from": "2026-07-25T00:00:00Z",
        "valid_until": "2026-07-25T23:59:59Z",
        "expected_pre_state_sha256": digest,
        "authorized_transition_sha256": digest,
        "config_sha256": digest,
        "profile_sha256": digest,
        "code_sha256": digest,
        "schema_sha256": digest,
        "deployment_sha256": digest,
        "signer_identity_sha256": digest,
        "network_identity_sha256": digest,
        "addresses": {
            "deployer_administrator": "0x" + "22" * 20,
            "runner": "0x" + "33" * 20,
        },
        "networks": [
            {
                "network_id": network,
                "chain_id": chain_id,
                "checkpoint_sha256": digest,
            }
            for network, chain_id in (
                ("op-sepolia", 11_155_420),
                ("arbitrum-sepolia", 421_614),
                ("base-sepolia", 84_532),
            )
        ],
        "deployment_ids": ["deployment-1"],
        "condition_scope": ["HH", "HL", "LH", "LL"],
        "planned_counts": {
            "pair_slots": 20,
            "designated_attempts": 40,
            "warmup_attempts": 0,
        },
        "max_retries_per_lineage": 1,
        "max_concurrency": 2,
        "allow_partial_conditions": False,
        "stop_policy_sha256": digest,
        "per_chain_limits": {
            "11155420": 1000,
            "421614": 1000,
            "84532": 1000,
        },
    }


def _approval(
    private: Ed25519PrivateKey, payload: dict[str, Any]
) -> dict[str, Any]:
    digest = canonical_payload_digest(payload)
    return {
        "schema_version": "xir-lab-approval-envelope-v1",
        "payload": payload,
        "payload_sha256": digest,
        "signature": private.sign(
            signature_message(APPROVAL_DOMAIN, digest)
        ).hex(),
    }


def _revocation(
    private: Ed25519PrivateKey, *, approval_id: str, sequence: int
) -> dict[str, Any]:
    payload = {
        "revocation_id": f"revocation-{sequence}",
        "approval_id": approval_id,
        "issuer_id": "issuer-1",
        "approval_key_id": "key-1",
        "issuer_sequence": sequence,
        "revoked_at": "2026-07-25T00:30:00Z",
        "reason": "fixture cancellation",
    }
    digest = canonical_payload_digest(payload)
    return {
        "schema_version": "xir-lab-revocation-record-v1",
        "payload": payload,
        "payload_sha256": digest,
        "signature": private.sign(
            signature_message(REVOCATION_DOMAIN, digest)
        ).hex(),
    }


def test_valid_approval_is_verified_and_consumed_once(tmp_path: Path) -> None:
    private, pinned = _key()
    verifier = ApprovalVerifier(store=_store(tmp_path), pinned_keys=(pinned,))
    document = _approval(private, _payload())
    verified = verifier.verify_and_consume(
        document, now=datetime(2026, 7, 25, 12, tzinfo=UTC)
    )
    assert verified.operation_type == "pilot"
    with pytest.raises(ApprovalError, match="consumed|sequence|replay"):
        verifier.verify_and_consume(
            document, now=datetime(2026, 7, 25, 12, tzinfo=UTC)
        )


def test_payload_digest_signature_and_time_are_all_enforced(tmp_path: Path) -> None:
    private, pinned = _key()
    verifier = ApprovalVerifier(store=_store(tmp_path), pinned_keys=(pinned,))
    document = _approval(private, _payload())
    document["payload"]["max_concurrency"] = 3
    with pytest.raises(ApprovalError, match="digest mismatch"):
        verifier.verify_and_consume(
            document, now=datetime(2026, 7, 25, 12, tzinfo=UTC)
        )
    document = _approval(private, _payload())
    document["signature"] = "00" * 64
    with pytest.raises(ApprovalError, match="signature"):
        verifier.verify_and_consume(
            document, now=datetime(2026, 7, 25, 12, tzinfo=UTC)
        )
    document = _approval(private, _payload())
    with pytest.raises(ApprovalError, match="currently valid"):
        verifier.verify_and_consume(
            document, now=datetime(2026, 7, 26, 12, tzinfo=UTC)
        )


def test_signed_revocation_blocks_approval(tmp_path: Path) -> None:
    private, pinned = _key()
    verifier = ApprovalVerifier(store=_store(tmp_path), pinned_keys=(pinned,))
    verifier.verify_and_record_revocation(
        _revocation(private, approval_id="approval-1", sequence=2)
    )
    with pytest.raises(ApprovalError, match="revoked"):
        verifier.verify_and_consume(
            _approval(private, _payload(sequence=1)),
            now=datetime(2026, 7, 25, 12, tzinfo=UTC),
        )


def test_unpinned_key_and_nonmonotonic_sequence_are_rejected(tmp_path: Path) -> None:
    private, pinned = _key()
    verifier = ApprovalVerifier(store=_store(tmp_path), pinned_keys=(pinned,))
    second = _payload(sequence=2)
    verifier.verify_and_consume(
        _approval(private, second), now=datetime(2026, 7, 25, 12, tzinfo=UTC)
    )
    with pytest.raises(ApprovalError, match="monotonic"):
        verifier.verify_and_consume(
            _approval(private, _payload(sequence=1)),
            now=datetime(2026, 7, 25, 12, tzinfo=UTC),
        )
    other_private = Ed25519PrivateKey.generate()
    with pytest.raises(ApprovalError, match="signature"):
        ApprovalVerifier(
            store=_store(tmp_path / "other"), pinned_keys=(pinned,)
        ).verify_and_consume(
            _approval(other_private, _payload()),
            now=datetime(2026, 7, 25, 12, tzinfo=UTC),
        )
