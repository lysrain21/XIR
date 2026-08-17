from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.root_signer import FinalizedRootCreation, FinalizedRootSigner
from xir_lab.native.xir_trace import (
    XIRContext,
    XIRRecord,
    message_id,
    root_id,
)


class StaticRootSource:
    def __init__(self, creation: FinalizedRootCreation) -> None:
        self.creation = creation

    def read_finalized_creation(self, transaction_hash: str) -> FinalizedRootCreation:
        assert transaction_hash == self.creation.transaction_hash
        return self.creation


def fixture() -> tuple[XIRRecord, XIRContext, FinalizedRootCreation]:
    gateway = (1, bytes.fromhex("11" * 20))
    runner = Account.from_key("0x" + "22" * 32)
    destination = (1, bytes.fromhex("33" * 20))
    payload = b"security-root-fixture"
    record = XIRRecord(
        source_gateway=gateway,
        source_app=(1, bytes.fromhex(runner.address[2:])),
        destination_app=destination,
        nonce=7,
        payload_hash=keccak(payload),
    )
    context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
    rid = root_id(record, context, 1)
    creation = FinalizedRootCreation(
        transaction_hash="0x" + "44" * 32,
        block_number=91,
        finalized_block_number=92,
        gateway_address="0x" + "55" * 20,
        transaction_sender=runner.address.lower(),
        event_rid=rid,
        event_mid=message_id(rid, destination),
        event_sender=runner.address.lower(),
        event_nonce=7,
        destination_app=destination,
        payload=payload,
        context=context,
        registry_version=1,
        gateway_id=gateway,
    )
    return record, context, creation


def test_distinct_root_signer_validates_finalized_event_before_signing(
    tmp_path: Path,
) -> None:
    record, context, creation = fixture()
    signer_key = "0x" + "66" * 32
    signer = FinalizedRootSigner(
        source=StaticRootSource(creation),
        private_key=signer_key,
        audit_path=tmp_path / "root-audit.jsonl",
    )

    signature = signer.sign(
        transaction_hash=creation.transaction_hash,
        record=record,
        context=context,
        registry_version=1,
    )

    recovered = Account.recover_message(
        encode_defunct(primitive=root_id(record, context, 1)), signature=signature
    )
    assert recovered.lower() == signer.address.lower()
    assert signer.address.lower() != creation.transaction_sender
    assert '"signed": true' in (tmp_path / "root-audit.jsonl").read_text()


def test_root_signer_audit_is_idempotent_across_durable_resume(
    tmp_path: Path,
) -> None:
    record, context, creation = fixture()
    audit_path = tmp_path / "root-audit.jsonl"
    signer = FinalizedRootSigner(
        source=StaticRootSource(creation),
        private_key="0x" + "66" * 32,
        audit_path=audit_path,
    )
    first = signer.sign(
        transaction_hash=creation.transaction_hash,
        record=record,
        context=context,
        registry_version=1,
    )
    second = signer.sign(
        transaction_hash=creation.transaction_hash,
        record=record,
        context=context,
        registry_version=1,
    )
    assert first == second
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 1


def test_root_signer_rejects_unfinalized_or_mismatched_creation(tmp_path: Path) -> None:
    record, context, creation = fixture()
    creation = FinalizedRootCreation(
        **{
            **creation.__dict__,
            "finalized_block_number": creation.block_number - 1,
            "event_nonce": creation.event_nonce + 1,
        }
    )
    signer = FinalizedRootSigner(
        source=StaticRootSource(creation),
        private_key="0x" + "77" * 32,
        audit_path=tmp_path / "root-audit.jsonl",
    )

    with pytest.raises(LocalTopologyError, match="event_nonce, finalized"):
        signer.sign(
            transaction_hash=creation.transaction_hash,
            record=record,
            context=context,
            registry_version=1,
        )
    assert '"signed": false' in (tmp_path / "root-audit.jsonl").read_text()
