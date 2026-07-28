from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.approved_operations import (
    ApprovedOperationExecutor,
    ApprovedTransaction,
    PublicOperationReceipt,
    build_approved_operation_batch,
)
from xir_lab.execute.signer import (
    PrivateSpool,
    PublicSignerIdentity,
    SignedTransaction,
    SignerCoordinator,
    SignerRequest,
)
from xir_lab.execute.signer_socket import unsigned_transaction_digest
from xir_lab.execute.submission import BroadcastResult
from xir_lab.faults import InjectedCrash, OneShotCrashInjector


def _request(network: str, chain_id: int, nonce: int) -> SignerRequest:
    calldata = bytes.fromhex("60016000")
    request = SignerRequest(
        network_id=network,
        chain_id=chain_id,
        signer_id="deployer",
        intent_id=f"deployment-{chain_id}-{nonce}",
        nonce=nonce,
        destination=None,
        value_wei=0,
        calldata_sha256=hashlib.sha256(calldata).hexdigest(),
        calldata_length=len(calldata),
        fee_limit_wei=100_000,
        role="deployer",
        config_sha256="11" * 32,
        code_sha256="22" * 32,
        gas_limit=100_000,
        max_fee_per_gas_wei=1,
        max_priority_fee_per_gas_wei=1,
        calldata_hex=calldata.hex(),
    )
    return SignerRequest(
        **{
            **request.__dict__,
            "unsigned_transaction_sha256": unsigned_transaction_digest(request),
        }
    )


class SignerFixture:
    def __init__(self) -> None:
        self.calls = 0

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        return PublicSignerIdentity(
            "deployer",
            network_id,
            "0x" + "aa" * 20,
            "33" * 32,
        )

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        self.calls += 1
        signed = f"signed:{operation_id}".encode()
        return SignedTransaction(
            operation_id,
            "0x" + hashlib.sha256(signed).hexdigest(),
            signed,
        )


class BroadcasterFixture:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[tuple[bytes, str]] = []

    def broadcast(
        self, signed_bytes: bytes, expected_transaction_hash: str
    ) -> BroadcastResult:
        self.calls.append((signed_bytes, expected_transaction_hash))
        return BroadcastResult(self.accepted, "fixture-rpc" if self.accepted else None)


class LookupFixture:
    def __init__(self) -> None:
        self.receipts: dict[tuple[int, str], PublicOperationReceipt] = {}
        self.nonces: dict[int, int] = {}

    def receipt(
        self, chain_id: int, transaction_hash: str
    ) -> PublicOperationReceipt | None:
        return self.receipts.get((chain_id, transaction_hash))

    def account_nonce(self, chain_id: int, address: str) -> int | None:
        assert address == "0x" + "aa" * 20
        return self.nonces.get(chain_id)


def _executor(
    tmp_path: Path,
    *,
    broadcaster: BroadcasterFixture | None = None,
    lookup: LookupFixture | None = None,
    crash_injector: OneShotCrashInjector | None = None,
) -> tuple[
    ApprovedOperationExecutor,
    SignerFixture,
    BroadcasterFixture,
    LookupFixture,
    tuple[ApprovedTransaction, ...],
]:
    requests = (
        _request("op-sepolia", 11_155_420, 0),
        _request("arbitrum-sepolia", 421_614, 0),
    )
    transactions = tuple(
        ApprovedTransaction(
            transaction_id=f"create-{index}",
            request=request,
            expected_created_address=f"0x{index + 1:040x}",
        )
        for index, request in enumerate(requests)
    )
    batch = build_approved_operation_batch(
        operation_id="deployment-1",
        operation_type="deployment",
        approval_id="approval-1",
        approval_payload_sha256="44" * 32,
        transactions=transactions,
    )
    store = EvidenceStore(tmp_path / "run" / "evidence.sqlite", tmp_path / "run" / "raw")
    store.initialize()
    signer_backend = SignerFixture()
    signer = SignerCoordinator(
        signer_backend,
        PrivateSpool(tmp_path / "private-spool"),
    )
    active_broadcaster = broadcaster or BroadcasterFixture()
    active_lookup = lookup or LookupFixture()
    executor = ApprovedOperationExecutor(
        batch=batch,
        journal_path=tmp_path / "run" / "deployment-journal.json",
        store=store,
        signer=signer,
        broadcaster=active_broadcaster,
        lookup=active_lookup,
        crash_injector=crash_injector,
    )
    return (
        executor,
        signer_backend,
        active_broadcaster,
        active_lookup,
        transactions,
    )


def _receipt(
    transaction: ApprovedTransaction,
    transaction_hash: str,
    *,
    address: str | None = None,
) -> PublicOperationReceipt:
    return PublicOperationReceipt(
        transaction_hash=transaction_hash,
        chain_id=transaction.request.chain_id,
        nonce=transaction.request.nonce,
        status=1,
        block_number=100,
        block_hash="0x" + "55" * 32,
        contract_address=address or transaction.expected_created_address,
        raw_bytes=b'{"fixture":"receipt"}',
        finalized=True,
    )


def test_approved_deployment_is_ordered_idempotent_and_preserves_receipts(
    tmp_path: Path,
) -> None:
    executor, signer, broadcaster, lookup, transactions = _executor(tmp_path)
    executor.initialize()
    assert executor.advance("create-0") == "submitted"
    transaction_hash = broadcaster.calls[0][1]
    lookup.receipts[(11_155_420, transaction_hash)] = _receipt(
        transactions[0], transaction_hash
    )
    assert executor.reconcile("create-0") == "finalized"
    assert executor.advance("create-0") == "finalized"
    assert signer.calls == 1
    assert executor.advance("create-1") == "submitted"
    journal = (tmp_path / "run" / "deployment-journal.json").read_text()
    assert "signed:" not in journal
    assert '"state":"submitted"' in journal


def test_broadcast_unknown_requires_hash_and_nonce_resolution_before_exact_repeat(
    tmp_path: Path,
) -> None:
    broadcaster = BroadcasterFixture(False)
    lookup = LookupFixture()
    executor, signer, _, _, _ = _executor(
        tmp_path,
        broadcaster=broadcaster,
        lookup=lookup,
    )
    assert executor.advance("create-0") == "broadcast_unknown"
    lookup.nonces[11_155_420] = 0
    assert executor.reconcile("create-0") == "broadcast_unknown"
    broadcaster.accepted = True
    assert executor.repeat_exact_broadcast("create-0").accepted
    assert signer.calls == 1
    assert broadcaster.calls[0][0] == broadcaster.calls[1][0]


def test_wrong_created_address_blocks_following_work(tmp_path: Path) -> None:
    executor, _, broadcaster, lookup, transactions = _executor(tmp_path)
    assert executor.advance("create-0") == "submitted"
    transaction_hash = broadcaster.calls[0][1]
    lookup.receipts[(11_155_420, transaction_hash)] = _receipt(
        transactions[0],
        transaction_hash,
        address="0x" + "ff" * 20,
    )
    assert executor.reconcile("create-0") == "blocked"


def test_crash_after_broadcast_is_resolved_by_exact_hash_receipt(
    tmp_path: Path,
) -> None:
    broadcaster = BroadcasterFixture()
    lookup = LookupFixture()
    injector = OneShotCrashInjector("after_broadcast_before_acknowledgement")
    executor, _, _, _, transactions = _executor(
        tmp_path,
        broadcaster=broadcaster,
        lookup=lookup,
        crash_injector=injector,
    )
    with pytest.raises(InjectedCrash):
        executor.advance("create-0")
    transaction_hash = broadcaster.calls[0][1]
    lookup.receipts[(11_155_420, transaction_hash)] = _receipt(
        transactions[0], transaction_hash
    )
    restarted, _, _, _, _ = _executor(
        tmp_path,
        broadcaster=broadcaster,
        lookup=lookup,
    )
    assert restarted.reconcile("create-0") == "finalized"
