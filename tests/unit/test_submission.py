from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.leases import (
    BudgetLimit,
    LeaseBudgetManager,
    PlannedStageBudget,
)
from xir_lab.execute.signer import (
    PrivateSpool,
    PublicSignerIdentity,
    SignedTransaction,
    SignerCoordinator,
    SignerError,
    SignerRequest,
)
from xir_lab.execute.submission import (
    BroadcastResult,
    GateEvidence,
    IntentPreparation,
    SubmissionCoordinator,
    SubmissionError,
)
from xir_lab.faults import CrashPoint, InjectedCrash, OneShotCrashInjector

NOW = datetime(2026, 7, 26, tzinfo=UTC)
CHAIN = 11_155_420
DIGEST = "ab" * 32


class FixtureSigner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        return PublicSignerIdentity("runner", network_id, "0x" + "11" * 20, DIGEST)

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        self.calls.append(operation_id)
        signed = hashlib.sha256((operation_id + request.intent_id).encode()).digest()
        return SignedTransaction(
            operation_id=operation_id,
            transaction_hash="0x" + hashlib.sha256(signed).hexdigest(),
            signed_bytes=signed,
        )


class FixtureBroadcaster:
    def __init__(self, *, accepted: bool = True, fail: bool = False) -> None:
        self.accepted = accepted
        self.fail = fail
        self.calls: list[str] = []

    def broadcast(
        self, signed_bytes: bytes, expected_transaction_hash: str
    ) -> BroadcastResult:
        self.calls.append(expected_transaction_hash)
        assert signed_bytes
        if self.fail:
            raise ConnectionError("fixture reset after send")
        return BroadcastResult(self.accepted, "fixture-rpc")


def _setup(
    tmp_path: Path,
    *,
    broadcaster: FixtureBroadcaster | None = None,
    crash_injector: OneShotCrashInjector | None = None,
    stage_name: str = "source_dispatch",
) -> tuple[
    EvidenceStore,
    LeaseBudgetManager,
    FixtureSigner,
    FixtureBroadcaster,
    SubmissionCoordinator,
    SignerRequest,
    GateEvidence,
]:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', ?)
            """,
            ("11" * 32, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hh', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-0', 'condition-hh', 0)
            """
        )
    store.insert_attempt(
        attempt_id="attempt-0",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="primary",
    )
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO stages(stage_id, attempt_id, ordinal, stage_name, state)
            VALUES ('stage-source', 'attempt-0', 0, ?, 'planned')
            """,
            (stage_name,),
        )
        connection.execute(
            """
            INSERT INTO approval_consumptions(
                approval_id, issuer_id, approval_key_id, issuer_sequence,
                operation_type, operation_id, payload_sha256,
                valid_from, valid_until, consumed_at
            ) VALUES (
                'approval-1', 'issuer', 'key-1', 1,
                'primary', 'run-1', ?, ?, ?, ?
            )
            """,
            (
                DIGEST,
                (NOW - timedelta(minutes=1)).isoformat(),
                (NOW + timedelta(hours=1)).isoformat(),
                NOW.isoformat(),
            ),
        )
    budgets = LeaseBudgetManager(store)
    budgets.configure_limits(
        run_id="run-1",
        limits=(BudgetLimit(CHAIN, 100, 100, 100, 0, 1_000),),
        observed_at=NOW,
    )
    budgets.reserve_complete_route(
        reservation_id="reservation-0",
        attempt_id="attempt-0",
        batch_id="batch-0",
        stages=(PlannedStageBudget("source", CHAIN, 80),),
        now=NOW,
    )
    budgets.mark_source_in_flight(reservation_id="reservation-0", now=NOW)
    budgets.acquire_nonce_subreservation(
        lease_id="nonce-lease-0",
        lineage_id="lineage-0",
        reservation_id="reservation-0",
        stage_key="source",
        signer_id="runner",
        holder_id="worker",
        nonce=7,
        requested_wei=80,
        ttl=timedelta(minutes=10),
        now=NOW,
    )
    request = SignerRequest(
        network_id="op-sepolia",
        chain_id=CHAIN,
        signer_id="runner",
        intent_id="intent-0",
        nonce=7,
        destination="0x" + "22" * 20,
        value_wei=0,
        calldata_sha256="cd" * 32,
        calldata_length=32,
        fee_limit_wei=80,
    )
    gates = GateEvidence(
        approval_id="approval-1",
        approval_payload_sha256=DIGEST,
        signer_id="runner",
        signer_identity_sha256="bc" * 32,
        network_identity_sha256="de" * 32,
        quote_sha256="ef" * 32,
        observed_nonce=7,
        checked_at=NOW,
        simulation_sha256="fa" * 32,
        simulation_valid_until=NOW + timedelta(minutes=5),
    )
    signer = FixtureSigner()
    rpc = broadcaster or FixtureBroadcaster()
    coordinator = SubmissionCoordinator(
        store=store,
        signer=SignerCoordinator(
            signer,
            PrivateSpool(
                tmp_path / "private-spool",
                crash_injector=crash_injector,
            ),
        ),
        broadcaster=rpc,
        crash_injector=crash_injector,
    )
    return store, budgets, signer, rpc, coordinator, request, gates


def _prepare(coordinator: SubmissionCoordinator, request: SignerRequest) -> str:
    return coordinator.prepare_intent(
        IntentPreparation(
            transaction_id="transaction-0",
            stage_id="stage-source",
            lineage_id="lineage-0",
            reservation_id="reservation-0",
            reservation_stage_key="source",
            approval_id="approval-1",
            approval_payload_sha256=DIGEST,
            signer_identity_sha256="bc" * 32,
            network_identity_sha256="de" * 32,
            quote_sha256="ef" * 32,
            quote_valid_until=NOW + timedelta(minutes=5),
            simulation_sha256="fa" * 32,
            simulation_valid_until=NOW + timedelta(minutes=5),
            payload_sha256="12" * 32,
            requested_wei=80,
            request=request,
            is_source_stage=True,
        ),
        now=NOW,
    )


def test_write_ahead_sequence_persists_hash_before_broadcast(
    tmp_path: Path,
) -> None:
    store, _, signer, rpc, coordinator, request, gates = _setup(tmp_path)
    operation_id = _prepare(coordinator, request)
    assert signer.calls == []

    reference = coordinator.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    assert reference.operation_id == operation_id
    with store.connect(read_only=True) as connection:
        signed = connection.execute(
            """
            SELECT state, signed_sha256, spool_relative_path
            FROM transactions WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()
        assert tuple(signed) == (
            "signed_hash_persisted",
            reference.signed_sha256,
            reference.relative_path,
        )

    result = coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    assert result.accepted
    assert len(rpc.calls) == 1
    coordinator.record_included(transaction_id="transaction-0", observed_at=NOW)
    coordinator.record_finalized(transaction_id="transaction-0", observed_at=NOW)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id = 'transaction-0'"
        ).fetchone()[0] == "finalized"
        states = [
            row[0]
            for row in connection.execute(
                """
                SELECT to_state FROM transition_journal
                WHERE entity_id = 'transaction-0' ORDER BY sequence
                """
            )
        ]
    assert states == [
        "prepared",
        "signer_return",
        "signed_hash_persisted",
        "broadcast_unknown",
        "submitted",
        "included",
        "finalized",
    ]


def test_rpc_reset_after_send_leaves_durable_broadcast_unknown(
    tmp_path: Path,
) -> None:
    rpc = FixtureBroadcaster(fail=True)
    store, _, _, _, coordinator, request, gates = _setup(
        tmp_path, broadcaster=rpc
    )
    _prepare(coordinator, request)
    coordinator.sign_prepared(
        transaction_id="transaction-0", request=request, gates=gates
    )
    with pytest.raises(ConnectionError, match="reset"):
        coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id = 'transaction-0'"
        ).fetchone()[0] == "broadcast_unknown"


def test_sign_and_every_repeat_broadcast_revalidate_all_bound_gates(
    tmp_path: Path,
) -> None:
    store, _, signer, rpc, coordinator, request, gates = _setup(tmp_path)
    _prepare(coordinator, request)
    changed_identity = GateEvidence(
        **{**gates.__dict__, "signer_identity_sha256": "00" * 32}
    )
    with pytest.raises(SubmissionError, match="gate changed"):
        coordinator.sign_prepared(
            transaction_id="transaction-0",
            request=request,
            gates=changed_identity,
        )
    changed_simulation = GateEvidence(
        **{**gates.__dict__, "simulation_sha256": "01" * 32}
    )
    with pytest.raises(SubmissionError, match="gate changed"):
        coordinator.sign_prepared(
            transaction_id="transaction-0",
            request=request,
            gates=changed_simulation,
        )
    assert signer.calls == []

    coordinator.sign_prepared(
        transaction_id="transaction-0", request=request, gates=gates
    )
    coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    stale = GateEvidence(
        **{**gates.__dict__, "checked_at": NOW + timedelta(minutes=6)}
    )
    with pytest.raises(SubmissionError, match="stale"):
        coordinator.broadcast(
            transaction_id="transaction-0",
            gates=stale,
            allow_repeat=True,
        )
    assert len(rpc.calls) == 1

    with store.write() as connection:
        connection.execute("UPDATE runs SET state = 'halted' WHERE run_id = 'run-1'")
    with pytest.raises(SubmissionError, match="stop state"):
        coordinator.broadcast(
            transaction_id="transaction-0",
            gates=gates,
            allow_repeat=True,
        )
    assert len(rpc.calls) == 1


def test_drain_refuses_unsubmitted_source_bytes(tmp_path: Path) -> None:
    store, _, _, rpc, coordinator, request, gates = _setup(tmp_path)
    _prepare(coordinator, request)
    coordinator.sign_prepared(
        transaction_id="transaction-0", request=request, gates=gates
    )
    with store.write() as connection:
        connection.execute("UPDATE runs SET state = 'drain' WHERE run_id = 'run-1'")
    with pytest.raises(SubmissionError, match="drain"):
        coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    assert rpc.calls == []


@pytest.mark.parametrize(
    "gate_failure",
    ["approval_expired", "approval_revoked", "identity_changed", "reservation_lost"],
)
def test_persisted_signed_bytes_revalidate_live_gates_before_first_broadcast(
    tmp_path: Path,
    gate_failure: str,
) -> None:
    store, _, _, rpc, coordinator, request, gates = _setup(tmp_path)
    _prepare(coordinator, request)
    coordinator.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    changed = gates
    expected = ""
    if gate_failure == "approval_expired":
        changed = GateEvidence(
            **{**gates.__dict__, "checked_at": NOW + timedelta(hours=2)}
        )
        expected = "approval is expired"
    elif gate_failure == "approval_revoked":
        with store.write() as connection:
            connection.execute(
                """
                INSERT INTO approval_revocations(
                    revocation_id, approval_id, issuer_id, approval_key_id,
                    issuer_sequence, payload_sha256, revoked_at
                ) VALUES ('revocation-1', 'approval-1', 'issuer', 'key-1',
                          2, ?, ?)
                """,
                ("34" * 32, NOW.isoformat()),
            )
        expected = "approval is revoked"
    elif gate_failure == "identity_changed":
        changed = GateEvidence(
            **{**gates.__dict__, "network_identity_sha256": "00" * 32}
        )
        expected = "gate changed"
    else:
        with store.write() as connection:
            connection.execute(
                """
                UPDATE transaction_subreservations SET state = 'released'
                WHERE reservation_id = 'reservation-0'
                """
            )
        expected = "reservation is no longer valid"
    with pytest.raises(SubmissionError, match=expected):
        coordinator.broadcast(
            transaction_id="transaction-0",
            gates=changed,
        )
    assert rpc.calls == []


def test_signer_return_recovery_reuses_operation_and_finishes_spool_commit(
    tmp_path: Path,
) -> None:
    store, _, signer, _, coordinator, request, gates = _setup(tmp_path)
    operation_id = _prepare(coordinator, request)
    with store.write() as connection:
        connection.execute(
            """
            UPDATE transactions SET state = 'signer_return'
            WHERE transaction_id = 'transaction-0'
            """
        )
    reference = coordinator.sign_prepared(
        transaction_id="transaction-0", request=request, gates=gates
    )
    assert reference.operation_id == operation_id
    assert signer.calls == [operation_id]


def test_recovery_quarantines_orphans_and_reports_corrupt_references(
    tmp_path: Path,
) -> None:
    _, _, _, _, coordinator, request, gates = _setup(tmp_path)
    _prepare(coordinator, request)
    reference = coordinator.sign_prepared(
        transaction_id="transaction-0", request=request, gates=gates
    )
    orphan = coordinator.signer.spool.root / "signed" / "ff" / "orphan.bin"
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b"orphan signed bytes")
    report = coordinator.recover_spool()
    assert report.quarantined_orphans == ("signed/ff/orphan.bin",)
    assert report.corrupt_references == ()
    assert report.recoverable_pending == ()
    assert not orphan.exists()

    (coordinator.signer.spool.root / reference.relative_path).write_bytes(b"truncated")
    report = coordinator.recover_spool()
    assert report.corrupt_references == ("transaction-0",)
    assert report.recoverable_pending == ()


@pytest.mark.parametrize(
    ("point", "expected_state", "phase"),
    [
        ("before_prepared_intent_commit", None, "prepare"),
        ("after_prepared_intent_commit", "prepared", "prepare"),
        ("after_signer_return", "prepared", "sign"),
        ("during_spool_temporary_write", "signer_return", "sign"),
        ("after_spool_file_fsync", "signer_return", "sign"),
        (
            "after_spool_rename_before_directory_fsync",
            "signer_return",
            "sign",
        ),
        (
            "after_spool_directory_fsync_before_database_reference",
            "signer_return",
            "sign",
        ),
        ("after_hash_reference_persistence", "signed_hash_persisted", "sign"),
        (
            "after_broadcast_before_acknowledgement",
            "broadcast_unknown",
            "broadcast",
        ),
        (
            "after_acknowledgement_before_receipt",
            "submitted",
            "broadcast",
        ),
    ],
)
def test_submission_crash_injection_boundaries_are_durable(
    tmp_path: Path,
    point: CrashPoint,
    expected_state: str | None,
    phase: str,
) -> None:
    injector = OneShotCrashInjector(point)
    store, _, signer, rpc, coordinator, request, gates = _setup(
        tmp_path,
        crash_injector=injector,
    )
    with pytest.raises(InjectedCrash, match=point):
        _prepare(coordinator, request)
        if phase in {"sign", "broadcast"}:
            coordinator.sign_prepared(
                transaction_id="transaction-0",
                request=request,
                gates=gates,
            )
        if phase == "broadcast":
            coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    assert injector.fired is True
    with store.connect(read_only=True) as connection:
        row = connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()
    assert (None if row is None else row[0]) == expected_state
    if phase == "prepare":
        assert signer.calls == []
        assert rpc.calls == []
    elif phase == "sign":
        assert len(signer.calls) == 1
        assert rpc.calls == []
    else:
        assert len(signer.calls) == 1
        assert len(rpc.calls) == 1


@pytest.mark.parametrize(
    ("point", "has_recoverable_pending"),
    [
        ("before_prepared_intent_commit", False),
        ("after_prepared_intent_commit", False),
        ("after_signer_return", False),
        ("during_spool_temporary_write", False),
        ("after_spool_file_fsync", False),
        ("after_spool_rename_before_directory_fsync", True),
        (
            "after_spool_directory_fsync_before_database_reference",
            True,
        ),
        ("after_hash_reference_persistence", False),
    ],
)
def test_every_prebroadcast_crash_recovers_one_intent_nonce_and_budget(
    tmp_path: Path,
    point: CrashPoint,
    has_recoverable_pending: bool,
) -> None:
    injector = OneShotCrashInjector(point)
    store, _, signer, rpc, coordinator, request, gates = _setup(
        tmp_path,
        crash_injector=injector,
    )
    with pytest.raises(InjectedCrash, match=point):
        _prepare(coordinator, request)
        coordinator.sign_prepared(
            transaction_id="transaction-0",
            request=request,
            gates=gates,
        )
    restarted = SubmissionCoordinator(
        store=store,
        signer=SignerCoordinator(
            signer,
            PrivateSpool(tmp_path / "private-spool"),
        ),
        broadcaster=rpc,
    )
    report = restarted.recover_spool()
    assert report.recoverable_pending == (
        ("transaction-0",) if has_recoverable_pending else ()
    )
    if point == "before_prepared_intent_commit":
        _prepare(restarted, request)
    reference = restarted.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    assert restarted.signer.spool.load(reference)
    assert rpc.calls == []
    with store.connect(read_only=True) as connection:
        counts = tuple(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "intents",
                "transactions",
                "nonce_leases",
                "budgets",
                "transaction_subreservations",
            )
        )
        state = connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()[0]
    assert counts == (1, 1, 1, 1, 1)
    assert state == "signed_hash_persisted"


def test_pending_durable_spool_refuses_changed_bytes_on_restart(
    tmp_path: Path,
) -> None:
    point: CrashPoint = "after_spool_rename_before_directory_fsync"
    injector = OneShotCrashInjector(point)
    store, _, _, rpc, coordinator, request, gates = _setup(
        tmp_path,
        crash_injector=injector,
    )
    _prepare(coordinator, request)
    with pytest.raises(InjectedCrash, match=point):
        coordinator.sign_prepared(
            transaction_id="transaction-0",
            request=request,
            gates=gates,
        )

    class ChangedSigner(FixtureSigner):
        def sign_transaction(
            self,
            operation_id: str,
            request: SignerRequest,
        ) -> SignedTransaction:
            self.calls.append(operation_id)
            signed = hashlib.sha256(
                (operation_id + request.intent_id + "-changed").encode()
            ).digest()
            return SignedTransaction(
                operation_id,
                "0x" + hashlib.sha256(signed).hexdigest(),
                signed,
            )

    restarted = SubmissionCoordinator(
        store=store,
        signer=SignerCoordinator(
            ChangedSigner(),
            PrivateSpool(tmp_path / "private-spool"),
        ),
        broadcaster=rpc,
    )
    assert restarted.recover_spool().recoverable_pending == ("transaction-0",)
    with pytest.raises(SignerError, match="different signed bytes"):
        restarted.sign_prepared(
            transaction_id="transaction-0",
            request=request,
            gates=gates,
        )
    assert rpc.calls == []


@pytest.mark.parametrize("damage", ["missing", "truncated", "digest_mismatch"])
def test_damaged_referenced_spool_never_reaches_broadcaster(
    tmp_path: Path,
    damage: str,
) -> None:
    _, _, _, rpc, coordinator, request, gates = _setup(tmp_path)
    _prepare(coordinator, request)
    reference = coordinator.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    path = coordinator.signer.spool.root / reference.relative_path
    if damage == "missing":
        path.unlink()
    elif damage == "truncated":
        path.write_bytes(b"x")
    else:
        path.write_bytes(b"x" * reference.signed_length)
    assert coordinator.recover_spool().corrupt_references == ("transaction-0",)
    with pytest.raises((OSError, SignerError)):
        coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    assert rpc.calls == []


@pytest.mark.parametrize(
    "stage_name",
    [
        "hyperlane_dispatch",
        "layerzero_send",
        "intermediate_forward",
        "destination_apply",
    ],
)
@pytest.mark.parametrize(
    "point",
    [
        "after_broadcast_before_acknowledgement",
        "after_acknowledgement_before_receipt",
    ],
)
def test_postbroadcast_crash_recovers_without_false_success_or_duplicate_charge(
    tmp_path: Path,
    stage_name: str,
    point: CrashPoint,
) -> None:
    injector = OneShotCrashInjector(point)
    store, budgets, _, _, coordinator, request, gates = _setup(
        tmp_path,
        crash_injector=injector,
        stage_name=stage_name,
    )
    _prepare(coordinator, request)
    coordinator.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    with pytest.raises(InjectedCrash, match=point):
        coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    with store.connect(read_only=True) as connection:
        state = connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()[0]
    assert state in {"broadcast_unknown", "submitted"}
    assert state != "finalized"
    budgets.mark_lineage_pending(lineage_id="lineage-0", state=state)
    coordinator.record_included(transaction_id="transaction-0", observed_at=NOW)
    budgets.record_included(
        lineage_id="lineage-0",
        actual_spent_wei=55,
        now=NOW,
    )
    budgets.record_included(
        lineage_id="lineage-0",
        actual_spent_wei=55,
        now=NOW,
    )
    coordinator.record_finalized(transaction_id="transaction-0", observed_at=NOW)
    budgets.finalize_lineage(
        lineage_id="lineage-0",
        actual_spent_wei=55,
        now=NOW,
    )
    budgets.finalize_lineage(
        lineage_id="lineage-0",
        actual_spent_wei=55,
        now=NOW,
    )
    snapshot = budgets.snapshots(run_id="run-1")[0]
    assert (
        snapshot.active_reserved_wei,
        snapshot.provisional_wei,
        snapshot.finalized_wei,
    ) == (0, 0, 55)
