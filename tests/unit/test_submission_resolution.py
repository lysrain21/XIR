from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.leases import (
    BudgetLimit,
    LeaseBudgetManager,
    PlannedStageBudget,
)
from xir_lab.execute.resolution import (
    AmbiguousSubmissionResolver,
    ReplacementManager,
    ResolutionError,
    TransactionProbe,
)
from xir_lab.execute.signer import (
    PrivateSpool,
    PublicSignerIdentity,
    SignedTransaction,
    SignerCoordinator,
    SignerRequest,
)
from xir_lab.execute.submission import (
    BroadcastResult,
    GateEvidence,
    IntentPreparation,
    SubmissionCoordinator,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)
CHAIN = 11_155_420


class FixtureSigner:
    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        return PublicSignerIdentity("runner", network_id, "0x" + "11" * 20, "22" * 32)

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        signed = hashlib.sha256((operation_id + request.intent_id).encode()).digest()
        return SignedTransaction(
            operation_id,
            "0x" + hashlib.sha256(signed).hexdigest(),
            signed,
        )


class UnknownBroadcaster:
    def broadcast(
        self, signed_bytes: bytes, expected_transaction_hash: str
    ) -> BroadcastResult:
        assert signed_bytes and expected_transaction_hash
        return BroadcastResult(False)


class FixtureLookup:
    def __init__(
        self,
        *,
        probe: TransactionProbe | None = None,
        nonce: int | None = 7,
        fail_hash: bool = False,
    ) -> None:
        self.probe = probe
        self.nonce = nonce
        self.fail_hash = fail_hash

    def transaction_by_hash(
        self, chain_id: int, transaction_hash: str
    ) -> TransactionProbe | None:
        assert chain_id == CHAIN and transaction_hash.startswith("0x")
        if self.fail_hash:
            raise ConnectionError("fixture hash lookup failed")
        return self.probe

    def account_nonce(self, chain_id: int, signer_address: str) -> int | None:
        assert chain_id == CHAIN and signer_address.startswith("0x")
        return self.nonce


def _setup(
    tmp_path: Path,
) -> tuple[
    EvidenceStore,
    RunControlManager,
    SubmissionCoordinator,
    SignerRequest,
    GateEvidence,
    IntentPreparation,
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
            VALUES ('stage-0', 'attempt-0', 0, 'source_dispatch', 'planned')
            """
        )
        connection.execute(
            """
            INSERT INTO approval_consumptions(
                approval_id, issuer_id, approval_key_id, issuer_sequence,
                operation_type, operation_id, payload_sha256,
                valid_from, valid_until, consumed_at
            ) VALUES (
                'approval-1', 'issuer', 'key', 1,
                'primary', 'run-1', ?, ?, ?, ?
            )
            """,
            (
                "aa" * 32,
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
        stages=(PlannedStageBudget("source", CHAIN, 100),),
        now=NOW,
    )
    budgets.mark_source_in_flight(reservation_id="reservation-0", now=NOW)
    budgets.acquire_nonce_subreservation(
        lease_id="nonce-lease",
        lineage_id="lineage-0",
        reservation_id="reservation-0",
        stage_key="source",
        signer_id="runner",
        holder_id="worker",
        nonce=7,
        requested_wei=100,
        ttl=timedelta(minutes=10),
        now=NOW,
    )
    controls = RunControlManager(store)
    controls.initialize(
        run_id="run-1",
        decision=ControlDecision("initial", "bb" * 32, "run-start"),
        now=NOW,
    )
    coordinator = SubmissionCoordinator(
        store=store,
        signer=SignerCoordinator(
            FixtureSigner(),
            PrivateSpool(tmp_path / "private-spool"),
        ),
        broadcaster=UnknownBroadcaster(),
    )
    request = SignerRequest(
        "op-sepolia",
        CHAIN,
        "runner",
        "intent-0",
        7,
        "0x" + "22" * 20,
        0,
        "cc" * 32,
        32,
        80,
    )
    gates = GateEvidence(
        "approval-1",
        "aa" * 32,
        "runner",
        "dd" * 32,
        "ee" * 32,
        "ff" * 32,
        7,
        NOW,
        "fa" * 32,
        NOW + timedelta(minutes=5),
    )
    preparation = IntentPreparation(
        transaction_id="transaction-0",
        stage_id="stage-0",
        lineage_id="lineage-0",
        reservation_id="reservation-0",
        reservation_stage_key="source",
        approval_id="approval-1",
        approval_payload_sha256="aa" * 32,
        signer_identity_sha256="dd" * 32,
        network_identity_sha256="ee" * 32,
        quote_sha256="ff" * 32,
        quote_valid_until=NOW + timedelta(minutes=5),
        simulation_sha256="fa" * 32,
        simulation_valid_until=NOW + timedelta(minutes=5),
        payload_sha256="12" * 32,
        requested_wei=80,
        request=request,
        is_source_stage=True,
    )
    coordinator.prepare_intent(preparation, now=NOW)
    coordinator.sign_prepared(
        transaction_id="transaction-0",
        request=request,
        gates=gates,
    )
    coordinator.broadcast(transaction_id="transaction-0", gates=gates)
    return store, controls, coordinator, request, gates, preparation


def _transaction_hash(store: EvidenceStore) -> str:
    with store.connect(read_only=True) as connection:
        return str(
            connection.execute(
                """
                SELECT transaction_hash FROM transactions
                WHERE transaction_id = 'transaction-0'
                """
            ).fetchone()[0]
        )


def test_precomputed_hash_resolves_pending_or_included_without_rebroadcast(
    tmp_path: Path,
) -> None:
    store, controls, _, _, _, _ = _setup(tmp_path)
    transaction_hash = _transaction_hash(store)
    resolver = AmbiguousSubmissionResolver(
        store=store,
        controls=controls,
        lookup=FixtureLookup(
            probe=TransactionProbe(transaction_hash, 7, True, True)
        ),
    )
    result = resolver.resolve(
        transaction_id="transaction-0",
        signer_address="0x" + "11" * 20,
        checked_at=NOW,
    )
    assert result.status == "included"
    assert not result.safe_to_repeat_exact_bytes
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()[0] == "included"


def test_exact_hash_absent_and_nonce_unconsumed_is_only_safe_repeat_case(
    tmp_path: Path,
) -> None:
    store, controls, _, _, _, _ = _setup(tmp_path)
    resolver = AmbiguousSubmissionResolver(
        store=store,
        controls=controls,
        lookup=FixtureLookup(probe=None, nonce=7),
    )
    result = resolver.resolve(
        transaction_id="transaction-0",
        signer_address="0x" + "11" * 20,
    )
    assert result.status == "not_found"
    assert result.safe_to_repeat_exact_bytes
    assert controls.state("run-1").mode == "running"


def test_consumed_nonce_without_hash_records_invariant_and_halts(
    tmp_path: Path,
) -> None:
    store, controls, _, _, _, _ = _setup(tmp_path)
    result = AmbiguousSubmissionResolver(
        store=store,
        controls=controls,
        lookup=FixtureLookup(probe=None, nonce=8),
    ).resolve(
        transaction_id="transaction-0",
        signer_address="0x" + "11" * 20,
        checked_at=NOW,
    )
    assert result.status == "conflict"
    assert controls.state("run-1").mode == "halted"
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM invariant_violations
            WHERE invariant_code = 'ambiguous_submission_conflict'
            """
        ).fetchone()[0] == 1


def test_lookup_error_remains_unknown_and_never_authorizes_repeat(
    tmp_path: Path,
) -> None:
    store, controls, _, _, _, _ = _setup(tmp_path)
    result = AmbiguousSubmissionResolver(
        store=store,
        controls=controls,
        lookup=FixtureLookup(fail_hash=True),
    ).resolve(
        transaction_id="transaction-0",
        signer_address="0x" + "11" * 20,
    )
    assert result.status == "unknown"
    assert not result.safe_to_repeat_exact_bytes
    assert controls.state("run-1").mode == "running"


def test_same_nonce_replacement_is_linked_budget_bounded_and_count_bounded(
    tmp_path: Path,
) -> None:
    store, _, coordinator, request, _, preparation = _setup(tmp_path)
    manager = ReplacementManager(
        store=store,
        submissions=coordinator,
        max_replacements_per_lineage=1,
    )
    replacement_request = replace(
        request,
        intent_id="intent-1",
        fee_limit_wei=100,
    )
    replacement = replace(
        preparation,
        transaction_id="transaction-1",
        request=replacement_request,
        requested_wei=100,
    )
    manager.prepare_replacement(
        prior_transaction_id="transaction-0",
        preparation=replacement,
        now=NOW,
    )
    with store.connect(read_only=True) as connection:
        row = connection.execute(
            """
            SELECT chain_id, nonce, replaces_transaction_id
            FROM transactions WHERE transaction_id = 'transaction-1'
            """
        ).fetchone()
    assert tuple(row) == (CHAIN, 7, "transaction-0")
    with store.write() as connection:
        connection.execute(
            """
            UPDATE transactions SET state = 'submitted'
            WHERE transaction_id = 'transaction-1'
            """
        )
    second = replace(
        replacement,
        transaction_id="transaction-2",
        request=replace(replacement_request, intent_id="intent-2"),
    )
    with pytest.raises(ResolutionError, match="limit exhausted"):
        manager.prepare_replacement(
            prior_transaction_id="transaction-1",
            preparation=second,
            now=NOW,
        )

    oversized = replace(
        replacement,
        transaction_id="transaction-large",
        request=replace(replacement_request, intent_id="intent-large"),
        requested_wei=101,
    )
    larger_manager = ReplacementManager(
        store=store,
        submissions=coordinator,
        max_replacements_per_lineage=2,
    )
    with pytest.raises(ResolutionError, match="safety gates"):
        larger_manager.prepare_replacement(
            prior_transaction_id="transaction-1",
            preparation=oversized,
            now=NOW,
        )
