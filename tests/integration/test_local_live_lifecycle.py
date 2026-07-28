from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xir_lab.analysis.recommendation import (
    PilotRecommendationInputs,
    build_pilot_recommendation,
)
from xir_lab.analysis.reconcile import CountExpectation, RunReconciler
from xir_lab.config.profiles import (
    LiveLimits,
    freeze_execution_profile,
    load_execution_profile,
    materialize_live_pilot,
)
from xir_lab.config.stages import load_stage_template_set
from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.approved_operations import (
    ApprovedOperationBatch,
    ApprovedOperationExecutor,
    ApprovedTransaction,
    PublicOperationReceipt,
    build_approved_operation_batch,
)
from xir_lab.execute.configuration_plans import (
    ConfigurationSimulation,
    ConfigurationTransition,
    ContractIdentityExpectation,
    ContractIdentityObservation,
    build_configuration_plan,
    configuration_signer_requests,
    freeze_deployment_identity,
    recollect_deployment_identity,
    simulate_configuration_plan,
)
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.executor import DurableBatchExecutor
from xir_lab.execute.scheduler import expand_plan
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

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "configs" / "profiles" / "pilot-template-v1.json"
STAGES = ROOT / "configs" / "stages" / "v1.json"
NOW = datetime(2026, 7, 28, tzinfo=UTC)
NETWORKS = (
    ("op-sepolia", 11_155_420),
    ("arbitrum-sepolia", 421_614),
    ("base-sepolia", 84_532),
)
CATEGORIES = (
    "endpoint",
    "peer",
    "selector",
    "security",
    "runner",
    "pause-drain",
    "xir-route-profile",
    "receiver-isolation",
)


class LocalSigner:
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
        signed = f"{operation_id}:{request.unsigned_transaction_sha256}".encode()
        return SignedTransaction(
            operation_id=operation_id,
            transaction_hash="0x" + hashlib.sha256(signed).hexdigest(),
            signed_bytes=signed,
        )


class LocalBroadcaster:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, str]] = []

    def broadcast(
        self, signed_bytes: bytes, expected_transaction_hash: str
    ) -> BroadcastResult:
        self.calls.append((signed_bytes, expected_transaction_hash))
        return BroadcastResult(True, f"local-rpc-{len(self.calls)}")


class LocalLookup:
    def __init__(self) -> None:
        self.receipts: dict[tuple[int, str], PublicOperationReceipt] = {}

    def receipt(
        self, chain_id: int, transaction_hash: str
    ) -> PublicOperationReceipt | None:
        return self.receipts.get((chain_id, transaction_hash))

    def account_nonce(self, chain_id: int, address: str) -> int | None:
        return 0


@dataclass(frozen=True)
class IdentityProvider:
    def observe(
        self, expected: ContractIdentityExpectation
    ) -> ContractIdentityObservation:
        return ContractIdentityObservation(
            contract_id=expected.contract_id,
            network_id=expected.network_id,
            chain_id=expected.chain_id,
            address=expected.address,
            runtime_code_sha256=expected.runtime_code_sha256,
            administrator=expected.administrator,
            runner=expected.runner,
            control_state_sha256=expected.expected_control_state_sha256,
            observation_block=100,
            status="pass",
            reason_codes=("local_mock_identity",),
        )


@dataclass(frozen=True)
class ConfigurationProvider:
    def simulate(
        self, transition: ConfigurationTransition
    ) -> ConfigurationSimulation:
        return ConfigurationSimulation(
            transition_id=transition.transition_id,
            success=True,
            gas_used=transition.gas_limit - 1,
            observed_post_state_sha256=transition.expected_post_state_sha256,
            reason_code="local_mock_success",
        )


def _request(
    *,
    network_id: str,
    chain_id: int,
    nonce: int,
    intent_id: str,
    destination: str | None,
) -> SignerRequest:
    calldata = bytes.fromhex("6001600055")
    request = SignerRequest(
        network_id=network_id,
        chain_id=chain_id,
        signer_id="deployer",
        intent_id=intent_id,
        nonce=nonce,
        destination=destination,
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


def _execute_batch(
    *,
    tmp_path: Path,
    store: EvidenceStore,
    batch: ApprovedOperationBatch,
    inject_recovery: bool,
) -> tuple[LocalBroadcaster, LocalLookup]:
    broadcaster = LocalBroadcaster()
    lookup = LocalLookup()
    signer = SignerCoordinator(
        LocalSigner(),
        PrivateSpool(tmp_path / "private-spool"),
    )
    journal = tmp_path / f"{batch.operation_type}-journal.json"
    injector = (
        OneShotCrashInjector("after_broadcast_before_acknowledgement")
        if inject_recovery
        else None
    )
    executor = ApprovedOperationExecutor(
        batch=batch,
        journal_path=journal,
        store=store,
        signer=signer,
        broadcaster=broadcaster,
        lookup=lookup,
        crash_injector=injector,
    )
    start = 0
    if inject_recovery:
        with pytest.raises(InjectedCrash):
            executor.advance(batch.transactions[0].transaction_id)
        approved = batch.transactions[0]
        transaction_hash = broadcaster.calls[-1][1]
        lookup.receipts[(approved.request.chain_id, transaction_hash)] = _receipt(
            approved, transaction_hash
        )
        executor = ApprovedOperationExecutor(
            batch=batch,
            journal_path=journal,
            store=store,
            signer=signer,
            broadcaster=broadcaster,
            lookup=lookup,
        )
        assert executor.reconcile(approved.transaction_id) == "finalized"
        start = 1
    for approved in batch.transactions[start:]:
        assert executor.advance(approved.transaction_id) == "submitted"
        transaction_hash = broadcaster.calls[-1][1]
        lookup.receipts[(approved.request.chain_id, transaction_hash)] = _receipt(
            approved, transaction_hash
        )
        assert executor.reconcile(approved.transaction_id) == "finalized"
    return broadcaster, lookup


def _receipt(
    approved: ApprovedTransaction,
    transaction_hash: str,
) -> PublicOperationReceipt:
    return PublicOperationReceipt(
        transaction_hash=transaction_hash,
        chain_id=approved.request.chain_id,
        nonce=approved.request.nonce,
        status=1,
        block_number=100 + approved.request.nonce,
        block_hash="0x" + "55" * 32,
        contract_address=approved.expected_created_address,
        raw_bytes=(
            f'{{"transaction_hash":"{transaction_hash}",'
            f'"operation":"{approved.transaction_id}"}}'
        ).encode(),
        finalized=True,
    )


def _deployment_batch() -> ApprovedOperationBatch:
    transactions = tuple(
        ApprovedTransaction(
            transaction_id=f"deploy-{network_id}",
            request=_request(
                network_id=network_id,
                chain_id=chain_id,
                nonce=0,
                intent_id=f"deploy-{network_id}",
                destination=None,
            ),
            expected_created_address=f"0x{index + 1:040x}",
        )
        for index, (network_id, chain_id) in enumerate(NETWORKS)
    )
    return build_approved_operation_batch(
        operation_id="local-deployment",
        operation_type="deployment",
        approval_id="local-deployment-approval",
        approval_payload_sha256="44" * 32,
        transactions=transactions,
    )


def _configuration_batch(
    store: EvidenceStore,
) -> tuple[ApprovedOperationBatch, str]:
    expectations = tuple(
        ContractIdentityExpectation(
            contract_id=f"router-{network_id}",
            network_id=network_id,
            chain_id=chain_id,
            address=f"0x{index + 1:040x}",
            runtime_code_sha256="66" * 32,
            administrator="0x" + "aa" * 20,
            runner="0x" + "bb" * 20,
            expected_control_state_sha256="77" * 32,
        )
        for index, (network_id, chain_id) in enumerate(NETWORKS)
    )
    identity = recollect_deployment_identity(expectations, IdentityProvider())
    assert identity.outcome == "pass"
    _, identity_freeze = freeze_deployment_identity(
        identity,
        observed_at=NOW,
        store=store,
    )
    nonces: dict[int, int] = {}
    transitions: list[ConfigurationTransition] = []
    for index, category in enumerate(CATEGORIES):
        network_id, chain_id = NETWORKS[index % len(NETWORKS)]
        nonce = nonces.get(chain_id, 1)
        nonces[chain_id] = nonce + 1
        transitions.append(
            ConfigurationTransition(
                transition_id=f"configure-{category}",
                category=category,  # type: ignore[arg-type]
                network_id=network_id,
                chain_id=chain_id,
                contract_id=f"router-{network_id}",
                destination=f"0x{(index % 3) + 1:040x}",
                sender="0x" + "aa" * 20,
                nonce=nonce,
                value_wei=0,
                calldata=bytes([index + 1, 0, 1]),
                gas_limit=100_000,
                max_fee_per_gas_wei=2,
                max_priority_fee_per_gas_wei=1,
                expected_pre_state_sha256="88" * 32,
                expected_post_state_sha256=f"{index + 1:064x}",
            )
        )
    plan = build_configuration_plan(
        plan_id="local-configuration",
        deployment_sha256=identity.deployment_sha256,
        transitions=tuple(transitions),
    )
    assert len(simulate_configuration_plan(plan, ConfigurationProvider())) == 8
    requests = configuration_signer_requests(
        plan,
        signer_id="deployer",
        config_sha256="11" * 32,
        code_sha256="22" * 32,
    )
    batch = build_approved_operation_batch(
        operation_id="local-configuration",
        operation_type="configuration",
        approval_id="local-configuration-approval",
        approval_payload_sha256="99" * 32,
        transactions=tuple(
            ApprovedTransaction(transition.transition_id, request)
            for transition, request in zip(plan.transitions, requests, strict=True)
        ),
    )
    return batch, identity_freeze


def _record_local_pilot(
    store: EvidenceStore,
    executor: DurableBatchExecutor,
) -> tuple[str, str]:
    first = executor.claim_next(
        holder_id="local-worker",
        ttl=timedelta(minutes=5),
        now=NOW,
    )
    assert first is not None
    restarted = DurableBatchExecutor(
        store=store,
        plan=executor.plan,
        templates=load_stage_template_set(STAGES),
    )
    assert restarted.snapshot(now=NOW).leased == 1

    raw_observations: list[tuple[str, str, str, str]] = []
    with store.write() as connection:
        attempts = connection.execute(
            """
            SELECT attempt.attempt_id, attempt.condition_id, attempt.arm,
                   condition.carrier_sequence
            FROM attempts AS attempt
            JOIN conditions AS condition
              ON condition.condition_id = attempt.condition_id
            ORDER BY attempt.schedule_index
            """
        ).fetchall()
        for index, attempt in enumerate(attempts):
            attempt_id = str(attempt["attempt_id"])
            stage = connection.execute(
                """
                SELECT stage_id, chain_id FROM stages
                WHERE attempt_id = ? ORDER BY ordinal DESC LIMIT 1
                """,
                (attempt_id,),
            ).fetchone()
            connection.execute(
                "UPDATE stages SET state = 'completed' WHERE attempt_id = ?",
                (attempt_id,),
            )
            connection.execute(
                "UPDATE attempts SET state = 'delivered' WHERE attempt_id = ?",
                (attempt_id,),
            )
            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, stage_id, signer_operation_id, chain_id, nonce,
                    state, payload_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, 'finalized', ?, ?)
                """,
                (
                    f"intent-{index}",
                    stage["stage_id"],
                    f"pilot-sign-{index}",
                    stage["chain_id"],
                    index,
                    hashlib.sha256(attempt_id.encode()).hexdigest(),
                    NOW.isoformat(),
                ),
            )
            transaction_hash = "0x" + f"{index + 1:064x}"
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce,
                    transaction_hash, state
                ) VALUES (?, ?, ?, ?, ?, 'finalized')
                """,
                (
                    f"pilot-transaction-{index}",
                    f"intent-{index}",
                    stage["chain_id"],
                    index,
                    transaction_hash,
                ),
            )
            connection.execute(
                """
                INSERT INTO attempt_outcome_observations(
                    outcome_observation_id, attempt_id, outcome_kind, outcome,
                    observed_utc, observer_session_id, observed_monotonic_ns
                ) VALUES (?, ?, 'deadline', 'delivered', ?, 'local-boot', ?)
                """,
                (
                    f"pilot-outcome-{index}",
                    attempt_id,
                    (NOW + timedelta(seconds=index + 1)).isoformat(),
                    index + 1,
                ),
            )
            raw_observations.append(
                (
                    attempt_id,
                    str(attempt["carrier_sequence"]),
                    str(attempt["arm"]),
                    transaction_hash,
                )
            )
    for attempt_id, condition, arm, transaction_hash in raw_observations:
        store.put_raw(
            (
                f'{{"attempt_id":"{attempt_id}",'
                f'"condition":"{condition}",'
                f'"arm":"{arm}",'
                f'"transaction_hash":"{transaction_hash}"}}'
            ).encode(),
            media_type="application/json",
            metadata={
                "kind": "local-pilot-observation",
                "attempt_id": attempt_id,
                "public_facts_only": True,
            },
        )
    restarted.leases.release_work(
        lease_id=first.work_lease_id,
        holder_id=first.holder_id,
    )
    restarted.assert_intent_before_broadcast()
    attempt_ids = tuple(item.attempt_id for item in executor.plan.attempts)
    reconciler = RunReconciler(store=store)
    scope_digest = reconciler.declare_freeze_scope(
        scope_id="local-pilot-scope",
        run_id=executor.plan.run_id,
        version=1,
        attempt_ids=attempt_ids,
    )
    report = reconciler.reconcile(
        run_id=executor.plan.run_id,
        expectations=tuple(
            CountExpectation(condition, arm, "pilot", 5)
            for condition in ("HH", "HL", "LH", "LL")
            for arm in ("baseline", "xir")
        ),
        freeze_scope_id="local-pilot-scope",
    )
    reconciler.require_valid(report)
    assert (
        report.planned,
        report.submitted,
        report.not_submitted,
        report.terminal_at_deadline,
        report.pending_backfill,
    ) == (40, 40, 0, 40, 0)
    rebuild_digest = hashlib.sha256(
        f"{executor.plan.plan_sha256}:{scope_digest}".encode()
    ).hexdigest()
    return scope_digest, rebuild_digest


def _closeout_batch() -> ApprovedOperationBatch:
    transactions = tuple(
        ApprovedTransaction(
            transaction_id=f"closeout-{network_id}",
            request=_request(
                network_id=network_id,
                chain_id=chain_id,
                nonce=10,
                intent_id=f"closeout-{network_id}",
                destination=f"0x{index + 1:040x}",
            ),
        )
        for index, (network_id, chain_id) in enumerate(NETWORKS)
    )
    return build_approved_operation_batch(
        operation_id="local-closeout",
        operation_type="closeout",
        approval_id="local-closeout-approval",
        approval_payload_sha256="aa" * 32,
        transactions=transactions,
    )


def test_complete_local_live_lifecycle_with_recovery(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()

    deployment_broadcasts, _ = _execute_batch(
        tmp_path=tmp_path / "deployment",
        store=store,
        batch=_deployment_batch(),
        inject_recovery=True,
    )
    assert len(deployment_broadcasts.calls) == 3

    configuration_batch, deployment_identity_freeze = _configuration_batch(store)
    configuration_broadcasts, _ = _execute_batch(
        tmp_path=tmp_path / "configuration",
        store=store,
        batch=configuration_batch,
        inject_recovery=False,
    )
    assert len(configuration_broadcasts.calls) == 8
    assert len(deployment_identity_freeze) == 64

    profile = materialize_live_pilot(
        load_execution_profile(PILOT),
        profile_id="local-live-pilot",
        limits=LiveLimits(
            max_retries_per_lineage=1,
            max_batch_attempts=4,
            max_duration_seconds=3_600,
            max_in_flight_attempts=2,
            chain_budget_wei={
                "11155420": 1_000_000,
                "421614": 1_000_000,
                "84532": 1_000_000,
            },
            stop_policy={
                "consecutive_failures": 2,
                "rolling_window": 10,
                "rolling_failure_rate": 0.3,
                "timeout_count": 2,
                "collector_backlog": 100,
                "collector_heartbeat_seconds": 30,
                "disk_floor_bytes": 1_000_000,
            },
            allow_partial_conditions=False,
        ),
    )
    profile_document, profile_freeze = freeze_execution_profile(profile, store=store)
    assert profile_document["counts"]["planned_designated_attempts"] == 40
    plan = expand_plan(profile, run_id="local-pilot-run")
    executor = DurableBatchExecutor(
        store=store,
        plan=plan,
        templates=load_stage_template_set(STAGES),
    )
    executor.register_plan(now=NOW)
    RunControlManager(store).initialize(
        run_id=plan.run_id,
        decision=ControlDecision("initial", "bb" * 32, "local-start"),
        now=NOW,
    )
    scope_freeze, rebuild_digest = _record_local_pilot(store, executor)
    recommendation, recommendation_digest = build_pilot_recommendation(
        PilotRecommendationInputs(
            run_id=plan.run_id,
            freeze_sha256=scope_freeze,
            reconciliation_valid=True,
            invariants_valid=True,
            pending_backfill=0,
            first_rebuild_sha256=rebuild_digest,
            second_rebuild_sha256=rebuild_digest,
            eligible_pairs_by_condition={
                "HH": 5,
                "HL": 5,
                "LH": 5,
                "LL": 5,
            },
            minimum_eligible_pairs_per_condition=5,
            hard_stop_triggered=False,
            unresolved_limitations=(),
        )
    )
    assert recommendation["recommendation"] == "go"
    assert recommendation["authority"]["authorizes_any_public_write"] is False
    assert len(profile_freeze) == len(recommendation_digest) == 64

    closeout_broadcasts, _ = _execute_batch(
        tmp_path=tmp_path / "closeout",
        store=store,
        batch=_closeout_batch(),
        inject_recovery=True,
    )
    assert len(closeout_broadcasts.calls) == 3
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM attempt_outcome_observations"
        ).fetchone()[0] == 40
        assert connection.execute(
            "SELECT count(*) FROM invariant_violations WHERE resolved_at IS NULL"
        ).fetchone()[0] == 0
