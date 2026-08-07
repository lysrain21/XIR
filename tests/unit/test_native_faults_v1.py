from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from eth_account import Account
from hexbytes import HexBytes

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.faults_handoff_v1 import build_handoff, sha256
from xir_lab.native.faults_v1 import (
    FaultingLayerZeroWorkerState,
    FaultingRunnerState,
    FaultInjectingNativeRunner,
    FaultInjector,
    FaultLedger,
    InjectedNativeFault,
    InjectedTransientFault,
    concurrent_recovery_identity,
    fault_attempt,
    final_revision_deployment_contract_valid,
    final_revision_prior_verifier_bindings_valid,
    freeze_fault_results,
    load_fault_config,
    scenario_map,
)
from xir_lab.native.layerzero import decode_packet
from xir_lab.native.layerzero_worker import LayerZeroWorkerState
from xir_lab.native.runner import NativeExperimentRunner, RunnerState

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "native" / "native-faults-v1.json"
PROFILE = ROOT / "configs" / "profiles" / "native-protocol-stack-v1.json"


def final_revision_deployment(
    *, runner: str = "0x" + "11" * 20, root_signer: str = "0x" + "22" * 20
) -> dict[str, object]:
    return {
        "schema_version": "xir-lab-native-application-deployment-v1",
        "runner": runner.lower(),
        "root_signer": root_signer.lower(),
        "chains": {"intermediate": {"h_in": "0xAA", "l_in": "0xBB"}},
        "prior_verifier_bindings": {
            "h_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
            "l_xir_out": {"H_AB": "0xaa", "L_AB": "0xbb"},
        },
    }


def packet_bytes() -> bytes:
    return (
        b"\x01"
        + (9).to_bytes(8, "big")
        + (49001).to_bytes(4, "big")
        + bytes.fromhex("00" * 12 + "11" * 20)
        + (49002).to_bytes(4, "big")
        + bytes.fromhex("00" * 12 + "22" * 20)
        + bytes.fromhex("33" * 32)
        + b"payload"
    )


def planned(
    tmp_path: Path, scenario_name: str, route: str = "HL"
) -> tuple[FaultLedger, str, NativeAttempt]:
    config, _ = load_fault_config(CONFIG)
    scenario = scenario_map(config)[scenario_name]
    attempt = fault_attempt(
        config=config,
        profile_path=PROFILE,
        route=route,
        scenario_name=scenario_name,
        repetition=0,
    )
    ledger = FaultLedger(tmp_path / "faults.sqlite")
    key = ledger.ensure_case(
        attempt=attempt,
        scenario=scenario,
        repetition=0,
        coordinator_stage=str(config["coordinator_stage"]),
    )
    ledger.arm(key)
    return ledger, key, attempt


def test_config_has_complete_fixed_matrix_and_stable_attempts() -> None:
    config, digest = load_fault_config(CONFIG)
    assert len(digest) == 64
    assert len(config["scenarios"]) == 10
    first = fault_attempt(
        config=config,
        profile_path=PROFILE,
        route="HL",
        scenario_name="pre_intent",
        repetition=0,
    )
    second = fault_attempt(
        config=config,
        profile_path=PROFILE,
        route="HL",
        scenario_name="pre_intent",
        repetition=0,
    )
    assert first == second
    assert first.attempt_id.startswith("fault_")


def test_final_revision_prior_verifier_binding_gate_checks_both_outbound_adapters() -> None:
    deployment = final_revision_deployment()
    assert final_revision_prior_verifier_bindings_valid(deployment)
    assert final_revision_deployment_contract_valid(deployment)
    deployment["prior_verifier_bindings"]["l_xir_out"]["H_AB"] = "0xcc"  # type: ignore[index]
    assert not final_revision_prior_verifier_bindings_valid(deployment)
    assert not final_revision_deployment_contract_valid(deployment)


def test_final_revision_deployment_rejects_combined_runner_and_root_signer() -> None:
    deployment = final_revision_deployment(root_signer="0x" + "11" * 20)
    assert not final_revision_deployment_contract_valid(deployment)


def test_fault_claim_is_one_shot_across_connections(tmp_path: Path) -> None:
    ledger, key, attempt = planned(tmp_path, "pre_intent")
    injector = FaultInjector(
        ledger=FaultLedger(ledger.path),
        actor="coordinator",
        attempt_id=attempt.attempt_id,
    )
    with pytest.raises(InjectedNativeFault):
        injector.hit("pre_intent", "destination_deliver", {"nonce": 7})
    injector.hit("pre_intent", "destination_deliver", {"nonce": 7})
    assert ledger.case(key)["status"] == "faulted"
    assert len(ledger.events(key)) == 1


def test_runner_state_injects_before_and_after_durable_records(tmp_path: Path) -> None:
    ledger, _, attempt = planned(tmp_path / "before", "pre_intent")
    state = RunnerState(tmp_path / "before" / "runner.sqlite")
    state.begin(attempt)
    proxy = FaultingRunnerState(
        state,
        FaultInjector(
            ledger=ledger,
            actor="coordinator",
            attempt_id=attempt.attempt_id,
        ),
    )
    with pytest.raises(InjectedNativeFault):
        proxy.record_stage(
            attempt.attempt_id,
            "destination_deliver",
            "intended",
            {"nonce": 4},
        )
    assert state.stage(attempt.attempt_id, "destination_deliver") is None

    ledger, _, attempt = planned(tmp_path / "signed", "post_sign_pre_broadcast")
    state = RunnerState(tmp_path / "signed" / "runner.sqlite")
    state.begin(attempt)
    proxy = FaultingRunnerState(
        state,
        FaultInjector(
            ledger=ledger,
            actor="coordinator",
            attempt_id=attempt.attempt_id,
        ),
    )
    proxy.record_stage(
        attempt.attempt_id,
        "destination_deliver",
        "intended",
        {"nonce": 8},
    )
    with pytest.raises(InjectedNativeFault):
        proxy.record_stage(
            attempt.attempt_id,
            "destination_deliver",
            "signed",
            {"nonce": 8, "raw_sha256": "ab" * 32},
            "0x" + "12" * 32,
        )
    signed = state.stage(attempt.attempt_id, "destination_deliver")
    assert signed is not None
    assert signed["state"] == "signed"


def test_transient_signal_uses_runner_retry_exception(tmp_path: Path) -> None:
    ledger, _, attempt = planned(tmp_path, "transient_retry_after_broadcast")
    injector = FaultInjector(
        ledger=ledger,
        actor="coordinator",
        attempt_id=attempt.attempt_id,
    )
    with pytest.raises(InjectedTransientFault):
        injector.hit(
            "post_broadcast_pre_acknowledgement",
            "destination_deliver",
            {"transaction_hash": "0x" + "34" * 32},
        )


def test_worker_action_is_durable_before_exit(tmp_path: Path) -> None:
    ledger, key, _ = planned(tmp_path, "worker_action_post_submit")
    base = LayerZeroWorkerState(tmp_path / "worker.sqlite")
    packet = decode_packet(packet_bytes())
    base.observe_packet(
        packet=packet,
        source_block=5,
        source_transaction_hash="0xabc",
        source_log_index=0,
    )
    guid = "0x" + packet.guid.hex()
    action = base.intend_action(
        guid=guid,
        stage="executor_execute",
        destination_chain_id=3133702,
        nonce=9,
        target="0x" + "44" * 20,
        call_data=b"call",
    )
    base.record_signed(str(action["action_id"]), b"signed", "0x" + "56" * 32)
    proxy = FaultingLayerZeroWorkerState(
        base, FaultInjector(ledger=ledger, actor="worker", attempt_id=None)
    )
    with pytest.raises(InjectedNativeFault):
        proxy.observe_action(
            str(action["action_id"]),
            "submitted",
            {"transaction_hash": "0x" + "56" * 32},
        )
    durable = base.action(guid, "executor_execute")
    assert durable is not None
    assert durable["status"] == "submitted"
    event = ledger.events(key)[0]
    assert event["details"]["guid"] == guid


def test_existing_plan_cannot_be_changed(tmp_path: Path) -> None:
    config, _ = load_fault_config(CONFIG)
    scenarios = scenario_map(config)
    attempt = fault_attempt(
        config=config,
        profile_path=PROFILE,
        route="HL",
        scenario_name="pre_intent",
        repetition=0,
    )
    ledger = FaultLedger(tmp_path / "faults.sqlite")
    ledger.ensure_case(
        attempt=attempt,
        scenario=scenarios["pre_intent"],
        repetition=0,
        coordinator_stage="destination_deliver",
    )
    changed = dict(scenarios["pre_intent"])
    changed["boundary"] = "post_intent_pre_sign"
    with pytest.raises(LocalTopologyError):
        ledger.ensure_case(
            attempt=attempt,
            scenario=changed,
            repetition=0,
            coordinator_stage="destination_deliver",
        )


def test_concurrent_recovery_requires_same_signed_transaction_identity() -> None:
    injected = {
        "nonce": 17,
        "transaction_hash": "0x" + "12" * 32,
        "raw_sha256": "34" * 32,
    }
    completion = {"attempt_id": "fault_" + "56" * 16, **injected}
    identity, valid = concurrent_recovery_identity(
        attempt_id=completion["attempt_id"],
        completions=[completion, completion],
        injected_details=injected,
        return_codes=[0, 0],
        completed_batch_count=1,
    )
    assert valid is True
    assert identity["recoveries"][0] == identity["injected"]
    changed = {**completion, "raw_sha256": "78" * 32}
    _, valid = concurrent_recovery_identity(
        attempt_id=completion["attempt_id"],
        completions=[completion, changed],
        injected_details=injected,
        return_codes=[0, 0],
        completed_batch_count=1,
    )
    assert valid is False


def test_concurrent_recovery_normalizes_transaction_hash_prefix() -> None:
    attempt_id = "fault_" + "56" * 16
    injected = {
        "nonce": 17,
        "transaction_hash": "0x" + "12" * 32,
        "raw_sha256": "34" * 32,
    }
    completion = {
        "attempt_id": attempt_id,
        "nonce": 17,
        "transaction_hash": "12" * 32,
        "raw_sha256": "34" * 32,
    }
    identity, valid = concurrent_recovery_identity(
        attempt_id=attempt_id,
        completions=[completion, completion],
        injected_details=injected,
        return_codes=[0, 0],
        completed_batch_count=1,
    )
    assert valid is True
    assert identity["injected"]["transaction_hash"] == "0x" + "12" * 32
    assert identity["recoveries"][0]["transaction_hash"] == "0x" + "12" * 32


def test_post_fix_runtime_scope_requires_isolation_and_live_agents(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "overlay"
    output = tmp_path / "results"
    for relative in (
        "native-application",
        "private/accounts",
        "provenance",
    ):
        (runtime / relative).mkdir(parents=True, exist_ok=True)
    for name in ("profile.json", "native-application/deployment.json"):
        (runtime / name).write_text("{}\n", encoding="utf-8")
    for name in ("runner.key", "root-signer.key"):
        (runtime / "private" / "accounts" / name).write_text("fixture\n", encoding="utf-8")
    agent_pids = source / "hyperlane" / "agents" / "pids"
    agent_pids.mkdir(parents=True)
    for name in (
        "validator-xirlocalsource",
        "validator-xirlocalintermediate",
        "validator-xirlocaldestination",
        "relayer",
    ):
        (agent_pids / f"{name}.pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    provenance = {
        "schema_version": "xir-lab-native-faults-v1-overlay-v1",
        "source_runtime": str(source.resolve()),
        "target_runtime": str(runtime.resolve()),
        "deployment_scope": "prior-verifier-final-revision-shared-idle",
        "source_worker_stopped": True,
        "private_keys_published": False,
    }
    (runtime / "provenance" / "overlay.json").write_text(json.dumps(provenance), encoding="utf-8")
    (source / "pids").mkdir()
    (source / "pids" / "layerzero-worker.pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_native_faults_v1.py"),
            "campaign",
            "--runtime-root",
            str(runtime),
            "--profile",
            str(runtime / "profile.json"),
            "--deployment",
            str(runtime / "native-application" / "deployment.json"),
            "--config",
            str(CONFIG),
            "--runner-key-file",
            str(runtime / "private" / "accounts" / "runner.key"),
            "--root-signer-key-file",
            str(runtime / "private" / "accounts" / "root-signer.key"),
            "--fault-ledger",
            str(output / "private" / "fault-ledger.sqlite"),
            "--runner-state",
            str(output / "private" / "runner.sqlite"),
            "--output-root",
            str(output),
            "--deployment-scope",
            "prior-verifier-final-revision-shared-idle",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "must remain stopped" in completed.stderr


def test_final_revision_runtime_scope_rejects_invalid_deployment_binding(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "overlay"
    output = tmp_path / "results"
    for relative in (
        "native-application",
        "private/accounts",
        "provenance",
    ):
        (runtime / relative).mkdir(parents=True, exist_ok=True)
    (runtime / "profile.json").write_text("{}\n", encoding="utf-8")
    deployment = final_revision_deployment()
    deployment["prior_verifier_bindings"]["h_xir_out"]["L_AB"] = "0xcc"  # type: ignore[index]
    (runtime / "native-application" / "deployment.json").write_text(
        json.dumps(deployment) + "\n", encoding="utf-8"
    )
    for name in ("runner.key", "root-signer.key"):
        (runtime / "private" / "accounts" / name).write_text("fixture\n", encoding="utf-8")
    agent_pids = source / "hyperlane" / "agents" / "pids"
    agent_pids.mkdir(parents=True)
    for name in (
        "validator-xirlocalsource",
        "validator-xirlocalintermediate",
        "validator-xirlocaldestination",
        "relayer",
    ):
        (agent_pids / f"{name}.pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    provenance = {
        "schema_version": "xir-lab-native-faults-v1-overlay-v1",
        "source_runtime": str(source.resolve()),
        "target_runtime": str(runtime.resolve()),
        "deployment_scope": "prior-verifier-final-revision-shared-idle",
        "source_worker_stopped": True,
        "private_keys_published": False,
    }
    (runtime / "provenance" / "overlay.json").write_text(json.dumps(provenance), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_native_faults_v1.py"),
            "campaign",
            "--runtime-root",
            str(runtime),
            "--profile",
            str(runtime / "profile.json"),
            "--deployment",
            str(runtime / "native-application" / "deployment.json"),
            "--config",
            str(CONFIG),
            "--runner-key-file",
            str(runtime / "private" / "accounts" / "runner.key"),
            "--root-signer-key-file",
            str(runtime / "private" / "accounts" / "root-signer.key"),
            "--fault-ledger",
            str(output / "private" / "fault-ledger.sqlite"),
            "--runner-state",
            str(output / "private" / "runner.sqlite"),
            "--output-root",
            str(output),
            "--deployment-scope",
            "prior-verifier-final-revision-shared-idle",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "lacks final-revision prior-verifier bindings" in completed.stderr


def test_overlay_refuses_pending_worker_state_before_creating_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    (source / "layerzero").mkdir(parents=True)
    (source / "private" / "accounts").mkdir(parents=True)
    for path in (
        source / "profile.json",
        source / "deployment.json",
        source / "layerzero" / "worker-config.json",
    ):
        path.write_text("{}\n", encoding="utf-8")
    (source / "deployment.json").write_text(
        json.dumps(final_revision_deployment()) + "\n", encoding="utf-8"
    )
    for name in ("runner.key", "root-signer.key", "layerzero-worker.key"):
        (source / "private" / "accounts" / name).write_text("fixture\n", encoding="ascii")
    worker = LayerZeroWorkerState(source / "layerzero" / "worker.sqlite")
    packet = decode_packet(packet_bytes())
    worker.observe_packet(
        packet=packet,
        source_block=5,
        source_transaction_hash="0xabc",
        source_log_index=0,
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prepare_native_faults_v1_overlay.py"),
            "--source-runtime",
            str(source),
            "--source-deployment",
            str(source / "deployment.json"),
            "--target-runtime",
            str(target),
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "pending packets or actions" in completed.stderr
    assert not target.exists()


def test_overlay_copies_an_idle_worker_database_without_overwrite(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    (source / "layerzero").mkdir(parents=True)
    (source / "private" / "accounts").mkdir(parents=True)
    for path in (
        source / "profile.json",
        source / "deployment.json",
        source / "layerzero" / "worker-config.json",
    ):
        path.write_text("{}\n", encoding="utf-8")
    keys = {
        name: f"{index:064x}"
        for index, name in enumerate(("runner", "root-signer", "layerzero-worker"), start=1)
    }
    deployment = final_revision_deployment(
        runner=Account.from_key(keys["runner"]).address,
        root_signer=Account.from_key(keys["root-signer"]).address,
    )
    (source / "deployment.json").write_text(json.dumps(deployment) + "\n", encoding="utf-8")
    for name, key in keys.items():
        (source / "private" / "accounts" / f"{name}.key").write_text(key + "\n", encoding="ascii")
    LayerZeroWorkerState(source / "layerzero" / "worker.sqlite")
    command = [
        sys.executable,
        str(ROOT / "scripts" / "prepare_native_faults_v1_overlay.py"),
        "--source-runtime",
        str(source),
        "--source-deployment",
        str(source / "deployment.json"),
        "--target-runtime",
        str(target),
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    provenance = json.loads((target / "provenance" / "overlay.json").read_text(encoding="utf-8"))
    assert provenance["worker_database"]["pending_packets"] == 0
    assert provenance["worker_database"]["pending_actions"] == 0
    assert provenance["deployment_scope"] == "prior-verifier-final-revision-shared-idle"
    assert provenance["prior_verifier_bindings"] == deployment["prior_verifier_bindings"]
    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode != 0
    assert "refusing overwrite" in second.stderr


@pytest.mark.parametrize(
    ("scenario_name", "send_calls", "wait_calls", "persist_calls"),
    (
        ("post_broadcast_pre_acknowledgement", 1, 0, 0),
        ("post_acknowledgement_pre_mining", 1, 0, 0),
        ("post_mining_pre_persistence", 1, 1, 0),
        ("post_persistence_pre_stage_commit", 1, 1, 1),
    ),
)
def test_rpc_boundaries_fire_after_the_named_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario_name: str,
    send_calls: int,
    wait_calls: int,
    persist_calls: int,
) -> None:
    ledger, _, attempt = planned(tmp_path, scenario_name)

    class FakeEth:
        def __init__(self) -> None:
            self.send_count = 0
            self.wait_count = 0

        def send_raw_transaction(self, raw: bytes) -> HexBytes:
            self.send_count += 1
            return HexBytes("0x" + "77" * 32)

        def wait_for_transaction_receipt(self, transaction_hash: HexBytes) -> dict[str, int]:
            self.wait_count += 1
            return {"blockNumber": 12, "status": 1, "gasUsed": 50_000}

    class FakeClient:
        def __init__(self) -> None:
            self.eth = FakeEth()

    calls = {"persist": 0}

    def base_persist(
        self: NativeExperimentRunner,
        *,
        transaction_hash: str,
        receipt: object,
        detail: dict[str, object],
    ) -> dict[str, object]:
        calls["persist"] += 1
        return {
            **detail,
            "receipt": "/private/receipt.json",
            "receipt_sha256": "88" * 32,
        }

    def base_transact(self: NativeExperimentRunner, **kwargs: object) -> dict[str, object]:
        client = self.clients[str(kwargs["role"])]
        transaction_hash = client.eth.send_raw_transaction(b"signed")
        receipt = client.eth.wait_for_transaction_receipt(transaction_hash)
        return self._persist_receipt(
            transaction_hash=transaction_hash.hex(), receipt=receipt, detail={}
        )

    monkeypatch.setattr(NativeExperimentRunner, "_persist_receipt", base_persist)
    monkeypatch.setattr(NativeExperimentRunner, "_transact", base_transact)
    runner = object.__new__(FaultInjectingNativeRunner)
    runner.clients = {"destination": FakeClient()}  # type: ignore[assignment]
    runner.fault_injector = FaultInjector(
        ledger=ledger, actor="coordinator", attempt_id=attempt.attempt_id
    )
    runner._fault_context = threading.local()
    with pytest.raises(InjectedNativeFault):
        runner._transact(
            attempt_id=attempt.attempt_id,
            stage="destination_deliver",
            role="destination",
            function=object(),
        )
    eth = runner.clients["destination"].eth
    assert eth.send_count == send_calls
    assert eth.wait_count == wait_calls
    assert calls["persist"] == persist_calls


def test_summary_counts_transient_fault_events(tmp_path: Path) -> None:
    config, _ = load_fault_config(CONFIG)
    ledger = FaultLedger(tmp_path / "faults.sqlite")
    for scenario in config["scenarios"]:
        for route in config["routes"]:
            for repetition in range(config["repetitions_per_route_scenario"]):
                attempt = fault_attempt(
                    config=config,
                    profile_path=PROFILE,
                    route=route,
                    scenario_name=scenario["name"],
                    repetition=repetition,
                )
                key = ledger.ensure_case(
                    attempt=attempt,
                    scenario=scenario,
                    repetition=repetition,
                    coordinator_stage=config["coordinator_stage"],
                )
                transaction_hash = "0x" + attempt.attempt_id.removeprefix("fault_") * 2
                signed_identity = {
                    "attempt_id": attempt.attempt_id,
                    "nonce": 1,
                    "transaction_hash": transaction_hash,
                    "raw_sha256": "ab" * 32,
                }
                concurrent_identity = (
                    {
                        "recoveries": [signed_identity, signed_identity],
                        "injected": signed_identity,
                    }
                    if scenario["name"] == "concurrent_retry"
                    else None
                )
                ledger.finish(
                    key,
                    {
                        "schema_version": "xir-lab-native-faults-v1-case-result-v1",
                        "case_key": key,
                        "attempt_id": attempt.attempt_id,
                        "route": route,
                        "scenario": scenario["name"],
                        "repetition": repetition,
                        "actor": scenario["actor"],
                        "boundary": scenario["boundary"],
                        "signal": scenario["signal"],
                        "before": {},
                        "after": {},
                        "mid": "0x" + "00" * 32,
                        "nonce_lineage": [1],
                        "transaction_lineage": [transaction_hash],
                        "raw_transaction_lineage": ["ab" * 32],
                        "stage_history": [],
                        "fault_events": [{"event_type": "fault_injected"}],
                        "retry_errors": [],
                        "application_event_transaction_hashes": [transaction_hash],
                        "worker_lineage": None,
                        "concurrent_recovery_identity": concurrent_identity,
                        "checks": {
                            "attempt_identity_stable": True,
                            "one_fault_injected": True,
                            "expected_process_exit_count": True,
                            "destination_stage_succeeded": True,
                            "single_nonce_lineage": True,
                            "single_transaction_lineage": True,
                            "single_raw_transaction_lineage": True,
                            "fault_nonce_matches_recovery": True,
                            "fault_transaction_matches_recovery": True,
                            "fault_raw_matches_recovery": True,
                            "one_application_event": True,
                            "attempt_consumed_once": True,
                            "gateway_consumed": True,
                            "transient_retry_recorded": True,
                            "concurrent_retries_joined": True,
                            "worker_action_recovered": True,
                        },
                        "valid": True,
                    },
                )
    deployment = tmp_path / "deployment.json"
    deployment.write_text("{}\n", encoding="utf-8")
    environment = {"test": True, "fault_source_bundle_sha256": "aa" * 32}
    summary = freeze_fault_results(
        ledger=ledger,
        config_path=CONFIG,
        deployment_path=deployment,
        output_root=tmp_path / "frozen",
        environment=environment,
    )
    transient = [
        group
        for group in summary["groups"]
        if group["scenario"] == "transient_retry_after_broadcast"
    ]
    assert len(transient) == 2
    assert all(group["faults_injected"] == 3 for group in transient)
    assert summary["valid"] is True
    validation = json.loads(
        (tmp_path / "frozen" / "publish" / "validation.json").read_text(encoding="utf-8")
    )
    assert validation["counts"]["stable_logical_attempt_id"] == 60
    assert validation["counts"]["one_destination_effect"] == 60
    assert validation["counts"]["single_raw_transaction_lineage"] == 60
    assert validation["counts"]["concurrent_recovery_shared_signed_identity"] == 6
    assert validation["valid"] is True
    rebuild_a = freeze_fault_results(
        ledger=ledger,
        config_path=CONFIG,
        deployment_path=deployment,
        output_root=tmp_path / "rebuild-a",
        environment=environment,
    )
    rebuild_b = freeze_fault_results(
        ledger=ledger,
        config_path=CONFIG,
        deployment_path=deployment,
        output_root=tmp_path / "rebuild-b",
        environment=environment,
    )
    assert rebuild_a["manifest_sha256"] == rebuild_b["manifest_sha256"]
    figure = tmp_path / "frozen" / "figure"
    figure.mkdir()
    pdf = figure / "recovery-overview-v2.pdf"
    svg = figure / "recovery-overview-v2.svg"
    figure_csv = figure / "recovery-overview-v2-source.csv"
    pdf.write_bytes(b"%PDF-1.4 fixture\n")
    svg.write_text("<svg/>\n", encoding="utf-8")
    figure_csv.write_text("fixture\n", encoding="utf-8")
    figure_source = {
        "provenance": {
            "source_summary_sha256": sha256(tmp_path / "frozen" / "publish" / "summary.json")
        },
        "output_sha256": {
            "pdf": sha256(pdf),
            "svg": sha256(svg),
            "csv": sha256(figure_csv),
        },
    }
    (figure / "recovery-overview-v2-source.json").write_text(
        json.dumps(figure_source, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    handoff = build_handoff(
        frozen_publish=tmp_path / "frozen" / "publish",
        rebuild_a_publish=tmp_path / "rebuild-a" / "publish",
        rebuild_b_publish=tmp_path / "rebuild-b" / "publish",
        figure_dir=figure,
        output=tmp_path / "handoff.json",
        schema_root=ROOT / "schemas",
    )
    assert handoff["denominator"]["exact"] is True
    assert handoff["matrix"]["all_groups_valid"] is True
    assert handoff["invariants"]["concurrent_recovery_shared_signed_identity"] is True
    assert handoff["valid"] is True
    rebuilt = freeze_fault_results(
        ledger=ledger,
        config_path=CONFIG,
        deployment_path=deployment,
        output_root=tmp_path / "frozen",
        environment=environment,
    )
    assert rebuilt["manifest_sha256"] == summary["manifest_sha256"]
    with pytest.raises(LocalTopologyError, match="refuses to overwrite"):
        freeze_fault_results(
            ledger=ledger,
            config_path=CONFIG,
            deployment_path=deployment,
            output_root=tmp_path / "frozen",
            environment={"test": False},
        )
