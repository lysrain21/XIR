#!/usr/bin/env python3
"""Execute the isolated native-faults-v1 controlled-recovery matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

from eth_account import Account

from xir_lab.native.faults_v1 import (
    FAULT_EXIT_CODE,
    FINAL_REVISION_SOURCE_SHA256,
    FaultInjectingNativeRunner,
    FaultLedger,
    InjectedNativeFault,
    fault_attempt,
    final_revision_deployment_contract_valid,
    final_revision_prior_verifier_bindings_valid,
    final_revision_source_lock_valid,
    freeze_fault_results,
    git_identity,
    load_fault_config,
    receiver_snapshot,
    reconcile_fault_case,
    scenario_map,
)
from xir_lab.native.runner import NativeExperimentRunner


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    parser.add_argument("--root-signer-key-file", type=Path, required=True)
    parser.add_argument("--fault-ledger", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument(
        "--deployment-scope",
        choices=("fresh", "prior-verifier-final-revision-shared-idle"),
        default="fresh",
    )


def private_key(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def runner_arguments(args: argparse.Namespace) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[1]
    return {
        "repository_root": repository,
        "runtime_root": args.runtime_root,
        "profile_path": args.profile,
        "deployment_path": args.deployment,
        "private_key": private_key(args.runner_key_file),
        "root_signer_private_key": private_key(args.root_signer_key_file),
        "state_path": args.runner_state,
        "raw_root": args.output_root / "private" / "native-receipts",
        "timeout_seconds": args.timeout_seconds,
        "concurrency": 1,
        "batch_attempts": 1,
    }


def plain_runner(args: argparse.Namespace) -> NativeExperimentRunner:
    return NativeExperimentRunner(**runner_arguments(args))


def validate_runtime_scope(args: argparse.Namespace) -> None:
    output_private = args.output_root.resolve() / "private"
    for label, path in (
        ("fault ledger", args.fault_ledger.resolve()),
        ("runner state", args.runner_state.resolve()),
    ):
        if not path.is_relative_to(output_private):
            raise RuntimeError(f"{label} must stay below the campaign private directory")
    if args.deployment_scope == "fresh":
        return
    runtime = args.runtime_root.resolve()
    expected_paths = {
        "profile": runtime / "profile.json",
        "deployment": runtime / "native-application" / "deployment.json",
        "runner_key": runtime / "private" / "accounts" / "runner.key",
        "root_signer_key": runtime / "private" / "accounts" / "root-signer.key",
    }
    supplied = {
        "profile": args.profile.resolve(),
        "deployment": args.deployment.resolve(),
        "runner_key": args.runner_key_file.resolve(),
        "root_signer_key": args.root_signer_key_file.resolve(),
    }
    mismatches = [name for name, path in supplied.items() if path != expected_paths[name]]
    if mismatches:
        raise RuntimeError("final-revision overlay path mismatch: " + ", ".join(mismatches))
    provenance_path = runtime / "provenance" / "overlay.json"
    if not provenance_path.is_file():
        raise RuntimeError("final-revision campaign requires overlay provenance")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if (
        provenance.get("schema_version") != "xir-lab-native-faults-v1-overlay-v1"
        or Path(str(provenance.get("target_runtime"))).resolve() != runtime
        or provenance.get("deployment_scope") != "prior-verifier-final-revision-shared-idle"
        or provenance.get("source_worker_stopped") is not True
        or provenance.get("private_keys_published") is not False
    ):
        raise RuntimeError("final-revision overlay provenance is invalid")
    source_worker_pid = Path(str(provenance["source_runtime"])) / "pids" / "layerzero-worker.pid"
    if source_worker_pid.is_file() and pid_alive(
        int(source_worker_pid.read_text(encoding="ascii"))
    ):
        raise RuntimeError("source LayerZero worker must remain stopped during overlay use")
    source_agent_pids = Path(str(provenance["source_runtime"])) / "hyperlane" / "agents" / "pids"
    for name in (
        "validator-xirlocalsource",
        "validator-xirlocalintermediate",
        "validator-xirlocaldestination",
        "relayer",
    ):
        pid_path = source_agent_pids / f"{name}.pid"
        if not pid_path.is_file() or not pid_alive(int(pid_path.read_text(encoding="ascii"))):
            raise RuntimeError(f"source Hyperlane agent is not running: {name}")
    deployment = cast(dict[str, Any], json.loads(args.deployment.read_text(encoding="utf-8")))
    if not final_revision_prior_verifier_bindings_valid(deployment):
        raise RuntimeError("campaign deployment lacks final-revision prior-verifier bindings")
    if not final_revision_deployment_contract_valid(deployment):
        raise RuntimeError(
            "campaign deployment is not the separated-signer final-revision contract"
        )
    repository = Path(__file__).resolve().parents[1]
    if not final_revision_source_lock_valid(repository):
        raise RuntimeError("campaign repository does not match the final-revision source lock")
    runner = Account.from_key(private_key(args.runner_key_file)).address.lower()
    root_signer = Account.from_key(private_key(args.root_signer_key_file)).address.lower()
    if runner != str(deployment["runner"]).lower():
        raise RuntimeError("runner key does not match the final-revision deployment")
    if root_signer != str(deployment["root_signer"]).lower() or root_signer == runner:
        raise RuntimeError("root signer is not separated or does not match the deployment")
    if (
        provenance.get("source_deployment_sha256")
        != hashlib.sha256(args.deployment.read_bytes()).hexdigest()
    ):
        raise RuntimeError("overlay provenance does not bind the supplied deployment")
    if provenance.get("final_revision_source_sha256") != FINAL_REVISION_SOURCE_SHA256:
        raise RuntimeError("overlay provenance does not bind the final source revision")


def select_attempt(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], Any]:
    config, _ = load_fault_config(args.config)
    scenario = scenario_map(config)[args.scenario]
    attempt = fault_attempt(
        config=config,
        profile_path=args.profile,
        route=args.route,
        scenario_name=args.scenario,
        repetition=args.repetition,
    )
    return config, scenario, attempt


def wait_for_barrier(ready_file: Path | None, release_file: Path | None) -> None:
    if ready_file is None and release_file is None:
        return
    if ready_file is None or release_file is None:
        raise RuntimeError("both ready and release files are required")
    ready_file.parent.mkdir(parents=True, exist_ok=True)
    ready_file.write_text(f"{os.getpid()}\n", encoding="ascii")
    deadline = time.monotonic() + 60
    while not release_file.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("concurrent recovery barrier timed out")
        time.sleep(0.02)


def run_case(args: argparse.Namespace) -> int:
    validate_runtime_scope(args)
    config, scenario, attempt = select_attempt(args)
    ledger = FaultLedger(args.fault_ledger)
    ledger.ensure_case(
        attempt=attempt,
        scenario=scenario,
        repetition=args.repetition,
        coordinator_stage=str(config["coordinator_stage"]),
    )
    runner = FaultInjectingNativeRunner(
        fault_ledger_path=args.fault_ledger,
        attempt_id=attempt.attempt_id,
        **runner_arguments(args),
    )
    wait_for_barrier(args.ready_file, args.release_file)
    try:
        runner._run_if_needed(attempt)
    except InjectedNativeFault as exc:
        print(
            json.dumps(
                {
                    "event": "controlled_coordinator_exit",
                    "attempt_id": attempt.attempt_id,
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        return FAULT_EXIT_CODE
    stage = runner.state.stage(attempt.attempt_id, "destination_deliver")
    if stage is None or stage["transaction_hash"] is None:
        raise RuntimeError("completed fault case lacks destination transaction identity")
    transaction_hash = str(stage["transaction_hash"]).lower()
    stage_detail = json.loads(stage["detail_json"])
    raw_path = runner.signed_root / f"{transaction_hash}.raw"
    if not raw_path.is_file():
        raise RuntimeError("completed fault case lacks its private signed transaction")
    print(
        json.dumps(
            {
                "event": "case_completion",
                "attempt_id": attempt.attempt_id,
                "nonce": int(stage_detail["nonce"]),
                "transaction_hash": transaction_hash,
                "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_default_worker(runtime_root: Path) -> bool:
    pid_path = runtime_root / "pids" / "layerzero-worker.pid"
    if not pid_path.is_file():
        return False
    pid = int(pid_path.read_text(encoding="ascii"))
    if not pid_alive(pid):
        return False
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 20
    while pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if pid_alive(pid):
        raise RuntimeError("default LayerZero worker did not stop")
    return True


class WorkerSupervisor:
    def __init__(
        self,
        *,
        args: argparse.Namespace,
        ledger: FaultLedger,
    ) -> None:
        self.args = args
        self.ledger = ledger
        self.repository = Path(__file__).resolve().parents[1]
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.active_case: str | None = None
        self.process: subprocess.Popen[str] | None = None
        self.failure: RuntimeError | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        private_root = args.output_root / "private" / "worker"
        private_root.mkdir(parents=True, exist_ok=True)
        self.log_path = private_root / "worker-supervisor.log"

    def command(self) -> list[str]:
        return [
            sys.executable,
            str(self.repository / "scripts" / "layerzero_worker_faults_v1.py"),
            "run",
            "--config",
            str(self.args.runtime_root / "layerzero" / "worker-config.json"),
            "--key-file",
            str(self.args.runtime_root / "private" / "accounts" / "layerzero-worker.key"),
            "--state",
            str(self.args.runtime_root / "layerzero" / "worker.sqlite"),
            "--raw-root",
            str(self.args.output_root / "private" / "worker-receipts"),
            "--fault-ledger",
            str(self.args.fault_ledger),
            "--batch-packets",
            "1",
        ]

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 20
        while self.process is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if self.process is None:
            raise RuntimeError("controlled LayerZero worker did not start")

    def set_active(self, case_key: str | None) -> None:
        with self.lock:
            self.active_case = case_key

    def _run(self) -> None:
        while not self.stop_event.is_set():
            with self.log_path.open("a", encoding="utf-8") as log:
                process = subprocess.Popen(
                    self.command(), stdout=log, stderr=subprocess.STDOUT, text=True
                )
                self.process = process
                return_code = process.wait()
            if self.stop_event.is_set():
                return
            with self.lock:
                case_key = self.active_case
            if case_key is not None:
                self.ledger.record_event(
                    case_key,
                    "child_exit",
                    actor="worker",
                    details={
                        "phase": "worker_fault",
                        "return_code": return_code,
                        "pid": process.pid,
                    },
                )
            if return_code != FAULT_EXIT_CODE:
                self.failure = RuntimeError(
                    f"controlled LayerZero worker exited unexpectedly: {return_code}"
                )
                return

    def check(self) -> None:
        if self.failure is not None:
            raise self.failure

    def close(self) -> None:
        self.stop_event.set()
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        self.thread.join(timeout=20)


def child_command(
    args: argparse.Namespace,
    *,
    route: str,
    scenario: str,
    repetition: int,
    ready_file: Path | None = None,
    release_file: Path | None = None,
) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run-case",
        "--runtime-root",
        str(args.runtime_root),
        "--profile",
        str(args.profile),
        "--deployment",
        str(args.deployment),
        "--config",
        str(args.config),
        "--runner-key-file",
        str(args.runner_key_file),
        "--root-signer-key-file",
        str(args.root_signer_key_file),
        "--fault-ledger",
        str(args.fault_ledger),
        "--runner-state",
        str(args.runner_state),
        "--output-root",
        str(args.output_root),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--deployment-scope",
        str(args.deployment_scope),
        "--route",
        route,
        "--scenario",
        scenario,
        "--repetition",
        str(repetition),
    ]
    if ready_file is not None and release_file is not None:
        command.extend(["--ready-file", str(ready_file), "--release-file", str(release_file)])
    return command


def parse_completion(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if candidate.get("event") == "case_completion":
            return cast(dict[str, Any], candidate)
    return None


def record_child(
    ledger: FaultLedger,
    case_key: str,
    phase: str,
    completed: subprocess.CompletedProcess[str],
    *,
    batch_id: str | None = None,
) -> dict[str, Any] | None:
    completion = parse_completion(completed.stdout)
    ledger.record_event(
        case_key,
        "child_exit",
        actor="coordinator",
        details={
            "phase": phase,
            "return_code": completed.returncode,
            "completion": completion,
            "batch_id": batch_id,
            "stdout_tail": completed.stdout[-1000:],
            "stderr_tail": completed.stderr[-1000:],
        },
    )
    return completion


def execute_child(
    ledger: FaultLedger,
    case_key: str,
    phase: str,
    command: list[str],
    expected: int,
) -> None:
    completed = subprocess.run(command, capture_output=True, text=True)
    record_child(ledger, case_key, phase, completed)
    if completed.returncode != expected:
        raise RuntimeError(
            f"native-faults-v1 child {phase} returned {completed.returncode}, "
            f"expected {expected}: {completed.stderr[-2000:]}"
        )


def execute_concurrent_recovery(
    args: argparse.Namespace,
    ledger: FaultLedger,
    case_key: str,
    route: str,
    scenario: str,
    repetition: int,
) -> None:
    prior_batches = sum(
        event["event_type"] == "concurrent_recovery_complete" for event in ledger.events(case_key)
    )
    batch_id = hashlib.sha256(f"{case_key}:concurrent:{prior_batches}".encode()).hexdigest()[:24]
    barrier = args.output_root / "private" / "barriers" / case_key.replace(":", "__")
    barrier.mkdir(parents=True, exist_ok=True)
    release = barrier / "release"
    ready = [barrier / "ready-0", barrier / "ready-1"]
    for path in [release, *ready]:
        if path.exists():
            path.unlink()
    processes = [
        subprocess.Popen(
            child_command(
                args,
                route=route,
                scenario=scenario,
                repetition=repetition,
                ready_file=ready[index],
                release_file=release,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(2)
    ]
    deadline = time.monotonic() + 60
    while not all(path.exists() for path in ready):
        if time.monotonic() >= deadline:
            for process in processes:
                process.terminate()
            raise RuntimeError("concurrent retry children did not reach the barrier")
        time.sleep(0.02)
    release.write_text("release\n", encoding="ascii")
    completions: list[dict[str, Any] | None] = []
    return_codes: list[int] = []
    stderr_tails: list[str] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=args.timeout_seconds * 2)
        completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        completions.append(
            record_child(
                ledger,
                case_key,
                "concurrent_recovery",
                completed,
                batch_id=batch_id,
            )
        )
        return_codes.append(int(process.returncode))
        stderr_tails.append(stderr[-2000:])
    if return_codes != [0, 0]:
        raise RuntimeError(f"concurrent retry children returned {return_codes}: {stderr_tails}")
    ledger.record_event(
        case_key,
        "concurrent_recovery_complete",
        actor="coordinator",
        details={
            "batch_id": batch_id,
            "return_codes": return_codes,
            "completions": completions,
        },
    )


def campaign(args: argparse.Namespace) -> dict[str, Any]:
    validate_runtime_scope(args)
    config, config_sha256 = load_fault_config(args.config)
    ledger = FaultLedger(args.fault_ledger)
    args.output_root.mkdir(parents=True, exist_ok=True)
    default_worker_was_running = stop_default_worker(args.runtime_root)
    supervisor = WorkerSupervisor(args=args, ledger=ledger)
    supervisor.start()
    try:
        for scenario in config["scenarios"]:
            scenario_name = str(scenario["name"])
            for route in config["routes"]:
                for repetition in range(int(config["repetitions_per_route_scenario"])):
                    attempt = fault_attempt(
                        config=config,
                        profile_path=args.profile,
                        route=str(route),
                        scenario_name=scenario_name,
                        repetition=repetition,
                    )
                    case_key = ledger.ensure_case(
                        attempt=attempt,
                        scenario=scenario,
                        repetition=repetition,
                        coordinator_stage=str(config["coordinator_stage"]),
                    )
                    current = ledger.case(case_key)
                    if current["status"] == "validated":
                        continue
                    if current["before"] is None:
                        ledger.set_before(case_key, receiver_snapshot(plain_runner(args), attempt))
                    supervisor.set_active(case_key)
                    supervisor.check()
                    command = child_command(
                        args,
                        route=str(route),
                        scenario=scenario_name,
                        repetition=repetition,
                    )
                    injected_now = False
                    if current["status"] in {"planned", "armed"}:
                        if current["status"] == "planned":
                            ledger.arm(case_key)
                        expected = (
                            0
                            if scenario["actor"] == "worker"
                            or scenario["signal"] == "transient_retry"
                            else FAULT_EXIT_CODE
                        )
                        execute_child(ledger, case_key, "injection", command, expected)
                        injected_now = True
                    if scenario["signal"] == "concurrent_retry":
                        completed_batches = [
                            event
                            for event in ledger.events(case_key)
                            if event["event_type"] == "concurrent_recovery_complete"
                        ]
                        if not completed_batches:
                            execute_concurrent_recovery(
                                args,
                                ledger,
                                case_key,
                                str(route),
                                scenario_name,
                                repetition,
                            )
                    elif scenario["actor"] != "worker" or not injected_now:
                        execute_child(ledger, case_key, "recovery", command, 0)
                    supervisor.check()
                    supervisor.set_active(None)
                    result = reconcile_fault_case(
                        runner=plain_runner(args),
                        ledger=ledger,
                        case_key=case_key,
                        worker_state_path=args.runtime_root / "layerzero" / "worker.sqlite",
                    )
                    if not result["valid"]:
                        raise RuntimeError(f"controlled recovery did not reconcile: {case_key}")
    finally:
        supervisor.close()
        if default_worker_was_running:
            subprocess.run(
                [
                    str(
                        Path(__file__).resolve().parents[1]
                        / "scripts"
                        / "native_stack_processes.sh"
                    ),
                    "start-worker",
                    str(args.runtime_root),
                ],
                check=True,
            )

    environment_path = args.output_root / "publish" / "environment.json"
    if environment_path.is_file():
        environment = json.loads(environment_path.read_text(encoding="utf-8"))
        environment.pop("schema_version", None)
    else:
        overlay_provenance = args.runtime_root / "provenance" / "overlay.json"
        environment = {
            **git_identity(Path(__file__).resolve().parents[1]),
            "runtime_namespace": str(args.runtime_root),
            "fault_ledger": str(args.fault_ledger),
            "runner_state": str(args.runner_state),
            "config_sha256": config_sha256,
            "default_worker_restored": default_worker_was_running,
            "controlled_campaign": True,
            "natural_interruptions_included": False,
            "deployment_scope": args.deployment_scope,
            "final_revision_source_sha256": FINAL_REVISION_SOURCE_SHA256,
            "profile_sha256": hashlib.sha256(args.profile.read_bytes()).hexdigest(),
            "overlay_provenance": (
                str(overlay_provenance) if overlay_provenance.is_file() else None
            ),
            "overlay_provenance_sha256": (
                hashlib.sha256(overlay_provenance.read_bytes()).hexdigest()
                if overlay_provenance.is_file()
                else None
            ),
        }
    return freeze_fault_results(
        ledger=ledger,
        config_path=args.config,
        deployment_path=args.deployment,
        output_root=args.output_root,
        environment=environment,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run-case")
    add_common(run_parser)
    run_parser.add_argument("--route", choices=("HL", "LH"), required=True)
    run_parser.add_argument("--scenario", required=True)
    run_parser.add_argument("--repetition", type=int, required=True)
    run_parser.add_argument("--ready-file", type=Path)
    run_parser.add_argument("--release-file", type=Path)
    campaign_parser = subparsers.add_parser("campaign")
    add_common(campaign_parser)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "run-case":
        raise SystemExit(run_case(args))
    summary = campaign(args)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
