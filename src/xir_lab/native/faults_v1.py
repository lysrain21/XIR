"""Controlled process-failure campaign for the isolated native carrier stack.

The module injects one durable-boundary failure per planned case. A separate
SQLite ledger makes each process-exit or transient-retry signal one-shot. The
normal native runner remains unchanged; this module wraps its durable state and
RPC calls only inside the ``native-faults-v1`` campaign.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import threading
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import jsonschema
from eth_utils import keccak  # type: ignore[attr-defined]
from requests import RequestException
from web3 import Web3

from xir_lab.localnet.native_profile import NativeAttempt, native_application_payload
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero_worker import LayerZeroWorkerState
from xir_lab.native.runner import NativeExperimentRunner, RunnerState
from xir_lab.native.xir_trace import message_id

FAULT_EXIT_CODE = 86

COORDINATOR_BOUNDARIES = frozenset(
    {
        "pre_intent",
        "post_intent_pre_sign",
        "post_sign_pre_broadcast",
        "post_broadcast_pre_acknowledgement",
        "post_acknowledgement_pre_mining",
        "post_mining_pre_persistence",
        "post_persistence_pre_stage_commit",
    }
)
WORKER_BOUNDARIES = frozenset({"worker_action_post_submit"})
REQUIRED_SCENARIOS = frozenset(
    {
        "pre_intent",
        "post_intent_pre_sign",
        "post_sign_pre_broadcast",
        "post_broadcast_pre_acknowledgement",
        "post_acknowledgement_pre_mining",
        "post_mining_pre_persistence",
        "post_persistence_pre_stage_commit",
        "worker_action_post_submit",
        "transient_retry_after_broadcast",
        "concurrent_retry",
    }
)
FINAL_REVISION_SOURCE_SHA256 = {
    "contracts/src/HyperlaneAdapter.sol": (
        "1ca91fb1cb8137d7b1cfb2ef5dc21ac95f45b22defea729f1535c73d33773f18"
    ),
    "contracts/src/LayerZeroAdapter.sol": (
        "042fbeeb00d93ce4ec077bbeeb944daed752c16f649460c5ee2df88218c53941"
    ),
    "src/xir_lab/native/deployer.py": (
        "788bf7f9d929a265da3a6e00dacca9b9b97913541b0cad9f49550addc6178653"
    ),
    "src/xir_lab/native/runner.py": (
        "02c43d51d3604c86ac9f4059684c443a03d98878f0ccb03a7be58b18238c4c1d"
    ),
}
FAULT_SOURCE_PATHS = (
    "configs/native/native-faults-v1.json",
    "configs/native/native-faults-v1-smoke.json",
    "schemas/native-faults-v1-config.schema.json",
    "schemas/native-faults-v1-case-result.schema.json",
    "schemas/native-faults-v1-summary.schema.json",
    "schemas/native-faults-v1-validation.schema.json",
    "schemas/native-faults-v1-handoff.schema.json",
    "src/xir_lab/native/faults_v1.py",
    "src/xir_lab/native/faults_handoff_v1.py",
    "src/xir_lab/native/faults_recovery_figure_v2.py",
    "scripts/run_native_faults_v1.py",
    "scripts/layerzero_worker_faults_v1.py",
    "scripts/analyze_native_faults_v1.py",
    "scripts/prepare_native_faults_v1_overlay.py",
    "scripts/render_native_faults_v1.py",
    "scripts/render_native_faults_recovery_v2.py",
    "scripts/build_native_faults_v1_handoff.py",
    "src/xir_lab/localnet/native_profile.py",
    "src/xir_lab/native/runner.py",
    "src/xir_lab/native/layerzero_worker.py",
    "src/xir_lab/native/root_signer.py",
    "src/xir_lab/native/xir_trace.py",
    "src/xir_lab/native/rpc.py",
    "scripts/native_stack_processes.sh",
    "scripts/layerzero_worker.py",
    "contracts/src/XIRGateway.sol",
    "contracts/src/XIREncoding.sol",
    "contracts/src/HyperlaneAdapter.sol",
    "contracts/src/LayerZeroAdapter.sol",
    "contracts/src/IXIRCarrierAdapter.sol",
    "contracts/src/native/NativeExperimentReceiver.sol",
    "contracts/src/native/NativeXIRTransitionRecorder.sol",
    "contracts/src/native/NativeRoutePayload.sol",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_immutable_text(path: Path, value: str) -> None:
    encoded = value.encode("utf-8")
    if path.exists():
        if path.read_bytes() != encoded:
            raise LocalTopologyError(
                f"native-faults-v1 refuses to overwrite changed evidence: {path}"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "hex"):
        return str(value.hex())
    return str(value)


def _canonical_transaction_hash(value: Any) -> str | None:
    """Return one representation for the same 32-byte transaction hash.

    Web3 RPC wrappers are inconsistent about whether ``HexBytes.hex()`` keeps
    the ``0x`` prefix.  Fault events use :func:`Web3.to_hex`, while the durable
    runner stores the result of ``HexBytes.hex()``.  Canonicalizing only valid
    32-byte hashes prevents that formatting difference from becoming a false
    lineage mismatch; malformed values remain visibly distinct.
    """

    if value is None:
        return None
    text = str(value).strip().lower()
    payload = text.removeprefix("0x")
    if len(payload) == 64 and all(character in "0123456789abcdef" for character in payload):
        return "0x" + payload
    return text


def final_revision_prior_verifier_bindings_valid(document: dict[str, Any]) -> bool:
    """Require both outbound adapters to bind each first-hop profile ingress."""

    try:
        intermediate = cast(dict[str, str], document["chains"]["intermediate"])
        expected = {
            outbound: {
                "H_AB": str(intermediate["h_in"]).lower(),
                "L_AB": str(intermediate["l_in"]).lower(),
            }
            for outbound in ("h_xir_out", "l_xir_out")
        }
    except (KeyError, TypeError):
        return False
    return document.get("prior_verifier_bindings") == expected


def final_revision_source_lock_valid(repository: Path) -> bool:
    """Match the exact administrator-bound implementation used by v2 evidence."""

    return all(
        (repository / relative).is_file() and _sha256(repository / relative) == expected
        for relative, expected in FINAL_REVISION_SOURCE_SHA256.items()
    )


def final_revision_deployment_contract_valid(document: dict[str, Any]) -> bool:
    """Reject pre-binding or combined runner/root-signer deployment manifests."""

    runner = str(document.get("runner", "")).lower()
    root_signer = str(document.get("root_signer", "")).lower()

    def address_pattern(value: str) -> bool:
        return (
            len(value) == 42
            and value.startswith("0x")
            and all(character in "0123456789abcdef" for character in value[2:])
        )

    return (
        document.get("schema_version") == "xir-lab-native-application-deployment-v1"
        and address_pattern(runner)
        and address_pattern(root_signer)
        and runner != root_signer
        and final_revision_prior_verifier_bindings_valid(document)
    )


def _validate_document(document: dict[str, Any], schema_name: str) -> None:
    schema = json.loads((_root() / "schemas" / schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise LocalTopologyError(f"{schema_name} validation failed at {location}: {first.message}")


def load_fault_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    document = json.loads(raw)
    schema = json.loads(
        (_root() / "schemas" / "native-faults-v1-config.schema.json").read_text(encoding="utf-8")
    )
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise LocalTopologyError(f"native-faults-v1 config error at {location}: {first.message}")
    scenarios = cast(list[dict[str, Any]], document["scenarios"])
    names = [str(item["name"]) for item in scenarios]
    if len(names) != len(set(names)):
        raise LocalTopologyError("native-faults-v1 scenario names must be unique")
    if document["campaign_id"] == "native-faults-v1-frozen":
        if set(names) != REQUIRED_SCENARIOS:
            raise LocalTopologyError("native-faults-v1 requires each frozen scenario once")
    elif not set(names).issubset(REQUIRED_SCENARIOS):
        raise LocalTopologyError("native-faults-v1 smoke contains an unknown scenario")
    for scenario in scenarios:
        actor = str(scenario["actor"])
        boundary = str(scenario["boundary"])
        if actor == "coordinator" and boundary not in COORDINATOR_BOUNDARIES:
            raise LocalTopologyError("coordinator scenario uses a worker-only boundary")
        if actor == "worker" and boundary not in WORKER_BOUNDARIES:
            raise LocalTopologyError("worker scenario uses a coordinator-only boundary")
        if actor == "worker" and not scenario.get("target_stage"):
            raise LocalTopologyError("worker scenario requires a target stage")
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def scenario_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in cast(list[dict[str, Any]], config["scenarios"])}


def fault_attempt(
    *,
    config: dict[str, Any],
    profile_path: Path,
    route: str,
    scenario_name: str,
    repetition: int,
) -> NativeAttempt:
    scenarios = [str(item["name"]) for item in cast(list[dict[str, Any]], config["scenarios"])]
    if route not in {"HL", "LH"} or scenario_name not in scenarios:
        raise LocalTopologyError("unknown native-faults-v1 route or scenario")
    repetitions = int(config["repetitions_per_route_scenario"])
    if not 0 <= repetition < repetitions:
        raise LocalTopologyError("native-faults-v1 repetition is outside the plan")
    sequence = scenarios.index(scenario_name) * repetitions + repetition
    material = f"{config['campaign_id']}:{route}:{scenario_name}:{repetition}".encode()
    payload = native_application_payload(
        profile_path=profile_path, phase="smoke", sequence=sequence
    )
    return NativeAttempt(
        attempt_id="fault_" + hashlib.sha256(material).hexdigest()[:32],
        phase="smoke",
        route=route,
        route_sequence=sequence,
        first_protocol="hyperlane" if route[0] == "H" else "layerzero-v2",
        second_protocol="hyperlane" if route[1] == "H" else "layerzero-v2",
        execution_class=f"native-faults-v1:{scenario_name}",
        xir=True,
        payload_bytes=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


class InjectedNativeFault(RuntimeError):
    """One-shot signal that terminates a controlled child process."""


class InjectedTransientFault(RequestException):
    """One-shot transport signal handled by the runner's normal retry loop."""


class FaultLedger:
    """Cross-process plan, fault-event, and recovery ledger."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path, timeout=60, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=60000;
            CREATE TABLE IF NOT EXISTS cases(
              case_key TEXT PRIMARY KEY,
              attempt_id TEXT NOT NULL UNIQUE,
              route TEXT NOT NULL,
              scenario TEXT NOT NULL,
              repetition INTEGER NOT NULL,
              actor TEXT NOT NULL,
              boundary TEXT NOT NULL,
              signal TEXT NOT NULL,
              target_stage TEXT NOT NULL,
              status TEXT NOT NULL,
              planned_json TEXT NOT NULL,
              before_json TEXT,
              result_json TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(route, scenario, repetition)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS events(
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_key TEXT NOT NULL REFERENCES cases(case_key),
              event_type TEXT NOT NULL,
              actor TEXT NOT NULL,
              boundary TEXT,
              stage TEXT,
              details_json TEXT NOT NULL,
              observed_at TEXT NOT NULL
            ) STRICT;
            """
        )
        self.connection.commit()

    @staticmethod
    def case_key(route: str, scenario: str, repetition: int) -> str:
        return f"{route}:{scenario}:{repetition:03d}"

    def ensure_case(
        self,
        *,
        attempt: NativeAttempt,
        scenario: dict[str, Any],
        repetition: int,
        coordinator_stage: str,
    ) -> str:
        key = self.case_key(attempt.route, str(scenario["name"]), repetition)
        target_stage = str(scenario.get("target_stage", coordinator_stage))
        planned = {
            "attempt": asdict(attempt),
            "scenario": scenario,
            "target_stage": target_stage,
        }
        with self.lock:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO cases(
                  case_key, attempt_id, route, scenario, repetition, actor,
                  boundary, signal, target_stage, status, planned_json,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?)
                """,
                (
                    key,
                    attempt.attempt_id,
                    attempt.route,
                    str(scenario["name"]),
                    repetition,
                    str(scenario["actor"]),
                    str(scenario["boundary"]),
                    str(scenario["signal"]),
                    target_stage,
                    json.dumps(planned, sort_keys=True),
                    _now(),
                    _now(),
                ),
            )
            row = self.connection.execute(
                "SELECT planned_json FROM cases WHERE case_key = ?", (key,)
            ).fetchone()
            if row is None or json.loads(row["planned_json"]) != planned:
                raise LocalTopologyError("native-faults-v1 case plan changed after creation")
            self.connection.commit()
        return key

    def set_before(self, case_key: str, snapshot: dict[str, Any]) -> None:
        with self.lock:
            current = self.connection.execute(
                "SELECT before_json FROM cases WHERE case_key = ?", (case_key,)
            ).fetchone()
            if current is None:
                raise LocalTopologyError("unknown native-faults-v1 case")
            encoded = json.dumps(snapshot, sort_keys=True)
            if current["before_json"] is not None and current["before_json"] != encoded:
                raise LocalTopologyError("native-faults-v1 before snapshot changed")
            self.connection.execute(
                "UPDATE cases SET before_json = ?, updated_at = ? WHERE case_key = ?",
                (encoded, _now(), case_key),
            )
            self.connection.commit()

    def arm(self, case_key: str) -> None:
        with self.lock:
            row = self.connection.execute(
                "SELECT status FROM cases WHERE case_key = ?", (case_key,)
            ).fetchone()
            if row is None:
                raise LocalTopologyError("cannot arm an unknown native-faults-v1 case")
            if str(row["status"]) in {"validated", "failed"}:
                return
            self.connection.execute(
                "UPDATE cases SET status='armed', updated_at=? WHERE case_key=?",
                (_now(), case_key),
            )
            self.connection.commit()

    def claim(
        self,
        *,
        actor: str,
        boundary: str,
        stage: str,
        details: dict[str, Any],
        attempt_id: str | None,
    ) -> dict[str, Any] | None:
        """Atomically claim one matching armed plan and persist the hit."""

        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            query = (
                "SELECT * FROM cases WHERE status='armed' AND actor=? "
                "AND boundary=? AND target_stage=?"
            )
            parameters: list[Any] = [actor, boundary, stage]
            if attempt_id is not None:
                query += " AND attempt_id=?"
                parameters.append(attempt_id)
            query += " ORDER BY case_key LIMIT 1"
            row = self.connection.execute(query, tuple(parameters)).fetchone()
            if row is None:
                self.connection.rollback()
                return None
            self.connection.execute(
                "UPDATE cases SET status='faulted', updated_at=? WHERE case_key=?",
                (_now(), str(row["case_key"])),
            )
            event_detail = {
                **_jsonable(details),
                "attempt_id": str(row["attempt_id"]),
                "scenario": str(row["scenario"]),
                "signal": str(row["signal"]),
            }
            self.connection.execute(
                """
                INSERT INTO events(
                  case_key, event_type, actor, boundary, stage, details_json,
                  observed_at
                ) VALUES (?, 'fault_injected', ?, ?, ?, ?, ?)
                """,
                (
                    str(row["case_key"]),
                    actor,
                    boundary,
                    stage,
                    json.dumps(event_detail, sort_keys=True),
                    _now(),
                ),
            )
            self.connection.commit()
            return dict(row)

    def record_event(
        self,
        case_key: str,
        event_type: str,
        *,
        actor: str,
        details: dict[str, Any],
        boundary: str | None = None,
        stage: str | None = None,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO events(
                  case_key, event_type, actor, boundary, stage, details_json,
                  observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_key,
                    event_type,
                    actor,
                    boundary,
                    stage,
                    json.dumps(_jsonable(details), sort_keys=True),
                    _now(),
                ),
            )
            self.connection.commit()

    def finish(self, case_key: str, result: dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                """
                UPDATE cases SET status=?, result_json=?, updated_at=?
                WHERE case_key=?
                """,
                (
                    "validated" if result["valid"] else "failed",
                    json.dumps(result, sort_keys=True),
                    _now(),
                    case_key,
                ),
            )
            self.connection.commit()

    def case(self, case_key: str) -> dict[str, Any]:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM cases WHERE case_key=?", (case_key,)
            ).fetchone()
        if row is None:
            raise LocalTopologyError("unknown native-faults-v1 case")
        return self._decode_case(row)

    def cases(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM cases ORDER BY route, scenario, repetition"
            ).fetchall()
        return [self._decode_case(row) for row in rows]

    def events(self, case_key: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM events WHERE case_key=? ORDER BY event_id", (case_key,)
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            output.append(item)
        return output

    @staticmethod
    def _decode_case(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["planned"] = json.loads(result.pop("planned_json"))
        result["before"] = (
            None if result["before_json"] is None else json.loads(result["before_json"])
        )
        result.pop("before_json")
        result["result"] = (
            None if result["result_json"] is None else json.loads(result["result_json"])
        )
        result.pop("result_json")
        return result


class FaultInjector:
    def __init__(
        self,
        *,
        ledger: FaultLedger,
        actor: str,
        attempt_id: str | None,
    ) -> None:
        self.ledger = ledger
        self.actor = actor
        self.attempt_id = attempt_id

    def hit(self, boundary: str, stage: str, details: dict[str, Any]) -> None:
        plan = self.ledger.claim(
            actor=self.actor,
            boundary=boundary,
            stage=stage,
            details=details,
            attempt_id=self.attempt_id,
        )
        if plan is None:
            return
        message = f"native-faults-v1 injected {plan['scenario']} at {boundary}:{stage}"
        if str(plan["signal"]) == "transient_retry":
            raise InjectedTransientFault(message)
        raise InjectedNativeFault(message)


class FaultingRunnerState:
    """Delegate RunnerState while adding intent/signing fault boundaries."""

    def __init__(self, state: RunnerState, injector: FaultInjector) -> None:
        self._state = state
        self._injector = injector

    def __getattr__(self, name: str) -> Any:
        return getattr(self._state, name)

    def record_stage(
        self,
        attempt_id: str,
        stage: str,
        state: str,
        detail: dict[str, Any],
        transaction_hash: str | None = None,
    ) -> None:
        context = {**_jsonable(detail), "transaction_hash": transaction_hash}
        if state == "intended":
            self._injector.hit("pre_intent", stage, context)
        self._state.record_stage(attempt_id, stage, state, detail, transaction_hash)
        if state == "intended":
            self._injector.hit("post_intent_pre_sign", stage, context)
        elif state == "signed":
            self._injector.hit("post_sign_pre_broadcast", stage, context)


class FaultInjectingNativeRunner(NativeExperimentRunner):
    """Native runner with isolated one-shot hooks around durable RPC boundaries."""

    def __init__(self, *, fault_ledger_path: Path, attempt_id: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.fault_ledger = FaultLedger(fault_ledger_path)
        self.fault_injector = FaultInjector(
            ledger=self.fault_ledger,
            actor="coordinator",
            attempt_id=attempt_id,
        )
        self.state = cast(Any, FaultingRunnerState(self.state, self.fault_injector))
        self._fault_context = threading.local()

    def _transact(self, **kwargs: Any) -> dict[str, Any]:
        attempt_id = str(kwargs["attempt_id"])
        stage = str(kwargs["stage"])
        role = str(kwargs["role"])
        client = self.clients[role]
        eth = client.eth
        original_send = eth.send_raw_transaction
        original_wait = eth.wait_for_transaction_receipt
        self._fault_context.value = (attempt_id, stage, role)

        def send_with_fault(raw: Any) -> Any:
            transaction_hash = original_send(raw)
            self.fault_injector.hit(
                "post_broadcast_pre_acknowledgement",
                stage,
                {
                    "role": role,
                    "transaction_hash": Web3.to_hex(transaction_hash).lower(),
                    "raw_sha256": hashlib.sha256(bytes(raw)).hexdigest(),
                },
            )
            return transaction_hash

        def wait_with_fault(transaction_hash: Any, *args: Any, **wait_kwargs: Any) -> Any:
            typed_hash = Web3.to_hex(transaction_hash).lower()
            self.fault_injector.hit(
                "post_acknowledgement_pre_mining",
                stage,
                {"role": role, "transaction_hash": typed_hash},
            )
            receipt = original_wait(transaction_hash, *args, **wait_kwargs)
            self.fault_injector.hit(
                "post_mining_pre_persistence",
                stage,
                {
                    "role": role,
                    "transaction_hash": typed_hash,
                    "block_number": int(receipt["blockNumber"]),
                    "status": int(receipt["status"]),
                },
            )
            return receipt

        eth.send_raw_transaction = send_with_fault  # type: ignore[assignment]
        eth.wait_for_transaction_receipt = wait_with_fault  # type: ignore[method-assign]
        try:
            return super()._transact(**kwargs)
        finally:
            eth.send_raw_transaction = original_send  # type: ignore[method-assign]
            eth.wait_for_transaction_receipt = original_wait  # type: ignore[method-assign]
            self._fault_context.value = None

    def _persist_receipt(
        self,
        *,
        transaction_hash: str,
        receipt: Any,
        detail: dict[str, Any],
    ) -> dict[str, Any]:
        result = super()._persist_receipt(
            transaction_hash=transaction_hash, receipt=receipt, detail=detail
        )
        context = getattr(self._fault_context, "value", None)
        if context is not None:
            _, stage, role = cast(tuple[str, str, str], context)
            self.fault_injector.hit(
                "post_persistence_pre_stage_commit",
                stage,
                {
                    "role": role,
                    "transaction_hash": transaction_hash.lower(),
                    "receipt": result.get("receipt"),
                    "receipt_sha256": result.get("receipt_sha256"),
                },
            )
        return result


class FaultingLayerZeroWorkerState:
    """Worker-state delegate that stops after a submitted action is durable."""

    def __init__(self, state: LayerZeroWorkerState, injector: FaultInjector) -> None:
        self._state = state
        self._injector = injector

    def __getattr__(self, name: str) -> Any:
        return getattr(self._state, name)

    def observe_action(self, action_id: str, state: str, details: dict[str, Any]) -> None:
        self._state.observe_action(action_id, state, details)
        if state != "submitted":
            return
        action = self._state.connection.execute(
            "SELECT * FROM actions WHERE action_id=?", (action_id,)
        ).fetchone()
        if action is None:
            raise LocalTopologyError("submitted LayerZero worker action disappeared")
        self._injector.hit(
            "worker_action_post_submit",
            str(action["stage"]),
            {
                "action_id": action_id,
                "guid": str(action["guid"]),
                "nonce": int(action["nonce"]),
                "transaction_hash": str(action["transaction_hash"]),
                "raw_sha256": hashlib.sha256(
                    bytes.fromhex(str(action["raw_transaction_hex"])[2:])
                ).hexdigest(),
                **_jsonable(details),
            },
        )


def receiver_snapshot(runner: NativeExperimentRunner, attempt: NativeAttempt) -> dict[str, Any]:
    receiver = runner._contract(
        "destination", "receiver", "NativeExperimentReceiver.sol", "NativeExperimentReceiver"
    )
    client = runner.clients["destination"]
    attempt_hash = keccak(text=attempt.attempt_id)
    return {
        "destination_block": int(client.eth.block_number),
        "delivery_count": int(receiver.functions.deliveryCount().call()),
        "attempt_consumed": bool(receiver.functions.consumedAttempts(attempt_hash).call()),
        "effect_state_hash": Web3.to_hex(receiver.functions.effectStateHash().call()),
    }


def _decoded_history(connection: sqlite3.Connection, attempt_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT history_id, stage, state, transaction_hash, detail_json, observed_at
        FROM stage_history WHERE attempt_id=? ORDER BY history_id
        """,
        (attempt_id,),
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["detail"] = json.loads(item.pop("detail_json"))
        result.append(item)
    return result


def concurrent_recovery_identity(
    *,
    attempt_id: str,
    completions: list[Any],
    injected_details: dict[str, Any],
    return_codes: list[Any],
    completed_batch_count: int,
) -> tuple[dict[str, Any], bool]:
    """Bind both recovery children to the exact injected signed transaction."""

    recovery_identities = [
        {
            "attempt_id": item.get("attempt_id"),
            "nonce": item.get("nonce"),
            "transaction_hash": _canonical_transaction_hash(item.get("transaction_hash")),
            "raw_sha256": item.get("raw_sha256"),
        }
        for item in completions
        if isinstance(item, dict)
    ]
    identity = {
        "recoveries": recovery_identities,
        "injected": {
            "attempt_id": attempt_id,
            "nonce": injected_details.get("nonce"),
            "transaction_hash": _canonical_transaction_hash(
                injected_details.get("transaction_hash")
            ),
            "raw_sha256": injected_details.get("raw_sha256"),
        },
    }
    valid = (
        completed_batch_count == 1
        and return_codes == [0, 0]
        and len(recovery_identities) == 2
        and recovery_identities[0] == recovery_identities[1]
        and recovery_identities[0] == identity["injected"]
    )
    return identity, valid


def reconcile_fault_case(
    *,
    runner: NativeExperimentRunner,
    ledger: FaultLedger,
    case_key: str,
    worker_state_path: Path,
) -> dict[str, Any]:
    case = ledger.case(case_key)
    attempt_data = cast(dict[str, Any], case["planned"]["attempt"])
    attempt = NativeAttempt(**attempt_data)
    connection = runner.state.connection
    attempt_row = connection.execute(
        "SELECT * FROM attempts WHERE attempt_id=?", (attempt.attempt_id,)
    ).fetchone()
    stage_row = connection.execute(
        "SELECT * FROM stages WHERE attempt_id=? AND stage='destination_deliver'",
        (attempt.attempt_id,),
    ).fetchone()
    history = _decoded_history(connection, attempt.attempt_id)
    delivery_history = [item for item in history if item["stage"] == "destination_deliver"]
    nonce_values = sorted(
        {int(item["detail"]["nonce"]) for item in delivery_history if "nonce" in item["detail"]}
    )
    transaction_hashes = sorted(
        {
            canonical
            for item in delivery_history
            if item["transaction_hash"] is not None
            if (canonical := _canonical_transaction_hash(item["transaction_hash"])) is not None
        }
    )
    raw_transaction_hashes = sorted(
        {
            str(item["detail"]["raw_sha256"]).lower()
            for item in delivery_history
            if item["detail"].get("raw_sha256") is not None
        }
    )
    events = ledger.events(case_key)
    injected = [item for item in events if item["event_type"] == "fault_injected"]
    child_exits = [item for item in events if item["event_type"] == "child_exit"]
    retry_errors = connection.execute(
        "SELECT * FROM attempt_errors WHERE attempt_id=? ORDER BY error_id",
        (attempt.attempt_id,),
    ).fetchall()

    before = cast(dict[str, Any], case["before"])
    after = receiver_snapshot(runner, attempt)
    receiver = runner._contract(
        "destination", "receiver", "NativeExperimentReceiver.sol", "NativeExperimentReceiver"
    )
    attempt_hash = keccak(text=attempt.attempt_id)
    event_logs = receiver.events.NativeEffectApplied().get_logs(
        from_block=int(before["destination_block"]),
        to_block=int(after["destination_block"]),
        argument_filters={"attemptId": attempt_hash},
    )

    gateway_consumed = False
    mid_hex: str | None = None
    if stage_row is not None:
        stage_detail = json.loads(stage_row["detail_json"])
        rid_hex = stage_detail.get("rid")
        if rid_hex:
            rid = bytes.fromhex(str(rid_hex).removeprefix("0x"))
            receiver_address = bytes.fromhex(str(receiver.address)[2:])
            mid = message_id(rid, (1, receiver_address))
            mid_hex = "0x" + mid.hex()
            gateway = runner._contract("destination", "gateway", "XIRGateway.sol", "XIRGateway")
            gateway_consumed = bool(gateway.functions.consumed(mid).call())

    worker_lineage: dict[str, Any] | None = None
    worker_valid = True
    if case["actor"] == "worker":
        dispatch_stage = (
            "second_protocol_dispatch" if attempt.route == "HL" else "first_protocol_dispatch"
        )
        dispatch = connection.execute(
            "SELECT detail_json FROM stages WHERE attempt_id=? AND stage=?",
            (attempt.attempt_id, dispatch_stage),
        ).fetchone()
        expected_guid = (
            None if dispatch is None else json.loads(dispatch["detail_json"]).get("evidence")
        )
        worker_connection = sqlite3.connect(worker_state_path)
        worker_connection.row_factory = sqlite3.Row
        actions = []
        if expected_guid is not None:
            actions = [
                {
                    **{
                        key: value
                        for key, value in dict(row).items()
                        if key != "raw_transaction_hex"
                    },
                    "raw_sha256": hashlib.sha256(
                        bytes.fromhex(str(row["raw_transaction_hex"])[2:])
                    ).hexdigest(),
                }
                for row in worker_connection.execute(
                    """
                    SELECT action_id, guid, stage, destination_chain_id, nonce,
                           target, calldata_sha256, raw_transaction_hex,
                           transaction_hash, status,
                           intended_at
                    FROM actions WHERE guid=? ORDER BY stage
                    """,
                    (expected_guid,),
                ).fetchall()
            ]
        worker_connection.close()
        injected_guid = injected[0]["details"].get("guid") if injected else None
        injected_action = injected[0]["details"].get("action_id") if injected else None
        matching_actions = [
            item
            for item in actions
            if item["stage"] == case["target_stage"] and item["action_id"] == injected_action
        ]
        worker_valid = (
            expected_guid is not None
            and injected_guid == expected_guid
            and len(actions) == 3
            and all(str(item["status"]) == "succeeded" for item in actions)
            and len(matching_actions) == 1
            and int(matching_actions[0]["nonce"]) == int(injected[0]["details"]["nonce"])
            and _canonical_transaction_hash(matching_actions[0]["transaction_hash"])
            == _canonical_transaction_hash(injected[0]["details"]["transaction_hash"])
            and str(matching_actions[0]["raw_sha256"]).lower()
            == str(injected[0]["details"]["raw_sha256"]).lower()
        )
        worker_lineage = {
            "expected_guid": expected_guid,
            "injected_guid": injected_guid,
            "actions": actions,
            "valid": worker_valid,
        }

    signal = str(case["signal"])
    crash_exit_count = sum(
        int(item["details"].get("return_code", 0)) == FAULT_EXIT_CODE for item in child_exits
    )
    expected_crashes = 0 if signal == "transient_retry" else 1
    transient_valid = len(retry_errors) >= 1 if signal == "transient_retry" else True
    concurrent_valid = True
    concurrent_identity: dict[str, Any] | None = None
    if signal == "concurrent_retry":
        completed_batches = [
            item for item in events if item["event_type"] == "concurrent_recovery_complete"
        ]
        completed_batch = completed_batches[-1] if completed_batches else None
        completions = (
            [] if completed_batch is None else completed_batch["details"].get("completions", [])
        )
        return_codes = (
            [] if completed_batch is None else completed_batch["details"].get("return_codes", [])
        )
        concurrent_identity, concurrent_valid = concurrent_recovery_identity(
            attempt_id=attempt.attempt_id,
            completions=completions,
            injected_details=injected[0]["details"] if injected else {},
            return_codes=return_codes,
            completed_batch_count=len(completed_batches),
        )

    injected_details = injected[0]["details"] if injected else {}
    injected_nonce = injected_details.get("nonce")
    fault_nonce_matches = (
        case["actor"] == "worker"
        or injected_nonce is None
        or (len(nonce_values) == 1 and int(injected_nonce) == nonce_values[0])
    )
    injected_transaction = injected_details.get("transaction_hash")
    fault_transaction_matches = (
        case["actor"] == "worker"
        or injected_transaction is None
        or (
            len(transaction_hashes) == 1
            and _canonical_transaction_hash(injected_transaction) == transaction_hashes[0]
        )
    )
    injected_raw_sha256 = injected_details.get("raw_sha256")
    fault_raw_matches = (
        case["actor"] == "worker"
        or injected_raw_sha256 is None
        or (
            len(raw_transaction_hashes) == 1
            and str(injected_raw_sha256).lower() == raw_transaction_hashes[0]
        )
    )

    checks = {
        "attempt_identity_stable": (
            attempt_row is not None
            and str(attempt_row["attempt_id"]) == attempt.attempt_id
            and str(attempt_row["status"]) == "succeeded"
        ),
        "one_fault_injected": len(injected) == 1,
        "expected_process_exit_count": crash_exit_count == expected_crashes,
        "destination_stage_succeeded": (
            stage_row is not None and str(stage_row["state"]) == "succeeded"
        ),
        "single_nonce_lineage": len(nonce_values) == 1,
        "single_transaction_lineage": len(transaction_hashes) == 1,
        "single_raw_transaction_lineage": len(raw_transaction_hashes) == 1,
        "fault_nonce_matches_recovery": fault_nonce_matches,
        "fault_transaction_matches_recovery": fault_transaction_matches,
        "fault_raw_matches_recovery": fault_raw_matches,
        "one_application_event": len(event_logs) == 1,
        "attempt_consumed_once": (
            not bool(before["attempt_consumed"]) and bool(after["attempt_consumed"])
        ),
        "gateway_consumed": gateway_consumed,
        "transient_retry_recorded": transient_valid,
        "concurrent_retries_joined": concurrent_valid,
        "worker_action_recovered": worker_valid,
    }
    result = {
        "schema_version": "xir-lab-native-faults-v1-case-result-v1",
        "case_key": case_key,
        "attempt_id": attempt.attempt_id,
        "route": attempt.route,
        "scenario": case["scenario"],
        "repetition": int(case["repetition"]),
        "actor": case["actor"],
        "boundary": case["boundary"],
        "signal": signal,
        "before": before,
        "after": after,
        "mid": mid_hex,
        "nonce_lineage": nonce_values,
        "transaction_lineage": transaction_hashes,
        "raw_transaction_lineage": raw_transaction_hashes,
        "stage_history": delivery_history,
        "fault_events": events,
        "retry_errors": [dict(row) for row in retry_errors],
        "application_event_transaction_hashes": [
            Web3.to_hex(log["transactionHash"]).lower() for log in event_logs
        ],
        "worker_lineage": worker_lineage,
        "concurrent_recovery_identity": concurrent_identity,
        "checks": checks,
        "valid": all(checks.values()),
    }
    ledger.finish(case_key, result)
    return result


def freeze_fault_results(
    *,
    ledger: FaultLedger,
    config_path: Path,
    deployment_path: Path,
    output_root: Path,
    environment: dict[str, Any],
) -> dict[str, Any]:
    """Write secret-free raw results, paper table, report, and verified manifest."""

    config, config_sha256 = load_fault_config(config_path)
    cases = ledger.cases()
    publish = output_root / "publish"
    raw = publish / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for case in cases:
        result = cast(dict[str, Any] | None, case["result"])
        if result is None:
            raise LocalTopologyError(f"native-faults-v1 case is unfinished: {case['case_key']}")
        _validate_document(result, "native-faults-v1-case-result.schema.json")
        results.append(result)
        _write_immutable_text(
            raw / f"{str(case['case_key']).replace(':', '__')}.json",
            json.dumps(result, indent=2, sort_keys=True) + "\n",
        )

    repetitions = int(config["repetitions_per_route_scenario"])
    expected = (
        len(cast(list[str], config["routes"]))
        * len(cast(list[Any], config["scenarios"]))
        * repetitions
    )
    groups: list[dict[str, Any]] = []
    for route in cast(list[str], config["routes"]):
        for scenario in cast(list[dict[str, Any]], config["scenarios"]):
            selected = [
                result
                for result in results
                if result["route"] == route and result["scenario"] == scenario["name"]
            ]
            groups.append(
                {
                    "route": route,
                    "scenario": scenario["name"],
                    "boundary": scenario["boundary"],
                    "repetitions": len(selected),
                    "validated": sum(bool(result["valid"]) for result in selected),
                    "faults_injected": sum(
                        len(
                            [
                                event
                                for event in result["fault_events"]
                                if event["event_type"] == "fault_injected"
                            ]
                        )
                        for result in selected
                    ),
                    "application_events": sum(
                        len(result["application_event_transaction_hashes"]) for result in selected
                    ),
                    "unique_tx_lineage": sum(
                        len(result["transaction_lineage"]) == 1 for result in selected
                    ),
                    "unique_raw_tx_lineage": sum(
                        len(result["raw_transaction_lineage"]) == 1 for result in selected
                    ),
                }
            )
    summary = {
        "schema_version": "xir-lab-native-faults-v1-summary-v1",
        "campaign_id": config["campaign_id"],
        "config_sha256": config_sha256,
        "deployment_sha256": _sha256(deployment_path),
        "expected_cases": expected,
        "observed_cases": len(results),
        "validated_cases": sum(bool(result["valid"]) for result in results),
        "failed_cases": sum(not bool(result["valid"]) for result in results),
        "groups": groups,
    }
    summary["valid"] = (
        summary["observed_cases"] == expected
        and summary["validated_cases"] == expected
        and summary["failed_cases"] == 0
        and all(
            group["repetitions"] == repetitions
            and group["validated"] == repetitions
            and group["faults_injected"] == repetitions
            and group["application_events"] == repetitions
            and group["unique_tx_lineage"] == repetitions
            and group["unique_raw_tx_lineage"] == repetitions
            for group in groups
        )
    )
    _validate_document(summary, "native-faults-v1-summary.schema.json")

    _write_immutable_text(
        publish / "case-results.json",
        json.dumps(results, indent=2, sort_keys=True) + "\n",
    )
    _write_immutable_text(
        publish / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    concurrent_results = [result for result in results if result["scenario"] == "concurrent_retry"]
    worker_results = [result for result in results if result["actor"] == "worker"]
    validation_counts = {
        "valid_results": sum(bool(result["valid"]) for result in results),
        "stable_logical_attempt_id": sum(
            bool(result["checks"]["attempt_identity_stable"]) for result in results
        ),
        "single_nonce_lineage": sum(len(result["nonce_lineage"]) == 1 for result in results),
        "single_transaction_lineage": sum(
            len(result["transaction_lineage"]) == 1 for result in results
        ),
        "single_raw_transaction_lineage": sum(
            len(result["raw_transaction_lineage"]) == 1 for result in results
        ),
        "one_destination_effect": sum(
            len(result["application_event_transaction_hashes"]) == 1 for result in results
        ),
        "concurrent_recovery_cases": len(concurrent_results),
        "concurrent_recovery_shared_signed_identity": sum(
            bool(result["checks"]["concurrent_retries_joined"]) for result in concurrent_results
        ),
        "worker_recovery_cases": len(worker_results),
        "worker_action_recovered": sum(
            bool(result["checks"]["worker_action_recovered"]) for result in worker_results
        ),
    }
    validation = {
        "schema_version": "xir-lab-native-faults-v1-validation-v1",
        "campaign_id": config["campaign_id"],
        "expected_cases": expected,
        "counts": validation_counts,
        "valid": summary["valid"]
        and validation_counts["valid_results"] == expected
        and validation_counts["stable_logical_attempt_id"] == expected
        and validation_counts["single_nonce_lineage"] == expected
        and validation_counts["single_transaction_lineage"] == expected
        and validation_counts["single_raw_transaction_lineage"] == expected
        and validation_counts["one_destination_effect"] == expected
        and validation_counts["concurrent_recovery_cases"]
        == validation_counts["concurrent_recovery_shared_signed_identity"]
        and validation_counts["worker_recovery_cases"]
        == validation_counts["worker_action_recovered"],
    }
    _validate_document(validation, "native-faults-v1-validation.schema.json")
    _write_immutable_text(
        publish / "validation.json",
        json.dumps(validation, indent=2, sort_keys=True) + "\n",
    )
    environment_document = {
        "schema_version": "xir-lab-native-faults-v1-environment-v1",
        **_jsonable(environment),
    }
    _write_immutable_text(
        publish / "environment.json",
        json.dumps(environment_document, indent=2, sort_keys=True) + "\n",
    )
    fields = (
        "route",
        "scenario",
        "boundary",
        "repetitions",
        "faults_injected",
        "unique_tx_lineage",
        "unique_raw_tx_lineage",
        "application_events",
        "validated",
    )
    csv_stream = io.StringIO(newline="")
    writer = csv.DictWriter(csv_stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows({field: group[field] for field in fields} for group in groups)
    _write_immutable_text(publish / "recovery-table.csv", csv_stream.getvalue())

    report = [
        "# Controlled native recovery experiment v1",
        "",
        f"The frozen matrix completed {summary['validated_cases']}/{expected} controlled cases.",
        "Each case injected one preregistered process-exit, transient-retry, or concurrent-recovery signal at a durable boundary and reused the same logical attempt and durable transaction state.",
        "Natural interruptions from the earlier long-running workload are excluded from these denominators.",
        "",
        "| Route | Scenario | Boundary | Cases | One tx lineage | One app effect | Valid |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for group in groups:
        report.append(
            f"| {group['route']} | {group['scenario']} | {group['boundary']} | "
            f"{group['repetitions']} | {group['unique_tx_lineage']} | "
            f"{group['application_events']} | {group['validated']} |"
        )
    report.extend(
        [
            "",
            "## Scope",
            "",
            "The campaign covers HL and LH routes on three local QBFT networks with self-hosted Hyperlane and LayerZero workers.",
            "It injects deterministic child-process and retry signals at registered durable boundaries; host power loss and network partition are outside this matrix.",
        ]
    )
    _write_immutable_text(publish / "REPORT.md", "\n".join(report) + "\n")

    secret_errors: list[str] = []
    forbidden_names = (".key", "private-signed", "mnemonic", "credential")
    for path in sorted(publish.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(publish)).lower()
        if any(token in relative for token in forbidden_names):
            secret_errors.append(f"forbidden filename: {relative}")
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        if "begin private key" in text or "private_key=" in text:
            secret_errors.append(f"private-key marker: {relative}")
    secret_scan = {
        "schema_version": "xir-lab-native-faults-v1-secret-scan-v1",
        "errors": secret_errors,
        "valid": not secret_errors,
    }
    _write_immutable_text(
        publish / "secret-scan.json",
        json.dumps(secret_scan, indent=2, sort_keys=True) + "\n",
    )

    excluded = {"manifest.json", "manifest.json.sha256", "manifest-verification.json"}
    files = []
    for path in sorted(publish.rglob("*")):
        if path.is_file() and path.name not in excluded:
            files.append(
                {
                    "path": str(path.relative_to(publish)),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
    manifest = {
        "schema_version": "xir-lab-native-faults-v1-manifest-v1",
        "campaign_id": config["campaign_id"],
        "files": files,
    }
    manifest_path = publish / "manifest.json"
    _write_immutable_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_sha256 = _sha256(manifest_path)
    _write_immutable_text(publish / "manifest.json.sha256", f"{manifest_sha256}  manifest.json\n")
    manifest_errors = []
    for item in files:
        path = publish / str(item["path"])
        if not path.is_file() or path.stat().st_size != cast(int, item["bytes"]):
            manifest_errors.append(f"missing or size mismatch: {item['path']}")
        elif _sha256(path) != item["sha256"]:
            manifest_errors.append(f"digest mismatch: {item['path']}")
    verification = {
        "schema_version": "xir-lab-native-faults-v1-manifest-verification-v1",
        "manifest_sha256": manifest_sha256,
        "file_count": len(files),
        "secret_scan_valid": secret_scan["valid"],
        "summary_valid": summary["valid"],
        "errors": manifest_errors,
        "valid": not manifest_errors and secret_scan["valid"] and summary["valid"],
    }
    _write_immutable_text(
        publish / "manifest-verification.json",
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
    )
    if not verification["valid"]:
        raise LocalTopologyError("native-faults-v1 publication validation failed")
    return {
        **summary,
        "manifest_sha256": manifest_sha256,
        "publish_root": str(publish),
    }


def git_identity(repository: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip() if completed.returncode == 0 else None
    source_files = [
        {
            "path": relative,
            "bytes": (repository / relative).stat().st_size,
            "sha256": _sha256(repository / relative),
        }
        for relative in FAULT_SOURCE_PATHS
    ]
    source_bundle = hashlib.sha256(
        json.dumps(source_files, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return {
        "repository_commit": commit,
        "repository_commit_available": commit is not None,
        "fault_source_files": source_files,
        "fault_source_bundle_sha256": source_bundle,
        "python": sys.version.split()[0],
        "generated_at": _now(),
    }
