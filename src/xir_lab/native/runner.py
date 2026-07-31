"""Resumable coordinator for HH, LL, HL-through-XIR, and LH-through-XIR."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.typed_transactions import TypedTransaction  # type: ignore[attr-defined]
from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]
from hexbytes import HexBytes
from requests import RequestException
from web3 import Web3
from web3.exceptions import Web3RPCError

from xir_lab.localnet.native_profile import (
    NativeAttempt,
    build_native_attempts,
    native_application_payload,
)
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import PROFILE_HASHES, ROUTE_IDS, gateway_typed_id
from xir_lab.native.layerzero import executor_lz_receive_options
from xir_lab.native.rpc import is_transient_rpc_error, qbft_web3
from xir_lab.native.xir_trace import (
    XIRContext,
    XIRReceipt,
    XIRRecord,
    next_prefix,
    receipt_tuple,
    record_tuple,
    root_id,
    root_prefix,
    transition_hash,
)


class RunnerState:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS attempts(
              attempt_id TEXT PRIMARY KEY,
              phase TEXT NOT NULL,
              route TEXT NOT NULL,
              route_sequence INTEGER NOT NULL,
              coordinates_json TEXT NOT NULL,
              status TEXT NOT NULL,
              started_at REAL NOT NULL,
              finished_at REAL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS stages(
              attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
              stage TEXT NOT NULL,
              state TEXT NOT NULL,
              transaction_hash TEXT,
              detail_json TEXT NOT NULL,
              observed_at REAL NOT NULL,
              PRIMARY KEY(attempt_id, stage)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS stage_history(
              history_id INTEGER PRIMARY KEY AUTOINCREMENT,
              attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
              stage TEXT NOT NULL,
              state TEXT NOT NULL,
              transaction_hash TEXT,
              detail_json TEXT NOT NULL,
              observed_at REAL NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS attempt_errors(
              error_id INTEGER PRIMARY KEY AUTOINCREMENT,
              attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
              error_class TEXT NOT NULL,
              error_message TEXT NOT NULL,
              retry_index INTEGER NOT NULL,
              observed_at REAL NOT NULL
            ) STRICT;
            """
        )
        self.connection.commit()

    def begin(self, attempt: NativeAttempt) -> bool:
        with self.lock:
            row = self.connection.execute(
                "SELECT status FROM attempts WHERE attempt_id = ?", (attempt.attempt_id,)
            ).fetchone()
            if row is not None:
                return str(row["status"]) != "succeeded"
            self.connection.execute(
                """
                INSERT INTO attempts(
                  attempt_id, phase, route, route_sequence, coordinates_json,
                  status, started_at
                ) VALUES (?, ?, ?, ?, ?, 'running', ?)
                """,
                (
                    attempt.attempt_id,
                    attempt.phase,
                    attempt.route,
                    attempt.route_sequence,
                    json.dumps(asdict(attempt), sort_keys=True),
                    time.time(),
                ),
            )
            self.connection.commit()
            return True

    def stage(self, attempt_id: str, stage: str) -> sqlite3.Row | None:
        with self.lock:
            return cast(
                sqlite3.Row | None,
                self.connection.execute(
                    "SELECT * FROM stages WHERE attempt_id = ? AND stage = ?",
                    (attempt_id, stage),
                ).fetchone(),
            )

    def record_stage(
        self,
        attempt_id: str,
        stage: str,
        state: str,
        detail: dict[str, Any],
        transaction_hash: str | None = None,
    ) -> None:
        with self.lock:
            observed_at = time.time()
            detail_json = json.dumps(detail, sort_keys=True)
            self.connection.execute(
                """
                INSERT INTO stage_history(
                  attempt_id, stage, state, transaction_hash, detail_json,
                  observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    stage,
                    state,
                    transaction_hash,
                    detail_json,
                    observed_at,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO stages(
                  attempt_id, stage, state, transaction_hash, detail_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(attempt_id, stage) DO UPDATE SET
                  state=excluded.state,
                  transaction_hash=excluded.transaction_hash,
                  detail_json=excluded.detail_json,
                  observed_at=excluded.observed_at
                """,
                (
                    attempt_id,
                    stage,
                    state,
                    transaction_hash,
                    detail_json,
                    observed_at,
                ),
            )
            self.connection.commit()

    def pending_signed_transactions(self) -> list[sqlite3.Row]:
        with self.lock:
            return list(
                self.connection.execute(
                    """
                    SELECT transaction_hash, detail_json
                    FROM stages
                    WHERE state='signed' AND transaction_hash IS NOT NULL
                    """
                ).fetchall()
            )

    def record_transient_error(
        self,
        attempt_id: str,
        error: BaseException,
        retry_index: int,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO attempt_errors(
                  attempt_id, error_class, error_message, retry_index, observed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    type(error).__name__,
                    str(error),
                    retry_index,
                    time.time(),
                ),
            )
            self.connection.commit()

    def finish(self, attempt_id: str) -> None:
        with self.lock:
            self.connection.execute(
                "UPDATE attempts SET status='succeeded', finished_at=? WHERE attempt_id=?",
                (time.time(), attempt_id),
            )
            self.connection.commit()

    def next_reserved_root_nonce(self) -> int:
        with self.lock:
            row = self.connection.execute(
                """
                SELECT MAX(CAST(json_extract(detail_json, '$.record_nonce') AS INTEGER))
                  AS maximum
                FROM stages
                WHERE stage = 'xir_root_record'
                """
            ).fetchone()
            if row is None or row["maximum"] is None:
                return 0
            return int(row["maximum"]) + 1


class NativeExperimentRunner:
    def __init__(
        self,
        *,
        repository_root: Path,
        runtime_root: Path,
        profile_path: Path,
        deployment_path: Path,
        private_key: str,
        state_path: Path,
        raw_root: Path,
        timeout_seconds: int = 300,
        concurrency: int = 16,
        batch_attempts: int = 256,
        submission_stop_file: Path | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.runtime_root = runtime_root
        self.profile_path = profile_path
        self.profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
        self.contracts = cast(dict[str, dict[str, str]], self.deployment["chains"])
        self.account = Account.from_key(private_key)
        self.private_key = private_key
        self.state = RunnerState(state_path)
        self.raw_root = raw_root
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self.signed_root = state_path.parent / "private-signed-transactions"
        self.signed_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.signed_root, 0o700)
        self.timeout_seconds = timeout_seconds
        if concurrency <= 0 or batch_attempts < concurrency:
            raise LocalTopologyError("native runner concurrency/batch limits are invalid")
        self.concurrency = concurrency
        self.batch_attempts = batch_attempts
        self.submission_stop_file = submission_stop_file
        self.chain_by_role = {
            str(chain["route_role"]): chain for chain in self.profile["chains"]
        }
        self.clients = {
            role: qbft_web3(str(chain["rpc_url"]))
            for role, chain in self.chain_by_role.items()
        }
        self.nonces = {
            role: int(client.eth.get_transaction_count(self.account.address, "pending"))
            for role, client in self.clients.items()
        }
        role_by_chain_id = {
            int(chain["chain_id"]): role
            for role, chain in self.chain_by_role.items()
        }
        for pending in self.state.pending_signed_transactions():
            transaction_hash = str(pending["transaction_hash"])
            raw_path = self.signed_root / f"{transaction_hash}.raw"
            if not raw_path.is_file():
                continue
            raw = raw_path.read_bytes()
            if Account.recover_transaction(raw).lower() != self.account.address.lower():
                raise LocalTopologyError(
                    "pending signed native transaction has an unexpected signer"
                )
            decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            role = role_by_chain_id.get(int(decoded["chainId"]))
            if role is None:
                raise LocalTopologyError(
                    "pending signed native transaction has an unexpected chain"
                )
            self.nonces[role] = max(
                self.nonces[role], int(decoded["nonce"]) + 1
            )
        self.nonce_locks = {role: threading.Lock() for role in self.clients}
        self.xir_nonce_lock = threading.Lock()
        self.xir_nonce_next: int | None = None
        self.artifact_root = repository_root / "contracts" / "out"
        self.options = executor_lz_receive_options(1_500_000)

    def _artifact(self, source: str, contract: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(
                (self.artifact_root / source / f"{contract}.json").read_text(
                    encoding="utf-8"
                )
            ),
        )

    def _contract(self, role: str, manifest_role: str, source: str, contract: str) -> Any:
        artifact = self._artifact(source, contract)
        return self.clients[role].eth.contract(
            address=Web3.to_checksum_address(self.contracts[role][manifest_role]),
            abi=artifact["abi"],
        )

    def _persist_receipt(
        self,
        *,
        transaction_hash: str,
        receipt: Any,
        detail: dict[str, Any],
    ) -> dict[str, Any]:
        receipt_document = cast(
            dict[str, Any], json.loads(Web3.to_json(cast(dict[Any, Any], receipt)))
        )
        receipt_path = self.raw_root / f"{transaction_hash}.json"
        receipt_path.write_text(
            json.dumps(receipt_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            **detail,
            "receipt": str(receipt_path),
            "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "gas_used": int(receipt["gasUsed"]),
            "block_number": int(receipt["blockNumber"]),
        }

    def _transact(
        self,
        *,
        attempt_id: str,
        stage: str,
        role: str,
        function: Any,
        value: int = 0,
        detail: dict[str, Any] | None = None,
        preallocated_nonce: int | None = None,
    ) -> dict[str, Any]:
        existing = self.state.stage(attempt_id, stage)
        client = self.clients[role]
        if existing is not None and str(existing["state"]) == "succeeded":
            existing_detail = cast(
                dict[str, Any], json.loads(existing["detail_json"])
            )
            existing_hash = existing["transaction_hash"]
            if existing_hash and "receipt" not in existing_detail:
                existing_receipt = client.eth.get_transaction_receipt(
                    HexStr(str(existing_hash))
                )
                if int(existing_receipt["status"]) != 1:
                    raise LocalTopologyError(
                        f"previous native route transaction reverted: {stage}"
                    )
                existing_detail = self._persist_receipt(
                    transaction_hash=str(existing_hash),
                    receipt=existing_receipt,
                    detail=existing_detail,
                )
                self.state.record_stage(
                    attempt_id,
                    stage,
                    "succeeded",
                    existing_detail,
                    str(existing_hash),
                )
            return existing_detail
        retry_lineage: list[dict[str, Any]] = []
        if existing is not None and existing["transaction_hash"]:
            prior_hash = str(existing["transaction_hash"])
            prior_hash_typed = HexStr(prior_hash)
            prior_detail = cast(
                dict[str, Any], json.loads(existing["detail_json"])
            )
            retry_lineage = list(prior_detail.get("retry_lineage", []))
            try:
                prior_receipt = client.eth.get_transaction_receipt(prior_hash_typed)
            except Exception:  # Web3 providers use different not-found exception classes.
                raw_path = self.signed_root / f"{prior_hash}.raw"
                if raw_path.is_file():
                    raw = raw_path.read_bytes()
                    decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
                    transaction_nonce = int(decoded["nonce"])
                    wait_for_prior = True
                    try:
                        client.eth.send_raw_transaction(raw)
                    except (ValueError, Web3RPCError) as exc:
                        message = str(exc).lower()
                        known = (
                            "already known" in message
                            or "known transaction" in message
                        )
                        nonce_consumed = (
                            "nonce too low" in message
                            and int(
                                client.eth.get_transaction_count(
                                    self.account.address, "latest"
                                )
                            )
                            > transaction_nonce
                        )
                        if nonce_consumed:
                            retry_lineage.append(
                                {
                                    "prior_transaction_hash": prior_hash,
                                    "prior_transaction_nonce": transaction_nonce,
                                    "resolution": "superseded_by_mined_nonce",
                                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                                }
                            )
                            self.state.record_stage(
                                attempt_id,
                                stage,
                                "superseded",
                                {
                                    **prior_detail,
                                    "retry_count": len(retry_lineage),
                                    "retry_lineage": retry_lineage,
                                },
                                prior_hash,
                            )
                            wait_for_prior = False
                        elif not known:
                            raise
                    if wait_for_prior:
                        prior_receipt = client.eth.wait_for_transaction_receipt(
                            prior_hash_typed, timeout=self.timeout_seconds
                        )
                    else:
                        prior_receipt = None
                else:
                    prior_receipt = None
            if prior_receipt is not None:
                if int(prior_receipt["status"]) != 1:
                    raise LocalTopologyError(
                        f"previous native route transaction reverted: {stage}"
                    )
                prior_detail = self._persist_receipt(
                    transaction_hash=prior_hash,
                    receipt=prior_receipt,
                    detail=prior_detail,
                )
                self.state.record_stage(
                    attempt_id, stage, "succeeded", prior_detail, prior_hash
                )
                return prior_detail
        if preallocated_nonce is None:
            with self.nonce_locks[role]:
                nonce = self.nonces[role]
                self.nonces[role] += 1
        else:
            nonce = preallocated_nonce
        built = cast(
            dict[str, Any],
            function.build_transaction(
                {
                    "from": self.account.address,
                    "value": value,
                    "chainId": int(self.chain_by_role[role]["chain_id"]),
                    "nonce": nonce,
                    "maxFeePerGas": max(int(client.eth.gas_price) * 2, 1),
                    "maxPriorityFeePerGas": 0,
                    "type": 2,
                    "gas": 8_000_000,
                }
            ),
        )
        call_data = bytes.fromhex(str(built["data"])[2:])
        intended = {
            "role": role,
            "nonce": nonce,
            "target": str(built["to"]).lower(),
            "calldata_sha256": hashlib.sha256(call_data).hexdigest(),
            **(detail or {}),
            "transaction_nonce": nonce,
            "retry_count": len(retry_lineage),
            "retry_lineage": retry_lineage,
        }
        self.state.record_stage(attempt_id, stage, "intended", intended)
        signed = self.account.sign_transaction(built)
        raw = bytes(signed.raw_transaction)
        raw_path = self.signed_root / f"{signed.hash.hex()}.raw"
        raw_path.write_bytes(raw)
        os.chmod(raw_path, 0o600)
        self.state.record_stage(
            attempt_id,
            stage,
            "signed",
            {
                **intended,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            },
            signed.hash.hex(),
        )
        tx_hash = client.eth.send_raw_transaction(raw)
        receipt = client.eth.wait_for_transaction_receipt(
            tx_hash, timeout=self.timeout_seconds
        )
        if int(receipt["status"]) != 1:
            failed_detail = self._persist_receipt(
                transaction_hash=tx_hash.hex(),
                receipt=receipt,
                detail=intended,
            )
            self.state.record_stage(
                attempt_id,
                stage,
                "failed",
                failed_detail,
                tx_hash.hex(),
            )
            raise LocalTopologyError(f"native route transaction reverted: {stage}")
        result = self._persist_receipt(
            transaction_hash=tx_hash.hex(),
            receipt=receipt,
            detail=intended,
        )
        self.state.record_stage(
            attempt_id, stage, "succeeded", result, tx_hash.hex()
        )
        return result

    def _wait_verify(
        self,
        *,
        role: str,
        adapter_role: str,
        protocol: str,
        profile_hash: bytes,
        evidence_hash: bytes,
        transition: bytes,
    ) -> None:
        source = "HyperlaneAdapter.sol" if protocol == "H" else "LayerZeroAdapter.sol"
        contract = "HyperlaneAdapter" if protocol == "H" else "LayerZeroAdapter"
        adapter = self._contract(role, adapter_role, source, contract)
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            if adapter.functions.verify(profile_hash, evidence_hash, transition).call():
                return
            time.sleep(0.5)
        raise LocalTopologyError(
            f"timed out waiting for {protocol} evidence at {role}:{adapter_role}"
        )

    def _layerzero_guid_from_stage(self, result: dict[str, Any]) -> bytes:
        receipt = json.loads(Path(result["receipt"]).read_text(encoding="utf-8"))
        topic = (
            "0x"
            + keccak(
                text="VerifiedEvidenceForwarded(bytes32,uint64,uint256)"
            ).hex()
        ).lower()
        for log in receipt["logs"]:
            topics = log.get("topics", [])
            if topics and str(topics[0]).lower() == topic and len(topics) >= 2:
                return bytes.fromhex(str(topics[1]).removeprefix("0x"))
        raise LocalTopologyError(
            "LayerZero adapter receipt lacks VerifiedEvidenceForwarded"
        )

    def run_phase(self, phase: str) -> None:
        attempts = build_native_attempts(
            profile_path=self.profile_path, phase=cast(Any, phase)
        )
        for offset in range(0, len(attempts), self.batch_attempts):
            if (
                self.submission_stop_file is not None
                and self.submission_stop_file.exists()
            ):
                raise LocalTopologyError(
                    "native submissions stopped by the resource monitor: "
                    f"{self.submission_stop_file}"
                )
            batch = attempts[offset : offset + self.batch_attempts]
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = [
                    pool.submit(self._run_if_needed, attempt) for attempt in batch
                ]
                for future in futures:
                    future.result()

    def _run_if_needed(self, attempt: NativeAttempt) -> None:
        if not self.state.begin(attempt):
            return
        transient_retry = 0
        transient_deadline: float | None = None
        while True:
            try:
                self.run_attempt(attempt)
                self.state.finish(attempt.attempt_id)
                return
            except (RequestException, Web3RPCError) as exc:
                if not is_transient_rpc_error(exc):
                    raise
                transient_retry += 1
                self.state.record_transient_error(
                    attempt.attempt_id, exc, transient_retry
                )
                if transient_deadline is None:
                    transient_deadline = time.monotonic() + self.timeout_seconds
                if time.monotonic() >= transient_deadline:
                    raise
                time.sleep(0.5)

    def run_attempt(self, attempt: NativeAttempt) -> None:
        application_payload = native_application_payload(
            profile_path=self.profile_path,
            phase=attempt.phase,
            sequence=attempt.route_sequence,
        )
        attempt_bytes32 = keccak(text=attempt.attempt_id)
        route_bytes = attempt.route.encode("ascii")
        payload = encode(
            ["(bytes32,bytes2,uint64,bytes)"],
            [(attempt_bytes32, route_bytes, attempt.route_sequence, application_payload)],
        )
        if not attempt.xir:
            self._run_homogeneous(attempt, payload)
            return
        self._run_heterogeneous(attempt, payload)

    def _run_homogeneous(self, attempt: NativeAttempt, payload: bytes) -> None:
        protocol = attempt.route[0]
        adapter_role = f"{protocol.lower()}_source"
        source_name = (
            "HyperlaneAdapter.sol" if protocol == "H" else "LayerZeroAdapter.sol"
        )
        contract_name = "HyperlaneAdapter" if protocol == "H" else "LayerZeroAdapter"
        adapter = self._contract("source", adapter_role, source_name, contract_name)
        options = b"" if protocol == "H" else self.options
        fee = int(
            adapter.functions.quoteBaseline(
                ROUTE_IDS[attempt.route], payload, options
            ).call()
        )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="source_dispatch",
            role="source",
            function=adapter.functions.sendBaselineSource(
                ROUTE_IDS[attempt.route], payload, options
            ),
            value=fee,
            detail={"protocol": protocol, "native_fee": fee},
        )
        receiver = self._contract(
            "destination",
            "receiver",
            "NativeExperimentReceiver.sol",
            "NativeExperimentReceiver",
        )
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            if receiver.functions.consumedAttempts(keccak(text=attempt.attempt_id)).call():
                self.state.record_stage(
                    attempt.attempt_id,
                    "destination_effect",
                    "succeeded",
                    {"receiver": receiver.address},
                )
                return
            time.sleep(0.5)
        raise LocalTopologyError("timed out waiting for homogeneous destination effect")

    def _run_heterogeneous(self, attempt: NativeAttempt, payload: bytes) -> None:
        source_id = gateway_typed_id(int(self.chain_by_role["source"]["chain_id"]))
        intermediate_id = gateway_typed_id(
            int(self.chain_by_role["intermediate"]["chain_id"])
        )
        destination_id = gateway_typed_id(
            int(self.chain_by_role["destination"]["chain_id"])
        )
        receiver_address = self.contracts["destination"]["receiver"]
        root_stage = self.state.stage(attempt.attempt_id, "xir_root_record")
        if root_stage is not None:
            source_gateway_nonce = int(
                json.loads(root_stage["detail_json"])["record_nonce"]
            )
            root_transaction_nonce = None
        else:
            source_gateway_nonce, root_transaction_nonce = (
                self._reserve_root_nonces()
            )
        record = XIRRecord(
            source_gateway=source_id,
            source_app=(1, bytes.fromhex(self.account.address[2:])),
            destination_app=(1, bytes.fromhex(receiver_address[2:])),
            nonce=source_gateway_nonce,
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
        rid = root_id(record, context, 1)
        signature = bytes(
            Account.sign_message(
                encode_defunct(primitive=rid), private_key=self.private_key
            ).signature
        )
        self._create_record(
            attempt,
            record,
            context,
            payload,
            preallocated_nonce=root_transaction_nonce,
        )
        first = attempt.route[0]
        second = attempt.route[1]
        first_profile = PROFILE_HASHES[f"{first}_AB"]
        second_profile = PROFILE_HASHES[f"{second}_BC"]
        transition_one = transition_hash(record, context, source_id, intermediate_id)
        evidence_one = self._dispatch_first_xir(
            attempt, first, first_profile, transition_one
        )
        self._wait_verify(
            role="intermediate",
            adapter_role=f"{first.lower()}_in",
            protocol=first,
            profile_hash=first_profile,
            evidence_hash=evidence_one,
            transition=transition_one,
        )
        receipt_one = XIRReceipt(
            source_id,
            intermediate_id,
            first_profile,
            evidence_one,
            transition_one,
            root_prefix(rid),
        )
        envelope_one = (
            record_tuple(record),
            (context.required_security, context.policy_hash),
            (1, signature),
            [receipt_tuple(receipt_one)],
        )
        recorder = self._contract(
            "intermediate",
            "xir_transition_recorder",
            "NativeXIRTransitionRecorder.sol",
            "NativeXIRTransitionRecorder",
        )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="xir_transition",
            role="intermediate",
            function=recorder.functions.record(payload, envelope_one, second_profile),
            detail={"outbound_profile": "0x" + second_profile.hex()},
        )
        transition_two = transition_hash(
            record, context, intermediate_id, destination_id
        )
        evidence_two = self._dispatch_second_xir(
            attempt,
            second,
            first_profile,
            evidence_one,
            transition_one,
            second_profile,
            transition_two,
        )
        destination_adapter = f"{second.lower()}_xir_in"
        self._wait_verify(
            role="destination",
            adapter_role=destination_adapter,
            protocol=second,
            profile_hash=first_profile,
            evidence_hash=evidence_one,
            transition=transition_one,
        )
        self._wait_verify(
            role="destination",
            adapter_role=destination_adapter,
            protocol=second,
            profile_hash=second_profile,
            evidence_hash=evidence_two,
            transition=transition_two,
        )
        receipt_two = XIRReceipt(
            intermediate_id,
            destination_id,
            second_profile,
            evidence_two,
            transition_two,
            next_prefix(receipt_one),
        )
        envelope_two = (
            record_tuple(record),
            (context.required_security, context.policy_hash),
            (1, signature),
            [receipt_tuple(receipt_one), receipt_tuple(receipt_two)],
        )
        gateway = self._contract(
            "destination", "gateway", "XIRGateway.sol", "XIRGateway"
        )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="destination_deliver",
            role="destination",
            function=gateway.functions.deliver(
                envelope_two, payload, receiver_address
            ),
            detail={
                "rid": "0x" + rid.hex(),
                "receipt_count": 2,
                "xir_transition_count": 1,
            },
        )

    def _reserve_root_nonces(self) -> tuple[int, int]:
        with self.xir_nonce_lock:
            if self.xir_nonce_next is None:
                gateway = self._contract(
                    "source", "gateway", "XIRGateway.sol", "XIRGateway"
                )
                self.xir_nonce_next = int(
                    gateway.functions.nextNonce(self.account.address).call()
                )
                self.xir_nonce_next = max(
                    self.xir_nonce_next, self.state.next_reserved_root_nonce()
                )
            value = self.xir_nonce_next
            self.xir_nonce_next += 1
            with self.nonce_locks["source"]:
                transaction_nonce = self.nonces["source"]
                self.nonces["source"] += 1
            return value, transaction_nonce

    def _create_record(
        self,
        attempt: NativeAttempt,
        record: XIRRecord,
        context: XIRContext,
        payload: bytes,
        preallocated_nonce: int | None,
    ) -> None:
        gateway = self._contract(
            "source", "gateway", "XIRGateway.sol", "XIRGateway"
        )
        completed = self.state.stage(attempt.attempt_id, "xir_root_record")
        if completed is None or str(completed["state"]) != "succeeded":
            current_nonce = int(
                gateway.functions.nextNonce(self.account.address).call()
            )
            if current_nonce == record.nonce:
                preview = gateway.functions.createRecord(
                    record.destination_app,
                    payload,
                    (context.required_security, context.policy_hash),
                    1,
                ).call({"from": self.account.address})
                expected_rid = root_id(record, context, 1)
                if bytes(preview[1]) != expected_rid:
                    raise LocalTopologyError(
                        "XIR root preview differs from recomputation"
                    )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="xir_root_record",
            role="source",
            function=gateway.functions.createRecord(
                record.destination_app,
                payload,
                (context.required_security, context.policy_hash),
                1,
            ),
            detail={
                "record_nonce": record.nonce,
                "record_payload_hash": "0x" + record.payload_hash.hex(),
            },
            preallocated_nonce=preallocated_nonce,
        )

    def _dispatch_first_xir(
        self,
        attempt: NativeAttempt,
        protocol: str,
        profile: bytes,
        transition: bytes,
    ) -> bytes:
        completed = self.state.stage(attempt.attempt_id, "first_protocol_dispatch")
        if completed is not None and str(completed["state"]) == "succeeded":
            completed_detail = cast(
                dict[str, Any], json.loads(completed["detail_json"])
            )
            if "evidence" in completed_detail:
                return bytes.fromhex(
                    str(completed_detail["evidence"]).removeprefix("0x")
                )
        adapter_role = f"{protocol.lower()}_source"
        if protocol == "H":
            evidence = keccak(
                b"XIR_NATIVE_FIRST_HYPERLANE_EVIDENCE_V1"
                + keccak(text=attempt.attempt_id)
            )
            adapter = self._contract(
                "source", adapter_role, "HyperlaneAdapter.sol", "HyperlaneAdapter"
            )
            body = encode(["bytes32", "bytes32", "bytes32"], [profile, transition, evidence])
            fee = int(adapter.functions.quote(body).call())
            self._transact(
                attempt_id=attempt.attempt_id,
                stage="first_protocol_dispatch",
                role="source",
                function=adapter.functions.sendSource(body),
                value=fee,
                detail={"evidence": "0x" + evidence.hex(), "native_fee": fee},
            )
            return evidence
        adapter = self._contract(
            "source", adapter_role, "LayerZeroAdapter.sol", "LayerZeroAdapter"
        )
        request: Any = ([], [], [], [], profile, transition, self.options)
        quote = adapter.functions.quoteForward(request).call()
        result = self._transact(
            attempt_id=attempt.attempt_id,
            stage="first_protocol_dispatch",
            role="source",
            function=adapter.functions.sendSource(request),
            value=int(quote[0]),
            detail={"native_fee": int(quote[0])},
        )
        evidence = self._layerzero_guid_from_stage(result)
        current = self.state.stage(attempt.attempt_id, "first_protocol_dispatch")
        self.state.record_stage(
            attempt.attempt_id,
            "first_protocol_dispatch",
            "succeeded",
            {**result, "evidence": "0x" + evidence.hex()},
            None if current is None else str(current["transaction_hash"]),
        )
        return evidence

    def _dispatch_second_xir(
        self,
        attempt: NativeAttempt,
        protocol: str,
        prior_profile: bytes,
        prior_evidence: bytes,
        prior_transition: bytes,
        current_profile: bytes,
        current_transition: bytes,
    ) -> bytes:
        completed = self.state.stage(attempt.attempt_id, "second_protocol_dispatch")
        if completed is not None and str(completed["state"]) == "succeeded":
            completed_detail = cast(
                dict[str, Any], json.loads(completed["detail_json"])
            )
            if "evidence" in completed_detail:
                return bytes.fromhex(
                    str(completed_detail["evidence"]).removeprefix("0x")
                )
        adapter_role = f"{protocol.lower()}_xir_out"
        verifier = self.contracts["intermediate"][f"{attempt.route[0].lower()}_in"]
        if protocol == "L":
            adapter = self._contract(
                "intermediate",
                adapter_role,
                "LayerZeroAdapter.sol",
                "LayerZeroAdapter",
            )
            layerzero_request = (
                [verifier],
                [prior_profile],
                [prior_evidence],
                [prior_transition],
                current_profile,
                current_transition,
                self.options,
            )
            quote = adapter.functions.quoteForward(layerzero_request).call()
            result = self._transact(
                attempt_id=attempt.attempt_id,
                stage="second_protocol_dispatch",
                role="intermediate",
                function=adapter.functions.sendSource(layerzero_request),
                value=int(quote[0]),
                detail={"native_fee": int(quote[0])},
            )
            evidence = self._layerzero_guid_from_stage(result)
            current = self.state.stage(
                attempt.attempt_id, "second_protocol_dispatch"
            )
            self.state.record_stage(
                attempt.attempt_id,
                "second_protocol_dispatch",
                "succeeded",
                {**result, "evidence": "0x" + evidence.hex()},
                None if current is None else str(current["transaction_hash"]),
            )
            return evidence
        adapter = self._contract(
            "intermediate",
            adapter_role,
            "HyperlaneAdapter.sol",
            "HyperlaneAdapter",
        )
        hyperlane_request = (
            [verifier],
            [prior_profile],
            [prior_evidence],
            [prior_transition],
            current_profile,
            current_transition,
        )
        inner = encode(
            ["(bytes32,bytes32,bytes32[],bytes32[],bytes32[])"],
            [
                (
                    current_profile,
                    current_transition,
                    [prior_profile],
                    [prior_evidence],
                    [prior_transition],
                )
            ],
        )
        body = encode(["uint8", "bytes"], [3, inner])
        sender = bytes.fromhex(
            "00" * 12 + self.contracts["intermediate"][adapter_role][2:]
        )
        evidence = keccak(
            encode(
                ["uint32", "bytes32", "bytes"],
                [
                    int(self.chain_by_role["intermediate"]["hyperlane_domain"]),
                    sender,
                    body,
                ],
            )
        )
        fee = int(adapter.functions.quoteBundle(hyperlane_request).call())
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="second_protocol_dispatch",
            role="intermediate",
            function=adapter.functions.sendSourceBundle(hyperlane_request),
            value=fee,
            detail={"evidence": "0x" + evidence.hex(), "native_fee": fee},
        )
        return evidence
