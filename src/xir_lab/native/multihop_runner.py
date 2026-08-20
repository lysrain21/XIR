"""Durable generalized runner for the five-chain multihop switching campaign."""

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

import rfc8785
from eth_abi.abi import encode
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction  # type: ignore[attr-defined]
from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]
from hexbytes import HexBytes
from requests import RequestException
from web3 import Web3
from web3.exceptions import Web3RPCError

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import executor_lz_receive_options
from xir_lab.native.multihop_deployer import (
    CHAIN_ROLES,
    REGISTRY_VERSION,
    adapter_key,
    multihop_gateway_typed_id,
    multihop_profile_hash,
)
from xir_lab.native.multihop_execution import heartbeat_writer_lease
from xir_lab.native.multihop_identity import DEPLOYMENT_NAMESPACE
from xir_lab.native.multihop_preflight import verify_multihop_preflight_document
from xir_lab.native.multihop_process_identity import current_process_identity
from xir_lab.native.multihop_scalability import (
    MultihopAttempt,
    MultihopPhase,
    iter_multihop_attempts,
    load_multihop_config,
    load_multihop_plan,
)
from xir_lab.native.root_signer import FinalizedRootSigner, Web3RootCreationSource
from xir_lab.native.rpc import is_transient_rpc_error, qbft_web3
from xir_lab.native.runner import RunnerState
from xir_lab.native.xir_trace import (
    XIRContext,
    XIRReceipt,
    XIRRecord,
    message_id,
    next_prefix,
    receipt_tuple,
    record_tuple,
    root_id,
    root_prefix,
    transition_hash,
)

MULTIHOP_EFFECT_TOPIC = (
    "0x"
    + keccak(
        text=(
            "NativeMultihopEffectApplied(bytes32,bytes32,uint64,bytes,bytes32,"
            "bytes32,bytes32,bytes32,uint256)"
        )
    ).hex()
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_transaction_hash(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x")


def _write_private_raw_durably(path: Path, raw: bytes) -> None:
    """Materialize one private raw file durably from its committed SQLite row."""

    if path.exists():
        if path.read_bytes() != raw:
            raise LocalTopologyError("multihop durable raw path contains different bytes")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise LocalTopologyError("host boot identity is unavailable") from exc
    if not value:
        raise LocalTopologyError("host boot identity is empty")
    return value


class MultihopRunnerState(RunnerState):
    """Runner state with dual-clock stage/event evidence."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.boot_id = _boot_id()
        runtime_root = Path(os.environ.get("XIR_LOCAL_RUNTIME_ROOT", str(path.parent)))
        self.process_identity = current_process_identity(runtime_root=runtime_root)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events(
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
              stage TEXT NOT NULL,
              event TEXT NOT NULL,
              source TEXT NOT NULL,
              chain_role TEXT,
              hop_index INTEGER,
              transaction_hash TEXT,
              utc_ns INTEGER NOT NULL,
              monotonic_ns INTEGER NOT NULL,
              boot_id TEXT NOT NULL,
              process_id INTEGER NOT NULL,
              process_identity_sha256 TEXT,
              thread_id INTEGER NOT NULL,
              detail_json TEXT NOT NULL
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS events_unique_boundary
              ON events(attempt_id, stage, event, source);
            CREATE TABLE IF NOT EXISTS phase_authority(
              singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
              authority_json TEXT NOT NULL,
              semantic_sha256 TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS durable_signed_transactions(
              attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
              stage TEXT NOT NULL,
              transaction_hash TEXT NOT NULL UNIQUE,
              raw_transaction BLOB NOT NULL,
              raw_sha256 TEXT NOT NULL,
              detail_json TEXT NOT NULL,
              PRIMARY KEY(attempt_id, stage)
            ) STRICT;
            """
        )
        event_columns = {
            str(row[1]) for row in self.connection.execute("PRAGMA table_info(events)")
        }
        if "process_identity_sha256" not in event_columns:
            self.connection.execute("ALTER TABLE events ADD COLUMN process_identity_sha256 TEXT")
        self.connection.commit()

    def bind_phase_authority(self, authority: dict[str, Any]) -> None:
        payload = dict(authority)
        expected = str(payload.pop("semantic_sha256", ""))
        observed = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
        if expected != observed:
            raise LocalTopologyError("phase authority semantic digest is invalid")
        authority_json = json.dumps(authority, sort_keys=True, separators=(",", ":"))
        with self.lock:
            row = self.connection.execute(
                "SELECT authority_json,semantic_sha256 FROM phase_authority WHERE singleton=1"
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO phase_authority VALUES(1,?,?)",
                    (authority_json, expected),
                )
                self.connection.commit()
            elif row["authority_json"] != authority_json or row["semantic_sha256"] != expected:
                raise LocalTopologyError("phase authority differs from durable runner state")

    def record_event(
        self,
        *,
        attempt_id: str,
        stage: str,
        event: str,
        source: str,
        detail: dict[str, Any],
        chain_role: str | None = None,
        hop_index: int | None = None,
        transaction_hash: str | None = None,
    ) -> None:
        public_detail = dict(detail)
        public_detail["_process_identity"] = self.process_identity
        with self.lock:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO events(
                  attempt_id, stage, event, source, chain_role, hop_index,
                  transaction_hash, utc_ns, monotonic_ns, boot_id, process_id,
                  process_identity_sha256, thread_id, detail_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    stage,
                    event,
                    source,
                    chain_role,
                    hop_index,
                    transaction_hash,
                    time.time_ns(),
                    time.monotonic_ns(),
                    self.boot_id,
                    os.getpid(),
                    self.process_identity["identity_sha256"],
                    threading.get_ident(),
                    json.dumps(public_detail, sort_keys=True),
                ),
            )
            self.connection.commit()

    def begin(self, attempt: NativeAttempt | MultihopAttempt) -> bool:
        """Resume only when the durable multihop coordinate is byte-exact."""

        with self.lock:
            row = self.connection.execute(
                """
                SELECT phase,route,route_sequence,coordinates_json,status
                FROM attempts WHERE attempt_id = ?
                """,
                (attempt.attempt_id,),
            ).fetchone()
            if row is not None:
                expected_coordinates = json.dumps(asdict(attempt), sort_keys=True)
                if (
                    str(row["phase"]) != attempt.phase
                    or str(row["route"]) != attempt.route
                    or int(row["route_sequence"]) != attempt.route_sequence
                    or str(row["coordinates_json"]) != expected_coordinates
                ):
                    raise LocalTopologyError(
                        "durable multihop attempt coordinates differ from the frozen plan"
                    )
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

    def record_stage(
        self,
        attempt_id: str,
        stage: str,
        state: str,
        detail: dict[str, Any],
        transaction_hash: str | None = None,
    ) -> None:
        with self.lock:
            self._insert_stage_and_event(
                attempt_id=attempt_id,
                stage=stage,
                state=state,
                detail=detail,
                transaction_hash=transaction_hash,
                update_current=True,
            )
            self.connection.commit()

    def _insert_stage_and_event(
        self,
        *,
        attempt_id: str,
        stage: str,
        state: str,
        detail: dict[str, Any],
        transaction_hash: str | None,
        update_current: bool,
    ) -> None:
        observed_at = time.time()
        utc_ns = time.time_ns()
        monotonic_ns = time.monotonic_ns()
        detail_json = json.dumps(detail, sort_keys=True)
        event_detail = dict(detail)
        event_detail["_process_identity"] = self.process_identity
        event_detail_json = json.dumps(event_detail, sort_keys=True)
        self.connection.execute(
            """
            INSERT INTO stage_history(
              attempt_id, stage, state, transaction_hash, detail_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (attempt_id, stage, state, transaction_hash, detail_json, observed_at),
        )
        if update_current:
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
                (attempt_id, stage, state, transaction_hash, detail_json, observed_at),
            )
        self.connection.execute(
            """
            INSERT OR IGNORE INTO events(
              attempt_id, stage, event, source, chain_role, hop_index,
              transaction_hash, utc_ns, monotonic_ns, boot_id, process_id,
              process_identity_sha256, thread_id, detail_json
            ) VALUES (?, ?, ?, 'coordinator', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                stage,
                state,
                cast(str | None, detail.get("role")),
                cast(int | None, detail.get("hop_index")),
                transaction_hash,
                utc_ns,
                monotonic_ns,
                self.boot_id,
                os.getpid(),
                self.process_identity["identity_sha256"],
                threading.get_ident(),
                event_detail_json,
            ),
        )

    def record_durable_signed_stage(
        self,
        *,
        attempt_id: str,
        stage: str,
        intended_detail: dict[str, Any],
        signed_detail: dict[str, Any],
        transaction_hash: str,
        raw_transaction: bytes,
    ) -> None:
        """Atomically bind raw bytes, transaction identity, intent, and events."""

        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute(
                    """
                    INSERT INTO durable_signed_transactions(
                      attempt_id,stage,transaction_hash,raw_transaction,raw_sha256,detail_json
                    ) VALUES (?,?,?,?,?,?)
                    """,
                    (
                        attempt_id,
                        stage,
                        transaction_hash,
                        raw_transaction,
                        hashlib.sha256(raw_transaction).hexdigest(),
                        json.dumps(signed_detail, sort_keys=True),
                    ),
                )
                self._insert_stage_and_event(
                    attempt_id=attempt_id,
                    stage=stage,
                    state="intended",
                    detail=intended_detail,
                    transaction_hash=None,
                    update_current=False,
                )
                self._insert_stage_and_event(
                    attempt_id=attempt_id,
                    stage=stage,
                    state="signed",
                    detail=signed_detail,
                    transaction_hash=transaction_hash,
                    update_current=True,
                )
                self.connection.commit()
            except sqlite3.Error:
                self.connection.rollback()
                raise

    def durable_signed_transaction(self, attempt_id: str, stage: str) -> sqlite3.Row | None:
        with self.lock:
            return cast(
                sqlite3.Row | None,
                self.connection.execute(
                    """
                    SELECT * FROM durable_signed_transactions
                    WHERE attempt_id=? AND stage=?
                    """,
                    (attempt_id, stage),
                ).fetchone(),
            )

    def pending_signed_transactions(self) -> list[sqlite3.Row]:
        """Return every pending stage with its DB-authoritative signed bytes."""

        with self.lock:
            return list(
                self.connection.execute(
                    """
                    SELECT s.attempt_id,s.stage,s.transaction_hash,s.detail_json,
                           d.raw_transaction,d.raw_sha256
                    FROM stages s
                    JOIN durable_signed_transactions d
                      ON d.attempt_id=s.attempt_id AND d.stage=s.stage
                    WHERE s.state='signed' AND s.transaction_hash IS NOT NULL
                    ORDER BY s.attempt_id,s.stage
                    """
                ).fetchall()
            )

    def next_reserved_root_nonce(self) -> int:
        """Return the next nonce reserved by this versioned runner schema."""

        with self.lock:
            row = self.connection.execute(
                """
                SELECT MAX(CAST(json_extract(detail_json, '$.record_nonce') AS INTEGER))
                  AS maximum
                FROM stages
                WHERE stage = 'root_create'
                """
            ).fetchone()
            if row is None or row["maximum"] is None:
                return 0
            return int(row["maximum"]) + 1


class NativeMultihopRunner:
    """Execute all routes through XIR receipts, including homogeneous routes."""

    def __init__(
        self,
        *,
        repository_root: Path,
        workspace_root: Path,
        runtime_root: Path,
        topology_path: Path,
        identity_path: Path,
        config_path: Path,
        plan_path: Path,
        deployment_path: Path,
        private_key: str,
        root_signer_private_key: str,
        state_path: Path,
        raw_root: Path,
        preflight_path: Path,
        review_gate_path: Path,
        phase_authority_path: Path,
        execution_authority: dict[str, Any],
        preregistration_path: Path,
        lease_path: Path,
        lease_token_path: Path,
        timeout_seconds: int = 300,
        concurrency: int | None = None,
        batch_attempts: int = 176,
        submission_stop_file: Path | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.runtime_root = runtime_root
        self.config_path = config_path
        self.config, self.config_sha256 = load_multihop_config(config_path)
        self.plan_path = plan_path
        self.plan: dict[str, Any] | None = None
        self.profile = json.loads(
            (repository_root / cast(str, self.config["profile"])).read_text(encoding="utf-8")
        )
        self.deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
        self.preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
        preflight_authority = verify_multihop_preflight_document(
            workspace_root=workspace_root,
            repository_root=repository_root,
            runtime_root=runtime_root,
            topology_path=topology_path,
            identity_path=identity_path,
            config_path=config_path,
            deployment_path=deployment_path,
            preregistration_path=preregistration_path,
            review_gate_path=review_gate_path,
            preflight_path=preflight_path,
            validator_volume_attestation_path=(
                runtime_root / "provenance/validator-volume-bootstrap.json"
            ),
            validator_volume_journal_path=(
                runtime_root / "provenance/validator-volume-transaction.json"
            ),
        )
        if preflight_authority["review_closure_sha256"] != execution_authority.get(
            "review_closure_sha256"
        ):
            raise LocalTopologyError("multihop runner preflight/review authority mismatch")
        self.execution_authority = {**execution_authority, **preflight_authority}
        self.preregistration_path = preregistration_path
        self.lease_path = lease_path
        self.lease_token_path = lease_token_path
        if self.deployment.get("namespace") != DEPLOYMENT_NAMESPACE:
            raise LocalTopologyError("multihop runner rejects another deployment namespace")
        self.contracts = cast(dict[str, dict[str, str]], self.deployment["chains"])
        self.account = Account.from_key(private_key)
        self.private_key = private_key
        self.root_signer_private_key = root_signer_private_key
        if self.account.address.lower() != str(self.deployment["runner"]).lower():
            raise LocalTopologyError("multihop runner key differs from deployment")
        root_account = Account.from_key(root_signer_private_key)
        if root_account.address.lower() != str(self.deployment["root_signer"]).lower():
            raise LocalTopologyError("multihop root-signer key differs from deployment")
        if root_account.address.lower() == self.account.address.lower():
            raise LocalTopologyError("multihop runner and root signer must be distinct")
        self.state = MultihopRunnerState(state_path)
        self.phase_authority = json.loads(phase_authority_path.read_text(encoding="utf-8"))
        expected_authority = {
            "review_gate_sha256": self.execution_authority["review_gate_sha256"],
            "review_closure_sha256": self.execution_authority["review_closure_sha256"],
            "lease_identity_sha256": self.execution_authority["lease_identity_sha256"],
            "lease_identity": self.execution_authority["lease_identity"],
            "preflight_sha256": self.execution_authority["preflight_sha256"],
            "preflight_semantic_sha256": self.execution_authority["preflight_semantic_sha256"],
            "validator_volume_attestation_sha256": self.preflight[
                "validator_volume_attestation_sha256"
            ],
            "validator_volume_attestation_semantic_sha256": self.preflight[
                "validator_volume_attestation_semantic_sha256"
            ],
            "validator_volume_journal_sha256": self.preflight["validator_volume_journal_sha256"],
            "validator_volume_journal_semantic_sha256": self.preflight[
                "validator_volume_journal_semantic_sha256"
            ],
            "toolchain_preflight_sha256": self.preflight["toolchain_preflight_sha256"],
            "toolchain_preflight_semantic_sha256": self.preflight[
                "toolchain_preflight_semantic_sha256"
            ],
            "config_sha256": _sha(config_path),
            "plan_sha256": _sha(plan_path),
            "deployment_sha256": _sha(deployment_path),
            "preregistration_sha256": _sha(preregistration_path),
        }
        if any(self.phase_authority.get(key) != value for key, value in expected_authority.items()):
            raise LocalTopologyError("phase authority input identities are invalid")
        self.state.bind_phase_authority(self.phase_authority)
        self.raw_root = raw_root
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self.signed_root = state_path.parent / "private-signed-transactions"
        self.signed_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.signed_root, 0o700)
        self.timeout_seconds = timeout_seconds
        configured_concurrency = int(self.config["concurrency"])
        self.concurrency = configured_concurrency if concurrency is None else concurrency
        if self.concurrency <= 0 or batch_attempts < self.concurrency:
            raise LocalTopologyError("multihop runner concurrency/batch limits are invalid")
        self.batch_attempts = batch_attempts
        self.submission_stop_file = submission_stop_file
        chains = cast(list[dict[str, Any]], self.profile["chains"])
        self.chain_by_role = {role: chain for role, chain in zip(CHAIN_ROLES, chains, strict=True)}
        self.clients = {
            role: qbft_web3(cast(str, chain["rpc_url"]))
            for role, chain in self.chain_by_role.items()
        }
        self.nonces = {
            role: int(client.eth.get_transaction_count(self.account.address, "pending"))
            for role, client in self.clients.items()
        }
        role_by_chain_id = {
            int(chain["chain_id"]): role for role, chain in self.chain_by_role.items()
        }
        for pending in self.state.pending_signed_transactions():
            transaction_hash = _canonical_transaction_hash(str(pending["transaction_hash"]))
            raw_path = self.signed_root / f"{transaction_hash}.raw"
            raw = bytes(pending["raw_transaction"])
            if hashlib.sha256(raw).hexdigest() != str(pending["raw_sha256"]):
                raise LocalTopologyError("pending multihop transaction DB raw digest differs")
            _write_private_raw_durably(raw_path, raw)
            detail = cast(dict[str, Any], json.loads(pending["detail_json"]))
            role = cast(str, detail.get("role"))
            self._validate_durable_raw(
                raw=raw,
                transaction_hash=transaction_hash,
                detail=detail,
                role=role,
            )
            decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            if role_by_chain_id.get(int(decoded["chainId"])) != role:
                raise LocalTopologyError("pending multihop transaction role differs from chain")
            self.nonces[role] = max(self.nonces[role], int(decoded["nonce"]) + 1)
        self.nonce_locks = {role: threading.Lock() for role in CHAIN_ROLES}
        self.xir_nonce_lock = threading.Lock()
        self.xir_nonce_next: int | None = None
        self.artifact_root = repository_root / "contracts" / "out"
        self.options = executor_lz_receive_options(1_500_000)
        source_gateway = self._contract("a", "gateway", "XIRGateway.sol", "XIRGateway")
        self.root_signer = FinalizedRootSigner(
            source=Web3RootCreationSource(self.clients["a"], source_gateway),
            private_key=root_signer_private_key,
            audit_path=state_path.parent / "root-signer-audit.jsonl",
        )

    def _validate_durable_raw(
        self,
        *,
        raw: bytes,
        transaction_hash: str,
        detail: dict[str, Any],
        role: str,
    ) -> None:
        if role not in self.chain_by_role:
            raise LocalTopologyError("multihop durable transaction has unknown chain role")
        decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        decoded_target = "0x" + bytes(decoded["to"]).hex()
        decoded_data = bytes(decoded["data"])
        observed_hash = _canonical_transaction_hash(Web3.keccak(raw).hex())
        expected_hash = _canonical_transaction_hash(transaction_hash)
        if (
            hashlib.sha256(raw).hexdigest() != detail.get("raw_sha256")
            or observed_hash != expected_hash
            or Account.recover_transaction(raw).lower() != self.account.address.lower()
            or int(decoded["chainId"]) != int(self.chain_by_role[role]["chain_id"])
            or int(decoded["nonce"]) != int(detail.get("nonce", -1))
            or decoded_target.lower() != str(detail.get("target", "")).lower()
            or hashlib.sha256(decoded_data).hexdigest() != str(detail.get("calldata_sha256", ""))
        ):
            raise LocalTopologyError("multihop durable raw transaction identity drift")

    def _artifact(self, source: str, contract: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(
                (self.artifact_root / source / f"{contract}.json").read_text(encoding="utf-8")
            ),
        )

    def _contract(self, role: str, manifest_role: str, source: str, contract: str) -> Any:
        artifact = self._artifact(source, contract)
        return self.clients[role].eth.contract(
            address=Web3.to_checksum_address(self.contracts[role][manifest_role]),
            abi=artifact["abi"],
        )

    def _persist_receipt(
        self, *, transaction_hash: str, receipt: Any, detail: dict[str, Any]
    ) -> dict[str, Any]:
        document = cast(dict[str, Any], json.loads(Web3.to_json(cast(dict[Any, Any], receipt))))
        path = self.raw_root / f"{transaction_hash}.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        transaction = self.clients[cast(str, detail["role"])].eth.get_transaction(
            HexStr(transaction_hash)
        )
        calldata = bytes(transaction["input"])
        return {
            **detail,
            "receipt": str(path),
            "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "gas_used": int(receipt["gasUsed"]),
            "block_number": int(receipt["blockNumber"]),
            "calldata_bytes": len(calldata),
            "calldata_sha256": hashlib.sha256(calldata).hexdigest(),
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
            return cast(dict[str, Any], json.loads(existing["detail_json"]))
        if existing is not None and existing["transaction_hash"]:
            prior_hash = _canonical_transaction_hash(str(existing["transaction_hash"]))
            raw_path = self.signed_root / f"{prior_hash}.raw"
            durable = self.state.durable_signed_transaction(attempt_id, stage)
            if durable is not None:
                raw = bytes(durable["raw_transaction"])
                if hashlib.sha256(raw).hexdigest() != str(durable["raw_sha256"]):
                    raise LocalTopologyError("durable signed multihop DB raw digest differs")
                _write_private_raw_durably(raw_path, raw)
                prior = cast(dict[str, Any], json.loads(existing["detail_json"]))
                self._validate_durable_raw(
                    raw=raw,
                    transaction_hash=prior_hash,
                    detail=prior,
                    role=role,
                )
                try:
                    client.eth.send_raw_transaction(raw)
                except (ValueError, Web3RPCError) as exc:
                    if not any(
                        token in str(exc).lower()
                        for token in ("already known", "known transaction", "nonce too low")
                    ):
                        raise
                receipt = client.eth.wait_for_transaction_receipt(
                    HexStr(prior_hash), timeout=self.timeout_seconds
                )
                if int(receipt["status"]) != 1:
                    raise LocalTopologyError(f"durable multihop transaction reverted: {stage}")
                result = self._persist_receipt(
                    transaction_hash=prior_hash, receipt=receipt, detail=prior
                )
                self.state.record_stage(attempt_id, stage, "succeeded", result, prior_hash)
                return result
            raise LocalTopologyError("durable signed multihop transaction DB row is missing")
        if existing is not None and str(existing["state"]) == "intended":
            raise LocalTopologyError(
                "durable intended multihop stage lacks immutable signed transaction"
            )
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
                    "gas": 12_000_000,
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
        }
        signed = self.account.sign_transaction(built)
        raw = bytes(signed.raw_transaction)
        transaction_hash = _canonical_transaction_hash(signed.hash.hex())
        signed_detail = {**intended, "raw_sha256": hashlib.sha256(raw).hexdigest()}
        self._validate_durable_raw(
            raw=raw,
            transaction_hash=transaction_hash,
            detail=signed_detail,
            role=role,
        )
        self.state.record_durable_signed_stage(
            attempt_id=attempt_id,
            stage=stage,
            intended_detail=intended,
            signed_detail=signed_detail,
            transaction_hash=transaction_hash,
            raw_transaction=raw,
        )
        raw_path = self.signed_root / f"{transaction_hash}.raw"
        _write_private_raw_durably(raw_path, raw)
        tx_hash = client.eth.send_raw_transaction(raw)
        receipt = client.eth.wait_for_transaction_receipt(tx_hash, timeout=self.timeout_seconds)
        result = self._persist_receipt(
            transaction_hash=tx_hash.hex(), receipt=receipt, detail=signed_detail
        )
        if int(receipt["status"]) != 1:
            self.state.record_stage(attempt_id, stage, "failed", result, tx_hash.hex())
            raise LocalTopologyError(f"multihop transaction reverted: {stage}")
        self.state.record_stage(attempt_id, stage, "succeeded", result, tx_hash.hex())
        return result

    def run_phase(self, phase: MultihopPhase) -> None:
        if self.phase_authority.get("phase") != phase:
            raise LocalTopologyError("phase authority differs from requested phase")
        self.plan, _ = load_multihop_plan(
            path=self.plan_path, config_path=self.config_path, phase=phase
        )
        attempts = iter_multihop_attempts(config_path=self.config_path, phase=phase)
        batch: list[MultihopAttempt] = []
        for attempt in attempts:
            batch.append(attempt)
            if len(batch) == self.batch_attempts:
                self._run_batch(batch)
                batch = []
        if batch:
            self._run_batch(batch)

    def _run_batch(self, attempts: list[MultihopAttempt]) -> None:
        heartbeat_writer_lease(
            lease_path=self.lease_path,
            token_path=self.lease_token_path,
            runtime_root=self.runtime_root,
            preregistration_path=self.preregistration_path,
        )
        self._raise_if_submissions_stopped()
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._run_if_needed, attempt) for attempt in attempts]
            for future in futures:
                future.result()

    def _run_if_needed(self, attempt: MultihopAttempt) -> None:
        if not self.state.begin(attempt):
            return
        retry = 0
        deadline: float | None = None
        while True:
            try:
                self.run_attempt(attempt)
                self.state.finish(attempt.attempt_id)
                return
            except (RequestException, Web3RPCError) as exc:
                if not is_transient_rpc_error(exc):
                    raise
                retry += 1
                self.state.record_transient_error(attempt.attempt_id, exc, retry)
                if deadline is None:
                    deadline = time.monotonic() + self.timeout_seconds
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    def run_attempt(self, attempt: MultihopAttempt) -> None:
        payload = self._application_payload(attempt)
        destination_role = CHAIN_ROLES[len(attempt.route)]
        receiver_address = self.contracts[destination_role]["receiver"]
        record, context, rid, signature = self._root(attempt, payload, receiver_address)
        receipts: list[XIRReceipt] = []
        for hop_index, protocol in enumerate(attempt.route, start=1):
            source_role = CHAIN_ROLES[hop_index - 1]
            destination_role = CHAIN_ROLES[hop_index]
            profile = multihop_profile_hash(attempt.route, hop_index)
            source_id = multihop_gateway_typed_id(int(self.chain_by_role[source_role]["chain_id"]))
            destination_id = multihop_gateway_typed_id(
                int(self.chain_by_role[destination_role]["chain_id"])
            )
            transition = transition_hash(record, context, source_id, destination_id)
            evidence = self._dispatch_hop(
                attempt=attempt,
                hop_index=hop_index,
                protocol=protocol,
                source_role=source_role,
                destination_role=destination_role,
                current_profile=profile,
                current_transition=transition,
                prior_receipts=receipts,
            )
            self._wait_bundle(
                attempt=attempt,
                hop_index=hop_index,
                protocol=protocol,
                destination_role=destination_role,
                current_profile=profile,
                current_evidence=evidence,
                current_transition=transition,
                prior_receipts=receipts,
            )
            prior_prefix = root_prefix(rid) if not receipts else next_prefix(receipts[-1])
            receipts.append(
                XIRReceipt(
                    source_id,
                    destination_id,
                    profile,
                    evidence,
                    transition,
                    prior_prefix,
                )
            )
            envelope = self._envelope(record, context, signature, receipts)
            if hop_index < len(attempt.route) and protocol != attempt.route[hop_index]:
                recorder = self._contract(
                    destination_role,
                    "transition_recorder",
                    "NativeMultihopTransitionRecorder.sol",
                    "NativeMultihopTransitionRecorder",
                )
                next_profile = multihop_profile_hash(attempt.route, hop_index + 1)
                self._transact(
                    attempt_id=attempt.attempt_id,
                    stage=f"hop_{hop_index + 1}_xir_transition",
                    role=destination_role,
                    function=recorder.functions.record(payload, envelope, hop_index, next_profile),
                    detail={
                        "hop_index": hop_index + 1,
                        "verified_receipt_count": len(receipts),
                        "outbound_profile": "0x" + next_profile.hex(),
                    },
                )
        final_envelope = self._envelope(record, context, signature, receipts)
        gateway = self._contract(destination_role, "gateway", "XIRGateway.sol", "XIRGateway")
        delivery = self._transact(
            attempt_id=attempt.attempt_id,
            stage="destination_verify_deliver",
            role=destination_role,
            function=gateway.functions.deliver(final_envelope, payload, receiver_address),
            detail={
                "hop_index": len(attempt.route),
                "receipt_count": len(receipts),
                "switch_count": attempt.switch_count,
                "rid": "0x" + rid.hex(),
            },
        )
        receiver = self._contract(
            destination_role,
            "receiver",
            "NativeMultihopReceiver.sol",
            "NativeMultihopReceiver",
        )
        attempt_key = keccak(text=attempt.attempt_id)
        if not receiver.functions.consumedAttempts(attempt_key).call():
            raise LocalTopologyError("multihop destination effect is not visible")
        expected_mid = message_id(rid, record.destination_app)
        delivery_receipt = cast(
            dict[str, Any],
            json.loads(Path(str(delivery["receipt"])).read_text(encoding="utf-8")),
        )
        effect_logs = [
            log
            for log in cast(list[dict[str, Any]], delivery_receipt["logs"])
            if str(log["address"]).lower() == receiver.address.lower()
            and cast(list[str], log.get("topics", []))
            and str(cast(list[str], log["topics"])[0]).lower() == MULTIHOP_EFFECT_TOPIC.lower()
        ]
        if len(effect_logs) != 1:
            raise LocalTopologyError(
                "multihop destination transaction lacks exactly one effect event"
            )
        effect_topics = cast(list[str], effect_logs[0]["topics"])
        if (
            len(effect_topics) != 4
            or effect_topics[1].lower() != "0x" + attempt_key.hex()
            or effect_topics[2].lower() != "0x" + expected_mid.hex()
            or int(effect_topics[3], 16) != attempt.route_sequence
        ):
            raise LocalTopologyError("multihop destination effect event differs from attempt")
        delivery_stage = self.state.stage(attempt.attempt_id, "destination_verify_deliver")
        if delivery_stage is None or not delivery_stage["transaction_hash"]:
            raise LocalTopologyError("multihop destination stage evidence is missing")
        self.state.record_event(
            attempt_id=attempt.attempt_id,
            stage="destination_effect_observation",
            event="observed",
            source="coordinator_read",
            detail={
                "receiver": receiver.address,
                "attempt_key": "0x" + attempt_key.hex(),
                "mid": "0x" + expected_mid.hex(),
                "route_sequence": attempt.route_sequence,
                "delivery_transaction_hash": str(delivery_stage["transaction_hash"]).lower(),
                "effect_event_count": 1,
                "delivery_receipt_sha256": delivery["receipt_sha256"],
            },
            chain_role=destination_role,
            hop_index=len(attempt.route),
        )

    def _application_payload(self, attempt: MultihopAttempt) -> bytes:
        config = self.config
        schedule = cast(dict[str, int], config["payload_schedule"])
        size = (
            schedule["minimum_bytes"]
            + (attempt.route_sequence % schedule["size_bucket_count"]) * schedule["size_step_bytes"]
        )
        material = (
            f"xir-multihop-v1:{config['fixed_seed']}:{attempt.phase}:{attempt.route_sequence}"
        ).encode()
        application = bytearray()
        counter = 0
        while len(application) < size:
            application.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
            counter += 1
        application_bytes = bytes(application[:size])
        if hashlib.sha256(application_bytes).hexdigest() != attempt.payload_sha256:
            raise LocalTopologyError("multihop payload differs from frozen plan")
        return encode(
            ["(bytes32,bytes,uint64,bytes)"],
            [
                (
                    keccak(text=attempt.attempt_id),
                    attempt.route.encode("ascii"),
                    attempt.route_sequence,
                    application_bytes,
                )
            ],
        )

    def _root(
        self, attempt: MultihopAttempt, payload: bytes, receiver_address: str
    ) -> tuple[XIRRecord, XIRContext, bytes, bytes]:
        source_id = multihop_gateway_typed_id(int(self.chain_by_role["a"]["chain_id"]))
        stage = self.state.stage(attempt.attempt_id, "root_create")
        if stage is None:
            gateway_nonce, transaction_nonce = self._reserve_root_nonces()
        else:
            gateway_nonce = int(json.loads(stage["detail_json"])["record_nonce"])
            transaction_nonce = None
        record = XIRRecord(
            source_gateway=source_id,
            source_app=(1, bytes.fromhex(self.account.address[2:])),
            destination_app=(1, bytes.fromhex(receiver_address[2:])),
            nonce=gateway_nonce,
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_MULTIHOP_POLICY_V1"))
        rid = root_id(record, context, REGISTRY_VERSION)
        gateway = self._contract("a", "gateway", "XIRGateway.sol", "XIRGateway")
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="root_create",
            role="a",
            function=gateway.functions.createRecord(
                record.destination_app,
                payload,
                (context.required_security, context.policy_hash),
                REGISTRY_VERSION,
            ),
            detail={
                "record_nonce": record.nonce,
                "record_payload_hash": "0x" + record.payload_hash.hex(),
            },
            preallocated_nonce=transaction_nonce,
        )
        root_stage = self.state.stage(attempt.attempt_id, "root_create")
        if root_stage is None or not root_stage["transaction_hash"]:
            raise LocalTopologyError("multihop root transaction evidence is missing")
        signature = self.root_signer.sign(
            transaction_hash=str(root_stage["transaction_hash"]),
            record=record,
            context=context,
            registry_version=REGISTRY_VERSION,
        )
        self.state.record_event(
            attempt_id=attempt.attempt_id,
            stage="root_certificate_ready",
            event="ready",
            source="root_signer",
            detail={
                "rid": "0x" + rid.hex(),
                "root_transaction_hash": str(root_stage["transaction_hash"]).lower(),
            },
            chain_role="a",
            hop_index=0,
            transaction_hash=str(root_stage["transaction_hash"]),
        )
        return record, context, rid, signature

    def _reserve_root_nonces(self) -> tuple[int, int]:
        with self.xir_nonce_lock:
            if self.xir_nonce_next is None:
                gateway = self._contract("a", "gateway", "XIRGateway.sol", "XIRGateway")
                self.xir_nonce_next = max(
                    int(gateway.functions.nextNonce(self.account.address).call()),
                    self.state.next_reserved_root_nonce(),
                )
            gateway_nonce = self.xir_nonce_next
            self.xir_nonce_next += 1
            with self.nonce_locks["a"]:
                transaction_nonce = self.nonces["a"]
                self.nonces["a"] += 1
            return gateway_nonce, transaction_nonce

    def _dispatch_hop(
        self,
        *,
        attempt: MultihopAttempt,
        hop_index: int,
        protocol: str,
        source_role: str,
        destination_role: str,
        current_profile: bytes,
        current_transition: bytes,
        prior_receipts: list[XIRReceipt],
    ) -> bytes:
        stage = f"hop_{hop_index}_{protocol.lower()}_dispatch"
        completed = self.state.stage(attempt.attempt_id, stage)
        if completed is not None and str(completed["state"]) == "succeeded":
            detail = cast(dict[str, Any], json.loads(completed["detail_json"]))
            if "native_message_id" not in detail:
                evidence_value = bytes.fromhex(cast(str, detail["evidence"]).removeprefix("0x"))
                detail["native_message_id"] = (
                    "0x" + evidence_value.hex()
                    if protocol == "L"
                    else self._hyperlane_message_id(detail)
                )
                self.state.record_stage(
                    attempt.attempt_id,
                    stage,
                    "succeeded",
                    detail,
                    cast(str | None, completed["transaction_hash"]),
                )
            return bytes.fromhex(cast(str, detail["evidence"]).removeprefix("0x"))
        adapter_role = adapter_key(attempt.route, hop_index, "out")
        verifier = (
            None
            if hop_index == 1
            else self.contracts[source_role][adapter_key(attempt.route, hop_index - 1, "in")]
        )
        verifiers = [] if verifier is None else [verifier] * len(prior_receipts)
        profiles = [receipt.profile_hash for receipt in prior_receipts]
        evidence_hashes = [receipt.evidence_hash for receipt in prior_receipts]
        transitions = [receipt.transition_hash for receipt in prior_receipts]
        common_detail = {
            "hop_index": hop_index,
            "protocol": protocol,
            "prior_receipt_count": len(prior_receipts),
            "destination_role": destination_role,
        }
        if protocol == "L":
            adapter = self._contract(
                source_role, adapter_role, "LayerZeroAdapter.sol", "LayerZeroAdapter"
            )
            request: Any = (
                verifiers,
                profiles,
                evidence_hashes,
                transitions,
                current_profile,
                current_transition,
                self.options,
            )
            fee = int(adapter.functions.quoteForward(request).call()[0])
            function = (
                adapter.functions.sendSource(request)
                if hop_index == 1
                else adapter.functions.forwardInFlight(request)
            )
            result = self._transact(
                attempt_id=attempt.attempt_id,
                stage=stage,
                role=source_role,
                function=function,
                value=fee,
                detail={**common_detail, "native_fee": fee},
            )
            evidence = self._layerzero_guid(result)
            native_message_id = "0x" + evidence.hex()
        elif protocol == "H":
            adapter = self._contract(
                source_role, adapter_role, "HyperlaneAdapter.sol", "HyperlaneAdapter"
            )
            request = (
                verifiers,
                profiles,
                evidence_hashes,
                transitions,
                current_profile,
                current_transition,
            )
            fee = int(adapter.functions.quoteBundle(request).call())
            function = (
                adapter.functions.sendSourceBundle(request)
                if hop_index == 1
                else adapter.functions.forwardInFlightBundle(request)
            )
            inner = encode(
                ["(bytes32,bytes32,bytes32[],bytes32[],bytes32[])"],
                [
                    (
                        current_profile,
                        current_transition,
                        profiles,
                        evidence_hashes,
                        transitions,
                    )
                ],
            )
            body = encode(["uint8", "bytes"], [3, inner])
            sender = bytes.fromhex("00" * 12 + self.contracts[source_role][adapter_role][2:])
            evidence = keccak(
                encode(
                    ["uint32", "bytes32", "bytes"],
                    [
                        int(self.chain_by_role[source_role]["hyperlane_domain"]),
                        sender,
                        body,
                    ],
                )
            )
            result = self._transact(
                attempt_id=attempt.attempt_id,
                stage=stage,
                role=source_role,
                function=function,
                value=fee,
                detail={
                    **common_detail,
                    "native_fee": fee,
                    "evidence": "0x" + evidence.hex(),
                },
            )
            native_message_id = self._hyperlane_message_id(result)
        else:
            raise LocalTopologyError(f"unsupported multihop protocol: {protocol}")
        current = self.state.stage(attempt.attempt_id, stage)
        self.state.record_stage(
            attempt.attempt_id,
            stage,
            "succeeded",
            {
                **result,
                "evidence": "0x" + evidence.hex(),
                "native_message_id": native_message_id,
            },
            None if current is None else cast(str | None, current["transaction_hash"]),
        )
        return evidence

    def _hyperlane_message_id(self, result: dict[str, Any]) -> str:
        receipt = json.loads(Path(cast(str, result["receipt"])).read_text(encoding="utf-8"))
        topic = (
            "0x" + keccak(text="HyperlaneDispatched(bytes32,uint32,bytes32,uint256)").hex()
        ).lower()
        for log in cast(list[dict[str, Any]], receipt["logs"]):
            topics = cast(list[str], log.get("topics", []))
            if topics and topics[0].lower() == topic and len(topics) >= 2:
                return topics[1].lower()
        raise LocalTopologyError("Hyperlane multihop receipt lacks dispatched message ID")

    def _layerzero_guid(self, result: dict[str, Any]) -> bytes:
        receipt = json.loads(Path(cast(str, result["receipt"])).read_text(encoding="utf-8"))
        topic = (
            "0x" + keccak(text="VerifiedEvidenceForwarded(bytes32,uint64,uint256)").hex()
        ).lower()
        for log in cast(list[dict[str, Any]], receipt["logs"]):
            topics = cast(list[str], log.get("topics", []))
            if topics and topics[0].lower() == topic and len(topics) >= 2:
                return bytes.fromhex(topics[1].removeprefix("0x"))
        raise LocalTopologyError("LayerZero multihop receipt lacks forwarded GUID")

    def _wait_bundle(
        self,
        *,
        attempt: MultihopAttempt,
        hop_index: int,
        protocol: str,
        destination_role: str,
        current_profile: bytes,
        current_evidence: bytes,
        current_transition: bytes,
        prior_receipts: list[XIRReceipt],
    ) -> None:
        source = "HyperlaneAdapter.sol" if protocol == "H" else "LayerZeroAdapter.sol"
        contract = "HyperlaneAdapter" if protocol == "H" else "LayerZeroAdapter"
        adapter_role = adapter_key(attempt.route, hop_index, "in")
        adapter = self._contract(destination_role, adapter_role, source, contract)
        deadline = time.monotonic() + self.timeout_seconds
        all_receipts = [
            *prior_receipts,
            XIRReceipt(
                multihop_gateway_typed_id(
                    int(self.chain_by_role[CHAIN_ROLES[hop_index - 1]]["chain_id"])
                ),
                multihop_gateway_typed_id(int(self.chain_by_role[destination_role]["chain_id"])),
                current_profile,
                current_evidence,
                current_transition,
                bytes(32),
            ),
        ]
        while time.monotonic() < deadline:
            self._raise_if_submissions_stopped()
            if all(
                adapter.functions.verify(
                    receipt.profile_hash,
                    receipt.evidence_hash,
                    receipt.transition_hash,
                ).call()
                for receipt in all_receipts
            ):
                self.state.record_event(
                    attempt_id=attempt.attempt_id,
                    stage=f"hop_{hop_index}_{protocol.lower()}_callback",
                    event="accepted",
                    source="coordinator_read",
                    detail={
                        "adapter": adapter.address,
                        "verified_tuple_count": len(all_receipts),
                    },
                    chain_role=destination_role,
                    hop_index=hop_index,
                )
                return
            time.sleep(0.5)
        raise LocalTopologyError(
            f"timed out waiting for multihop bundle at {destination_role}:{adapter_role}"
        )

    def _raise_if_submissions_stopped(self) -> None:
        if self.submission_stop_file is not None and self.submission_stop_file.exists():
            raise LocalTopologyError("multihop submissions stopped by resource monitor")

    @staticmethod
    def _envelope(
        record: XIRRecord,
        context: XIRContext,
        signature: bytes,
        receipts: list[XIRReceipt],
    ) -> tuple[Any, ...]:
        return (
            record_tuple(record),
            (context.required_security, context.policy_hash),
            (REGISTRY_VERSION, signature),
            [receipt_tuple(receipt) for receipt in receipts],
        )
