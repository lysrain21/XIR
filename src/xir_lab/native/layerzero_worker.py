"""Durable self-hosted worker for official LayerZero V2 private-chain components."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from eth_abi.abi import decode
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction  # type: ignore[attr-defined]
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import Web3RPCError

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import (
    EVENT_TOPICS,
    LayerZeroPacket,
    build_dvn_instruction,
    decode_packet,
    encode_commit_verification,
    encode_dvn_execute,
    encode_executor_submission,
)
from xir_lab.native.multihop_process_identity import current_process_identity
from xir_lab.native.rpc import qbft_web3

STAGES = ("dvn_execute", "commit_verification", "executor_execute")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise LocalTopologyError("LayerZero worker boot identity unavailable") from exc
    if not value:
        raise LocalTopologyError("LayerZero worker boot identity empty")
    return value


@dataclass(frozen=True)
class WorkerChain:
    chain_id: int
    eid: int
    rpc_url: str
    endpoint: str
    receive_uln: str
    dvn: str
    executor: str
    start_block: int


def load_worker_chains(path: Path) -> dict[int, WorkerChain]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "xir-lab-layerzero-worker-config-v1":
        raise LocalTopologyError("LayerZero worker config schema is missing or invalid")
    items = document.get("chains")
    if not isinstance(items, list) or len(items) not in {3, 5}:
        raise LocalTopologyError("LayerZero worker requires exactly three or five chains")
    result: dict[int, WorkerChain] = {}
    for item in items:
        chain = WorkerChain(
            chain_id=int(item["chain_id"]),
            eid=int(item["eid"]),
            rpc_url=str(item["rpc_url"]),
            endpoint=Web3.to_checksum_address(item["endpoint"]),
            receive_uln=Web3.to_checksum_address(item["receive_uln"]),
            dvn=Web3.to_checksum_address(item["dvn"]),
            executor=Web3.to_checksum_address(item["executor"]),
            start_block=int(item["start_block"]),
        )
        if chain.eid in result:
            raise LocalTopologyError("duplicate LayerZero worker EID")
        result[chain.eid] = chain
    return result


class LayerZeroWorkerState:
    """Private durable state; raw signed transactions never enter Git."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.boot_id = _boot_id()
        runtime_root = Path(os.environ.get("XIR_LOCAL_RUNTIME_ROOT", str(path.parent.parent)))
        self.process_identity = current_process_identity(runtime_root=runtime_root)
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS cursors (
                source_eid INTEGER PRIMARY KEY,
                next_block INTEGER NOT NULL CHECK(next_block >= 0),
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS packets (
                guid TEXT PRIMARY KEY,
                source_eid INTEGER NOT NULL,
                destination_eid INTEGER NOT NULL,
                source_block INTEGER NOT NULL,
                source_transaction_hash TEXT NOT NULL,
                source_log_index INTEGER NOT NULL,
                encoded_packet_hex TEXT NOT NULL,
                packet_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source_eid, source_transaction_hash, source_log_index)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS actions (
                action_id TEXT PRIMARY KEY,
                guid TEXT NOT NULL REFERENCES packets(guid),
                stage TEXT NOT NULL,
                destination_chain_id INTEGER NOT NULL,
                nonce INTEGER NOT NULL,
                target TEXT NOT NULL,
                calldata_bytes INTEGER NOT NULL,
                calldata_hex TEXT,
                calldata_sha256 TEXT NOT NULL,
                raw_transaction_hex TEXT,
                transaction_hash TEXT,
                status TEXT NOT NULL,
                intended_at TEXT NOT NULL,
                UNIQUE(guid, stage),
                UNIQUE(destination_chain_id, nonce)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL REFERENCES actions(action_id),
                state TEXT NOT NULL,
                raw_sha256 TEXT,
                detail_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                utc_ns INTEGER NOT NULL,
                monotonic_ns INTEGER NOT NULL,
                boot_id TEXT NOT NULL,
                process_id INTEGER NOT NULL
                ,process_identity_sha256 TEXT
            ) STRICT;
            """
        )
        columns = {str(row[1]) for row in self.connection.execute("PRAGMA table_info(actions)")}
        if "calldata_bytes" not in columns:
            self.connection.execute("ALTER TABLE actions ADD COLUMN calldata_bytes INTEGER")
        if "calldata_hex" not in columns:
            self.connection.execute("ALTER TABLE actions ADD COLUMN calldata_hex TEXT")
        observation_columns = {
            str(row[1]) for row in self.connection.execute("PRAGMA table_info(observations)")
        }
        for name, sql_type in (
            ("utc_ns", "INTEGER"),
            ("monotonic_ns", "INTEGER"),
            ("boot_id", "TEXT"),
            ("process_id", "INTEGER"),
            ("process_identity_sha256", "TEXT"),
        ):
            if name not in observation_columns:
                self.connection.execute(f"ALTER TABLE observations ADD COLUMN {name} {sql_type}")
        self.connection.commit()

    def _record_observation(
        self,
        *,
        action_id: str,
        state: str,
        details: dict[str, Any],
        raw_sha256: str | None = None,
    ) -> None:
        public_details = dict(details)
        public_details["_process_identity"] = self.process_identity
        self.connection.execute(
            """
            INSERT INTO observations(
              action_id,state,raw_sha256,detail_json,observed_at,
              utc_ns,monotonic_ns,boot_id,process_id,process_identity_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                state,
                raw_sha256,
                json.dumps(public_details, sort_keys=True),
                _now(),
                time.time_ns(),
                time.monotonic_ns(),
                self.boot_id,
                os.getpid(),
                self.process_identity["identity_sha256"],
            ),
        )

    def cursor(self, source_eid: int, default: int) -> int:
        row = self.connection.execute(
            "SELECT next_block FROM cursors WHERE source_eid = ?", (source_eid,)
        ).fetchone()
        return default if row is None else int(row["next_block"])

    def advance_cursor(self, source_eid: int, next_block: int) -> None:
        self.connection.execute(
            """
            INSERT INTO cursors(source_eid, next_block, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(source_eid) DO UPDATE SET
              next_block = excluded.next_block, updated_at = excluded.updated_at
            """,
            (source_eid, next_block, _now()),
        )
        self.connection.commit()

    def observe_packet(
        self,
        *,
        packet: LayerZeroPacket,
        source_block: int,
        source_transaction_hash: str,
        source_log_index: int,
    ) -> None:
        encoded_hex = "0x" + packet.encoded.hex()
        self.connection.execute(
            """
            INSERT OR IGNORE INTO packets(
              guid, source_eid, destination_eid, source_block,
              source_transaction_hash, source_log_index, encoded_packet_hex,
              packet_sha256, status, observed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'observed', ?, ?)
            """,
            (
                "0x" + packet.guid.hex(),
                packet.source_eid,
                packet.destination_eid,
                source_block,
                source_transaction_hash.lower(),
                source_log_index,
                encoded_hex,
                hashlib.sha256(packet.encoded).hexdigest(),
                _now(),
                _now(),
            ),
        )
        self.connection.commit()

    def ready_packets(
        self, source_heads: Mapping[int, int], confirmations: int
    ) -> list[sqlite3.Row]:
        rows = self.connection.execute(
            "SELECT * FROM packets WHERE status != 'delivered' ORDER BY source_block, source_log_index"
        ).fetchall()
        return [
            row
            for row in rows
            if source_heads[int(row["source_eid"])] >= int(row["source_block"]) + confirmations
        ]

    def action(self, guid: str, stage: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self.connection.execute(
                "SELECT * FROM actions WHERE guid = ? AND stage = ?", (guid, stage)
            ).fetchone(),
        )

    def intend_action(
        self,
        *,
        guid: str,
        stage: str,
        destination_chain_id: int,
        nonce: int,
        target: str,
        call_data: bytes,
    ) -> sqlite3.Row:
        action_id = "lz_" + hashlib.sha256(f"{guid}:{stage}".encode()).hexdigest()[:24]
        outer_transaction = self.connection.in_transaction
        savepoint = f"intend_action_{action_id}"
        if outer_transaction:
            self.connection.execute(f"SAVEPOINT {savepoint}")
        else:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            durable_row = self.connection.execute(
                "SELECT MAX(nonce) FROM actions WHERE destination_chain_id = ?",
                (destination_chain_id,),
            ).fetchone()
            durable_nonce = None if durable_row is None else durable_row[0]
            if durable_nonce is not None:
                nonce = max(nonce, int(durable_nonce) + 1)
            self.connection.execute(
                """
                INSERT INTO actions(
                  action_id, guid, stage, destination_chain_id, nonce, target,
                  calldata_bytes, calldata_hex, calldata_sha256, status, intended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'intended', ?)
                """,
                (
                    action_id,
                    guid,
                    stage,
                    destination_chain_id,
                    nonce,
                    target.lower(),
                    len(call_data),
                    "0x" + call_data.hex(),
                    hashlib.sha256(call_data).hexdigest(),
                    _now(),
                ),
            )
            self._record_observation(action_id=action_id, state="intended", details={})
            if outer_transaction:
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                self.connection.commit()
        except BaseException:
            if outer_transaction:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                self.connection.rollback()
            raise
        return cast(
            sqlite3.Row,
            self.connection.execute(
                "SELECT * FROM actions WHERE action_id = ?", (action_id,)
            ).fetchone(),
        )

    def record_signed(self, action_id: str, raw: bytes, transaction_hash: str) -> None:
        raw_hex = "0x" + raw.hex()
        digest = hashlib.sha256(raw).hexdigest()
        self.connection.execute(
            """
            UPDATE actions SET raw_transaction_hex = ?, transaction_hash = ?,
              status = 'signed' WHERE action_id = ? AND status = 'intended'
            """,
            (raw_hex, transaction_hash.lower(), action_id),
        )
        self._record_observation(
            action_id=action_id,
            state="signed",
            raw_sha256=digest,
            details={"transaction_hash": transaction_hash.lower()},
        )
        self.connection.commit()

    def observe_action(self, action_id: str, state: str, details: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE actions SET status = ? WHERE action_id = ?",
            (state, action_id),
        )
        self._record_observation(action_id=action_id, state=state, details=details)
        self.connection.commit()

    def mark_delivered(self, guid: str) -> None:
        self.connection.execute(
            "UPDATE packets SET status = 'delivered', updated_at = ? WHERE guid = ?",
            (_now(), guid),
        )
        self.connection.commit()


class LayerZeroWorker:
    """Polls PacketSent and completes the official DVN/ULN/Executor sequence."""

    def __init__(
        self,
        *,
        chains: dict[int, WorkerChain],
        private_key: str,
        state: LayerZeroWorkerState,
        raw_root: Path,
        confirmations: int = 1,
        executor_gas_limit: int = 1_500_000,
        batch_packets: int = 100,
    ) -> None:
        self.chains = chains
        self.account = Account.from_key(private_key)
        self.private_key = private_key
        self.state = state
        self.raw_root = raw_root
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self.confirmations = confirmations
        self.executor_gas_limit = executor_gas_limit
        if batch_packets <= 0:
            raise LocalTopologyError("LayerZero worker batch size must be positive")
        self.batch_packets = batch_packets
        self.web3 = {eid: qbft_web3(chain.rpc_url, timeout=30) for eid, chain in chains.items()}

    def collect(self, maximum_block_span: int = 1000) -> None:
        topic = EVENT_TOPICS["packet_sent"]
        for eid, chain in self.chains.items():
            client = self.web3[eid]
            head = client.eth.block_number
            start = self.state.cursor(eid, chain.start_block)
            while start <= head:
                end = min(start + maximum_block_span - 1, head)
                logs = client.eth.get_logs(
                    {
                        "fromBlock": start,
                        "toBlock": end,
                        "address": cast(Any, chain.endpoint),
                        "topics": [topic],
                    }
                )
                for log in logs:
                    encoded_packet, _, _ = decode(["bytes", "bytes", "address"], bytes(log["data"]))
                    packet = decode_packet(cast(bytes, encoded_packet))
                    if packet.source_eid != eid:
                        raise LocalTopologyError("LayerZero PacketSent source EID mismatch")
                    if packet.destination_eid not in self.chains:
                        raise LocalTopologyError("LayerZero packet targets unknown EID")
                    self.state.observe_packet(
                        packet=packet,
                        source_block=int(log["blockNumber"]),
                        source_transaction_hash=log["transactionHash"].hex(),
                        source_log_index=int(log["logIndex"]),
                    )
                self.state.advance_cursor(eid, end + 1)
                start = end + 1

    def process(self) -> None:
        heads = {eid: int(client.eth.block_number) for eid, client in self.web3.items()}
        ready = self.state.ready_packets(heads, self.confirmations)[: self.batch_packets]
        pending: list[tuple[Web3, str, str, str]] = []
        packet_guids: list[str] = []
        for row in ready:
            packet = decode_packet(bytes.fromhex(str(row["encoded_packet_hex"])[2:]))
            packet_guid = "0x" + packet.guid.hex()
            packet_guids.append(packet_guid)
            destination = self.chains[packet.destination_eid]
            expiration = int(time.time()) + 3600
            instruction = build_dvn_instruction(
                vid=destination.eid,
                receive_uln_address=destination.receive_uln,
                packet=packet,
                confirmations=self.confirmations,
                expiration=expiration,
                signer_private_key=self.private_key,
            )
            actions = (
                ("dvn_execute", destination.dvn, encode_dvn_execute(instruction)),
                (
                    "commit_verification",
                    destination.receive_uln,
                    encode_commit_verification(packet),
                ),
                (
                    "executor_execute",
                    destination.executor,
                    encode_executor_submission(packet, self.executor_gas_limit),
                ),
            )
            for stage, target, call_data in actions:
                submitted = self._submit_stage(
                    guid=packet_guid,
                    stage=stage,
                    chain=destination,
                    target=target,
                    call_data=call_data,
                )
                if submitted is not None:
                    pending.append(submitted)
        for client, action_id, transaction_hash, stage in pending:
            self._finalize_stage(client, action_id, transaction_hash, stage)
        for guid in packet_guids:
            stages = [self.state.action(guid, stage) for stage in STAGES]
            if all(
                action is not None and str(action["status"]) == "succeeded" for action in stages
            ):
                self.state.mark_delivered(guid)

    def _submit_stage(
        self,
        *,
        guid: str,
        stage: str,
        chain: WorkerChain,
        target: str,
        call_data: bytes,
    ) -> tuple[Web3, str, str, str] | None:
        client = self.web3[chain.eid]
        action = self.state.action(guid, stage)
        if action is not None and str(action["status"]) == "succeeded":
            return None
        if action is None:
            nonce = client.eth.get_transaction_count(self.account.address, "pending")
            action = self.state.intend_action(
                guid=guid,
                stage=stage,
                destination_chain_id=chain.chain_id,
                nonce=nonce,
                target=target,
                call_data=call_data,
            )
        if (
            int(action["destination_chain_id"]) != chain.chain_id
            or str(action["target"]).lower() != target.lower()
            or not str(action["calldata_hex"] or "")
        ):
            raise LocalTopologyError("LayerZero durable intended action identity drift")
        frozen_call_data = bytes.fromhex(str(action["calldata_hex"])[2:])
        if len(frozen_call_data) != int(action["calldata_bytes"]) or hashlib.sha256(
            frozen_call_data
        ).hexdigest() != str(action["calldata_sha256"]):
            raise LocalTopologyError("LayerZero durable intended calldata drift")
        raw_hex = action["raw_transaction_hex"]
        transaction_hash = action["transaction_hash"]
        if raw_hex is None:
            transaction = {
                "chainId": chain.chain_id,
                "nonce": int(action["nonce"]),
                "to": target,
                "data": frozen_call_data,
                "value": 0,
                "gas": 5_000_000,
                "maxFeePerGas": max(client.eth.gas_price * 2, 1),
                "maxPriorityFeePerGas": 0,
                "type": 2,
            }
            signed = self.account.sign_transaction(transaction)
            raw = bytes(signed.raw_transaction)
            transaction_hash = signed.hash.hex()
            self.state.record_signed(str(action["action_id"]), raw, transaction_hash)
        else:
            raw = bytes.fromhex(str(raw_hex)[2:])
        decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        decoded_target = "0x" + bytes(decoded["to"]).hex()
        decoded_data = bytes(decoded["data"])
        expected_hash = Web3.keccak(raw).hex().lower()
        if (
            Account.recover_transaction(raw).lower() != self.account.address.lower()
            or int(decoded["chainId"]) != chain.chain_id
            or int(decoded["nonce"]) != int(action["nonce"])
            or decoded_target.lower() != str(action["target"]).lower()
            or decoded_data != frozen_call_data
            or str(transaction_hash).lower() != expected_hash
        ):
            raise LocalTopologyError("LayerZero durable raw transaction identity drift")
        try:
            client.eth.send_raw_transaction(raw)
        except (ValueError, Web3RPCError) as exc:
            message = str(exc).lower()
            accepted_prior_broadcast = (
                "already known" in message
                or "known transaction" in message
                or "nonce too low" in message
            )
            if not accepted_prior_broadcast:
                raise
        self.state.observe_action(
            str(action["action_id"]),
            "submitted",
            {"transaction_hash": transaction_hash},
        )
        return client, str(action["action_id"]), str(transaction_hash), stage

    def _finalize_stage(
        self,
        client: Web3,
        action_id: str,
        transaction_hash: str,
        stage: str,
    ) -> None:
        receipt = client.eth.wait_for_transaction_receipt(HexBytes(transaction_hash), timeout=120)
        receipt_json = Web3.to_json(cast(dict[Any, Any], receipt))
        receipt_path = self.raw_root / f"{transaction_hash}.receipt.json"
        receipt_path.write_text(receipt_json + "\n", encoding="utf-8")
        if int(receipt["status"]) != 1:
            self.state.observe_action(
                action_id,
                "failed",
                {"transaction_hash": transaction_hash, "receipt": str(receipt_path)},
            )
            raise LocalTopologyError(f"LayerZero worker stage reverted: {stage}")
        expected_topic = {
            "dvn_execute": EVENT_TOPICS["payload_verified"],
            "commit_verification": EVENT_TOPICS["packet_verified"],
            "executor_execute": EVENT_TOPICS["packet_delivered"],
        }[stage].lower()
        observed_topics = {
            "0x" + bytes(log["topics"][0]).hex() for log in receipt["logs"] if log["topics"]
        }
        if expected_topic not in observed_topics:
            self.state.observe_action(
                action_id,
                "failed",
                {
                    "transaction_hash": transaction_hash,
                    "receipt": str(receipt_path),
                    "error": "expected official event missing",
                    "expected_topic": expected_topic,
                },
            )
            raise LocalTopologyError(
                f"LayerZero worker stage lacks official success event: {stage}"
            )
        self.state.observe_action(
            action_id,
            "succeeded",
            {
                "transaction_hash": transaction_hash,
                "block_number": int(receipt["blockNumber"]),
                "gas_used": int(receipt["gasUsed"]),
                "receipt": str(receipt_path),
                "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            },
        )
