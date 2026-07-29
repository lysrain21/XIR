"""Deploy and execute the bounded three-stage controlled local workload."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785
from eth_account import Account
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3
from web3.exceptions import TimeExhausted, TransactionNotFound, Web3RPCError

from xir_lab.localnet.topology import (
    LocalIdentityManifest,
    LocalTopology,
    LocalTopologyError,
)

LocalPhase = Literal["smoke", "rehearsal", "scale"]
STAGE_NAMES = ("source", "intermediate", "destination")
CONDITIONS = ("HH", "HL", "LH", "LL")
PHASE_SLOTS = {"smoke": 5, "rehearsal": 125, "scale": 1250}
PAYLOAD_HASH = Web3.keccak(text="xir-local-scale-payload-v1")


@dataclass(frozen=True)
class LocalAttempt:
    attempt_id: bytes
    pair_id: bytes
    condition: str
    condition_index: int
    arm: str
    xir: bool
    slot: int
    sequence_index: int


def _schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _profile(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read local workload profile: {path}") from exc
    errors = list(
        jsonschema.Draft202012Validator(
            _schema("local-scale-profile-v1.schema.json")
        ).iter_errors(document)
    )
    if errors:
        raise LocalTopologyError(f"invalid local workload profile: {errors[0].message}")
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def _coordinate_digest(seed: str, domain: str, *values: str | int) -> bytes:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": domain,
                "seed": seed,
                "coordinates": list(values),
            }
        )
    ).digest()


def build_local_attempts(
    *,
    profile_path: Path,
    phase: LocalPhase,
) -> tuple[LocalAttempt, ...]:
    """Expand the exact balanced phase schedule without a network call."""

    profile, _ = _profile(profile_path)
    seed = cast(str, profile["fixed_seed"])
    pair_rows = [
        (condition, condition_index, slot)
        for condition_index, condition in enumerate(CONDITIONS)
        for slot in range(PHASE_SLOTS[phase])
    ]
    pair_rows.sort(
        key=lambda item: _coordinate_digest(
            seed,
            f"{phase}-pair-order",
            item[0],
            item[2],
        )
    )
    attempts: list[LocalAttempt] = []
    for condition, condition_index, slot in pair_rows:
        pair_id = _coordinate_digest(seed, phase, condition, slot)
        arms = ["baseline", "xir"]
        if _coordinate_digest(seed, f"{phase}-arm-order", condition, slot)[-1] & 1:
            arms.reverse()
        for arm in arms:
            attempt_id = _coordinate_digest(seed, phase, condition, arm, slot)
            attempts.append(
                LocalAttempt(
                    attempt_id=attempt_id,
                    pair_id=pair_id,
                    condition=condition,
                    condition_index=condition_index,
                    arm=arm,
                    xir=arm == "xir",
                    slot=slot,
                    sequence_index=len(attempts),
                )
            )
    expected = PHASE_SLOTS[phase] * len(CONDITIONS) * 2
    if len(attempts) != expected:
        raise LocalTopologyError("local workload expansion count mismatch")
    cells = {
        (condition, arm): sum(
            item.condition == condition and item.arm == arm for item in attempts
        )
        for condition in CONDITIONS
        for arm in ("baseline", "xir")
    }
    if set(cells.values()) != {PHASE_SLOTS[phase]}:
        raise LocalTopologyError("local workload condition/arm balance mismatch")
    return tuple(attempts)


def _artifact(path: Path) -> tuple[list[dict[str, Any]], str, str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
        abi = cast(list[dict[str, Any]], document["abi"])
        bytecode = cast(str, document["bytecode"]["object"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise LocalTopologyError(f"cannot read LocalScaleWorkload artifact: {path}") from exc
    if not bytecode.startswith("0x") or len(bytecode) <= 2:
        raise LocalTopologyError("local workload artifact has no creation bytecode")
    return abi, bytecode, hashlib.sha256(raw).hexdigest()


def _private_account(runtime_root: Path, role: str) -> Any:
    path = runtime_root / "private" / "accounts" / f"{role}.key"
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise LocalTopologyError(f"cannot read local {role} key") from exc
    return Account.from_key(value)


def _provider(topology: LocalTopology, network_index: int) -> Web3:
    network = topology.networks[network_index]
    provider = HTTPProvider(
        f"http://127.0.0.1:{network.host_rpc_port}",
        request_kwargs={"timeout": 10},
    )
    web3 = Web3(provider)
    if not web3.is_connected() or web3.eth.chain_id != network.chain_id:
        raise LocalTopologyError(f"local RPC identity mismatch: {network.network_id}")
    return web3


def deploy_local_workloads(
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
    runtime_root: Path,
    artifact_path: Path,
) -> Path:
    """Deploy one stage contract per chain with the local deployer."""

    abi, bytecode, artifact_sha256 = _artifact(artifact_path)
    deployer = _private_account(runtime_root, "deployer")
    runner = _private_account(runtime_root, "runner")
    if deployer.address.lower() != manifest.deployer.lower():
        raise LocalTopologyError("local deployer key differs from identity manifest")
    if runner.address.lower() != manifest.runner.lower():
        raise LocalTopologyError("local runner key differs from identity manifest")
    contracts: list[dict[str, Any]] = []
    for index, network in enumerate(topology.networks):
        web3 = _provider(topology, index)
        factory = web3.eth.contract(abi=abi, bytecode=bytecode)
        transaction = factory.constructor(
            network.chain_id,
            index,
            runner.address,
        ).build_transaction(
            {
                "from": deployer.address,
                "chainId": network.chain_id,
                "nonce": web3.eth.get_transaction_count(deployer.address, "pending"),
                "gas": 5_000_000,
                "gasPrice": 0,
            }
        )
        signed = deployer.sign_transaction(transaction)
        transaction_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(transaction_hash, timeout=60)
        contract_address = receipt.get("contractAddress")
        if receipt["status"] != 1 or contract_address is None:
            raise LocalTopologyError(f"local workload deployment failed: {network.network_id}")
        contracts.append(
            {
                "network_id": network.network_id,
                "chain_id": network.chain_id,
                "stage": STAGE_NAMES[index],
                "address": contract_address,
                "transaction_hash": transaction_hash.to_0x_hex(),
                "block_number": receipt["blockNumber"],
            }
        )
    payload = {
        "domain": "xir-lab-local-deployment-v1",
        "environment": "controlled-local-qbft",
        "topology_sha256": topology.source_sha256,
        "identity_manifest_sha256": manifest.payload_sha256,
        "artifact_sha256": artifact_sha256,
        "contracts": contracts,
    }
    document = {
        "schema_version": "xir-lab-local-deployment-v1",
        "payload_sha256": hashlib.sha256(
            rfc8785.dumps(payload)  # type: ignore[arg-type]
        ).hexdigest(),
        "payload": payload,
    }
    output = runtime_root / "deployment.json"
    output.write_bytes(
        rfc8785.dumps(document) + b"\n"  # type: ignore[arg-type]
    )
    return output


def _load_deployment(
    path: Path,
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read local deployment: {path}") from exc
    errors = list(
        jsonschema.Draft202012Validator(
            _schema("local-deployment-v1.schema.json")
        ).iter_errors(document)
    )
    if errors:
        raise LocalTopologyError(f"invalid local deployment: {errors[0].message}")
    payload = cast(dict[str, Any], document["payload"])
    if hashlib.sha256(rfc8785.dumps(payload)).hexdigest() != document["payload_sha256"]:
        raise LocalTopologyError("local deployment payload digest mismatch")
    if (
        payload["topology_sha256"] != topology.source_sha256
        or payload["identity_manifest_sha256"] != manifest.payload_sha256
    ):
        raise LocalTopologyError("local deployment identity mismatch")
    return payload


def _database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS local_stages (
            attempt_id TEXT NOT NULL,
            stage INTEGER NOT NULL,
            condition TEXT NOT NULL,
            arm TEXT NOT NULL,
            transaction_hash TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            state TEXT NOT NULL,
            block_number INTEGER,
            gas_used INTEGER,
            calldata_bytes INTEGER NOT NULL DEFAULT 0,
            submitted_at REAL NOT NULL,
            finalized_at REAL,
            PRIMARY KEY (attempt_id, stage)
        )
        """
    )
    connection.commit()
    return connection


def require_reconciled_local_phase(
    *,
    runtime_root: Path,
    phase: Literal["smoke", "rehearsal"],
) -> None:
    """Require the exact prior-phase terminal count before progression."""

    expected = PHASE_SLOTS[phase] * len(CONDITIONS) * 2 * len(STAGE_NAMES)
    path = runtime_root / "evidence" / f"{phase}.sqlite"
    if not path.is_file():
        raise LocalTopologyError(f"reconciled {phase} evidence is required")
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            row = connection.execute(
                """
                SELECT count(*) FROM local_stages
                WHERE state = 'finalized'
                """
            ).fetchone()
    except sqlite3.Error as exc:
        raise LocalTopologyError(f"cannot validate reconciled {phase} evidence") from exc
    if row is None or int(row[0]) != expected:
        raise LocalTopologyError(
            f"reconciled {phase} evidence must contain {expected} finalized stages"
        )


def _prior_digest(attempt: LocalAttempt, stage: int) -> bytes:
    if stage == 0:
        return bytes(32)
    return bytes(
        Web3.solidity_keccak(
            ["string", "bytes32", "bytes32", "uint8", "bool", "bytes32", "uint8"],
            [
                "XIR_LOCAL_STAGE_V1",
                attempt.attempt_id,
                attempt.pair_id,
                attempt.condition_index,
                attempt.xir,
                PAYLOAD_HASH,
                stage - 1,
            ],
        )
    )


def execute_local_phase(
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
    runtime_root: Path,
    profile_path: Path,
    deployment_path: Path,
    artifact_path: Path,
    phase: LocalPhase,
    batch_size: int,
) -> dict[str, Any]:
    """Submit bounded stage batches with a private exact-byte recovery spool."""

    if batch_size < 1 or batch_size > 250:
        raise LocalTopologyError("local workload batch size must be between 1 and 250")
    attempts = build_local_attempts(profile_path=profile_path, phase=phase)
    _, profile_sha256 = _profile(profile_path)
    try:
        deployment_sha256 = hashlib.sha256(deployment_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise LocalTopologyError(
            f"cannot hash local deployment: {deployment_path}"
        ) from exc
    deployment = _load_deployment(
        deployment_path,
        topology=topology,
        manifest=manifest,
    )
    abi, _, artifact_sha256 = _artifact(artifact_path)
    runner = _private_account(runtime_root, "runner")
    if runner.address.lower() != manifest.runner.lower():
        raise LocalTopologyError("local runner key differs from identity manifest")
    contracts = cast(list[dict[str, Any]], deployment["contracts"])
    evidence_path = runtime_root / "evidence" / f"{phase}.sqlite"
    connection = _database(evidence_path)
    spool_root = runtime_root / "private" / "signed-spool" / phase
    spool_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    rpc_requests = 0
    try:
        for batch_start in range(0, len(attempts), batch_size):
            batch = attempts[batch_start : batch_start + batch_size]
            for stage, network in enumerate(topology.networks):
                web3 = _provider(topology, stage)
                contract = web3.eth.contract(
                    address=contracts[stage]["address"],
                    abi=abi,
                )
                next_nonce = int(
                    web3.eth.get_transaction_count(runner.address, "pending")
                )
                rpc_requests += 2
                pending: list[tuple[LocalAttempt, str, Path]] = []
                for attempt in batch:
                    attempt_hex = "0x" + attempt.attempt_id.hex()
                    row = connection.execute(
                        """
                        SELECT transaction_hash, state, nonce
                        FROM local_stages
                        WHERE attempt_id = ? AND stage = ?
                        """,
                        (attempt_hex, stage),
                    ).fetchone()
                    if row is not None and row[1] == "finalized":
                        continue
                    if row is not None:
                        transaction_hash = str(row[0])
                        next_nonce = max(next_nonce, int(row[2]) + 1)
                        spool_path = spool_root / transaction_hash.removeprefix("0x")
                        if not spool_path.is_file():
                            raise LocalTopologyError("local signed recovery bytes are missing")
                        try:
                            recovered_receipt = web3.eth.get_transaction_receipt(
                                HexBytes(transaction_hash)
                            )
                            rpc_requests += 1
                        except TransactionNotFound:
                            recovered_receipt = None
                            rpc_requests += 1
                        if recovered_receipt is not None:
                            if recovered_receipt["status"] != 1:
                                raise LocalTopologyError(
                                    "recovered local stage transaction reverted: "
                                    f"{transaction_hash}"
                                )
                            connection.execute(
                                """
                                UPDATE local_stages
                                SET state = 'finalized', block_number = ?, gas_used = ?,
                                    finalized_at = ?
                                WHERE attempt_id = ? AND stage = ?
                                """,
                                (
                                    recovered_receipt["blockNumber"],
                                    recovered_receipt["gasUsed"],
                                    time.time(),
                                    attempt_hex,
                                    stage,
                                ),
                            )
                            connection.commit()
                            spool_path.unlink(missing_ok=True)
                            continue
                    else:
                        transaction = contract.functions.recordStage(
                            attempt.attempt_id,
                            attempt.pair_id,
                            attempt.condition_index,
                            attempt.xir,
                            PAYLOAD_HASH,
                            _prior_digest(attempt, stage),
                        ).build_transaction(
                            {
                                "from": runner.address,
                                "chainId": network.chain_id,
                                "nonce": next_nonce,
                                "gas": 300_000,
                                "gasPrice": 0,
                            }
                        )
                        signed = runner.sign_transaction(transaction)
                        transaction_hash = signed.hash.to_0x_hex()
                        spool_path = spool_root / transaction_hash.removeprefix("0x")
                        spool_path.write_bytes(bytes(signed.raw_transaction))
                        spool_path.chmod(0o600)
                        connection.execute(
                            """
                            INSERT INTO local_stages (
                                attempt_id, stage, condition, arm,
                                transaction_hash, nonce, state, submitted_at
                                , calldata_bytes
                            ) VALUES (?, ?, ?, ?, ?, ?, 'prepared', ?, ?)
                            """,
                            (
                                attempt_hex,
                                stage,
                                attempt.condition,
                                attempt.arm,
                                transaction_hash,
                                next_nonce,
                                time.time(),
                                len(
                                    HexBytes(
                                        cast(str, transaction["data"])
                                    )
                                ),
                            ),
                        )
                        connection.commit()
                        next_nonce += 1
                    raw = spool_path.read_bytes()
                    sync_deadline = time.monotonic() + 60
                    while True:
                        try:
                            web3.eth.send_raw_transaction(raw)
                            break
                        except (ValueError, Web3RPCError) as exc:
                            message = str(exc).lower()
                            if (
                                "initial sync is still in progress" in message
                                and time.monotonic() < sync_deadline
                            ):
                                time.sleep(2)
                                continue
                            if (
                                "already known" not in message
                                and "known transaction" not in message
                            ):
                                raise
                            break
                    connection.execute(
                        """
                        UPDATE local_stages SET state = 'submitted'
                        WHERE attempt_id = ? AND stage = ?
                        """,
                        (attempt_hex, stage),
                    )
                    connection.commit()
                    rpc_requests += 1
                    pending.append((attempt, transaction_hash, spool_path))
                for attempt, transaction_hash, spool_path in pending:
                    try:
                        receipt = web3.eth.wait_for_transaction_receipt(
                            HexBytes(transaction_hash),
                            timeout=90,
                        )
                    except TimeExhausted as exc:
                        raise LocalTopologyError(
                            f"local transaction receipt timed out: {transaction_hash}"
                        ) from exc
                    rpc_requests += 1
                    if receipt["status"] != 1:
                        raise LocalTopologyError(
                            f"local stage transaction reverted: {transaction_hash}"
                        )
                    connection.execute(
                        """
                        UPDATE local_stages
                        SET state = 'finalized', block_number = ?, gas_used = ?,
                            finalized_at = ?
                        WHERE attempt_id = ? AND stage = ?
                        """,
                        (
                            receipt["blockNumber"],
                            receipt["gasUsed"],
                            time.time(),
                            "0x" + attempt.attempt_id.hex(),
                            stage,
                        ),
                    )
                    connection.commit()
                    spool_path.unlink(missing_ok=True)
        row = connection.execute(
            """
            SELECT count(*), coalesce(sum(gas_used), 0),
                   coalesce(sum(calldata_bytes), 0),
                   min(submitted_at), max(finalized_at)
            FROM local_stages WHERE state = 'finalized'
            """
        ).fetchone()
        finalized = int(row[0])
        gas_used = int(row[1])
        calldata_bytes = int(row[2])
        first_submitted_at = float(row[3])
        last_finalized_at = float(row[4])
        expected = len(attempts) * 3
        if finalized != expected:
            raise LocalTopologyError("local workload physical reconciliation failed")
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        return {
            "schema_version": "xir-lab-local-phase-summary-v1",
            "environment": "controlled-local-qbft",
            "phase": phase,
            "started_at": datetime.fromtimestamp(first_submitted_at, UTC).isoformat(),
            "completed_at": datetime.fromtimestamp(last_finalized_at, UTC).isoformat(),
            "topology_sha256": topology.source_sha256,
            "identity_manifest_sha256": manifest.payload_sha256,
            "profile_sha256": profile_sha256,
            "deployment_sha256": deployment_sha256,
            "artifact_sha256": artifact_sha256,
            "attempts": len(attempts),
            "physical_transactions": finalized,
            "gas_used": gas_used,
            "calldata_bytes": calldata_bytes,
            "rpc_requests": rpc_requests,
            "elapsed_seconds": last_finalized_at - first_submitted_at,
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
        }
    finally:
        connection.close()
