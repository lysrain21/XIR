"""Deploy and execute the bounded four-route paper workload."""

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
from eth_abi.abi import encode
from eth_account import Account
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3
from web3.exceptions import TimeExhausted, TransactionNotFound, Web3RPCError
from web3.logs import DISCARD
from web3.middleware import ExtraDataToPOAMiddleware

from xir_lab.localnet.topology import (
    LocalIdentityManifest,
    LocalTopology,
    LocalTopologyError,
)

LocalPhase = Literal["smoke", "rehearsal", "scale"]
STAGE_NAMES = ("source", "intermediate", "destination")
ROUTES = ("HH", "HL", "LH", "LL")
PHASE_ROUTE_ATTEMPTS = {"smoke": 10, "rehearsal": 250, "scale": 10_000}
CARRIERS = {"hyperlane": 0, "layerzero-v2": 1}
ROUTE_SEMANTICS = {
    "HH": ("hyperlane", "hyperlane", False),
    "HL": ("hyperlane", "layerzero-v2", True),
    "LH": ("layerzero-v2", "hyperlane", True),
    "LL": ("layerzero-v2", "layerzero-v2", False),
}


@dataclass(frozen=True)
class LocalAttempt:
    attempt_id: bytes
    route: str
    route_index: int
    first_carrier: str
    second_carrier: str
    execution_class: str
    xir: bool
    route_sequence: int
    sequence_index: int
    payload_hash: bytes
    payload_bytes: int


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
            _schema("local-paper-scale-profile-v2.schema.json")
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
    route_rows = [
        (route, route_index, route_sequence)
        for route_index, route in enumerate(ROUTES)
        for route_sequence in range(PHASE_ROUTE_ATTEMPTS[phase])
    ]
    route_rows.sort(
        key=lambda item: _coordinate_digest(
            seed,
            f"{phase}-route-order-v2",
            item[0],
            item[2],
        )
    )
    attempts: list[LocalAttempt] = []
    payload_config = cast(dict[str, int], profile["payload"])
    for route, route_index, route_sequence in route_rows:
        first_carrier, second_carrier, xir = ROUTE_SEMANTICS[route]
        payload_bytes = payload_config["minimum_bytes"] + (
            route_sequence % payload_config["size_bucket_count"]
        ) * payload_config["size_step_bytes"]
        attempt_id = _coordinate_digest(
            seed, f"{phase}-attempt-v2", route, route_sequence
        )
        payload_hash = _coordinate_digest(
            seed,
            f"{phase}-payload-v2",
            route_sequence,
            payload_bytes,
        )
        attempts.append(
            LocalAttempt(
                attempt_id=attempt_id,
                route=route,
                route_index=route_index,
                first_carrier=first_carrier,
                second_carrier=second_carrier,
                execution_class=(
                    "heterogeneous-xir" if xir else "homogeneous-native"
                ),
                xir=xir,
                route_sequence=route_sequence,
                sequence_index=len(attempts),
                payload_hash=payload_hash,
                payload_bytes=payload_bytes,
            )
        )
    expected = PHASE_ROUTE_ATTEMPTS[phase] * len(ROUTES)
    if len(attempts) != expected:
        raise LocalTopologyError("local workload expansion count mismatch")
    route_counts = {
        route: sum(item.route == route for item in attempts)
        for route in ROUTES
    }
    if set(route_counts.values()) != {PHASE_ROUTE_ATTEMPTS[phase]}:
        raise LocalTopologyError("local workload route balance mismatch")
    payload_buckets = {
        route: sorted(item.payload_bytes for item in attempts if item.route == route)
        for route in ROUTES
    }
    if len({tuple(values) for values in payload_buckets.values()}) != 1:
        raise LocalTopologyError("local workload payload balance mismatch")
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
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
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
        CREATE TABLE IF NOT EXISTS local_route_stages (
            attempt_id TEXT NOT NULL,
            stage INTEGER NOT NULL,
            route TEXT NOT NULL,
            route_index INTEGER NOT NULL,
            route_sequence INTEGER NOT NULL,
            sequence_index INTEGER NOT NULL,
            first_carrier TEXT NOT NULL,
            second_carrier TEXT NOT NULL,
            execution_class TEXT NOT NULL,
            xir INTEGER NOT NULL,
            payload_hash TEXT NOT NULL,
            payload_bytes INTEGER NOT NULL,
            chain_id INTEGER NOT NULL,
            network_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            signer_address TEXT NOT NULL,
            transaction_hash TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            retry_generation INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL,
            block_number INTEGER,
            block_hash TEXT,
            block_timestamp INTEGER,
            receipt_status INTEGER,
            gas_limit INTEGER NOT NULL,
            gas_used INTEGER,
            effective_gas_price INTEGER,
            calldata_bytes INTEGER NOT NULL DEFAULT 0,
            calldata_hash TEXT NOT NULL,
            prepared_at REAL NOT NULL,
            submitted_at REAL,
            finalized_at REAL,
            prior_envelope TEXT,
            stage_envelope TEXT,
            xir_transition_digest TEXT,
            route_event_count INTEGER,
            xir_event_count INTEGER,
            application_event_count INTEGER,
            error_class TEXT,
            error_message TEXT,
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

    expected = PHASE_ROUTE_ATTEMPTS[phase] * len(ROUTES) * len(STAGE_NAMES)
    path = runtime_root / "evidence" / f"{phase}.sqlite"
    if not path.is_file():
        raise LocalTopologyError(f"reconciled {phase} evidence is required")
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            row = connection.execute(
                """
                SELECT count(*) FROM local_route_stages
                WHERE state = 'finalized'
                """
            ).fetchone()
    except sqlite3.Error as exc:
        raise LocalTopologyError(f"cannot validate reconciled {phase} evidence") from exc
    if row is None or int(row[0]) != expected:
        raise LocalTopologyError(
            f"reconciled {phase} evidence must contain {expected} finalized stages"
        )


def _envelope(attempt: LocalAttempt, protocol: str, hop: int) -> bytes:
    domain = Web3.keccak(
        text=(
            "CONTROLLED_HYPERLANE_ENVELOPE_V2"
            if protocol == "hyperlane"
            else "CONTROLLED_LAYERZERO_V2_ENVELOPE_V2"
        )
    )
    return bytes(
        Web3.keccak(
            encode(
                ["bytes32", "bytes32", "uint8", "bytes32", "uint32", "uint8"],
                [
                    domain,
                    attempt.attempt_id,
                    attempt.route_index,
                    attempt.payload_hash,
                    attempt.payload_bytes,
                    hop,
                ],
            )
        )
    )


def _prior_digest(attempt: LocalAttempt, stage: int) -> bytes:
    if stage == 0:
        return bytes(32)
    if stage == 1:
        return _envelope(attempt, attempt.first_carrier, 0)
    return _envelope(attempt, attempt.second_carrier, 1)


def _expected_stage_envelope(attempt: LocalAttempt, stage: int) -> bytes:
    protocol = attempt.first_carrier if stage == 0 else attempt.second_carrier
    return _envelope(attempt, protocol, stage)


def _expected_transition(attempt: LocalAttempt) -> bytes | None:
    if not attempt.xir:
        return None
    return bytes(
        Web3.keccak(
            encode(
                [
                    "bytes32",
                    "bytes32",
                    "uint8",
                    "uint8",
                    "uint8",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                ],
                [
                    Web3.keccak(text="XIR_LOCAL_TRANSITION_V2"),
                    attempt.attempt_id,
                    attempt.route_index,
                    CARRIERS[attempt.first_carrier],
                    CARRIERS[attempt.second_carrier],
                    attempt.payload_hash,
                    _envelope(attempt, attempt.first_carrier, 0),
                    _envelope(attempt, attempt.second_carrier, 1),
                ],
            )
        )
    )


def _event_hex(value: Any) -> str:
    return HexBytes(value).to_0x_hex()


def _finalize_stage(
    *,
    connection: sqlite3.Connection,
    web3: Web3,
    contract: Any,
    receipt: Any,
    attempt: LocalAttempt,
    stage: int,
    block_cache: dict[str, Any],
) -> None:
    if int(receipt["status"]) != 1:
        raise LocalTopologyError(
            f"local stage transaction reverted: {_event_hex(receipt['transactionHash'])}"
        )
    route_events = contract.events.RouteStageRecorded().process_receipt(
        receipt, errors=DISCARD
    )
    xir_events = contract.events.XIRTransitionRecorded().process_receipt(
        receipt, errors=DISCARD
    )
    application_events = contract.events.ApplicationEffectRecorded().process_receipt(
        receipt, errors=DISCARD
    )
    expected_xir_events = int(attempt.xir and stage == 1)
    expected_application_events = int(stage == 2)
    if (
        len(route_events) != 1
        or len(xir_events) != expected_xir_events
        or len(application_events) != expected_application_events
    ):
        raise LocalTopologyError("local route event cardinality mismatch")
    route_args = route_events[0]["args"]
    expected_stage_envelope = _expected_stage_envelope(attempt, stage)
    if (
        bytes(route_args["attemptId"]) != attempt.attempt_id
        or int(route_args["route"]) != attempt.route_index
        or int(route_args["stage"]) != stage
        or int(route_args["firstCarrier"]) != CARRIERS[attempt.first_carrier]
        or int(route_args["secondCarrier"]) != CARRIERS[attempt.second_carrier]
        or bool(route_args["xir"]) != attempt.xir
        or bytes(route_args["payloadHash"]) != attempt.payload_hash
        or int(route_args["payloadBytes"]) != attempt.payload_bytes
        or bytes(route_args["priorEnvelope"]) != _prior_digest(attempt, stage)
        or bytes(route_args["stageEnvelope"]) != expected_stage_envelope
    ):
        raise LocalTopologyError("local route event semantic mismatch")
    transition = _expected_transition(attempt)
    if expected_xir_events:
        xir_args = xir_events[0]["args"]
        if (
            bytes(xir_args["transitionDigest"]) != transition
            or bytes(xir_args["inboundEnvelope"])
            != _envelope(attempt, attempt.first_carrier, 0)
            or bytes(xir_args["outboundEnvelope"])
            != _envelope(attempt, attempt.second_carrier, 1)
        ):
            raise LocalTopologyError("local XIR transition event mismatch")
    if expected_application_events:
        application_args = application_events[0]["args"]
        if (
            bytes(application_args["attemptId"]) != attempt.attempt_id
            or bytes(application_args["payloadHash"]) != attempt.payload_hash
        ):
            raise LocalTopologyError("local application event mismatch")

    block_hash = _event_hex(receipt["blockHash"])
    block = block_cache.get(block_hash)
    if block is None:
        block = web3.eth.get_block(receipt["blockHash"])
        block_cache[block_hash] = block
    connection.execute(
        """
        UPDATE local_route_stages
        SET state = 'finalized', block_number = ?, block_hash = ?,
            block_timestamp = ?, receipt_status = ?, gas_used = ?,
            effective_gas_price = ?, finalized_at = ?, prior_envelope = ?,
            stage_envelope = ?, xir_transition_digest = ?,
            route_event_count = ?, xir_event_count = ?,
            application_event_count = ?, error_class = NULL,
            error_message = NULL
        WHERE attempt_id = ? AND stage = ?
        """,
        (
            int(receipt["blockNumber"]),
            block_hash,
            int(block["timestamp"]),
            int(receipt["status"]),
            int(receipt["gasUsed"]),
            int(receipt.get("effectiveGasPrice", 0)),
            time.time(),
            _event_hex(_prior_digest(attempt, stage)),
            _event_hex(expected_stage_envelope),
            _event_hex(transition) if transition is not None and stage == 1 else None,
            len(route_events),
            len(xir_events),
            len(application_events),
            _event_hex(attempt.attempt_id),
            stage,
        ),
    )
    connection.commit()


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
    block_cache: dict[str, Any] = {}
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
                        FROM local_route_stages
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
                            _finalize_stage(
                                connection=connection,
                                web3=web3,
                                contract=contract,
                                receipt=recovered_receipt,
                                attempt=attempt,
                                stage=stage,
                                block_cache=block_cache,
                            )
                            spool_path.unlink(missing_ok=True)
                            continue
                    else:
                        transaction = contract.functions.recordRouteStage(
                            attempt.attempt_id,
                            attempt.route_index,
                            CARRIERS[attempt.first_carrier],
                            CARRIERS[attempt.second_carrier],
                            attempt.xir,
                            attempt.payload_hash,
                            attempt.payload_bytes,
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
                            INSERT INTO local_route_stages (
                                attempt_id, stage, route, route_index,
                                route_sequence, sequence_index, first_carrier,
                                second_carrier, execution_class, xir,
                                payload_hash, payload_bytes, chain_id, network_id,
                                contract_address, signer_address,
                                transaction_hash, nonce, state, gas_limit,
                                calldata_bytes, calldata_hash, prepared_at
                            ) VALUES (
                                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                ?, ?, 'prepared', ?, ?, ?, ?
                            )
                            """,
                            (
                                attempt_hex,
                                stage,
                                attempt.route,
                                attempt.route_index,
                                attempt.route_sequence,
                                attempt.sequence_index,
                                attempt.first_carrier,
                                attempt.second_carrier,
                                attempt.execution_class,
                                int(attempt.xir),
                                _event_hex(attempt.payload_hash),
                                attempt.payload_bytes,
                                network.chain_id,
                                network.network_id,
                                str(contracts[stage]["address"]),
                                runner.address,
                                transaction_hash,
                                next_nonce,
                                300_000,
                                len(
                                    HexBytes(
                                        cast(str, transaction["data"])
                                    )
                                ),
                                Web3.keccak(
                                    HexBytes(cast(str, transaction["data"]))
                                ).to_0x_hex(),
                                time.time(),
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
                        UPDATE local_route_stages
                        SET state = 'submitted', submitted_at = ?
                        WHERE attempt_id = ? AND stage = ?
                        """,
                        (time.time(), attempt_hex, stage),
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
                    _finalize_stage(
                        connection=connection,
                        web3=web3,
                        contract=contract,
                        receipt=receipt,
                        attempt=attempt,
                        stage=stage,
                        block_cache=block_cache,
                    )
                    spool_path.unlink(missing_ok=True)
        row = connection.execute(
            """
            SELECT count(*), coalesce(sum(gas_used), 0),
                   coalesce(sum(calldata_bytes), 0),
                   min(prepared_at), max(finalized_at),
                   coalesce(sum(xir_event_count), 0),
                   coalesce(sum(application_event_count), 0)
            FROM local_route_stages WHERE state = 'finalized'
            """
        ).fetchone()
        finalized = int(row[0])
        gas_used = int(row[1])
        calldata_bytes = int(row[2])
        first_submitted_at = float(row[3])
        last_finalized_at = float(row[4])
        xir_transitions = int(row[5])
        application_effects = int(row[6])
        expected = len(attempts) * 3
        if finalized != expected:
            raise LocalTopologyError("local workload physical reconciliation failed")
        expected_xir = sum(attempt.xir for attempt in attempts)
        if xir_transitions != expected_xir or application_effects != len(attempts):
            raise LocalTopologyError("local workload event reconciliation failed")
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        return {
            "schema_version": "xir-lab-local-paper-phase-summary-v2",
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
            "route_counts": {
                route: sum(attempt.route == route for attempt in attempts)
                for route in ROUTES
            },
            "xir_transitions": xir_transitions,
            "application_effects": application_effects,
            "gas_used": gas_used,
            "calldata_bytes": calldata_bytes,
            "rpc_requests": rpc_requests,
            "elapsed_seconds": last_finalized_at - first_submitted_at,
            "evidence_path": str(evidence_path),
            "evidence_sha256": evidence_sha256,
        }
    finally:
        connection.close()
