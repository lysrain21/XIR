"""Deterministic statistics and reconciliation for the multihop campaign."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import sqlite3
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal, cast

import numpy as np
import rfc8785
import yaml
from eth_abi.abi import encode
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_freeze_v2 import secret_scan as scan_secrets
from xir_lab.native.multihop_deployer import (
    REGISTRY_VERSION,
    adapter_key,
    multihop_gateway_typed_id,
    multihop_profile_hash,
)
from xir_lab.native.multihop_effects import _expected_effect_lineage, validate_effect_audit
from xir_lab.native.multihop_hyperlane_observer import load_hyperlane_observer_events
from xir_lab.native.multihop_identity import config_identity, phase_role
from xir_lab.native.multihop_process_identity import process_identity_sha256
from xir_lab.native.multihop_scalability import (
    ROUTE_ORDER,
    MultihopPhase,
    expected_coordinator_transactions,
    expected_physical_transactions,
    iter_multihop_attempts,
    load_multihop_config,
    switch_count,
)
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

Metric = Literal["gas", "calldata_bytes", "latency_seconds"]
METRICS: tuple[Metric, ...] = ("gas", "calldata_bytes", "latency_seconds")
EQUIVALENCE_ROUTES = (("HH", "HL"), ("HHH", "HHL"), ("HHHH", "HHHL"))
APPROVED_VERIFIER_SELECTOR = "0x" + keccak(text="verify(bytes32,bytes32,bytes32)").hex()[:8]
HYPERLANE_PROCESS_TOPIC = "0x" + keccak(text="ProcessId(bytes32)").hex()
ENVELOPE_ABI_TYPE = (
    "(((uint8,bytes),(uint8,bytes),(uint8,bytes),uint64,bytes32),"
    "(uint8,bytes32),(uint32,bytes),"
    "((uint8,bytes),(uint8,bytes),bytes32,bytes32,bytes32,bytes32)[])"
)
TAIL_LATENCY_REPORTING: dict[str, Any] = {
    "p95": "descriptive_point_estimate",
    "p99": "descriptive_point_estimate",
    "dependence_aware_interval_required": False,
    "release_gate": False,
    "scope": "shared_host_alpha_system",
}


def _tail_latency_reporting_from_preregistration(path: Path) -> dict[str, Any]:
    document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    estimands = document.get("estimands")
    if not isinstance(estimands, dict):
        raise LocalTopologyError("preregistration estimands are absent")
    boundary = estimands.get("tail_latency_reporting")
    if boundary != TAIL_LATENCY_REPORTING:
        raise LocalTopologyError("preregistered tail-latency reporting boundary drift")
    return dict(TAIL_LATENCY_REPORTING)


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bound_process_identity(detail_json: str, expected_digest: str) -> dict[str, Any]:
    """Recover and verify the public stable identity bound to one clock row."""

    detail = cast(dict[str, Any], json.loads(detail_json))
    identity = detail.get("_process_identity")
    if not isinstance(identity, dict):
        raise LocalTopologyError("stable process identity document is absent")
    document = cast(dict[str, Any], identity)
    if (
        document.get("schema_version") != "xir-lab-native-multihop-process-identity-v1"
        or process_identity_sha256(document) != expected_digest
    ):
        raise LocalTopologyError("stable process identity binding is invalid")
    return document


def _encoded_application_payload(
    *, config: dict[str, Any], phase: MultihopPhase, sequence: int, attempt_id: str, route: str
) -> bytes:
    schedule = cast(dict[str, int], config["payload_schedule"])
    size = (
        schedule["minimum_bytes"]
        + (sequence % schedule["size_bucket_count"]) * schedule["size_step_bytes"]
    )
    material = f"xir-multihop-v1:{config['fixed_seed']}:{phase}:{sequence}".encode()
    application = bytearray()
    counter = 0
    while len(application) < size:
        application.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return encode(
        ["(bytes32,bytes,uint64,bytes)"],
        [
            (
                keccak(text=attempt_id),
                route.encode("ascii"),
                sequence,
                bytes(application[:size]),
            )
        ],
    )


def _encoded_envelope_size(
    record: XIRRecord, context: XIRContext, receipts: list[XIRReceipt]
) -> int:
    # The root signature is always a 65-byte ECDSA signature.  ABI encoded size
    # depends on dynamic lengths, not the signature values, so a zero-filled
    # public placeholder produces the exact byte length without freezing a key.
    envelope = (
        record_tuple(record),
        (context.required_security, context.policy_hash),
        (REGISTRY_VERSION, bytes(65)),
        [receipt_tuple(receipt) for receipt in receipts],
    )
    return len(encode([ENVELOPE_ABI_TYPE], [envelope]))


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({field for row in rows for field in row})
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _coefficient_rows(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten fitted coefficients and dependence-aware intervals for audit."""

    rows: list[dict[str, Any]] = []
    for model in models:
        linear = cast(dict[str, Any], model["linear"])
        coefficients = cast(dict[str, float], linear["coefficients"])
        intervals = cast(dict[str, dict[str, float]], model["coefficient_intervals"])
        for coefficient in sorted(coefficients):
            interval = intervals[coefficient]
            rows.append(
                {
                    "metric": model["metric"],
                    "coefficient": coefficient,
                    "estimate": coefficients[coefficient],
                    "ci_low": interval["ci_low"],
                    "ci_high": interval["ci_high"],
                    "confidence": interval["confidence"],
                    "n": linear["n"],
                    "r_squared": linear["r_squared"],
                    "sample_role": model["sample_role"],
                    "superlinear_anomaly": model["superlinear_anomaly"],
                }
            )
    return rows


def _public_event_rows(runner_state_path: Path, phase: MultihopPhase) -> list[dict[str, Any]]:
    """Export clock boundaries without copying private or raw transaction material."""

    with sqlite3.connect(f"file:{runner_state_path}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT e.* FROM events e
            JOIN attempts a ON a.attempt_id=e.attempt_id
            WHERE a.phase=? ORDER BY e.event_id
            """,
            (phase,),
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        identity_digest = str(row["process_identity_sha256"])
        identity = _bound_process_identity(str(row["detail_json"]), identity_digest)
        result.append(
            {
                "event_id": int(row["event_id"]),
                "attempt_id": str(row["attempt_id"]),
                "stage": str(row["stage"]),
                "event": str(row["event"]),
                "source": str(row["source"]),
                "chain_role": row["chain_role"],
                "hop_index": row["hop_index"],
                "transaction_hash": row["transaction_hash"],
                "utc_ns": int(row["utc_ns"]),
                "monotonic_ns": int(row["monotonic_ns"]),
                "boot_id": str(row["boot_id"]),
                "process_id": int(row["process_id"]),
                "process_identity_sha256": identity_digest,
                "process_identity": identity,
                "thread_id": int(row["thread_id"]),
                "detail_semantic_sha256": hashlib.sha256(
                    rfc8785.dumps(json.loads(str(row["detail_json"])))
                ).hexdigest(),
            }
        )
    return result


def _resource_summary(path: Path, event_rows: list[dict[str, Any]]) -> dict[str, Any]:
    samples = [
        cast(dict[str, Any], json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if (
        len(samples) < 2
        or [int(row.get("sequence", -1)) for row in samples] != list(range(len(samples)))
        or any(
            row.get("schema_version") != "xir-lab-native-multihop-resource-sample-v1"
            for row in samples
        )
    ):
        raise LocalTopologyError("resource monitor inventory is incomplete")
    utc_values = [int(row["utc_ns"]) for row in samples]
    monotonic_values = [int(row["monotonic_ns"]) for row in samples]
    if utc_values != sorted(utc_values) or monotonic_values != sorted(monotonic_values):
        raise LocalTopologyError("resource monitor clocks are not monotonic")
    event_utc = [int(row["utc_ns"]) for row in event_rows]
    if not event_utc or utc_values[0] > min(event_utc) or utc_values[-1] < max(event_utc):
        raise LocalTopologyError("resource monitor does not cover the campaign events")

    def process_ids(name: str) -> list[int]:
        return sorted(
            {
                int(process["pid"])
                for sample in samples
                for process in cast(list[dict[str, Any]], sample["processes"])
                if process.get("name") == name
                and process.get("healthy") is True
                and process.get("pid") is not None
            }
        )

    loads = [float(cast(list[float], row["load_average"])[0]) for row in samples]
    memory = [int(cast(dict[str, Any], row["memory"])["available_bytes"]) for row in samples]
    disk = [int(cast(dict[str, Any], row["runtime_disk"])["available_bytes"]) for row in samples]
    gap_rows = [
        {"sequence": int(sample["sequence"]), **gap}
        for sample in samples
        for gap in cast(list[dict[str, Any]], sample["gaps"])
    ]
    return {
        "schema_version": "xir-lab-native-multihop-resource-summary-v1",
        "source_sha256": _sha256_path(path),
        "sample_count": len(samples),
        "first_utc_ns": utc_values[0],
        "last_utc_ns": utc_values[-1],
        "campaign_event_coverage": True,
        "boot_ids": sorted({str(row["boot_id"]) for row in samples}),
        "load_average_1m": {
            "median": float(np.median(loads)),
            "p95": float(np.quantile(loads, 0.95)),
            "maximum": max(loads),
        },
        "minimum_memory_available_bytes": min(memory),
        "minimum_runtime_disk_available_bytes": min(disk),
        "runner_process_ids": process_ids("runner"),
        "layerzero_worker_process_ids": process_ids("layerzero-worker"),
        "monitor_gap_count": len(gap_rows),
        "monitor_gaps": gap_rows,
        "latency_exclusion_policy": (
            "resource_load_is_reported_as_context_only; only preregistered complete "
            "sequence-block interruption reasons enter sensitivity exclusions"
        ),
    }


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            document = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"multihop evidence RPC failed: {method}") from exc
    if not isinstance(document, dict) or document.get("error") is not None:
        raise LocalTopologyError(f"multihop evidence RPC error: {method}")
    return document.get("result")


def capture_hyperlane_processes(
    *,
    profile_path: Path,
    runtime_root: Path,
    start_blocks: dict[str, int],
    end_blocks: dict[str, int],
    observer_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    profile = cast(dict[str, Any], json.loads(profile_path.read_text(encoding="utf-8")))
    observer_events = load_hyperlane_observer_events(observer_path)
    observer_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observer_events:
        transaction_hash = row.get("transaction_hash")
        if isinstance(transaction_hash, str) and transaction_hash:
            observer_by_hash[transaction_hash.lower()].append(row)
    messages: dict[str, dict[str, Any]] = {}
    for index, chain in enumerate(cast(list[dict[str, Any]], profile["chains"])):
        role = chr(ord("a") + index)
        if role == "a":
            continue
        if role not in start_blocks or role not in end_blocks:
            raise LocalTopologyError(f"missing Hyperlane process scan bounds: {role}")
        name = f"xirlocalchain{role}"
        address_path = runtime_root / "hyperlane/registry/chains" / name / "addresses.yaml"
        addresses = yaml.safe_load(address_path.read_text(encoding="utf-8"))
        mailbox = str(addresses["mailbox"]).lower()
        default_ism = str(addresses["defaultIsm"]).lower()
        rpc_url = str(chain["rpc_url"])
        for first in range(start_blocks[role], end_blocks[role] + 1, 2000):
            logs = _rpc(
                rpc_url,
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(first),
                        "toBlock": hex(min(first + 1999, end_blocks[role])),
                        "address": mailbox,
                        "topics": [HYPERLANE_PROCESS_TOPIC],
                    }
                ],
            )
            if not isinstance(logs, list):
                raise LocalTopologyError("Hyperlane process log query is invalid")
            for log in logs:
                if not isinstance(log, dict) or len(log.get("topics", [])) < 2:
                    raise LocalTopologyError("Hyperlane ProcessId log is invalid")
                message_id = str(log["topics"][1]).lower()
                transaction_hash = str(log["transactionHash"]).lower()
                if message_id in messages:
                    raise LocalTopologyError(f"duplicate Hyperlane ProcessId: {message_id}")
                transaction = _rpc(rpc_url, "eth_getTransactionByHash", [transaction_hash])
                receipt = _rpc(rpc_url, "eth_getTransactionReceipt", [transaction_hash])
                if not isinstance(transaction, dict) or not isinstance(receipt, dict):
                    raise LocalTopologyError("Hyperlane process transaction is unavailable")
                transaction_target = str(transaction.get("to", "")).lower()
                if transaction_target != mailbox:
                    raise LocalTopologyError(
                        "Hyperlane process transaction target is not the frozen Mailbox"
                    )
                boundaries = observer_by_hash.get(transaction_hash, [])
                submitted = [row for row in boundaries if row.get("event") == "submitted_observed"]
                mined = [row for row in boundaries if row.get("event") == "mined_observed"]
                identities_valid = True
                for boundary in submitted + mined:
                    for prefix in ("observer", "relayer"):
                        identity = boundary.get(f"{prefix}_process_identity")
                        digest = str(boundary.get(f"{prefix}_process_identity_sha256", ""))
                        identities_valid = (
                            identities_valid
                            and isinstance(identity, dict)
                            and identity.get("schema_version")
                            == "xir-lab-native-multihop-process-identity-v1"
                            and process_identity_sha256(cast(dict[str, Any], identity)) == digest
                        )
                stable_identity = (
                    len(submitted) == 1
                    and len(mined) == 1
                    and identities_valid
                    and len({str(row["boot_id"]) for row in boundaries}) == 1
                    and all(str(row.get("chain_role")) == role for row in boundaries)
                    and int(submitted[0]["utc_ns"]) <= int(mined[0]["utc_ns"])
                    and int(submitted[0]["monotonic_ns"]) <= int(mined[0]["monotonic_ns"])
                )
                if not stable_identity:
                    raise LocalTopologyError(
                        "Hyperlane process transaction lacks stable dual-clock observer boundaries"
                    )
                call_data = bytes.fromhex(str(transaction["input"]).removeprefix("0x"))
                messages[message_id] = {
                    "chain_role": role,
                    "chain_id": int(chain["chain_id"]),
                    "message_id": message_id,
                    "transaction_hash": transaction_hash,
                    "mailbox": mailbox,
                    "default_ism": default_ism,
                    "block_number": int(str(receipt["blockNumber"]), 16),
                    "transaction_index": int(str(receipt["transactionIndex"]), 16),
                    "status": int(str(receipt["status"]), 16),
                    "gas_used": int(str(receipt["gasUsed"]), 16),
                    "calldata_bytes": len(call_data),
                    "calldata_sha256": hashlib.sha256(call_data).hexdigest(),
                    "receipt_semantic_sha256": hashlib.sha256(rfc8785.dumps(receipt)).hexdigest(),
                    "observer_boundary_valid": True,
                    "observer_boot_id": str(submitted[0]["boot_id"]),
                    "observer_process_id": int(submitted[0]["observer_process_id"]),
                    "relayer_process_id": int(submitted[0]["relayer_process_id"]),
                    "submitted_observer_process_id": int(submitted[0]["observer_process_id"]),
                    "submitted_observer_process_identity_sha256": str(
                        submitted[0]["observer_process_identity_sha256"]
                    ),
                    "submitted_observer_process_identity": submitted[0][
                        "observer_process_identity"
                    ],
                    "mined_observer_process_id": int(mined[0]["observer_process_id"]),
                    "mined_observer_process_identity_sha256": str(
                        mined[0]["observer_process_identity_sha256"]
                    ),
                    "mined_observer_process_identity": mined[0]["observer_process_identity"],
                    "submitted_relayer_process_id": int(submitted[0]["relayer_process_id"]),
                    "submitted_relayer_process_identity_sha256": str(
                        submitted[0]["relayer_process_identity_sha256"]
                    ),
                    "submitted_relayer_process_identity": submitted[0]["relayer_process_identity"],
                    "mined_relayer_process_id": int(mined[0]["relayer_process_id"]),
                    "mined_relayer_process_identity_sha256": str(
                        mined[0]["relayer_process_identity_sha256"]
                    ),
                    "mined_relayer_process_identity": mined[0]["relayer_process_identity"],
                    "restart_crossing": (
                        str(submitted[0]["observer_process_identity_sha256"])
                        != str(mined[0]["observer_process_identity_sha256"])
                        or str(submitted[0]["relayer_process_identity_sha256"])
                        != str(mined[0]["relayer_process_identity_sha256"])
                    ),
                    # Nanosecond clocks exceed the RFC 8785 / IEEE-754 safe
                    # integer domain on real hosts.  Preserve their exact
                    # values as canonical decimal strings; every comparison
                    # above and every downstream duration calculation parses
                    # them explicitly with int().
                    "submitted_utc_ns": str(int(submitted[0]["utc_ns"])),
                    "submitted_monotonic_ns": str(int(submitted[0]["monotonic_ns"])),
                    "submitted_source": str(submitted[0]["source"]),
                    "mined_utc_ns": str(int(mined[0]["utc_ns"])),
                    "mined_monotonic_ns": str(int(mined[0]["monotonic_ns"])),
                    "mined_source": str(mined[0]["source"]),
                }
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-hyperlane-processes-v1",
        "start_blocks": start_blocks,
        "end_blocks": end_blocks,
        "observer_sha256": hashlib.sha256(observer_path.read_bytes()).hexdigest(),
        "observer_event_count": len(observer_events),
        "messages": messages,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    _write_json(output_path, document)
    return document


def moving_block_interval(
    values: list[float],
    *,
    repetitions: int,
    block_length: int,
    confidence: float,
    seed: int,
    statistic: Literal["mean", "median"] = "mean",
) -> tuple[float, float, float]:
    if not values or repetitions <= 0 or block_length <= 0 or not 0 < confidence < 1:
        raise LocalTopologyError("invalid moving-block bootstrap input")
    data = np.asarray(values, dtype=float)
    n = len(data)
    block = min(block_length, n)
    blocks = math.ceil(n / block)
    rng = np.random.default_rng(seed)
    samples = np.empty(repetitions, dtype=float)
    for index in range(repetitions):
        starts = rng.integers(0, n, size=blocks)
        selected = np.concatenate([np.arange(start, start + block) % n for start in starts])[:n]
        sample = data[selected]
        samples[index] = float(np.mean(sample)) if statistic == "mean" else float(np.median(sample))
    alpha = (1.0 - confidence) / 2.0
    point = float(np.mean(data)) if statistic == "mean" else float(np.median(data))
    return point, float(np.quantile(samples, alpha)), float(np.quantile(samples, 1 - alpha))


def linear_model(
    rows: list[dict[str, Any]],
    *,
    response: str,
    predictors: tuple[str, ...],
) -> dict[str, Any]:
    if len(rows) <= len(predictors) + 1:
        raise LocalTopologyError("linear model is underdetermined")
    design = np.asarray(
        [[1.0, *(float(row[name]) for name in predictors)] for row in rows],
        dtype=float,
    )
    values = np.asarray([float(row[response]) for row in rows], dtype=float)
    coefficients, _, rank, _ = np.linalg.lstsq(design, values, rcond=None)
    if rank != design.shape[1]:
        raise LocalTopologyError("linear model design is rank deficient")
    fitted = design @ coefficients
    residual = values - fitted
    total = float(np.sum((values - np.mean(values)) ** 2))
    r_squared = 1.0 if total == 0 else 1.0 - float(np.sum(residual**2)) / total
    return {
        "n": len(rows),
        "response": response,
        "predictors": ["intercept", *predictors],
        "coefficients": {
            name: float(value)
            for name, value in zip(("intercept", *predictors), coefficients, strict=True)
        },
        "r_squared": r_squared,
        "residual_mean": float(np.mean(residual)),
        "residual_rmse": float(np.sqrt(np.mean(residual**2))),
    }


def bootstrap_coefficient_intervals(
    rows: list[dict[str, Any]],
    *,
    response: str,
    predictors: tuple[str, ...],
    repetitions: int,
    block_length: int,
    confidence: float,
    seed: int,
) -> dict[str, dict[str, float]]:
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["sequence"])].append(row)
    sequences = sorted(grouped)
    if not sequences:
        raise LocalTopologyError("coefficient bootstrap has no matched blocks")
    coefficient_names = ("intercept", *predictors)
    point = cast(
        dict[str, float],
        linear_model(rows, response=response, predictors=predictors)["coefficients"],
    )
    sequence_xtx: list[np.ndarray] = []
    sequence_xty: list[np.ndarray] = []
    sequence_index = {sequence: index for index, sequence in enumerate(sequences)}
    for sequence in sequences:
        sequence_rows = grouped[sequence]
        design = np.asarray(
            [[1.0, *(float(row[name]) for name in predictors)] for row in sequence_rows],
            dtype=float,
        )
        values = np.asarray([float(row[response]) for row in sequence_rows], dtype=float)
        sequence_xtx.append(design.T @ design)
        sequence_xty.append(design.T @ values)
    xtx_by_sequence = np.asarray(sequence_xtx)
    xty_by_sequence = np.asarray(sequence_xty)
    block = min(block_length, len(sequences))
    blocks = math.ceil(len(sequences) / block)
    rng = np.random.default_rng(seed)
    estimates: dict[str, list[float]] = {name: [] for name in coefficient_names}
    for _ in range(repetitions):
        starts = rng.integers(0, len(sequences), size=blocks)
        selected = [
            sequences[index % len(sequences)]
            for start in starts
            for index in range(start, start + block)
        ][: len(sequences)]
        counts = np.bincount(
            [sequence_index[sequence] for sequence in selected],
            minlength=len(sequences),
        ).astype(float)
        xtx = np.tensordot(counts, xtx_by_sequence, axes=(0, 0))
        xty = np.tensordot(counts, xty_by_sequence, axes=(0, 0))
        try:
            coefficients = np.linalg.solve(xtx, xty)
        except np.linalg.LinAlgError as exc:
            raise LocalTopologyError("bootstrap linear model design is rank deficient") from exc
        for name, value in zip(coefficient_names, coefficients, strict=True):
            estimates[name].append(float(value))
    alpha = (1 - confidence) / 2
    return {
        name: {
            "estimate": float(point[name]),
            "ci_low": float(np.quantile(estimates[name], alpha)),
            "ci_high": float(np.quantile(estimates[name], 1 - alpha)),
            "confidence": confidence,
        }
        for name in coefficient_names
    }


def bootstrap_coefficient_interval(
    rows: list[dict[str, Any]],
    *,
    response: str,
    predictors: tuple[str, ...],
    coefficient: str,
    repetitions: int,
    block_length: int,
    confidence: float,
    seed: int,
) -> tuple[float, float, float]:
    intervals = bootstrap_coefficient_intervals(
        rows,
        response=response,
        predictors=predictors,
        repetitions=repetitions,
        block_length=block_length,
        confidence=confidence,
        seed=seed,
    )
    if coefficient not in intervals:
        raise LocalTopologyError(f"unknown bootstrap coefficient: {coefficient}")
    selected = intervals[coefficient]
    return selected["estimate"], selected["ci_low"], selected["ci_high"]


def summarize_attempt_metrics(
    rows: list[dict[str, Any]],
    *,
    config: dict[str, Any],
    incident_sequences: set[int] | None = None,
) -> dict[str, Any]:
    expected_per_route = int(config["attempts_per_route"]["scale"])
    by_route: dict[str, list[dict[str, Any]]] = {
        route: sorted(
            [row for row in rows if row["route"] == route],
            key=lambda row: int(row["sequence"]),
        )
        for route in ROUTE_ORDER
    }
    if any(len(values) != expected_per_route for values in by_route.values()):
        raise LocalTopologyError(
            f"formal attempt metrics are not 11 routes x {expected_per_route:,}"
        )
    sequence_sets = {
        route: {int(row["sequence"]) for row in values} for route, values in by_route.items()
    }
    if any(values != set(range(expected_per_route)) for values in sequence_sets.values()):
        raise LocalTopologyError("formal matched sequences are incomplete")
    for row in rows:
        route = str(row["route"])
        if int(row["coordinator_transactions"]) != expected_coordinator_transactions(route):
            raise LocalTopologyError("observed coordinator transaction count differs from theory")
        if int(row["physical_transactions"]) != expected_physical_transactions(route):
            raise LocalTopologyError("observed physical transaction count differs from theory")

    invalid_latency_sequences = sorted(
        (
            {
                int(row["sequence"])
                for row in rows
                if not math.isfinite(float(row["latency_seconds"]))
                or not bool(row.get("latency_clock_valid", True))
            }
            | (incident_sequences or set())
        )
    )
    latency_rows = [row for row in rows if int(row["sequence"]) not in invalid_latency_sequences]
    expected_latency_rows = (expected_per_route - len(invalid_latency_sequences)) * len(ROUTE_ORDER)
    if len(latency_rows) != expected_latency_rows or any(
        not math.isfinite(float(row["latency_seconds"])) for row in latency_rows
    ):
        raise LocalTopologyError("latency sensitivity is not composed of complete 11-route blocks")

    bootstrap = cast(dict[str, Any], config["bootstrap"])
    predictors = ("hop_count", "switch_count", "starts_with_l")
    experiment_one_routes = set(
        cast(
            list[str],
            cast(dict[str, Any], config["experiments"])["switch_count_scalability"],
        )
    )
    models: list[dict[str, Any]] = []
    for metric in METRICS:
        model_rows = [
            row
            for row in (latency_rows if metric == "latency_seconds" else rows)
            if str(row["route"]) in experiment_one_routes
        ]
        model = linear_model(model_rows, response=metric, predictors=predictors)
        seed = int.from_bytes(
            hashlib.sha256(f"model:{metric}:{bootstrap['seed']}".encode()).digest()[:8],
            "big",
        )
        coefficient_intervals = bootstrap_coefficient_intervals(
            model_rows,
            response=metric,
            predictors=predictors,
            repetitions=int(bootstrap["repetitions"]),
            block_length=int(bootstrap["block_length"]),
            confidence=float(bootstrap["confidence"]),
            seed=seed,
        )
        quadratic = linear_model(
            [{**row, "switch_squared": float(row["switch_count"]) ** 2} for row in model_rows],
            response=metric,
            predictors=(*predictors, "switch_squared"),
        )
        models.append(
            {
                "metric": metric,
                "routes": sorted(experiment_one_routes),
                "sample_role": (
                    "interruption_free_complete_blocks_sensitivity"
                    if metric == "latency_seconds"
                    else "primary_all_validated_effects"
                ),
                "linear": model,
                "coefficient_intervals": coefficient_intervals,
                "switch_marginal": {
                    **coefficient_intervals["switch_count"],
                    "confidence": bootstrap["confidence"],
                },
                "hop_marginal": coefficient_intervals["hop_count"],
                "direction_marginal": coefficient_intervals["starts_with_l"],
                "quadratic_diagnostic": quadratic,
                "superlinear_anomaly": (
                    abs(float(quadratic["coefficients"]["switch_squared"]))
                    > abs(float(model["coefficients"]["switch_count"])) * 0.25
                    and float(quadratic["r_squared"]) - float(model["r_squared"]) > 0.01
                ),
            }
        )
    full_latency_model_rows = [
        row
        for row in rows
        if str(row["route"]) in experiment_one_routes
        and math.isfinite(float(row["latency_seconds"]))
    ]
    if not full_latency_model_rows:
        raise LocalTopologyError("full-sample latency model has no valid clock rows")
    full_latency_model = linear_model(
        full_latency_model_rows,
        response="latency_seconds",
        predictors=predictors,
    )
    full_latency_intervals = bootstrap_coefficient_intervals(
        full_latency_model_rows,
        response="latency_seconds",
        predictors=predictors,
        repetitions=int(bootstrap["repetitions"]),
        block_length=int(bootstrap["block_length"]),
        confidence=float(bootstrap["confidence"]),
        seed=int.from_bytes(
            hashlib.sha256(f"model:latency_seconds:full:{bootstrap['seed']}".encode()).digest()[:8],
            "big",
        ),
    )
    full_latency_quadratic = linear_model(
        [
            {**row, "switch_squared": float(row["switch_count"]) ** 2}
            for row in full_latency_model_rows
        ],
        response="latency_seconds",
        predictors=(*predictors, "switch_squared"),
    )
    models.append(
        {
            "metric": "latency_seconds",
            "routes": sorted(experiment_one_routes),
            "sample_role": "primary_all_finite_clock_attempts_including_incidents",
            "linear": full_latency_model,
            "coefficient_intervals": full_latency_intervals,
            "switch_marginal": full_latency_intervals["switch_count"],
            "hop_marginal": full_latency_intervals["hop_count"],
            "direction_marginal": full_latency_intervals["starts_with_l"],
            "quadratic_diagnostic": full_latency_quadratic,
            "superlinear_anomaly": (
                abs(float(full_latency_quadratic["coefficients"]["switch_squared"]))
                > abs(float(full_latency_model["coefficients"]["switch_count"])) * 0.25
                and float(full_latency_quadratic["r_squared"])
                - float(full_latency_model["r_squared"])
                > 0.01
            ),
        }
    )

    cell_rows: list[dict[str, Any]] = []
    for route, values in by_route.items():
        for metric in METRICS:
            samples = (
                [
                    (
                        "primary_all_finite_clock_attempts_including_incidents",
                        [row for row in values if math.isfinite(float(row[metric]))],
                    ),
                    (
                        "interruption_free_complete_blocks_sensitivity",
                        [
                            row
                            for row in values
                            if int(row["sequence"]) not in invalid_latency_sequences
                        ],
                    ),
                ]
                if metric == "latency_seconds"
                else [("primary_all_validated_effects", values)]
            )
            for sample_role, selected in samples:
                series = [float(row[metric]) for row in selected]
                cell_rows.append(
                    {
                        "route": route,
                        "hop_count": len(route),
                        "switch_count": switch_count(route),
                        "metric": metric,
                        "n": len(series),
                        "sample_role": sample_role,
                        "mean": float(np.mean(series)),
                        "median": float(np.median(series)),
                        "p95": float(np.quantile(series, 0.95)),
                        "p99": float(np.quantile(series, 0.99)),
                        "tail_point_estimates_role": (
                            "descriptive" if metric == "latency_seconds" else "not_applicable"
                        ),
                        "tail_scope": (
                            "shared_host_alpha_system"
                            if metric == "latency_seconds"
                            else "not_applicable"
                        ),
                        "tail_inferential": False,
                        "tail_release_gate": False,
                    }
                )

    lookup = {(str(row["route"]), int(row["sequence"])): row for row in rows}
    equivalence_rows: list[dict[str, Any]] = []
    bounds = cast(dict[str, float], config["equivalence_bounds"])
    for metric, source_metric, bound_key in (
        (
            "latency_seconds",
            "core_switch_latency_seconds",
            "latency_seconds_per_prefix_receipt",
        ),
        ("gas", "core_switch_gas", "gas_per_prefix_receipt"),
        (
            "calldata_bytes",
            "core_switch_calldata_bytes",
            "calldata_bytes_per_prefix_receipt",
        ),
    ):
        sample_specs: list[tuple[str, list[int]]]
        if metric == "latency_seconds":
            required_routes = {switched for _, switched in EQUIVALENCE_ROUTES}
            full_sequences = [
                sequence
                for sequence in range(expected_per_route)
                if all(
                    math.isfinite(float(lookup[(route, sequence)][source_metric]))
                    for route in required_routes
                )
            ]
            sample_specs = [
                ("primary_all_finite_clock_blocks_including_incidents", full_sequences),
                (
                    "interruption_free_complete_blocks_sensitivity",
                    [
                        sequence
                        for sequence in full_sequences
                        if sequence not in invalid_latency_sequences
                    ],
                ),
            ]
        else:
            sample_specs = [("primary_all_validated_effects", list(range(expected_per_route)))]
        for sample_role, sequences in sample_specs:
            fit_rows = []
            for _homogeneous, switched in EQUIVALENCE_ROUTES:
                for sequence in sequences:
                    source = lookup[(switched, sequence)]
                    fit_rows.append(
                        {
                            "sequence": sequence,
                            "prefix_receipt_count": int(source["prefix_receipt_count"]),
                            "core_switch_cost": float(source[source_metric]),
                        }
                    )
            if not fit_rows:
                raise LocalTopologyError("equivalence sample has no complete blocks")
            seed = int.from_bytes(
                hashlib.sha256(
                    f"equivalence:{metric}:{sample_role}:{bootstrap['seed']}".encode()
                ).digest()[:8],
                "big",
            )
            estimate, low, high = bootstrap_coefficient_interval(
                fit_rows,
                response="core_switch_cost",
                predictors=("prefix_receipt_count",),
                coefficient="prefix_receipt_count",
                repetitions=int(bootstrap["repetitions"]),
                block_length=int(bootstrap["block_length"]),
                confidence=float(bounds["confidence"]),
                seed=seed,
            )
            bound = float(bounds[bound_key])
            equivalence_rows.append(
                {
                    "metric": metric,
                    "estimand": (
                        "direct_transition_transaction_plus_approved_prior_verifier_"
                        "call_slope_per_prefix_receipt"
                    ),
                    "source_metric": source_metric,
                    "estimate": estimate,
                    "ci_low": low,
                    "ci_high": high,
                    "confidence": bounds["confidence"],
                    "lower_bound": -bound,
                    "upper_bound": bound,
                    "lower_one_sided_test_pass": low > -bound,
                    "upper_one_sided_test_pass": high < bound,
                    "tost_pass": low > -bound and high < bound,
                    "equivalent": low > -bound and high < bound,
                    "n": len(fit_rows),
                    "matched_sequence_count": len(sequences),
                    "sample_role": sample_role,
                }
            )

    paired_rows: list[dict[str, Any]] = []
    calibrated_rows: list[dict[str, Any]] = []
    for homogeneous, switched in EQUIVALENCE_ROUTES:
        for metric in METRICS:
            sample_specs = (
                [
                    (
                        "primary_all_finite_clock_blocks_including_incidents",
                        [
                            sequence
                            for sequence in range(expected_per_route)
                            if all(
                                math.isfinite(float(lookup[(route, sequence)][metric]))
                                for route in (homogeneous, switched, "H", "L")
                            )
                        ],
                    ),
                    (
                        "interruption_free_complete_blocks_sensitivity",
                        [
                            sequence
                            for sequence in range(expected_per_route)
                            if sequence not in invalid_latency_sequences
                        ],
                    ),
                ]
                if metric == "latency_seconds"
                else [("primary_all_validated_effects", list(range(expected_per_route)))]
            )
            for sample_role, sequences in sample_specs:
                deltas = [
                    float(lookup[(switched, sequence)][metric])
                    - float(lookup[(homogeneous, sequence)][metric])
                    for sequence in sequences
                ]
                seed = int.from_bytes(
                    hashlib.sha256(
                        f"pair:{homogeneous}:{switched}:{metric}:{sample_role}:{bootstrap['seed']}".encode()
                    ).digest()[:8],
                    "big",
                )
                point, low, high = moving_block_interval(
                    deltas,
                    repetitions=int(bootstrap["repetitions"]),
                    block_length=int(bootstrap["block_length"]),
                    confidence=float(bootstrap["confidence"]),
                    seed=seed,
                )
                paired_rows.append(
                    {
                        "homogeneous_route": homogeneous,
                        "switched_route": switched,
                        "prefix_hops": len(switched) - 1,
                        "metric": metric,
                        "n_pairs": len(deltas),
                        "estimate": point,
                        "ci_low": low,
                        "ci_high": high,
                        "sample_role": sample_role,
                    }
                )
                native_deltas = [
                    float(lookup[("L", sequence)][metric]) - float(lookup[("H", sequence)][metric])
                    for sequence in sequences
                ]
                calibrated = [
                    delta - native_delta
                    for delta, native_delta in zip(deltas, native_deltas, strict=True)
                ]
                calibrated_point, calibrated_low, calibrated_high = moving_block_interval(
                    calibrated,
                    repetitions=int(bootstrap["repetitions"]),
                    block_length=int(bootstrap["block_length"]),
                    confidence=float(bootstrap["confidence"]),
                    seed=seed ^ 0x584952,
                )
                calibrated_rows.append(
                    {
                        "homogeneous_route": homogeneous,
                        "switched_route": switched,
                        "native_calibration": "matched_one_hop_L_minus_H",
                        "estimand": "equal_hop_delta_minus_native_carrier_delta",
                        "metric": metric,
                        "n_pairs": len(calibrated),
                        "estimate": calibrated_point,
                        "ci_low": calibrated_low,
                        "ci_high": calibrated_high,
                        "sample_role": sample_role,
                        "model_based": True,
                    }
                )
    receipt_growth_models: list[dict[str, Any]] = []
    switched_routes = {switch for _, switch in EQUIVALENCE_ROUTES}
    for response in (
        "encoded_envelope_bytes",
        "final_delivery_calldata_bytes",
        "final_gateway_exclusive_residual_gas",
        "final_registry_and_verifier_subcall_gas",
        "final_receiver_subcall_gas",
        "final_other_direct_subcall_gas",
    ):
        growth_rows = [row for row in rows if str(row["route"]) in switched_routes]
        seed = int.from_bytes(
            hashlib.sha256(f"receipt-growth:{response}:{bootstrap['seed']}".encode()).digest()[:8],
            "big",
        )
        estimate, low, high = bootstrap_coefficient_interval(
            growth_rows,
            response=response,
            predictors=("prefix_receipt_count",),
            coefficient="prefix_receipt_count",
            repetitions=int(bootstrap["repetitions"]),
            block_length=int(bootstrap["block_length"]),
            confidence=float(bootstrap["confidence"]),
            seed=seed,
        )
        receipt_growth_models.append(
            {
                "response": response,
                "predictor": "prefix_receipt_count",
                "routes": sorted(switched_routes),
                "n": len(growth_rows),
                "slope": estimate,
                "ci_low": low,
                "ci_high": high,
                "confidence": bootstrap["confidence"],
                "zero_slope_equivalence_tested": False,
                "theoretical_abi_byte_increment": (
                    int(
                        np.median(
                            [
                                int(row["theoretical_last_receipt_envelope_byte_increment"])
                                for row in growth_rows
                            ]
                        )
                    )
                    if response in {"encoded_envelope_bytes", "final_delivery_calldata_bytes"}
                    else None
                ),
                "observed_minus_theoretical_byte_increment": (
                    estimate
                    - int(
                        np.median(
                            [
                                int(row["theoretical_last_receipt_envelope_byte_increment"])
                                for row in growth_rows
                            ]
                        )
                    )
                    if response in {"encoded_envelope_bytes", "final_delivery_calldata_bytes"}
                    else None
                ),
                "interpretation": (
                    "encoding_derived_exact_growth"
                    if response in {"encoded_envelope_bytes", "final_delivery_calldata_bytes"}
                    else "trace_component_growth_direct_calls_plus_gateway_residual"
                ),
            }
        )
    transaction_rows: list[dict[str, Any]] = []
    for route, values in by_route.items():
        coordinator_values = {int(row["coordinator_transactions"]) for row in values}
        physical_values = {int(row["physical_transactions"]) for row in values}
        if len(coordinator_values) != 1 or len(physical_values) != 1:
            raise LocalTopologyError("per-route transaction accounting is not exact")
        transaction_rows.append(
            {
                "route": route,
                "n": len(values),
                "observed_coordinator_transactions_per_attempt": coordinator_values.pop(),
                "theoretical_coordinator_transactions_per_attempt": expected_coordinator_transactions(
                    route
                ),
                "observed_physical_transactions_per_attempt": physical_values.pop(),
                "theoretical_physical_transactions_per_attempt": expected_physical_transactions(
                    route
                ),
            }
        )
    return {
        "cell_summary": cell_rows,
        "models": models,
        "equivalence": equivalence_rows,
        "paired_switch_marginals": paired_rows,
        "carrier_calibrated_switch_marginals": calibrated_rows,
        "receipt_growth_models": receipt_growth_models,
        "transaction_summary": transaction_rows,
        "latency_sensitivity": {
            "selection_unit": "complete_11_route_sequence_block",
            "primary_attempts": len(rows),
            "included_attempts": len(latency_rows),
            "excluded_attempts": len(rows) - len(latency_rows),
            "excluded_sequences": invalid_latency_sequences,
            "included_per_route": expected_per_route - len(invalid_latency_sequences),
            "mandatory_limitation": (
                "All five QBFT chains and carrier services share one host; gas and calldata "
                "are load-invariant primary evidence, while latency is conditional on the "
                "recorded shared-host resource regime and is not generalized to independent hosts."
            ),
        },
    }


def reconstruct_attempt_metrics(
    *,
    config_path: Path,
    profile_path: Path | None = None,
    component_lock_path: Path | None = None,
    source_lock_root: Path | None = None,
    phase: MultihopPhase,
    runner_state_path: Path,
    worker_state_path: Path,
    hyperlane_process_path: Path,
    root_signer_audit_path: Path | None = None,
    deployment_path: Path,
    trace_state_path: Path | None = None,
    allow_missing_traces_for_capture: bool = False,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    config, _ = load_multihop_config(
        config_path,
        profile_path_override=profile_path,
        component_lock_path_override=component_lock_path,
        source_root_override=source_lock_root,
    )
    repository_root = config_path.resolve().parents[2]
    effective_profile_path = (
        repository_root / str(config["profile"]) if profile_path is None else profile_path
    )
    profile = cast(
        dict[str, Any],
        json.loads(effective_profile_path.read_text(encoding="utf-8")),
    )
    deployment = cast(dict[str, Any], json.loads(deployment_path.read_text(encoding="utf-8")))
    identity = config_identity(config)
    if deployment.get("namespace") != config["namespace"]:
        raise LocalTopologyError("analysis deployment namespace differs from config")
    chain_role_by_id = {
        int(chain["chain_id"]): role
        for role, chain in zip(
            ("a", "b", "c", "d", "e"),
            cast(list[dict[str, Any]], profile["chains"]),
            strict=True,
        )
    }
    expected = {
        attempt.attempt_id: attempt
        for attempt in iter_multihop_attempts(
            config_path=config_path,
            phase=phase,
            profile_path_override=effective_profile_path,
            component_lock_path_override=component_lock_path,
            source_root_override=source_lock_root,
        )
    }
    root_audits: dict[str, dict[str, Any]] = {}
    if root_signer_audit_path is not None:
        for line in root_signer_audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = cast(dict[str, Any], json.loads(line))
            transaction_hash = str(row.get("transaction_hash", "")).lower()
            if transaction_hash in root_audits:
                raise LocalTopologyError("root-signer audit repeats a transaction")
            root_audits[transaction_hash] = row
        if len(root_audits) != len(expected):
            raise LocalTopologyError("root-signer audit denominator is not exact")
    elif phase == "scale":
        raise LocalTopologyError("formal analysis requires frozen root-signer audit")
    runner = sqlite3.connect(runner_state_path)
    runner.row_factory = sqlite3.Row
    worker = sqlite3.connect(worker_state_path)
    worker.row_factory = sqlite3.Row
    traces = None
    if trace_state_path is not None:
        traces = sqlite3.connect(trace_state_path)
        traces.row_factory = sqlite3.Row
        if (
            traces.execute("PRAGMA quick_check").fetchone()[0] != "ok"
            or traces.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='traces'"
            ).fetchone()
            is None
        ):
            raise LocalTopologyError("multihop trace database is invalid")
    processes = cast(
        dict[str, dict[str, Any]],
        json.loads(hyperlane_process_path.read_text(encoding="utf-8"))["messages"],
    )
    attempts = {
        str(row["attempt_id"]): row
        for row in runner.execute("SELECT * FROM attempts WHERE phase=?", (phase,))
    }
    if set(attempts) != set(expected) or any(
        str(row["status"]) != "succeeded" for row in attempts.values()
    ):
        raise LocalTopologyError("runner attempts do not exactly match frozen plan")
    worker_actions: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in worker.execute("SELECT * FROM actions WHERE status='succeeded' ORDER BY guid,stage"):
        worker_actions[str(row["guid"]).lower()].append(row)

    physical_rows: list[dict[str, Any]] = []
    stage_metric_rows: list[dict[str, Any]] = []
    receipt_rows: list[dict[str, Any]] = []
    metrics: list[dict[str, Any]] = []
    for attempt_id, attempt in expected.items():
        component_clock_valid = True
        hyperlane_clock_valid = True
        layerzero_clock_valid = True
        stages = {
            str(row["stage"]): row
            for row in runner.execute("SELECT * FROM stages WHERE attempt_id=?", (attempt_id,))
        }
        required = (
            {"root_create", "destination_verify_deliver"}
            | {
                f"hop_{index}_{protocol.lower()}_dispatch"
                for index, protocol in enumerate(attempt.route, start=1)
            }
            | {
                f"hop_{index + 1}_xir_transition"
                for index, (left, right) in enumerate(
                    zip(attempt.route, attempt.route[1:]), start=1
                )
                if left != right
            }
        )
        if set(stages) != required or any(
            str(row["state"]) != "succeeded" or not row["transaction_hash"]
            for row in stages.values()
        ):
            raise LocalTopologyError(f"invalid coordinator stages: {attempt_id}")
        rows: list[dict[str, Any]] = []
        transition_gas = 0
        transition_calldata = 0
        for stage_name, stage in stages.items():
            detail = cast(dict[str, Any], json.loads(str(stage["detail_json"])))
            item: dict[str, Any] = {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "stage": stage_name,
                "kind": "coordinator",
                "chain_role": str(detail["role"]),
                "chain_id": int(
                    next(
                        chain["chain_id"]
                        for chain in cast(list[dict[str, Any]], profile["chains"])
                        if chain_role_by_id[int(chain["chain_id"])] == str(detail["role"])
                    )
                ),
                "hop_index": int(detail.get("hop_index", 0)),
                "native_message_id": str(detail.get("native_message_id", "")),
                "transaction_hash": str(stage["transaction_hash"]).lower(),
                "gas": int(detail["gas_used"]),
                "calldata_bytes": int(detail["calldata_bytes"]),
                "raw_transaction_sha256": str(detail["raw_sha256"]),
                "raw_transaction_availability": "captured_runner_signed_transaction",
                "receipt_sha256": str(detail["receipt_sha256"]),
            }
            rows.append(item)
            if stage_name.endswith("_xir_transition"):
                transition_gas += item["gas"]
                transition_calldata += item["calldata_bytes"]
        for hop_index, protocol in enumerate(attempt.route, start=1):
            dispatch = stages[f"hop_{hop_index}_{protocol.lower()}_dispatch"]
            detail = cast(dict[str, Any], json.loads(str(dispatch["detail_json"])))
            native_id = str(detail["native_message_id"]).lower()
            if protocol == "H":
                process = processes.get(native_id)
                if process is None or int(process["status"]) != 1:
                    raise LocalTopologyError(f"missing Hyperlane process: {native_id}")
                component_clock_valid = component_clock_valid and bool(
                    process.get("observer_boundary_valid")
                )
                hyperlane_clock_valid = hyperlane_clock_valid and bool(
                    process.get("observer_boundary_valid")
                )
                rows.append(
                    {
                        "attempt_id": attempt_id,
                        "route": attempt.route,
                        "sequence": attempt.route_sequence,
                        "stage": f"hop_{hop_index}_hyperlane_process",
                        "kind": "hyperlane_agent",
                        "chain_role": str(process["chain_role"]),
                        "chain_id": int(
                            next(
                                chain["chain_id"]
                                for chain in cast(list[dict[str, Any]], profile["chains"])
                                if chain_role_by_id[int(chain["chain_id"])]
                                == str(process["chain_role"])
                            )
                        ),
                        "hop_index": hop_index,
                        "native_message_id": native_id,
                        "transaction_hash": str(process["transaction_hash"]).lower(),
                        "gas": int(process["gas_used"]),
                        "calldata_bytes": int(process["calldata_bytes"]),
                        "raw_transaction_sha256": None,
                        "raw_transaction_availability": (
                            "not_exposed_by_independent_hyperlane_relayer"
                        ),
                        "receipt_sha256": str(process["receipt_semantic_sha256"]),
                    }
                )
            else:
                actions = worker_actions.get(native_id, [])
                if len(actions) != 3 or {str(row["stage"]) for row in actions} != {
                    "dvn_execute",
                    "commit_verification",
                    "executor_execute",
                }:
                    raise LocalTopologyError(f"invalid LayerZero actions: {native_id}")
                for action in actions:
                    observations = worker.execute(
                        """
                        SELECT detail_json,monotonic_ns,boot_id,process_id,
                               process_identity_sha256
                        FROM observations WHERE action_id=? AND state='succeeded'
                        """,
                        (action["action_id"],),
                    ).fetchall()
                    if len(observations) != 1:
                        raise LocalTopologyError("LayerZero action lacks one success observation")
                    detail_row = json.loads(str(observations[0]["detail_json"]))
                    submitted_observations = worker.execute(
                        """
                        SELECT detail_json,monotonic_ns,boot_id,process_id,
                               process_identity_sha256
                        FROM observations
                        WHERE action_id=? AND state='submitted'
                        ORDER BY observation_id
                        """,
                        (action["action_id"],),
                    ).fetchall()
                    worker_boundaries = [*submitted_observations, observations[0]]
                    boundary_identities = [
                        _bound_process_identity(
                            str(boundary["detail_json"]),
                            str(boundary["process_identity_sha256"]),
                        )
                        for boundary in worker_boundaries
                    ]
                    worker_boundary_valid = (
                        bool(submitted_observations)
                        and all(row["monotonic_ns"] is not None for row in worker_boundaries)
                        and len({str(row["boot_id"]) for row in worker_boundaries}) == 1
                        and len({str(row["process_identity_sha256"]) for row in worker_boundaries})
                        == 1
                    )
                    component_clock_valid = component_clock_valid and worker_boundary_valid
                    layerzero_clock_valid = layerzero_clock_valid and worker_boundary_valid
                    worker_latency = (
                        (
                            int(observations[0]["monotonic_ns"])
                            - int(submitted_observations[0]["monotonic_ns"])
                        )
                        / 1e9
                        if worker_boundary_valid
                        else float("nan")
                    )
                    signed_observations = worker.execute(
                        """
                        SELECT raw_sha256,detail_json FROM observations
                        WHERE action_id=? AND state='signed'
                        """,
                        (action["action_id"],),
                    ).fetchall()
                    if (
                        len(signed_observations) != 1
                        or len(str(signed_observations[0]["raw_sha256"])) != 64
                    ):
                        raise LocalTopologyError("LayerZero action lacks one signed raw digest")
                    rows.append(
                        {
                            "attempt_id": attempt_id,
                            "route": attempt.route,
                            "sequence": attempt.route_sequence,
                            "stage": f"hop_{hop_index}_layerzero_{action['stage']}",
                            "kind": "layerzero_worker",
                            "chain_role": chain_role_by_id[int(action["destination_chain_id"])],
                            "chain_id": int(action["destination_chain_id"]),
                            "hop_index": hop_index,
                            "native_message_id": native_id,
                            "transaction_hash": str(action["transaction_hash"]).lower(),
                            "gas": int(detail_row["gas_used"]),
                            "calldata_bytes": int(action["calldata_bytes"]),
                            "raw_transaction_sha256": str(signed_observations[0]["raw_sha256"]),
                            "raw_transaction_availability": ("captured_worker_signed_transaction"),
                            "receipt_sha256": str(detail_row["receipt_sha256"]),
                            "worker_process_identity_sha256": str(
                                observations[0]["process_identity_sha256"]
                            ),
                            "worker_process_identity": boundary_identities[-1],
                            "component_latency_seconds": worker_latency,
                            "component_latency_boundary": ("worker_first_submitted_to_succeeded"),
                            "component_latency_is_non_additive": True,
                        }
                    )
        if len({row["transaction_hash"] for row in rows}) != len(rows):
            raise LocalTopologyError(f"duplicate physical transaction: {attempt_id}")
        for item in rows:
            availability = str(item["raw_transaction_availability"])
            raw_digest = item["raw_transaction_sha256"]
            if availability.startswith("captured_"):
                if not isinstance(raw_digest, str) or len(raw_digest) != 64:
                    raise LocalTopologyError("captured physical transaction lacks raw SHA-256")
            elif (
                availability != "not_exposed_by_independent_hyperlane_relayer"
                or raw_digest is not None
            ):
                raise LocalTopologyError("physical raw availability is ambiguous")
            if len(str(item["receipt_sha256"])) != 64:
                raise LocalTopologyError("physical receipt digest is invalid")
        if traces is not None:
            for item in rows:
                transaction_hash = "0x" + str(item["transaction_hash"]).lower().removeprefix("0x")
                trace_evidence = traces.execute(
                    """
                    SELECT receipt_gas,trace_json,semantic_sha256,raw_sha256
                    FROM traces
                    WHERE chain_role=? AND transaction_hash=?
                    """,
                    (item["chain_role"], transaction_hash),
                ).fetchall()
                if len(trace_evidence) != 1:
                    raise LocalTopologyError(
                        f"physical transaction lacks one frozen trace: {transaction_hash}"
                    )
                trace = cast(
                    dict[str, Any],
                    json.loads(str(trace_evidence[0]["trace_json"])),
                )
                semantic = dict(trace)
                semantic.pop("semantic_sha256", None)
                if (
                    int(trace_evidence[0]["receipt_gas"]) != int(item["gas"])
                    or str(trace_evidence[0]["semantic_sha256"])
                    != hashlib.sha256(rfc8785.dumps(semantic)).hexdigest()
                    or str(trace["transaction_hash"]) != transaction_hash
                ):
                    raise LocalTopologyError("frozen trace reconciliation failed")
                if trace.get("trace_unavailable") is True:
                    if not (identity.evidence_namespace == "native-multihop-switching-pilot-v1"):
                        raise LocalTopologyError("trace unavailable is forbidden for formal evidence")
                    item["trace_unavailable"] = True
                    item["trace_unavailable_reason"] = str(trace["trace_unavailable_reason"])
                    item["trace_top_level_execution_gas"] = None
                    item["trace_receipt_minus_execution_gas"] = None
                    item["trace_internal_call_count"] = None
                else:
                    item["trace_top_level_execution_gas"] = int(trace["top_level_execution_gas"])
                    item["trace_receipt_minus_execution_gas"] = int(trace["receipt_minus_trace_gas"])
                    item["trace_internal_call_count"] = int(trace["internal_call_count"])
                item["sender"] = str(trace["sender"]).lower()
                item["target"] = str(trace["target"]).lower()
                item["nonce"] = int(trace["nonce"])
                item["calldata_sha256"] = str(trace["calldata_sha256"])
                item["block_number"] = int(trace["block_number"])
                item["block_hash"] = str(trace["block_hash"]).lower()
                item["transaction_index"] = int(trace["transaction_index"])
                item["status"] = int(trace["status"])
                item["raw_transaction_sha256"] = str(trace["raw_sha256"])
                item["raw_transaction_availability"] = "captured_besu_raw_transaction"
                if (
                    str(trace_evidence[0]["raw_sha256"]) != str(trace["raw_sha256"])
                    or int(item["chain_id"]) != int(trace["chain_id"])
                    or int(item["status"]) != 1
                    or len(str(item["sender"]).removeprefix("0x")) != 40
                    or len(str(item["target"]).removeprefix("0x")) != 40
                    or len(str(item["calldata_sha256"])) != 64
                    or len(str(item["block_hash"]).removeprefix("0x")) != 64
                ):
                    raise LocalTopologyError("physical raw/receipt lineage is incomplete")
                item["trace_component_calls_json"] = json.dumps(
                    [
                        {
                            "trace_address": row["trace_address"],
                            "component": row["component"],
                            "gas_used": row["gas_used"],
                            "input_selector": row["input_selector"],
                        }
                        for row in cast(list[dict[str, Any]], trace["traces"])
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                )
        elif phase == "scale" and not allow_missing_traces_for_capture:
            raise LocalTopologyError("formal analysis requires frozen Besu traces")
        if traces is not None and any(
            not isinstance(row.get("hop_index"), int)
            or not isinstance(row.get("chain_id"), int)
            or not row.get("sender")
            or not row.get("target")
            or int(row.get("block_number", -1)) < 0
            or len(str(row.get("block_hash", "")).removeprefix("0x")) != 64
            or int(row.get("status", 0)) != 1
            for row in rows
        ):
            raise LocalTopologyError("physical transaction mandatory lineage is incomplete")
        events = runner.execute(
            "SELECT * FROM events WHERE attempt_id=? ORDER BY monotonic_ns", (attempt_id,)
        ).fetchall()
        boot_ids = {str(row["boot_id"]) for row in events}
        starts = [
            int(row["monotonic_ns"])
            for row in events
            if row["stage"] == "root_create"
            and row["event"] == "intended"
            and row["source"] == "coordinator"
        ]
        effect = [
            int(row["monotonic_ns"])
            for row in events
            if row["stage"] == "destination_effect_observation" and row["event"] == "observed"
        ]
        if len(starts) != 1 or len(effect) != 1:
            raise LocalTopologyError("attempt lacks exact intended/effect event pair")
        latency = float("nan") if len(boot_ids) != 1 else (effect[0] - starts[0]) / 1e9
        event_lookup = {
            (str(row["stage"]), str(row["event"]), str(row["source"])): row for row in events
        }
        payload = _encoded_application_payload(
            config=config,
            phase=phase,
            sequence=attempt.route_sequence,
            attempt_id=attempt_id,
            route=attempt.route,
        )
        receiver = str(deployment["routes"][attempt.route]["receiver"])
        root_stage_detail = cast(
            dict[str, Any], json.loads(str(stages["root_create"]["detail_json"]))
        )
        record = XIRRecord(
            source_gateway=multihop_gateway_typed_id(
                int(cast(list[dict[str, Any]], profile["chains"])[0]["chain_id"])
            ),
            source_app=(
                1,
                bytes.fromhex(str(deployment["runner"]).removeprefix("0x")),
            ),
            destination_app=(1, bytes.fromhex(receiver.removeprefix("0x"))),
            nonce=int(root_stage_detail["record_nonce"]),
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_MULTIHOP_POLICY_V1"))
        rid = root_id(record, context, REGISTRY_VERSION)
        if (
            str(root_stage_detail["record_payload_hash"]).lower()
            != "0x" + record.payload_hash.hex()
        ):
            raise LocalTopologyError("root record payload hash reconstruction failed")
        root_ready = event_lookup.get(("root_certificate_ready", "ready", "root_signer"))
        if root_ready is None:
            raise LocalTopologyError("root certificate event is missing")
        root_ready_detail = cast(dict[str, Any], json.loads(str(root_ready["detail_json"])))
        destination_stage_detail = cast(
            dict[str, Any],
            json.loads(str(stages["destination_verify_deliver"]["detail_json"])),
        )
        if (
            str(root_ready_detail["rid"]).lower() != "0x" + rid.hex()
            or str(destination_stage_detail["rid"]).lower() != "0x" + rid.hex()
            or int(destination_stage_detail["receipt_count"]) != len(attempt.route)
        ):
            raise LocalTopologyError("rid or final receipt count reconstruction failed")
        if root_audits:
            root_transaction_hash = str(stages["root_create"]["transaction_hash"]).lower()
            root_audit = root_audits.get(root_transaction_hash)
            if (
                root_audit is None
                or root_audit.get("schema_version") != "xir-lab-finalized-root-signature-audit-v1"
                or root_audit.get("signed") is not True
                or not isinstance(root_audit.get("checks"), dict)
                or not cast(dict[str, bool], root_audit["checks"])
                or not all(cast(dict[str, bool], root_audit["checks"]).values())
                or str(root_audit.get("rid", "")).lower() != "0x" + rid.hex()
                or str(root_audit.get("mid", "")).lower()
                != "0x" + message_id(rid, record.destination_app).hex()
                or str(root_audit.get("runner", "")).lower() != str(deployment["runner"]).lower()
                or str(root_audit.get("root_signer", "")).lower()
                != str(deployment["root_signer"]).lower()
            ):
                raise LocalTopologyError("root-signer audit reconciliation failed")
        reconstructed_receipts: list[XIRReceipt] = []
        for hop_index, protocol in enumerate(attempt.route, start=1):
            dispatch_name = f"hop_{hop_index}_{protocol.lower()}_dispatch"
            dispatch_detail = cast(
                dict[str, Any], json.loads(str(stages[dispatch_name]["detail_json"]))
            )
            source_chain = cast(list[dict[str, Any]], profile["chains"])[hop_index - 1]
            destination_chain = cast(list[dict[str, Any]], profile["chains"])[hop_index]
            source_id = multihop_gateway_typed_id(int(source_chain["chain_id"]))
            destination_id = multihop_gateway_typed_id(int(destination_chain["chain_id"]))
            expected_transition = transition_hash(record, context, source_id, destination_id)
            evidence = bytes.fromhex(str(dispatch_detail["evidence"]).removeprefix("0x"))
            prefix = (
                root_prefix(rid)
                if not reconstructed_receipts
                else next_prefix(reconstructed_receipts[-1])
            )
            receipt = XIRReceipt(
                source_id,
                destination_id,
                multihop_profile_hash(attempt.route, hop_index),
                evidence,
                expected_transition,
                prefix,
            )
            reconstructed_receipts.append(receipt)
            receipt_rows.append(
                {
                    "attempt_id": attempt_id,
                    "route": attempt.route,
                    "sequence": attempt.route_sequence,
                    "hop_index": hop_index,
                    "protocol": protocol,
                    "source_chain_role": chr(ord("a") + hop_index - 1),
                    "destination_chain_role": chr(ord("a") + hop_index),
                    "profile_hash": "0x" + receipt.profile_hash.hex(),
                    "evidence_hash": "0x" + receipt.evidence_hash.hex(),
                    "transition_hash": "0x" + receipt.transition_hash.hex(),
                    "prior_prefix": "0x" + receipt.prior_prefix.hex(),
                    "next_prefix": "0x" + next_prefix(receipt).hex(),
                    "native_message_id": str(dispatch_detail["native_message_id"]).lower(),
                }
            )
            transition_name = f"hop_{hop_index + 1}_xir_transition"
            if transition_name in stages:
                transition_detail = cast(
                    dict[str, Any],
                    json.loads(str(stages[transition_name]["detail_json"])),
                )
                if (
                    int(transition_detail["verified_receipt_count"]) != hop_index
                    or str(transition_detail["outbound_profile"]).lower()
                    != "0x" + multihop_profile_hash(attempt.route, hop_index + 1).hex()
                ):
                    raise LocalTopologyError("switch prefix/profile reconstruction failed")
        mid = message_id(rid, record.destination_app)
        effect_event = event_lookup.get(
            (
                "destination_effect_observation",
                "observed",
                "coordinator_read",
            )
        )
        if effect_event is None:
            raise LocalTopologyError("destination effect observation is missing")
        effect_detail = cast(dict[str, Any], json.loads(str(effect_event["detail_json"])))
        if (
            int(effect_detail.get("effect_event_count", 0)) != 1
            or str(effect_detail.get("attempt_key", "")).lower()
            != "0x" + keccak(text=attempt_id).hex()
            or str(effect_detail.get("mid", "")).lower() != "0x" + mid.hex()
            or int(effect_detail.get("route_sequence", -1)) != attempt.route_sequence
            or str(effect_detail.get("delivery_transaction_hash", "")).lower()
            != str(stages["destination_verify_deliver"]["transaction_hash"]).lower()
            or len(str(effect_detail.get("delivery_receipt_sha256", ""))) != 64
        ):
            raise LocalTopologyError("destination exact-one-effect evidence is invalid")

        def trace_attribution(selected: list[dict[str, Any]]) -> dict[str, Any]:
            if not selected:
                return {
                    "trace_transaction_count": 0,
                    "trace_top_level_execution_gas": 0,
                    "trace_internal_call_count": 0,
                    "trace_component_calls_json": "[]",
                    "trace_internal_gas_is_inclusive_non_additive": True,
                }
            unavailable = [row for row in selected if row.get("trace_unavailable") is True]
            available = [
                row for row in selected
                if row.get("trace_unavailable") is not True
                and row.get("trace_top_level_execution_gas") is not None
            ]
            complete = len(available) + len(unavailable) == len(selected)
            if traces is not None and not complete:
                raise LocalTopologyError("stage trace attribution is incomplete")
            component_calls = [
                {
                    "transaction_hash": row["transaction_hash"],
                    "calls": json.loads(str(row["trace_component_calls_json"])),
                }
                for row in selected
                if "trace_component_calls_json" in row
            ]
            return {
                "trace_transaction_count": len(available),
                "trace_unavailable_transaction_count": len(unavailable),
                "trace_top_level_execution_gas": sum(
                    int(row.get("trace_top_level_execution_gas") or 0) for row in available
                ),
                "trace_internal_call_count": sum(
                    int(row.get("trace_internal_call_count") or 0) for row in available
                ),
                "trace_component_calls_json": json.dumps(
                    component_calls, sort_keys=True, separators=(",", ":")
                ),
                "trace_internal_gas_is_inclusive_non_additive": True,
            }

        def interval(start_key: tuple[str, str, str], end_key: tuple[str, str, str]) -> float:
            if len(boot_ids) != 1 or start_key not in event_lookup or end_key not in event_lookup:
                return float("nan")
            return (
                int(event_lookup[end_key]["monotonic_ns"])
                - int(event_lookup[start_key]["monotonic_ns"])
            ) / 1e9

        root_detail = cast(dict[str, Any], json.loads(str(stages["root_create"]["detail_json"])))
        stage_metric_rows.append(
            {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "stage_order": 0,
                "stage": "root_create_mined",
                "stage_level": "route_boundary",
                "boundary_start": "root_create:intended",
                "boundary_end": "root_create:succeeded",
                "latency_seconds": interval(
                    ("root_create", "intended", "coordinator"),
                    ("root_create", "succeeded", "coordinator"),
                ),
                "gas": int(root_detail["gas_used"]),
                "calldata_bytes": int(root_detail["calldata_bytes"]),
                "timing_kind": "host_monotonic_transaction_interval",
                **trace_attribution([row for row in rows if row["stage"] == "root_create"]),
            }
        )
        stage_metric_rows.append(
            {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "stage_order": 1,
                "stage": "root_certificate_ready",
                "stage_level": "route_boundary",
                "boundary_start": "root_create:succeeded",
                "boundary_end": "root_certificate_ready:ready",
                "latency_seconds": interval(
                    ("root_create", "succeeded", "coordinator"),
                    ("root_certificate_ready", "ready", "root_signer"),
                ),
                "gas": 0,
                "calldata_bytes": 0,
                "timing_kind": "host_monotonic_signer_interval",
                **trace_attribution([]),
            }
        )
        stage_order = 2
        for hop_index, protocol in enumerate(attempt.route, start=1):
            dispatch_stage = f"hop_{hop_index}_{protocol.lower()}_dispatch"
            hop_physical = [
                row
                for row in rows
                if row["stage"] == dispatch_stage
                or str(row["stage"]).startswith(f"hop_{hop_index}_hyperlane_")
                or str(row["stage"]).startswith(f"hop_{hop_index}_layerzero_")
            ]
            stage_metric_rows.append(
                {
                    "attempt_id": attempt_id,
                    "route": attempt.route,
                    "sequence": attempt.route_sequence,
                    "stage_order": stage_order,
                    "stage": f"hop_{hop_index}_{protocol.lower()}_transport_and_ingress",
                    "stage_level": "route_boundary",
                    "boundary_start": f"{dispatch_stage}:intended",
                    "boundary_end": f"hop_{hop_index}_{protocol.lower()}_callback:accepted",
                    "latency_seconds": interval(
                        (dispatch_stage, "intended", "coordinator"),
                        (
                            f"hop_{hop_index}_{protocol.lower()}_callback",
                            "accepted",
                            "coordinator_read",
                        ),
                    ),
                    "gas": sum(int(row["gas"]) for row in hop_physical),
                    "calldata_bytes": sum(int(row["calldata_bytes"]) for row in hop_physical),
                    "timing_kind": "host_monotonic_native_delivery_interval",
                    "atomic_ingress_subcall_latency": "grouped_not_separately_observable",
                    "receipt_count_after_stage": hop_index,
                    **trace_attribution(hop_physical),
                }
            )
            stage_order += 1
            if protocol == "L":
                layerzero_order = {
                    "dvn_execute": 1,
                    "commit_verification": 2,
                    "executor_execute": 3,
                }
                component_rows = sorted(
                    [row for row in hop_physical if row["kind"] == "layerzero_worker"],
                    key=lambda row: layerzero_order[
                        str(row["stage"]).split(f"hop_{hop_index}_layerzero_", 1)[1]
                    ],
                )
                for component_row in component_rows:
                    worker_stage = str(component_row["stage"]).split(
                        f"hop_{hop_index}_layerzero_", 1
                    )[1]
                    stage_metric_rows.append(
                        {
                            "attempt_id": attempt_id,
                            "route": attempt.route,
                            "sequence": attempt.route_sequence,
                            "stage_order": stage_order - 1,
                            "component_order": layerzero_order[worker_stage],
                            "stage": (f"hop_{hop_index}_layerzero_{worker_stage}_mined"),
                            "stage_level": "component_diagnostic",
                            "boundary_start": (f"worker:{worker_stage}:first_submitted"),
                            "boundary_end": f"worker:{worker_stage}:succeeded",
                            "latency_seconds": float(component_row["component_latency_seconds"]),
                            "gas": int(component_row["gas"]),
                            "calldata_bytes": int(component_row["calldata_bytes"]),
                            "timing_kind": ("worker_monotonic_transaction_interval_non_additive"),
                            "overlap_warning": (
                                "worker transactions are nonce ordered but submission-to-mined intervals may overlap"
                            ),
                            **trace_attribution([component_row]),
                        }
                    )
            transition_name = f"hop_{hop_index + 1}_xir_transition"
            if transition_name in stages:
                transition_detail = cast(
                    dict[str, Any],
                    json.loads(str(stages[transition_name]["detail_json"])),
                )
                stage_metric_rows.append(
                    {
                        "attempt_id": attempt_id,
                        "route": attempt.route,
                        "sequence": attempt.route_sequence,
                        "stage_order": stage_order,
                        "stage": transition_name,
                        "stage_level": "route_boundary",
                        "boundary_start": f"{transition_name}:intended",
                        "boundary_end": f"{transition_name}:succeeded",
                        "latency_seconds": interval(
                            (transition_name, "intended", "coordinator"),
                            (transition_name, "succeeded", "coordinator"),
                        ),
                        "gas": int(transition_detail["gas_used"]),
                        "calldata_bytes": int(transition_detail["calldata_bytes"]),
                        "timing_kind": "host_monotonic_transaction_interval",
                        "approved_verifier_work_in_this_transaction": False,
                        "verified_receipt_count": int(transition_detail["verified_receipt_count"]),
                        **trace_attribution(
                            [row for row in rows if row["stage"] == transition_name]
                        ),
                    }
                )
                stage_order += 1
                next_protocol = attempt.route[hop_index]
                switched_dispatch_name = f"hop_{hop_index + 1}_{next_protocol.lower()}_dispatch"
                switched_dispatch = next(
                    row for row in rows if row["stage"] == switched_dispatch_name
                )
                stage_metric_rows.append(
                    {
                        "attempt_id": attempt_id,
                        "route": attempt.route,
                        "sequence": attempt.route_sequence,
                        "stage_order": stage_order,
                        "stage": (
                            f"hop_{hop_index + 1}_switch_outbound_dispatch_"
                            "with_approved_prior_verification"
                        ),
                        "stage_level": "component_diagnostic_non_additive",
                        "boundary_start": f"{switched_dispatch_name}:intended",
                        "boundary_end": f"{switched_dispatch_name}:succeeded",
                        "latency_seconds": interval(
                            (switched_dispatch_name, "intended", "coordinator"),
                            (switched_dispatch_name, "succeeded", "coordinator"),
                        ),
                        "gas": int(switched_dispatch["gas"]),
                        "calldata_bytes": int(switched_dispatch["calldata_bytes"]),
                        "timing_kind": (
                            "host_monotonic_same_dispatch_total_includes_carrier_"
                            "launch_inclusive_non_additive"
                        ),
                        "approved_prior_verifier_executes_inside_this_dispatch": True,
                        "gas_is_inclusive_non_additive_with_hop_transport": True,
                        "latency_is_inclusive_non_additive_with_hop_transport": True,
                        **trace_attribution([switched_dispatch]),
                    }
                )
        destination_detail = cast(
            dict[str, Any],
            json.loads(str(stages["destination_verify_deliver"]["detail_json"])),
        )
        stage_metric_rows.append(
            {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "stage_order": stage_order,
                "stage": "destination_verify_deliver",
                "stage_level": "route_boundary",
                "boundary_start": "destination_verify_deliver:intended",
                "boundary_end": "destination_verify_deliver:succeeded",
                "latency_seconds": interval(
                    ("destination_verify_deliver", "intended", "coordinator"),
                    ("destination_verify_deliver", "succeeded", "coordinator"),
                ),
                "gas": int(destination_detail["gas_used"]),
                "calldata_bytes": int(destination_detail["calldata_bytes"]),
                "timing_kind": "host_monotonic_transaction_interval",
                "atomic_trace_checks_latency": "grouped_not_separately_observable",
                "receipt_count": len(attempt.route),
                **trace_attribution(
                    [row for row in rows if row["stage"] == "destination_verify_deliver"]
                ),
            }
        )
        stage_order += 1
        stage_metric_rows.append(
            {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "stage_order": stage_order,
                "stage": "destination_effect_observation",
                "stage_level": "route_boundary",
                "boundary_start": "destination_verify_deliver:succeeded",
                "boundary_end": "destination_effect_observation:observed",
                "latency_seconds": interval(
                    ("destination_verify_deliver", "succeeded", "coordinator"),
                    (
                        "destination_effect_observation",
                        "observed",
                        "coordinator_read",
                    ),
                ),
                "gas": 0,
                "calldata_bytes": 0,
                "timing_kind": "host_monotonic_read_observation_interval",
                **trace_attribution([]),
            }
        )
        transition_latencies: list[float] = []
        switch_dispatch_latencies: list[float] = []
        switch_dispatch_gas = 0
        switch_dispatch_calldata = 0
        approved_prior_verifier_gas = 0
        approved_prior_verifier_call_count = 0
        for stage_name in required:
            if not stage_name.endswith("_xir_transition"):
                continue
            transition_latency = interval(
                (stage_name, "intended", "coordinator"),
                (stage_name, "succeeded", "coordinator"),
            )
            if not math.isfinite(transition_latency) and len(boot_ids) == 1:
                raise LocalTopologyError("switch stage lacks exact event pair")
            transition_latencies.append(transition_latency)
            next_hop = int(stage_name.split("_", 2)[1])
            next_protocol = attempt.route[next_hop - 1].lower()
            dispatch_name = f"hop_{next_hop}_{next_protocol}_dispatch"
            dispatch_detail = cast(
                dict[str, Any], json.loads(str(stages[dispatch_name]["detail_json"]))
            )
            dispatch_latency = interval(
                (dispatch_name, "intended", "coordinator"),
                (dispatch_name, "succeeded", "coordinator"),
            )
            switch_dispatch_latencies.append(dispatch_latency)
            switch_dispatch_gas += int(dispatch_detail["gas_used"])
            switch_dispatch_calldata += int(dispatch_detail["calldata_bytes"])
            dispatch_physical = next(row for row in rows if row["stage"] == dispatch_name)
            if traces is not None and dispatch_physical.get("trace_unavailable") is not True:
                expected_component = adapter_key(attempt.route, next_hop - 1, "in")
                component_calls = cast(
                    list[dict[str, Any]],
                    json.loads(str(dispatch_physical["trace_component_calls_json"])),
                )
                approved_calls = [
                    call
                    for call in component_calls
                    if call.get("component") == expected_component
                    and call.get("input_selector") == APPROVED_VERIFIER_SELECTOR
                    and call.get("gas_used") is not None
                ]
                if len(approved_calls) != next_hop - 1:
                    raise LocalTopologyError(
                        "switched dispatch approved-verifier trace attribution is incomplete"
                    )
                approved_prior_verifier_call_count += len(approved_calls)
                approved_prior_verifier_gas += sum(int(call["gas_used"]) for call in approved_calls)
        switch_latency = (
            0.0
            if not transition_latencies
            else (
                sum(transition_latencies) + sum(switch_dispatch_latencies)
                if all(
                    math.isfinite(value)
                    for value in [*transition_latencies, *switch_dispatch_latencies]
                )
                else float("nan")
            )
        )
        encoded_envelope_bytes = _encoded_envelope_size(record, context, reconstructed_receipts)
        envelope_without_receipts_bytes = _encoded_envelope_size(record, context, [])
        final_delivery_physical = [
            row for row in rows if row["stage"] == "destination_verify_deliver"
        ]
        if len(final_delivery_physical) != 1:
            raise LocalTopologyError("final delivery physical transaction is not unique")
        final_delivery_row = final_delivery_physical[0]
        if (
            traces is not None
            and final_delivery_row.get("trace_unavailable") is not True
            and "trace_top_level_execution_gas" not in final_delivery_row
        ):
            raise LocalTopologyError("final delivery trace gas is missing")
        final_trace_components = {
            "gateway_exclusive_residual_gas": 0,
            "registry_and_verifier_subcall_gas": 0,
            "receiver_subcall_gas": 0,
            "other_direct_subcall_gas": 0,
        }
        if traces is not None and final_delivery_row.get("trace_unavailable") is not True:
            component_calls = cast(
                list[dict[str, Any]],
                json.loads(str(final_delivery_row["trace_component_calls_json"])),
            )
            direct_calls = [
                call
                for call in component_calls
                if len(cast(list[int], call["trace_address"])) == 1
                and call.get("gas_used") is not None
            ]
            direct_total = sum(int(call["gas_used"]) for call in direct_calls)
            top_level = int(final_delivery_row["trace_top_level_execution_gas"])
            if direct_total > top_level:
                raise LocalTopologyError("destination direct subcall gas exceeds trace total")
            final_trace_components["gateway_exclusive_residual_gas"] = top_level - direct_total
            for call in direct_calls:
                component = str(call["component"])
                gas_used = int(call["gas_used"])
                if component == "receiver":
                    key = "receiver_subcall_gas"
                elif component == "registry" or component.endswith("_in"):
                    key = "registry_and_verifier_subcall_gas"
                else:
                    key = "other_direct_subcall_gas"
                final_trace_components[key] += gas_used
            if sum(final_trace_components.values()) != top_level:
                raise LocalTopologyError("destination trace component gas does not reconcile")
        previous_envelope_bytes = _encoded_envelope_size(
            record, context, reconstructed_receipts[:-1]
        )
        physical_rows.extend(rows)
        metrics.append(
            {
                "attempt_id": attempt_id,
                "route": attempt.route,
                "sequence": attempt.route_sequence,
                "hop_count": attempt.hop_count,
                "switch_count": attempt.switch_count,
                "starts_with_l": int(attempt.route.startswith("L")),
                "receipt_count": attempt.receipt_count,
                "prefix_receipt_count": max(attempt.receipt_count - 1, 0),
                "carried_prior_tuple_count": max(attempt.receipt_count - 1, 0),
                "encoded_envelope_bytes": encoded_envelope_bytes,
                "envelope_without_receipts_bytes": envelope_without_receipts_bytes,
                "encoded_receipt_region_bytes": (
                    encoded_envelope_bytes - envelope_without_receipts_bytes
                ),
                "theoretical_last_receipt_envelope_byte_increment": (
                    encoded_envelope_bytes - previous_envelope_bytes
                ),
                "final_delivery_calldata_bytes": int(final_delivery_row["calldata_bytes"]),
                "final_trace_execution_gas": (
                    None
                    if final_delivery_row.get("trace_unavailable") is True
                    else int(final_delivery_row.get("trace_top_level_execution_gas") or 0)
                ),
                "final_gateway_exclusive_residual_gas": final_trace_components[
                    "gateway_exclusive_residual_gas"
                ],
                "final_registry_and_verifier_subcall_gas": final_trace_components[
                    "registry_and_verifier_subcall_gas"
                ],
                "final_receiver_subcall_gas": final_trace_components["receiver_subcall_gas"],
                "final_other_direct_subcall_gas": final_trace_components[
                    "other_direct_subcall_gas"
                ],
                "coordinator_transactions": len(stages),
                "physical_transactions": len(rows),
                "gas": sum(int(row["gas"]) for row in rows),
                "calldata_bytes": sum(int(row["calldata_bytes"]) for row in rows),
                "latency_seconds": latency,
                "switch_stage_gas": transition_gas + switch_dispatch_gas,
                "switch_stage_calldata_bytes": (transition_calldata + switch_dispatch_calldata),
                "switch_stage_latency_seconds": switch_latency,
                "transition_transaction_gas": transition_gas,
                "transition_transaction_calldata_bytes": transition_calldata,
                "transition_transaction_latency_seconds": sum(transition_latencies),
                "approved_prior_verifier_gas": approved_prior_verifier_gas,
                "approved_prior_verifier_call_count": approved_prior_verifier_call_count,
                "core_switch_gas": transition_gas + approved_prior_verifier_gas,
                "core_switch_calldata_bytes": transition_calldata,
                "core_switch_latency_seconds": sum(transition_latencies),
                "core_switch_estimand_definition": (
                    "dedicated_transition_transaction_plus_approved_prior_verifier_"
                    "internal_call_gas_with_transaction_boundary_calldata_and_latency"
                ),
                "switch_outbound_dispatch_gas": switch_dispatch_gas,
                "switch_outbound_dispatch_calldata_bytes": switch_dispatch_calldata,
                "switch_outbound_dispatch_latency_seconds": sum(switch_dispatch_latencies),
                "switch_stage_definition": (
                    "transition_transaction_plus_next_outbound_dispatch_with_approved_prior_verification"
                ),
                "latency_clock_valid": len(boot_ids) == 1 and component_clock_valid,
                "latency_exclusion_reason": (
                    None
                    if len(boot_ids) == 1 and component_clock_valid
                    else (
                        "host_boot_change"
                        if len(boot_ids) != 1
                        else (
                            "hyperlane_relayer_process_or_boot_change"
                            if not hyperlane_clock_valid
                            else "layerzero_worker_process_or_boot_change"
                        )
                    )
                ),
                "rid": "0x" + rid.hex(),
                "mid": "0x" + mid.hex(),
                "final_prefix": "0x" + next_prefix(reconstructed_receipts[-1]).hex(),
            }
        )
    runner.close()
    worker.close()
    if traces is not None:
        traces.close()
    return metrics, physical_rows, stage_metric_rows, receipt_rows


def capture_multihop_incidents(
    *,
    runner_state_path: Path,
    phase: MultihopPhase,
    output_path: Path,
    worker_state_path: Path | None = None,
    hyperlane_process_path: Path | None = None,
) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{runner_state_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    attempts = {
        str(row["attempt_id"]): row
        for row in connection.execute(
            "SELECT attempt_id,route,route_sequence FROM attempts WHERE phase=?",
            (phase,),
        )
    }
    records: list[dict[str, Any]] = []
    selected_sequences: set[int] = set()
    worker_boundaries: dict[str, list[sqlite3.Row]] = defaultdict(list)
    worker_connection: sqlite3.Connection | None = None
    hyperlane_boundaries: dict[str, dict[str, Any]] = {}
    if hyperlane_process_path is not None:
        hyperlane_document = cast(
            dict[str, Any], json.loads(hyperlane_process_path.read_text(encoding="utf-8"))
        )
        hyperlane_messages = cast(dict[str, dict[str, Any]], hyperlane_document.get("messages", {}))
        for stage in connection.execute(
            """
            SELECT attempt_id,detail_json FROM stages
            WHERE attempt_id IN (SELECT attempt_id FROM attempts WHERE phase=?)
              AND stage LIKE 'hop_%_h_dispatch' AND state='succeeded'
            """,
            (phase,),
        ):
            detail = cast(dict[str, Any], json.loads(str(stage["detail_json"])))
            message_id = str(detail.get("native_message_id", "")).lower()
            process = hyperlane_messages.get(message_id)
            if process is None:
                raise LocalTopologyError("Hyperlane incident mapping lacks process evidence")
            process_identities_valid = True
            for boundary in ("submitted", "mined"):
                for prefix in ("observer", "relayer"):
                    identity = process.get(f"{boundary}_{prefix}_process_identity")
                    digest = str(process.get(f"{boundary}_{prefix}_process_identity_sha256", ""))
                    process_identities_valid = (
                        process_identities_valid
                        and isinstance(identity, dict)
                        and identity.get("schema_version")
                        == "xir-lab-native-multihop-process-identity-v1"
                        and process_identity_sha256(cast(dict[str, Any], identity)) == digest
                    )
            prior = hyperlane_boundaries.setdefault(
                str(stage["attempt_id"]),
                {
                    "boot_ids": set(),
                    "relayer_process_ids": set(),
                    "observer_process_ids": set(),
                    "relayer_process_identity_sha256": set(),
                    "observer_process_identity_sha256": set(),
                    "valid": True,
                },
            )
            cast(set[str], prior["boot_ids"]).add(str(process.get("observer_boot_id")))
            cast(set[int], prior["relayer_process_ids"]).add(
                int(process.get("submitted_relayer_process_id", -1))
            )
            cast(set[int], prior["relayer_process_ids"]).add(
                int(process.get("mined_relayer_process_id", -1))
            )
            cast(set[int], prior["observer_process_ids"]).add(
                int(process.get("submitted_observer_process_id", -1))
            )
            cast(set[int], prior["observer_process_ids"]).add(
                int(process.get("mined_observer_process_id", -1))
            )
            cast(set[str], prior["relayer_process_identity_sha256"]).update(
                {
                    str(process.get("submitted_relayer_process_identity_sha256", "")),
                    str(process.get("mined_relayer_process_identity_sha256", "")),
                }
            )
            cast(set[str], prior["observer_process_identity_sha256"]).update(
                {
                    str(process.get("submitted_observer_process_identity_sha256", "")),
                    str(process.get("mined_observer_process_identity_sha256", "")),
                }
            )
            prior["valid"] = (
                prior["valid"]
                and process_identities_valid
                and process.get("observer_boundary_valid") is True
                and all(
                    value >= 0
                    for value in cast(set[int], prior["relayer_process_ids"])
                    | cast(set[int], prior["observer_process_ids"])
                )
                and all(
                    len(value) == 64 and all(character in "0123456789abcdef" for character in value)
                    for value in cast(set[str], prior["relayer_process_identity_sha256"])
                    | cast(set[str], prior["observer_process_identity_sha256"])
                )
            )
    if worker_state_path is not None:
        worker_connection = sqlite3.connect(f"file:{worker_state_path}?mode=ro", uri=True)
        worker_connection.row_factory = sqlite3.Row
        for stage in connection.execute(
            """
            SELECT attempt_id,detail_json FROM stages
            WHERE attempt_id IN (SELECT attempt_id FROM attempts WHERE phase=?)
              AND stage LIKE 'hop_%_l_dispatch' AND state='succeeded'
            """,
            (phase,),
        ):
            detail = cast(dict[str, Any], json.loads(str(stage["detail_json"])))
            guid = str(detail.get("native_message_id", "")).lower()
            if not guid:
                raise LocalTopologyError("LayerZero incident mapping lacks GUID")
            rows = worker_connection.execute(
                """
                    SELECT o.boot_id,o.process_id,o.process_identity_sha256,o.detail_json
                    FROM actions a
                JOIN observations o ON o.action_id=a.action_id
                WHERE lower(a.guid)=? AND o.state IN ('submitted','succeeded')
                """,
                (guid,),
            ).fetchall()
            if not rows:
                raise LocalTopologyError("LayerZero incident mapping lacks boundaries")
            worker_boundaries[str(stage["attempt_id"])].extend(rows)
    identity_by_attempt: dict[str, dict[str, Any]] = {}
    sequence_identities: dict[int, dict[str, set[Any]]] = defaultdict(
        lambda: {
            "runner_boot_ids": set(),
            "runner_process_ids": set(),
            "runner_process_identity_sha256": set(),
            "worker_boot_ids": set(),
            "worker_process_ids": set(),
            "worker_process_identity_sha256": set(),
            "hyperlane_boot_ids": set(),
            "hyperlane_relayer_process_ids": set(),
            "hyperlane_observer_process_ids": set(),
            "hyperlane_relayer_process_identity_sha256": set(),
            "hyperlane_observer_process_identity_sha256": set(),
        }
    )
    for attempt_id, attempt in attempts.items():
        event_rows = connection.execute(
            """
            SELECT boot_id,process_id,process_identity_sha256,detail_json
            FROM events WHERE attempt_id=?
            """,
            (attempt_id,),
        ).fetchall()
        worker_rows = worker_boundaries.get(attempt_id, [])
        hyperlane = hyperlane_boundaries.get(attempt_id)
        runner_identity_digests = {str(row["process_identity_sha256"]) for row in event_rows}
        worker_identity_digests = {
            str(row["process_identity_sha256"])
            for row in worker_rows
            if row["process_identity_sha256"] is not None
        }
        for row in event_rows:
            _bound_process_identity(str(row["detail_json"]), str(row["process_identity_sha256"]))
        for row in worker_rows:
            _bound_process_identity(str(row["detail_json"]), str(row["process_identity_sha256"]))
        for label, digests in (
            ("runner", runner_identity_digests),
            ("worker", worker_identity_digests),
        ):
            has_rows = bool(event_rows if label == "runner" else worker_rows)
            if has_rows and (
                not digests
                or any(
                    len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                    for value in digests
                )
            ):
                raise LocalTopologyError(f"{label} stable process identity is absent")
        identity = {
            "boot_ids": sorted({str(row["boot_id"]) for row in event_rows}),
            "process_ids": sorted({int(row["process_id"]) for row in event_rows}),
            "process_identity_sha256": sorted(runner_identity_digests),
            "worker_boot_ids": sorted(
                {str(row["boot_id"]) for row in worker_rows if row["boot_id"] is not None}
            ),
            "worker_process_ids": sorted(
                {int(row["process_id"]) for row in worker_rows if row["process_id"] is not None}
            ),
            "worker_process_identity_sha256": sorted(worker_identity_digests),
            "hyperlane": hyperlane,
        }
        identity_by_attempt[attempt_id] = identity
        aggregate = sequence_identities[int(attempt["route_sequence"])]
        cast(set[str], aggregate["runner_boot_ids"]).update(cast(list[str], identity["boot_ids"]))
        cast(set[int], aggregate["runner_process_ids"]).update(
            cast(list[int], identity["process_ids"])
        )
        cast(set[str], aggregate["runner_process_identity_sha256"]).update(
            cast(list[str], identity["process_identity_sha256"])
        )
        cast(set[str], aggregate["worker_boot_ids"]).update(
            cast(list[str], identity["worker_boot_ids"])
        )
        cast(set[int], aggregate["worker_process_ids"]).update(
            cast(list[int], identity["worker_process_ids"])
        )
        cast(set[str], aggregate["worker_process_identity_sha256"]).update(
            cast(list[str], identity["worker_process_identity_sha256"])
        )
        if hyperlane is not None:
            cast(set[str], aggregate["hyperlane_boot_ids"]).update(
                cast(set[str], hyperlane["boot_ids"])
            )
            cast(set[int], aggregate["hyperlane_relayer_process_ids"]).update(
                cast(set[int], hyperlane["relayer_process_ids"])
            )
            cast(set[int], aggregate["hyperlane_observer_process_ids"]).update(
                cast(set[int], hyperlane["observer_process_ids"])
            )
            cast(set[str], aggregate["hyperlane_relayer_process_identity_sha256"]).update(
                cast(set[str], hyperlane["relayer_process_identity_sha256"])
            )
            cast(set[str], aggregate["hyperlane_observer_process_identity_sha256"]).update(
                cast(set[str], hyperlane["observer_process_identity_sha256"])
            )
    sequence_reasons: dict[int, list[str]] = defaultdict(list)
    for sequence, identities in sequence_identities.items():
        if len(identities["runner_boot_ids"]) > 1:
            sequence_reasons[sequence].append("host_boot_change")
        elif len(identities["runner_process_identity_sha256"]) > 1:
            sequence_reasons[sequence].append("host_process_interruption")
        if (
            len(identities["worker_boot_ids"]) > 1
            or len(identities["worker_process_identity_sha256"]) > 1
        ):
            sequence_reasons[sequence].append("layerzero_worker_process_or_boot_change")
        if (
            len(identities["hyperlane_boot_ids"]) > 1
            or len(identities["hyperlane_relayer_process_identity_sha256"]) > 1
            or len(identities["hyperlane_observer_process_identity_sha256"]) > 1
        ):
            sequence_reasons[sequence].append("hyperlane_relayer_process_or_boot_change")
    for attempt_id, attempt in attempts.items():
        identity = identity_by_attempt[attempt_id]
        boot_ids = cast(list[str], identity["boot_ids"])
        process_ids = cast(list[int], identity["process_ids"])
        reasons = []
        if len(boot_ids) > 1:
            reasons.append("host_boot_change")
        elif len(process_ids) > 1:
            reasons.append("host_process_interruption")
        worker_rows = worker_boundaries.get(attempt_id, [])
        worker_boot_ids = cast(list[str], identity["worker_boot_ids"])
        worker_process_ids = cast(list[int], identity["worker_process_ids"])
        if worker_rows and (
            any(row["boot_id"] is None or row["process_id"] is None for row in worker_rows)
            or len({str(row["boot_id"]) for row in worker_rows}) > 1
            or len({int(row["process_id"]) for row in worker_rows}) > 1
        ):
            reasons.append("layerzero_worker_process_or_boot_change")
        hyperlane = hyperlane_boundaries.get(attempt_id)
        if hyperlane is not None and (
            hyperlane.get("valid") is not True
            or len(cast(set[str], hyperlane["boot_ids"])) != 1
            or len(cast(set[int], hyperlane["relayer_process_ids"])) != 1
            or len(cast(set[int], hyperlane["observer_process_ids"])) != 1
        ):
            reasons.append("hyperlane_relayer_process_or_boot_change")
        for reason in sequence_reasons[int(attempt["route_sequence"])]:
            if reason not in reasons:
                reasons.append(reason)
        errors = [
            {
                "error_class": str(row["error_class"]),
                "error_message": str(row["error_message"]),
                "retry_index": int(row["retry_index"]),
            }
            for row in connection.execute(
                """
                SELECT error_class,error_message,retry_index FROM attempt_errors
                WHERE attempt_id=? ORDER BY error_id
                """,
                (attempt_id,),
            )
        ]
        for reason in reasons:
            selected_sequences.add(int(attempt["route_sequence"]))
            records.append(
                {
                    "attempt_id": attempt_id,
                    "route": str(attempt["route"]),
                    "route_sequence": int(attempt["route_sequence"]),
                    "reason": reason,
                    "boot_ids": boot_ids,
                    "process_ids": process_ids,
                    "layerzero_worker_boot_ids": worker_boot_ids,
                    "layerzero_worker_process_ids": worker_process_ids,
                    "hyperlane_observer": (
                        None
                        if hyperlane is None
                        else {
                            "boot_ids": sorted(cast(set[str], hyperlane["boot_ids"])),
                            "relayer_process_ids": sorted(
                                cast(set[int], hyperlane["relayer_process_ids"])
                            ),
                            "observer_process_ids": sorted(
                                cast(set[int], hyperlane["observer_process_ids"])
                            ),
                        }
                    ),
                    "transient_errors": errors,
                    "latency_sensitivity_excluded": True,
                }
            )
        if errors and not reasons:
            records.append(
                {
                    "attempt_id": attempt_id,
                    "route": str(attempt["route"]),
                    "route_sequence": int(attempt["route_sequence"]),
                    "reason": "transient_rpc_retry",
                    "boot_ids": boot_ids,
                    "process_ids": process_ids,
                    "layerzero_worker_boot_ids": worker_boot_ids,
                    "layerzero_worker_process_ids": worker_process_ids,
                    "transient_errors": errors,
                    "latency_sensitivity_excluded": False,
                }
            )
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-incidents-v1",
        "phase": phase,
        "selection_unit": "complete_11_route_sequence_block",
        "eligible_reasons": [
            "host_process_interruption",
            "host_boot_change",
            "layerzero_worker_process_or_boot_change",
            "hyperlane_relayer_process_or_boot_change",
        ],
        "excluded_sequences": sorted(selected_sequences),
        "records": records,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    _write_json(output_path, document)
    connection.close()
    if worker_connection is not None:
        worker_connection.close()
    return document


def publish_multihop_analysis(
    *,
    config_path: Path,
    profile_path: Path | None = None,
    component_lock_path: Path | None = None,
    source_lock_root: Path | None = None,
    phase: MultihopPhase,
    runner_state_path: Path,
    worker_state_path: Path,
    hyperlane_process_path: Path,
    root_signer_audit_path: Path | None = None,
    deployment_path: Path,
    trace_state_path: Path,
    incident_path: Path,
    resource_monitor_path: Path,
    effect_audit_path: Path,
    provenance_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists() and any(output_root.iterdir()):
        raise LocalTopologyError("multihop analysis output must be empty")
    output_root.mkdir(parents=True, exist_ok=True)
    config, config_sha256 = load_multihop_config(
        config_path,
        profile_path_override=profile_path,
        component_lock_path_override=component_lock_path,
        source_root_override=source_lock_root,
    )
    tail_latency_reporting = _tail_latency_reporting_from_preregistration(
        provenance_root / "preregistration.json"
    )
    effective_profile_path = (
        config_path.resolve().parents[2] / str(config["profile"])
        if profile_path is None
        else profile_path
    )
    effective_profile = cast(
        dict[str, Any],
        json.loads(effective_profile_path.read_text(encoding="utf-8")),
    )
    metrics, physical, stage_metrics, receipt_lineage = reconstruct_attempt_metrics(
        config_path=config_path,
        profile_path=effective_profile_path,
        component_lock_path=component_lock_path,
        source_lock_root=source_lock_root,
        phase=phase,
        runner_state_path=runner_state_path,
        worker_state_path=worker_state_path,
        hyperlane_process_path=hyperlane_process_path,
        root_signer_audit_path=root_signer_audit_path,
        deployment_path=deployment_path,
        trace_state_path=trace_state_path,
    )
    effect_audit = cast(dict[str, Any], json.loads(effect_audit_path.read_text(encoding="utf-8")))
    validate_effect_audit(
        effect_audit,
        phase=phase,
        expected_effects=_expected_effect_lineage(
            runner_state_path=runner_state_path,
            trace_state_path=trace_state_path,
            phase=phase,
        ),
        expected_bindings={
            "baseline_sha256": hashlib.sha256(
                (effect_audit_path.parent / "effect-baseline.json").read_bytes()
            ).hexdigest(),
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "profile_sha256": hashlib.sha256(effective_profile_path.read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
        },
        expected_namespace=config_identity(config).evidence_namespace,
    )
    incidents = cast(dict[str, Any], json.loads(incident_path.read_text(encoding="utf-8")))
    if (
        incidents.get("schema_version") != "xir-lab-native-multihop-incidents-v1"
        or incidents.get("phase") != phase
        or incidents.get("eligible_reasons")
        != config["incident_policy"]["eligible_sensitivity_reasons"]
    ):
        raise LocalTopologyError("incident inventory differs from preregistered policy")
    incident_semantic = dict(incidents)
    incident_digest = str(incident_semantic.pop("semantic_sha256", ""))
    if hashlib.sha256(rfc8785.dumps(incident_semantic)).hexdigest() != incident_digest:
        raise LocalTopologyError("incident inventory semantic digest drift")
    incident_sequences = {int(value) for value in cast(list[int], incidents["excluded_sequences"])}
    identity = config_identity(config)
    result_role = phase_role(config, phase)
    claim_eligible = identity.claim_eligible and phase == "scale"
    analysis = {
        "schema_version": "xir-lab-native-multihop-analysis-v1",
        "namespace": identity.evidence_namespace,
        "phase": phase,
        "result_role": result_role,
        "claim_eligible": claim_eligible,
        "attempt_count": len(metrics),
        "tail_latency_reporting": tail_latency_reporting,
        **(
            summarize_attempt_metrics(metrics, config=config, incident_sequences=incident_sequences)
            if phase == "scale"
            else {}
        ),
        "incident_inventory_sha256": _sha256_path(incident_path),
    }
    if phase == "scale":
        bootstrap = cast(dict[str, Any], config["bootstrap"])
        excluded_latency_sequences = {
            int(value)
            for value in cast(list[int], analysis["latency_sensitivity"]["excluded_sequences"])
        }
        stage_summary: list[dict[str, Any]] = []
        grouped_stages: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in stage_metrics:
            grouped_stages[(str(row["route"]), str(row["stage"]), int(row["stage_order"]))].append(
                row
            )
        for (route, stage, order), values in sorted(grouped_stages.items()):
            full_latency_values = [
                float(row["latency_seconds"])
                for row in values
                if math.isfinite(float(row["latency_seconds"]))
            ]
            latency_values = [
                float(row["latency_seconds"])
                for row in values
                if int(row["sequence"]) not in excluded_latency_sequences
                and math.isfinite(float(row["latency_seconds"]))
            ]
            if not latency_values:
                raise LocalTopologyError(
                    f"stage has no valid latency observations: {route}:{stage}"
                )
            seed = int.from_bytes(
                hashlib.sha256(f"stage:{route}:{stage}:{bootstrap['seed']}".encode()).digest()[:8],
                "big",
            )
            point, low, high = moving_block_interval(
                latency_values,
                repetitions=int(bootstrap["repetitions"]),
                block_length=int(bootstrap["block_length"]),
                confidence=float(bootstrap["confidence"]),
                seed=seed,
                statistic="median",
            )
            stage_summary.append(
                {
                    "route": route,
                    "stage": stage,
                    "stage_order": order,
                    "stage_level": values[0]["stage_level"],
                    "component_order": values[0].get("component_order"),
                    "n": len(values),
                    "latency_n": len(latency_values),
                    "full_finite_latency_n": len(full_latency_values),
                    "full_finite_latency_median_seconds": float(np.median(full_latency_values)),
                    "latency_median_seconds": point,
                    "latency_ci_low": low,
                    "latency_ci_high": high,
                    "gas_mean": float(np.mean([float(row["gas"]) for row in values])),
                    "calldata_mean_bytes": float(
                        np.mean([float(row["calldata_bytes"]) for row in values])
                    ),
                    "timing_kind": values[0]["timing_kind"],
                    "boundary_start": values[0]["boundary_start"],
                    "boundary_end": values[0]["boundary_end"],
                    "sample_role": "interruption_free_complete_blocks_sensitivity",
                    "trace_transactions_mean": float(
                        np.mean([float(row["trace_transaction_count"]) for row in values])
                    ),
                    "trace_top_level_execution_gas_mean": float(
                        np.mean([float(row["trace_top_level_execution_gas"]) for row in values])
                    ),
                    "trace_internal_call_count_mean": float(
                        np.mean([float(row["trace_internal_call_count"]) for row in values])
                    ),
                    "trace_internal_gas_is_inclusive_non_additive": True,
                    "approved_verifier_work_in_this_transaction": values[0].get(
                        "approved_verifier_work_in_this_transaction"
                    ),
                    "approved_prior_verifier_executes_inside_this_dispatch": values[0].get(
                        "approved_prior_verifier_executes_inside_this_dispatch"
                    ),
                    "verified_receipt_count": values[0].get("verified_receipt_count"),
                    "gas_is_inclusive_non_additive_with_hop_transport": values[0].get(
                        "gas_is_inclusive_non_additive_with_hop_transport"
                    ),
                    "latency_is_inclusive_non_additive_with_hop_transport": values[0].get(
                        "latency_is_inclusive_non_additive_with_hop_transport"
                    ),
                    "latency_interval_is_non_additive": (
                        str(values[0]["stage_level"]).startswith("component_diagnostic")
                    ),
                }
            )
        analysis["stage_summary"] = stage_summary
    event_rows = _public_event_rows(runner_state_path, phase)
    resource_summary = _resource_summary(resource_monitor_path, event_rows)
    analysis["resource_summary"] = resource_summary
    _write_csv(output_root / "attempt-metrics.csv", metrics)
    _write_csv(output_root / "physical-transactions.csv", physical)
    _write_csv(output_root / "events.csv", event_rows)
    _write_csv(output_root / "stage-metrics.csv", stage_metrics)
    _write_csv(output_root / "receipt-lineage.csv", receipt_lineage)
    _write_json(output_root / "incident-inventory.json", incidents)
    _write_json(output_root / "resource-summary.json", resource_summary)
    if phase == "scale":
        _write_csv(
            output_root / "cell-summary.csv",
            cast(list[dict[str, Any]], analysis["cell_summary"]),
        )
        _write_json(output_root / "regression-models.json", analysis["models"])
        _write_csv(
            output_root / "regression-coefficients.csv",
            _coefficient_rows(cast(list[dict[str, Any]], analysis["models"])),
        )
        _write_json(output_root / "equivalence.json", analysis["equivalence"])
        _write_csv(
            output_root / "equivalence.csv",
            cast(list[dict[str, Any]], analysis["equivalence"]),
        )
        _write_csv(
            output_root / "paired-switch-marginals.csv",
            cast(list[dict[str, Any]], analysis["paired_switch_marginals"]),
        )
        _write_csv(
            output_root / "carrier-calibrated-switch-marginals.csv",
            cast(
                list[dict[str, Any]],
                analysis["carrier_calibrated_switch_marginals"],
            ),
        )
        _write_json(
            output_root / "receipt-growth-models.json",
            analysis["receipt_growth_models"],
        )
        _write_csv(
            output_root / "receipt-growth-models.csv",
            cast(list[dict[str, Any]], analysis["receipt_growth_models"]),
        )
        _write_csv(
            output_root / "transaction-summary.csv",
            cast(list[dict[str, Any]], analysis["transaction_summary"]),
        )
        _write_csv(
            output_root / "stage-summary.csv",
            cast(list[dict[str, Any]], analysis["stage_summary"]),
        )
    _write_json(output_root / "analysis.json", analysis)
    expected_physical = sum(int(row["physical_transactions"]) for row in metrics)
    validation_unavailable_count = sum(
        row.get("trace_unavailable") is True for row in physical
    )
    validation: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-analysis-validation-v1",
        "namespace": identity.evidence_namespace,
        "phase": phase,
        "result_role": result_role,
        "claim_eligible": claim_eligible,
        "attempt_count": len(metrics),
        "physical_transaction_count": len(physical),
        "receipt_count": len(receipt_lineage),
        "event_count": len(event_rows),
        "expected_physical_transaction_count": expected_physical,
        "trace_reconciled_transaction_count": sum(
            "trace_top_level_execution_gas" in row and row.get("trace_unavailable") is not True
            for row in physical
        ),
        "trace_unavailable_transaction_count": sum(
            row.get("trace_unavailable") is True for row in physical
        ),
        "exact_effect_denominator": len(metrics),
        "complete_block_range_effect_audit": True,
        "tail_latency_reporting_reconciled": (
            analysis.get("tail_latency_reporting") == TAIL_LATENCY_REPORTING
            and all(
                row.get("tail_point_estimates_role") == "descriptive"
                and row.get("tail_scope") == "shared_host_alpha_system"
                and row.get("tail_inferential") is False
                and row.get("tail_release_gate") is False
                for row in cast(list[dict[str, Any]], analysis.get("cell_summary", []))
                if row.get("metric") == "latency_seconds"
            )
        ),
        "effect_audit_sha256": _sha256_path(effect_audit_path),
        "errors": [],
        "valid": (
            len(physical) == expected_physical
            and sum(int(row["receipt_count"]) for row in metrics) == len(receipt_lineage)
            and len(event_rows) > len(metrics)
            and (
                sum(
                    "trace_top_level_execution_gas" in row
                    or row.get("trace_unavailable") is True
                    for row in physical
                )
                == len(physical)
            )
            and (
                validation_unavailable_count == 0
                or (identity.evidence_namespace == "native-multihop-switching-pilot-v1" and not claim_eligible)
            )
            and analysis.get("tail_latency_reporting") == TAIL_LATENCY_REPORTING
            and all(
                row.get("tail_point_estimates_role") == "descriptive"
                and row.get("tail_scope") == "shared_host_alpha_system"
                and row.get("tail_inferential") is False
                and row.get("tail_release_gate") is False
                for row in cast(list[dict[str, Any]], analysis.get("cell_summary", []))
                if row.get("metric") == "latency_seconds"
            )
        ),
    }
    if not validation["valid"]:
        raise LocalTopologyError("multihop publication validation failed")
    _write_json(output_root / "validation.json", validation)
    provenance_output = output_root / "provenance"
    provenance_output.mkdir()
    provenance_files = (
        "config.json",
        "profile.json",
        "component-lock.json",
        "plan.json",
        "deployment.json",
        "preflight.json",
        "preregistration.json",
        "implementation-source-manifest.json",
        "review-closure.json",
        "review-gate.json",
        "phase-authority.json",
        "topology.json",
        "identity-manifest.json",
        "validator-volume-bootstrap.json",
        "validator-volume-transaction.json",
        "toolchain-preflight.json",
        "normalized-stages.schema.json",
        "stage-template-set.schema.json",
        "effect-baseline.json",
        "effect-audit.json",
        "frozen-source-manifest.json",
    )
    for name in provenance_files:
        source = provenance_root / name
        if not source.is_file():
            raise LocalTopologyError(f"public provenance is incomplete: {name}")
        shutil.copyfile(source, provenance_output / name)
    report_lines = [
        "# Native multihop switching analysis",
        "",
        f"- Phase: `{phase}`",
        f"- Logical attempts/effects: {len(metrics):,}",
        f"- Physical transactions: {len(physical):,}",
        f"- Ordered hop receipts: {len(receipt_lineage):,}",
        "- Transaction formulas, typed rid/mid/receipt prefixes, native message IDs, and frozen Besu traces reconcile exactly.",
        "- Internal trace gas is inclusive and non-additive; same-transaction checks are not assigned fabricated wall-clock durations.",
    ]
    if phase == "scale":
        sensitivity = cast(dict[str, Any], analysis["latency_sensitivity"])
        report_lines.extend(
            [
                f"- Primary denominator: {sensitivity['primary_attempts']:,}.",
                f"- Interruption-free latency sensitivity: {sensitivity['included_attempts']:,} attempts; {sensitivity['excluded_attempts']:,} excluded as complete 11-route blocks.",
                "- Equivalence is reported only when the complete preregistered 90% interval lies inside its bound.",
                "- P95 and P99 are descriptive point estimates for this shared-host alpha system; they are non-inferential and are not release gates.",
            ]
        )
    (output_root / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    secret_errors = scan_secrets(output_root)
    secret_scan: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-secret-scan-v1",
        "forbidden_file_suffixes": [".key", ".raw", ".sqlite", ".pem"],
        "errors": secret_errors,
    }
    secret_scan["valid"] = not secret_scan["errors"]
    _write_json(output_root / "secret-scan.json", secret_scan)
    manifest: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-analysis-manifest-v1",
        "namespace": identity.evidence_namespace,
        "phase": phase,
        "result_role": result_role,
        "claim_eligible": claim_eligible,
        "config_sha256": config_sha256,
        "profile_sha256": _sha256_path(effective_profile_path),
        "component_lock_sha256": cast(dict[str, str], effective_profile["component_lock"])[
            "sha256"
        ],
        "source_lock_inventory_sha256": hashlib.sha256(
            rfc8785.dumps(config["source_sha256"])
        ).hexdigest(),
        "root_signer_audit_sha256": (
            _sha256_path(root_signer_audit_path) if root_signer_audit_path is not None else None
        ),
        "attempt_count": len(metrics),
        "physical_transaction_count": len(physical),
        "receipt_count": len(receipt_lineage),
        "event_count": len(event_rows),
        "validation_valid": validation["valid"],
        "secret_scan_valid": secret_scan["valid"],
        "files": [],
    }
    for path in sorted(output_root.rglob("*")):
        if path.is_file():
            cast(list[dict[str, Any]], manifest["files"]).append(
                {
                    "path": str(path.relative_to(output_root)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "bytes": path.stat().st_size,
                }
            )
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write_json(output_root / "manifest.json", manifest)
    return manifest
