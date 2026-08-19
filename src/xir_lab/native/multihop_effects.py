"""Complete-block-range effect reconciliation for multihop campaigns."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

import rfc8785
from web3 import Web3

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_deployer import CHAIN_ROLES
from xir_lab.native.multihop_identity import config_identity
from xir_lab.native.multihop_scalability import (
    MultihopPhase,
    iter_multihop_attempts,
    load_multihop_config,
)
from xir_lab.native.rpc import qbft_web3

EFFECT_LOG_BLOCK_WINDOW = 2_000
EFFECT_DESTINATION_ROLES = CHAIN_ROLES[1:]


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"effect evidence input is unavailable: {path}") from exc
    if not isinstance(value, dict):
        raise LocalTopologyError("effect evidence input must be a JSON object")
    return cast(dict[str, Any], value)


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact(repository_root: Path) -> dict[str, Any]:
    return _load(
        repository_root / "contracts/out/NativeMultihopReceiver.sol/NativeMultihopReceiver.json"
    )


def _semantic(document: dict[str, Any]) -> dict[str, Any]:
    payload = dict(document)
    payload["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    return payload


def _profile_chains_by_role(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    chains = cast(list[dict[str, Any]], profile.get("chains", []))
    by_role = {str(chain.get("label", "")).lower(): chain for chain in chains}
    if set(by_role) != set(CHAIN_ROLES) or len(chains) != len(CHAIN_ROLES):
        raise LocalTopologyError("effect profile must map exactly chains A through E")
    return by_role


def capture_effect_baseline(
    *,
    repository_root: Path,
    profile_path: Path,
    deployment_path: Path,
    config_path: Path,
    phase: MultihopPhase,
    output_path: Path,
) -> dict[str, Any]:
    """Freeze receiver counters and heads immediately before one phase."""

    profile = _load(profile_path)
    deployment = _load(deployment_path)
    raw_config = _load(config_path)
    evidence_namespace = (
        "native-multihop-switching-pilot-v1"
        if cast(dict[str, Any], raw_config.get("result_roles", {})).get("scale")
        == "pilot_diagnostic_only"
        else "native-multihop-switching-v1"
    )
    abi = _artifact(repository_root)["abi"]
    chains = _profile_chains_by_role(profile)
    rows: list[dict[str, Any]] = []
    for role in EFFECT_DESTINATION_ROLES:
        chain = chains[role]
        client = qbft_web3(str(chain["rpc_url"]))
        receiver_address = str(deployment["chains"][role]["receiver"])
        receiver = client.eth.contract(address=Web3.to_checksum_address(receiver_address), abi=abi)
        start_block = int(client.eth.block_number)
        start_block_hash = client.eth.get_block(start_block)["hash"].hex()
        rows.append(
            {
                "chain_role": role,
                "chain_id": int(chain["chain_id"]),
                "receiver": receiver_address.lower(),
                "start_block_inclusive": start_block,
                "start_block_hash": "0x" + start_block_hash.removeprefix("0x").lower(),
                "delivery_count_before": int(receiver.functions.deliveryCount().call()),
            }
        )
    document = _semantic(
        {
            "schema_version": "xir-lab-native-multihop-effect-baseline-v1",
            "namespace": evidence_namespace,
            "phase": phase,
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
            "receivers": rows,
        }
    )
    _write(output_path, document)
    return document


def _validate_semantic(document: dict[str, Any], *, schema: str) -> None:
    semantic = dict(document)
    expected = str(semantic.pop("semantic_sha256", ""))
    if (
        document.get("schema_version") != schema
        or hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != expected
    ):
        raise LocalTopologyError("effect evidence semantic digest is invalid")


def _build_effect_hash_index(expected: dict[str, Any]) -> dict[str, tuple[str, Any]]:
    """Hash each expected attempt once and reject the theoretical collision case."""

    index: dict[str, tuple[str, Any]] = {}
    for attempt_id, attempt in expected.items():
        digest = Web3.keccak(text=attempt_id).hex().removeprefix("0x").lower()
        if digest in index:
            raise LocalTopologyError("effect attempt hash collision")
        index[digest] = (attempt_id, attempt)
    return index


def _block_windows(
    start_block_inclusive: int,
    end_block_inclusive: int,
    *,
    window_size: int = EFFECT_LOG_BLOCK_WINDOW,
) -> list[dict[str, int]]:
    """Partition (start, end] into contiguous bounded inclusive RPC windows."""

    if start_block_inclusive < 0 or end_block_inclusive < start_block_inclusive:
        raise LocalTopologyError("effect block range is invalid")
    if window_size <= 0:
        raise LocalTopologyError("effect block window must be positive")
    windows: list[dict[str, int]] = []
    cursor = start_block_inclusive + 1
    while cursor <= end_block_inclusive:
        window_end = min(cursor + window_size - 1, end_block_inclusive)
        windows.append({"from_block": cursor, "to_block": window_end})
        cursor = window_end + 1
    return windows


def _valid_block_windows(
    windows: list[dict[str, Any]], *, start_block_inclusive: int, end_block_inclusive: int
) -> bool:
    expected = _block_windows(start_block_inclusive, end_block_inclusive)
    return windows == expected and all(
        int(row["to_block"]) - int(row["from_block"]) + 1 <= EFFECT_LOG_BLOCK_WINDOW
        for row in windows
    )


def _fetch_effect_logs(event_source: Any, windows: list[dict[str, int]]) -> list[Any]:
    """Fetch all fixed windows and impose one canonical on-chain ordering."""

    logs: list[Any] = []
    for window in windows:
        logs.extend(
            event_source.get_logs(
                from_block=window["from_block"],
                to_block=window["to_block"],
            )
        )
    logs.sort(
        key=lambda event: (
            int(event["blockNumber"]),
            int(event["transactionIndex"]),
            int(event["logIndex"]),
        )
    )
    return logs


def _expected_effect_lineage(
    *, runner_state_path: Path, trace_state_path: Path, phase: MultihopPhase
) -> dict[str, dict[str, Any]]:
    with (
        sqlite3.connect(f"file:{runner_state_path}?mode=ro", uri=True) as runner,
        sqlite3.connect(f"file:{trace_state_path}?mode=ro", uri=True) as traces,
    ):
        runner.row_factory = sqlite3.Row
        traces.row_factory = sqlite3.Row
        rows = runner.execute(
            """
            SELECT a.attempt_id,a.route,a.route_sequence,
                   s.transaction_hash,e.chain_role,e.detail_json
            FROM attempts a
            JOIN stages s ON s.attempt_id=a.attempt_id
                         AND s.stage='destination_verify_deliver'
                         AND s.state='succeeded'
            JOIN events e ON e.attempt_id=a.attempt_id
                         AND e.stage='destination_effect_observation'
                         AND e.event='observed'
            WHERE a.phase=? AND a.status='succeeded'
            """,
            (phase,),
        ).fetchall()
        expected: dict[str, dict[str, Any]] = {}
        for row in rows:
            attempt_id = str(row["attempt_id"])
            detail = cast(dict[str, Any], json.loads(str(row["detail_json"])))
            transaction_hash = "0x" + str(row["transaction_hash"]).lower().removeprefix("0x")
            trace_rows = traces.execute(
                "SELECT trace_json FROM traces WHERE chain_role=? AND transaction_hash=?",
                (str(row["chain_role"]), transaction_hash),
            ).fetchall()
            if len(trace_rows) != 1:
                raise LocalTopologyError("effect lineage lacks one frozen delivery trace")
            trace = cast(dict[str, Any], json.loads(str(trace_rows[0]["trace_json"])))
            observed_delivery_hash = (
                "0x"
                + str(detail.get("delivery_transaction_hash", ""))
                .lower()
                .removeprefix("0x")
            )
            if (
                observed_delivery_hash != transaction_hash
                or int(trace.get("status", 0)) != 1
            ):
                raise LocalTopologyError("effect lineage runner/trace binding differs")
            expected[attempt_id] = {
                "attempt_id": attempt_id,
                "route": str(row["route"]),
                "route_sequence": int(row["route_sequence"]),
                "chain_role": str(row["chain_role"]),
                "transaction_hash": transaction_hash,
                "message_id": str(detail["mid"]).lower(),
                "block_number": int(trace["block_number"]),
                "block_hash": str(trace["block_hash"]).lower(),
            }
        return expected


def validate_effect_audit(
    document: dict[str, Any],
    *,
    phase: MultihopPhase,
    expected_effects: dict[str, dict[str, Any]],
    expected_bindings: dict[str, str],
    expected_namespace: str = "native-multihop-switching-v1",
) -> None:
    """Validate a frozen exact-one audit without network access."""

    _validate_semantic(document, schema="xir-lab-native-multihop-effect-reconciliation-v1")
    effects = cast(list[dict[str, Any]], document.get("effects", []))
    receiver_checks = cast(list[dict[str, Any]], document.get("receiver_checks", []))
    expected_attempt_ids = set(expected_effects)
    observed_ids = [str(row.get("attempt_id", "")) for row in effects]
    observed_by_id = {str(row.get("attempt_id", "")): row for row in effects}
    checks_by_role = {str(row.get("chain_role", "")): row for row in receiver_checks}
    effects_by_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in effects:
        effects_by_role[str(row.get("chain_role", ""))].append(row)
    valid = (
        document.get("namespace") == expected_namespace
        and document.get("phase") == phase
        and all(document.get(key) == value for key, value in expected_bindings.items())
        and document.get("valid") is True
        and int(document.get("expected_effect_count", -1)) == len(expected_attempt_ids)
        and int(document.get("observed_effect_count", -1)) == len(expected_attempt_ids)
        and len(observed_ids) == len(set(observed_ids))
        and set(observed_ids) == expected_attempt_ids
        and document.get("complete_block_range_scanned") is True
        and document.get("receiver_counters_reconciled") is True
        and len(receiver_checks) == len(EFFECT_DESTINATION_ROLES)
        and set(checks_by_role) == set(EFFECT_DESTINATION_ROLES)
        and all(
            int(row.get("status", 0)) == 1
            and int(row.get("block_number", -1)) >= 0
            and int(row.get("log_index", -1)) >= 0
            and len(str(row.get("transaction_hash", "")).removeprefix("0x")) == 64
            and len(str(row.get("message_id", "")).removeprefix("0x")) == 64
            and len(str(row.get("block_hash", "")).removeprefix("0x")) == 64
            for row in effects
        )
        and all(
            all(observed_by_id[attempt_id].get(key) == value for key, value in expected.items())
            for attempt_id, expected in expected_effects.items()
        )
        and all(
            int(row.get("end_block_inclusive", -1)) >= int(row.get("start_block_inclusive", 0))
            and len(str(row.get("start_block_hash", "")).removeprefix("0x")) == 64
            and len(str(row.get("end_block_hash", "")).removeprefix("0x")) == 64
            and int(row.get("counter_delta", -1))
            == int(row.get("delivery_count_after", -1)) - int(row.get("delivery_count_before", -1))
            == int(row.get("expected_delta", -2))
            == int(row.get("event_count", -3))
            == len(effects_by_role[str(row["chain_role"])])
            and _valid_block_windows(
                cast(list[dict[str, Any]], row.get("scan_windows", [])),
                start_block_inclusive=int(row.get("start_block_inclusive", -1)),
                end_block_inclusive=int(row.get("end_block_inclusive", -1)),
            )
            and all(
                int(effect.get("block_number", -1)) > int(row.get("start_block_inclusive", -1))
                and int(effect.get("block_number", -1)) <= int(row.get("end_block_inclusive", -1))
                for effect in effects_by_role[str(row["chain_role"])]
            )
            for row in receiver_checks
        )
        and sum(int(row["expected_delta"]) for row in receiver_checks) == len(expected_attempt_ids)
    )
    if not valid:
        raise LocalTopologyError("frozen complete-range exact-one effect audit is invalid")


def reconcile_effects(
    *,
    repository_root: Path,
    profile_path: Path,
    deployment_path: Path,
    config_path: Path,
    phase: MultihopPhase,
    baseline_path: Path,
    runner_state_path: Path,
    trace_state_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Scan every receiver event from its frozen start block through the final head."""

    profile = _load(profile_path)
    config, _ = load_multihop_config(config_path)
    evidence_namespace = config_identity(config).evidence_namespace
    baseline = _load(baseline_path)
    _validate_semantic(baseline, schema="xir-lab-native-multihop-effect-baseline-v1")
    if (
        baseline.get("phase") != phase
        or baseline.get("config_sha256") != hashlib.sha256(config_path.read_bytes()).hexdigest()
        or baseline.get("profile_sha256") != hashlib.sha256(profile_path.read_bytes()).hexdigest()
        or baseline.get("deployment_sha256")
        != hashlib.sha256(deployment_path.read_bytes()).hexdigest()
    ):
        raise LocalTopologyError("effect baseline phase/config/profile/deployment binding drift")
    expected_lineage = _expected_effect_lineage(
        runner_state_path=runner_state_path,
        trace_state_path=trace_state_path,
        phase=phase,
    )
    attempts = tuple(iter_multihop_attempts(config_path=config_path, phase=phase))
    expected_by_role: dict[str, dict[str, Any]] = defaultdict(dict)
    for attempt in attempts:
        expected_by_role[CHAIN_ROLES[attempt.hop_count]][attempt.attempt_id] = attempt
    hash_index_by_role = {
        role: _build_effect_hash_index(expected_by_role.get(role, {}))
        for role in EFFECT_DESTINATION_ROLES
    }
    abi = _artifact(repository_root)["abi"]
    chains = _profile_chains_by_role(profile)
    baseline_by_role = {
        str(row["chain_role"]): row for row in cast(list[dict[str, Any]], baseline["receivers"])
    }
    effects: list[dict[str, Any]] = []
    receiver_checks: list[dict[str, Any]] = []
    for role in EFFECT_DESTINATION_ROLES:
        chain = chains[role]
        row = baseline_by_role[role]
        client = qbft_web3(str(chain["rpc_url"]))
        address = Web3.to_checksum_address(str(row["receiver"]))
        receiver = client.eth.contract(address=address, abi=abi)
        observed_start_hash = client.eth.get_block(int(row["start_block_inclusive"]))["hash"].hex()
        if (
            "0x" + observed_start_hash.removeprefix("0x").lower()
            != str(row["start_block_hash"]).lower()
        ):
            raise LocalTopologyError("effect baseline start block hash is no longer canonical")
        end_block = int(client.eth.block_number)
        end_block_hash = client.eth.get_block(end_block)["hash"].hex()
        scan_windows = _block_windows(int(row["start_block_inclusive"]), end_block)
        logs = _fetch_effect_logs(
            receiver.events.NativeMultihopEffectApplied(), scan_windows
        )
        expected = expected_by_role.get(role, {})
        expected_hashes = hash_index_by_role[role]
        observed_for_role: set[str] = set()
        for event in logs:
            args = event["args"]
            attempt_id_hex = bytes(args["attemptId"]).hex().lower()
            matched = expected_hashes.get(attempt_id_hex)
            if matched is None or matched[0] in observed_for_role:
                raise LocalTopologyError(
                    "receiver block range contains an unexpected/duplicate effect"
                )
            attempt_id, attempt = matched
            transaction_hash = event["transactionHash"].hex()
            receipt = client.eth.get_transaction_receipt(transaction_hash)
            route_bytes = bytes(args["route"]).decode("ascii")
            if (
                int(receipt["status"]) != 1
                or route_bytes != attempt.route
                or int(args["routeSequence"]) != attempt.route_sequence
            ):
                raise LocalTopologyError("receiver effect payload/receipt differs from plan")
            observed_for_role.add(attempt_id)
            effects.append(
                {
                    "attempt_id": attempt_id,
                    "route": attempt.route,
                    "route_sequence": attempt.route_sequence,
                    "chain_role": role,
                    "chain_id": int(chain["chain_id"]),
                    "receiver": str(row["receiver"]).lower(),
                    "transaction_hash": "0x" + transaction_hash.removeprefix("0x").lower(),
                    "block_number": int(event["blockNumber"]),
                    "block_hash": "0x" + event["blockHash"].hex().removeprefix("0x").lower(),
                    "log_index": int(event["logIndex"]),
                    "status": int(receipt["status"]),
                    "message_id": "0x" + bytes(args["messageId"]).hex(),
                    "delivery_count": int(args["deliveryCount"]),
                }
            )
        after = int(receiver.functions.deliveryCount().call())
        expected_delta = len(expected)
        receiver_checks.append(
            {
                "chain_role": role,
                "start_block_inclusive": int(row["start_block_inclusive"]),
                "end_block_inclusive": end_block,
                "start_block_hash": str(row["start_block_hash"]).lower(),
                "end_block_hash": "0x" + end_block_hash.removeprefix("0x").lower(),
                "delivery_count_before": int(row["delivery_count_before"]),
                "delivery_count_after": after,
                "counter_delta": after - int(row["delivery_count_before"]),
                "event_count": len(logs),
                "expected_delta": expected_delta,
                "scan_windows": scan_windows,
            }
        )
    document = _semantic(
        {
            "schema_version": "xir-lab-native-multihop-effect-reconciliation-v1",
            "namespace": evidence_namespace,
            "phase": phase,
            "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
            "valid": True,
            "expected_effect_count": len(attempts),
            "observed_effect_count": len(effects),
            "receiver_checks": receiver_checks,
            "effects": sorted(effects, key=lambda item: item["attempt_id"]),
            "complete_block_range_scanned": True,
            "receiver_counters_reconciled": True,
        }
    )
    validate_effect_audit(
        document,
        phase=phase,
        expected_effects=expected_lineage,
        expected_bindings={
            "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
        },
        expected_namespace=evidence_namespace,
    )
    _write(output_path, document)
    return document
