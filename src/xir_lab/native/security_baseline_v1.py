"""Strict payload-only native-carrier capability campaign.

This follow-up reuses the B0 contracts from ``native-ablation-v2`` while using
an independent plan, runner database, raw-evidence root, and publication tree.
Static field absence is reported as capability evidence. Dynamic cases report
only behavior that was actually submitted through native Hyperlane/LayerZero.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785
from eth_abi.abi import decode, encode
from eth_account import Account
from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_v1 import (
    HYPERLANE_PROCESS_TOPIC,
    LAYERS,
    ROUTES,
    AblationAttempt,
    NativeAblationRunner,
    _hex,
    _index_layerzero_actions,
    _query_logs,
    _receipt_dispatch_id,
    _retry_rpc_read,
    expected_prior_verifier_bindings,
    final_revision_bindings_valid,
    query_onchain_prior_verifier_bindings,
)
from xir_lab.native.deployer import PROFILE_HASHES
from xir_lab.native.rpc import qbft_web3

BaselineCase = Literal[
    "history_absent_delivery",
    "between_hop_payload_substitution",
    "route_label_substitution",
    "inactive_profile_unchecked",
    "new_native_envelope_replay",
]
CASES: tuple[BaselineCase, ...] = (
    "history_absent_delivery",
    "between_hop_payload_substitution",
    "route_label_substitution",
    "inactive_profile_unchecked",
    "new_native_envelope_replay",
)
REPLAY_REJECTED_TOPIC = (
    "0x" + keccak(text="AblationReplayRejected(bytes32,bytes32,uint8,address)").hex()
)
EFFECT_TOPIC = (
    "0x"
    + keccak(
        text=(
            "AblationEffectApplied(bytes32,bytes2,uint8,uint64,bytes32,bytes32,"
            "bytes32,bytes32,uint256)"
        )
    ).hex()
)


@dataclass(frozen=True)
class BaselineCaseAttempt:
    entry: AblationAttempt
    case_name: BaselineCase
    repetition: int
    expected_primary_effect: bool = True
    expected_replay_rejection: bool = False

    def document(self) -> dict[str, Any]:
        return {
            **self.entry.document(),
            "case_name": self.case_name,
            "repetition": self.repetition,
            "expected_primary_effect": self.expected_primary_effect,
            "expected_replay_rejection": self.expected_replay_rejection,
        }


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _schema(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((_repository_root() / "schemas" / name).read_text(encoding="utf-8")),
    )


def _validate_schema(document: dict[str, Any], name: str) -> None:
    errors = sorted(
        jsonschema.Draft202012Validator(_schema(name)).iter_errors(document),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise LocalTopologyError(f"{name} violation at {location}: {errors[0].message}")


def load_baseline_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    document = cast(dict[str, Any], json.loads(raw))
    _validate_schema(document, "native-security-baseline-v1-config.schema.json")
    return document, hashlib.sha256(raw).hexdigest()


def _application_bytes(
    *, seed: str, case_name: BaselineCase, repetition: int, variant: str
) -> bytes:
    material = f"{seed}:{case_name}:{repetition}:{variant}".encode()
    return hashlib.shake_256(material).digest(96 + repetition % 5 * 16)


def build_case_route_payload(
    item: BaselineCaseAttempt,
    *,
    seed: str,
    mutated_application: bool = False,
    substituted_route_label: bool = False,
) -> bytes:
    route = item.entry.attempt.route
    route_label = route[::-1] if substituted_route_label else route
    variant = "mutated" if mutated_application else "original"
    application = _application_bytes(
        seed=seed,
        case_name=item.case_name,
        repetition=item.repetition,
        variant=variant,
    )
    return encode(
        ["(bytes32,bytes2,uint64,bytes)"],
        [
            (
                keccak(text=item.entry.attempt.attempt_id),
                route_label.encode("ascii"),
                item.repetition,
                application,
            )
        ],
    )


def b0_carrier_payload(route_payload: bytes) -> bytes:
    return encode(["uint8", "bytes"], [0, route_payload])


def matched_inactive_profile(route: str) -> bytes:
    if route not in ROUTES:
        raise LocalTopologyError(f"baseline route has no matched XIR profile: {route}")
    return PROFILE_HASHES[f"{route[0]}_AB"]


def build_baseline_plan(config_path: Path) -> tuple[BaselineCaseAttempt, ...]:
    config, _ = load_baseline_config(config_path)
    seed = str(config["fixed_seed"])
    repetitions = int(config["repetitions"])
    plan: list[BaselineCaseAttempt] = []
    for repetition in range(repetitions):
        case_rotation = repetition % len(CASES)
        case_order = CASES[case_rotation:] + CASES[:case_rotation]
        route_order = ROUTES if repetition % 2 == 0 else tuple(reversed(ROUTES))
        slot = 0
        for case_name in case_order:
            for route in route_order:
                identity = {
                    "namespace": config["namespace"],
                    "seed": seed,
                    "case": case_name,
                    "route": route,
                    "repetition": repetition,
                }
                attempt_id = "basev1_" + hashlib.sha256(rfc8785.dumps(identity)).hexdigest()[:32]
                original_application = _application_bytes(
                    seed=seed,
                    case_name=case_name,
                    repetition=repetition,
                    variant="original",
                )
                native = NativeAttempt(
                    attempt_id=attempt_id,
                    phase=cast(Any, "security_baseline"),
                    route=route,
                    route_sequence=repetition,
                    first_protocol=route[0],
                    second_protocol=route[1],
                    execution_class="native_security_baseline_v1",
                    xir=False,
                    payload_bytes=len(original_application),
                    payload_sha256=hashlib.sha256(original_application).hexdigest(),
                )
                entry = AblationAttempt(
                    attempt=native,
                    layer=LAYERS[0],
                    pair_id=(
                        "basepair_"
                        + hashlib.sha256(
                            rfc8785.dumps(
                                {
                                    "namespace": config["namespace"],
                                    "case": case_name,
                                    "repetition": repetition,
                                }
                            )
                        ).hexdigest()[:24]
                    ),
                    interleave_block=repetition,
                    interleave_slot=slot,
                    logical_nonce=repetition * len(CASES) + CASES.index(case_name),
                )
                plan.append(
                    BaselineCaseAttempt(
                        entry=entry,
                        case_name=case_name,
                        repetition=repetition,
                        expected_replay_rejection=(case_name == "new_native_envelope_replay"),
                    )
                )
                slot += 1
    validate_baseline_plan(plan, repetitions=repetitions)
    return tuple(plan)


def validate_baseline_plan(
    plan: list[BaselineCaseAttempt] | tuple[BaselineCaseAttempt, ...],
    *,
    repetitions: int,
) -> None:
    expected_cells = {(route, case_name) for route in ROUTES for case_name in CASES}
    ids: set[str] = set()
    counts = {cell: 0 for cell in expected_cells}
    blocks: dict[int, list[BaselineCaseAttempt]] = {}
    for item in plan:
        attempt_id = item.entry.attempt.attempt_id
        if attempt_id in ids:
            raise LocalTopologyError("duplicate baseline capability attempt id")
        ids.add(attempt_id)
        cell = (item.entry.attempt.route, item.case_name)
        if cell not in expected_cells:
            raise LocalTopologyError(f"unexpected baseline capability cell: {cell}")
        counts[cell] += 1
        blocks.setdefault(item.repetition, []).append(item)
    if set(counts.values()) != {repetitions}:
        raise LocalTopologyError(f"unbalanced baseline capability cells: {counts}")
    if len(blocks) != repetitions:
        raise LocalTopologyError("baseline capability repetition count mismatch")
    for repetition, block in blocks.items():
        if {(item.entry.attempt.route, item.case_name) for item in block} != expected_cells:
            raise LocalTopologyError(f"baseline block {repetition} lacks a route/case cell")
        if sorted(item.entry.interleave_slot for item in block) != list(range(10)):
            raise LocalTopologyError(f"baseline block {repetition} has invalid slots")


def write_baseline_plan(path: Path, plan: tuple[BaselineCaseAttempt, ...]) -> str:
    document = {
        "schema_version": "xir-lab-native-security-baseline-v1-plan",
        "namespace": "native-security-baseline-v1",
        "attempt_count": len(plan),
        "cells": {
            f"{route}_{case_name}": sum(
                item.entry.attempt.route == route and item.case_name == case_name for item in plan
            )
            for route in ROUTES
            for case_name in CASES
        },
        "attempts": [item.document() for item in plan],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def partition_baseline_block(
    block: tuple[BaselineCaseAttempt, ...] | list[BaselineCaseAttempt],
) -> tuple[list[BaselineCaseAttempt], list[BaselineCaseAttempt]]:
    """Keep registry mutations outside every concurrent execution group."""

    ordinary = [item for item in block if item.case_name != "inactive_profile_unchecked"]
    inactive = [item for item in block if item.case_name == "inactive_profile_unchecked"]
    if len(block) != 10 or len(ordinary) != 8 or len(inactive) != 2:
        raise LocalTopologyError("baseline interleave block does not contain 8+2 serial split")
    return ordinary, inactive


def capability_rows() -> list[dict[str, Any]]:
    source_entrypoint = "sendBaselineSource(bytes32,bytes,bytes)"
    destination_entrypoint = "baselineCarrierReceive(bytes32,bytes)"
    return [
        {
            "field": "application_route_payload",
            "expressible": True,
            "destination_visible": True,
            "calldata_path": "B0 carrier payload: (uint8=0, bytes routePayload)",
            "entrypoint": source_entrypoint,
            "enforcement_stage": "destination application validation",
            "evidence_class": "ABI_and_calldata_digest",
        },
        {
            "field": "final_native_message_id",
            "expressible": True,
            "destination_visible": True,
            "calldata_path": "injected by final native adapter",
            "entrypoint": destination_entrypoint,
            "enforcement_stage": "application replay map",
            "evidence_class": "native_adapter_callback",
        },
        {
            "field": "first_hop_native_authentication",
            "expressible": True,
            "destination_visible": False,
            "calldata_path": "terminates at NativeAblationIngressV1",
            "entrypoint": "baselineCarrierReceive(bytes32,bytes) at the intermediate network",
            "enforcement_stage": "first native adapter and intermediate ingress",
            "evidence_class": "native_adapter_callback_not_destination_bound",
        },
        {
            "field": "prior_hop_native_message_id",
            "expressible": False,
            "destination_visible": False,
            "calldata_path": "absent",
            "entrypoint": destination_entrypoint,
            "enforcement_stage": "none",
            "evidence_class": "ABI_field_absence",
        },
        {
            "field": "verifier_profile_or_version",
            "expressible": False,
            "destination_visible": False,
            "calldata_path": "absent",
            "entrypoint": destination_entrypoint,
            "enforcement_stage": "none",
            "evidence_class": "ABI_field_absence",
        },
        {
            "field": "registry_version_or_status",
            "expressible": False,
            "destination_visible": False,
            "calldata_path": "absent",
            "entrypoint": destination_entrypoint,
            "enforcement_stage": "none",
            "evidence_class": "ABI_field_absence",
        },
        {
            "field": "ordered_receipt_history",
            "expressible": False,
            "destination_visible": False,
            "calldata_path": "absent",
            "entrypoint": destination_entrypoint,
            "enforcement_stage": "none",
            "evidence_class": "ABI_field_absence",
        },
    ]


class NativeSecurityBaselineRunner(NativeAblationRunner):
    """Execute five strict B0 capability cases through both native orders."""

    def __init__(
        self,
        *,
        baseline_config_path: Path,
        registry_owner_private_key: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.baseline_config_path = baseline_config_path
        self.baseline_config, _ = load_baseline_config(baseline_config_path)
        required_namespace = str(self.baseline_config["required_environment_namespace"])
        if self.ablation_config["namespace"] != required_namespace:
            raise LocalTopologyError(
                f"baseline requires {required_namespace}, got {self.ablation_config['namespace']}"
            )
        if self.deployment.get("namespace") != required_namespace:
            raise LocalTopologyError("baseline deployment is not the final-revision environment")
        if not final_revision_bindings_valid(self.deployment):
            raise LocalTopologyError("baseline deployment prior-verifier bindings are invalid")
        if query_onchain_prior_verifier_bindings(
            self.clients["intermediate"], self.deployment
        ) != expected_prior_verifier_bindings(self.deployment):
            raise LocalTopologyError("baseline on-chain prior-verifier bindings are invalid")
        if self.deployment.get("final_revision_source_sha256") != self.baseline_config.get(
            "final_revision_source_sha256"
        ):
            raise LocalTopologyError("baseline final-revision source lock mismatch")
        self.registry = self._contract("destination", "registry", "XIRRegistry.sol", "XIRRegistry")
        self.registry_owner = Account.from_key(registry_owner_private_key)
        self.registry_owner_lock = threading.Lock()
        if self.registry.functions.owner().call().lower() != self.registry_owner.address.lower():
            raise LocalTopologyError("registry owner key does not match deployed registry")

    def run_baseline_campaign(self) -> None:
        plan = build_baseline_plan(self.baseline_config_path)
        concurrency = int(self.baseline_config["concurrency"])
        for offset in range(0, len(plan), 10):
            block = plan[offset : offset + 10]
            ordinary, inactive = partition_baseline_block(block)
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(self._run_case, item) for item in ordinary]
                for future in futures:
                    future.result()
            for item in inactive:
                self._run_case(item)

    def _run_case(self, item: BaselineCaseAttempt) -> None:
        entry = item.entry
        attempt = entry.attempt
        if not self.state.begin(attempt):
            return
        seed = str(self.baseline_config["fixed_seed"])
        first_route_payload = build_case_route_payload(item, seed=seed)
        second_route_payload = build_case_route_payload(
            item,
            seed=seed,
            mutated_application=(item.case_name == "between_hop_payload_substitution"),
            substituted_route_label=(item.case_name == "route_label_substitution"),
        )
        first_carrier_payload = b0_carrier_payload(first_route_payload)
        second_carrier_payload = b0_carrier_payload(second_route_payload)
        profile_hash = (
            matched_inactive_profile(attempt.route)
            if item.case_name == "inactive_profile_unchecked"
            else None
        )
        original_profile = (
            self._profile_snapshot(profile_hash) if profile_hash is not None else None
        )
        if original_profile is not None and not original_profile[6]:
            raise LocalTopologyError("matched XIR first-hop profile is not active before B0 case")
        self.state.record_stage(
            attempt.attempt_id,
            "case_materialized",
            "succeeded",
            {
                "case_name": item.case_name,
                "route": attempt.route,
                "repetition": item.repetition,
                "first_route_payload_sha256": hashlib.sha256(first_route_payload).hexdigest(),
                "second_route_payload_sha256": hashlib.sha256(second_route_payload).hexdigest(),
                "first_carrier_payload_sha256": hashlib.sha256(first_carrier_payload).hexdigest(),
                "second_carrier_payload_sha256": hashlib.sha256(second_carrier_payload).hexdigest(),
                "semantic_payload_changed": first_route_payload != second_route_payload,
                "profile_or_history_field_present": False,
                "matched_xir_profile_hash": (
                    "" if profile_hash is None else "0x" + profile_hash.hex()
                ),
                "original_profile": (
                    None
                    if original_profile is None
                    else self._profile_snapshot_document(original_profile)
                ),
            },
        )
        try:
            if profile_hash is not None and original_profile is not None:
                disabled = (*original_profile[:6], False)
                self._set_registry_profile(
                    attempt_id=attempt.attempt_id,
                    stage="profile_disable",
                    profile_hash=profile_hash,
                    snapshot=disabled,
                )
                observed = self._profile_snapshot(profile_hash)
                if observed[6]:
                    raise LocalTopologyError("matched XIR profile remained active")
                self.state.record_stage(
                    attempt.attempt_id,
                    "inactive_profile_observed",
                    "succeeded",
                    {
                        "profile_hash": "0x" + profile_hash.hex(),
                        "enabled": False,
                        "snapshot": self._profile_snapshot_document(observed),
                        "profile_carried_by_b0": False,
                        "matched_xir_case": "profile_inactive",
                    },
                )
            self.dispatch_baseline_first(
                entry,
                first_carrier_payload,
                stage="baseline_first_dispatch",
                authentication_stage="baseline_first_authenticated",
            )
            self.dispatch_baseline_second(
                entry,
                second_carrier_payload,
                stage="baseline_second_dispatch",
            )
            self.wait_ablation_effect(entry, stage="destination_effect")
            if item.expected_replay_rejection:
                start_block = int(self.clients["destination"].eth.block_number)
                self.dispatch_baseline_second(
                    entry,
                    second_carrier_payload,
                    stage="replay_second_dispatch",
                )
                replay_log = self._wait_replay_rejection(
                    attempt_hash=keccak(text=attempt.attempt_id),
                    first_block=start_block,
                )
                self.state.record_stage(
                    attempt.attempt_id,
                    "replay_rejected",
                    "succeeded",
                    {
                        "transaction_hash": _hex(replay_log["transactionHash"]).lower(),
                        "block_number": int(replay_log["blockNumber"]),
                        "enforcement_stage": "destination_application_replay",
                        "application_effect": False,
                    },
                )
        finally:
            if profile_hash is not None and original_profile is not None:
                self._set_registry_profile(
                    attempt_id=attempt.attempt_id,
                    stage="profile_restore",
                    profile_hash=profile_hash,
                    snapshot=original_profile,
                )
                restored = self._profile_snapshot(profile_hash)
                if restored != original_profile:
                    raise LocalTopologyError("registry profile restoration mismatch")
                self.state.record_stage(
                    attempt.attempt_id,
                    "profile_restored",
                    "succeeded",
                    {
                        "profile_hash": "0x" + profile_hash.hex(),
                        "restored": True,
                        "snapshot": self._profile_snapshot_document(restored),
                    },
                )
        self.state.record_stage(
            attempt.attempt_id,
            "baseline_complete",
            "succeeded",
            {
                "case_name": item.case_name,
                "route": attempt.route,
                "repetition": item.repetition,
                "expected_primary_effect": True,
                "expected_replay_rejection": item.expected_replay_rejection,
            },
        )
        self.state.finish(attempt.attempt_id)

    def _profile_snapshot(
        self, profile_hash: bytes
    ) -> tuple[bytes, bytes, str, int, int, int, bool]:
        raw = self.registry.functions.profileAt(profile_hash).call()
        return (
            bytes(raw[0]),
            bytes(raw[1]),
            str(raw[2]),
            int(raw[3]),
            int(raw[4]),
            int(raw[5]),
            bool(raw[6]),
        )

    @staticmethod
    def _profile_snapshot_document(
        snapshot: tuple[bytes, bytes, str, int, int, int, bool],
    ) -> dict[str, Any]:
        return {
            "src_hash": "0x" + snapshot[0].hex(),
            "dst_hash": "0x" + snapshot[1].hex(),
            "adapter": snapshot[2].lower(),
            "security_level": snapshot[3],
            "valid_after": snapshot[4],
            "valid_until": snapshot[5],
            "enabled": snapshot[6],
        }

    def _set_registry_profile(
        self,
        *,
        attempt_id: str,
        stage: str,
        profile_hash: bytes,
        snapshot: tuple[bytes, bytes, str, int, int, int, bool],
    ) -> dict[str, Any]:
        """Set and durably evidence one real profile using the registry owner."""

        client = self.clients["destination"]
        existing = self.state.stage(attempt_id, stage)
        if (
            existing is not None
            and str(existing["state"]) == "succeeded"
            and self._profile_snapshot(profile_hash) == snapshot
        ):
            return cast(dict[str, Any], json.loads(str(existing["detail_json"])))
        with self.registry_owner_lock:
            nonce = int(client.eth.get_transaction_count(self.registry_owner.address, "pending"))
            function = self.registry.functions.setProfile(profile_hash, snapshot)
            built = cast(
                dict[str, Any],
                function.build_transaction(
                    {
                        "from": self.registry_owner.address,
                        "chainId": int(self.chain_by_role["destination"]["chain_id"]),
                        "nonce": nonce,
                        "maxFeePerGas": max(int(client.eth.gas_price) * 2, 1),
                        "maxPriorityFeePerGas": 0,
                        "type": 2,
                        "gas": 2_000_000,
                    }
                ),
            )
            call_data = bytes.fromhex(str(built["data"])[2:])
            intended = {
                "role": "destination",
                "nonce": nonce,
                "transaction_nonce": nonce,
                "target": str(built["to"]).lower(),
                "calldata_sha256": hashlib.sha256(call_data).hexdigest(),
                "profile_hash": "0x" + profile_hash.hex(),
                "profile_snapshot": self._profile_snapshot_document(snapshot),
            }
            self.state.record_stage(attempt_id, stage, "intended", intended)
            signed = self.registry_owner.sign_transaction(built)
            raw = bytes(signed.raw_transaction)
            transaction_hash = signed.hash.hex()
            raw_path = self.signed_root / f"{transaction_hash}.raw"
            raw_path.write_bytes(raw)
            os.chmod(raw_path, 0o600)
            self.state.record_stage(
                attempt_id,
                stage,
                "signed",
                {**intended, "raw_sha256": hashlib.sha256(raw).hexdigest()},
                transaction_hash,
            )
            try:
                client.eth.send_raw_transaction(raw)
            except Exception as exc:
                if "already known" not in str(exc).lower():
                    raise
            receipt = client.eth.wait_for_transaction_receipt(
                HexStr(transaction_hash), timeout=self.timeout_seconds
            )
            if int(receipt["status"]) != 1:
                raise LocalTopologyError(f"registry owner transaction reverted: {stage}")
            detail = self._persist_receipt(
                transaction_hash=transaction_hash,
                receipt=receipt,
                detail=intended,
            )
            self.state.record_stage(attempt_id, stage, "succeeded", detail, transaction_hash)
            return detail

    def _wait_replay_rejection(self, *, attempt_hash: bytes, first_block: int) -> Any:
        deadline = time.monotonic() + self.timeout_seconds
        receiver = self.contracts["destination"]["ablation_receiver"]
        while time.monotonic() < deadline:
            logs = self.clients["destination"].eth.get_logs(
                cast(
                    Any,
                    {
                        "fromBlock": first_block,
                        "toBlock": "latest",
                        "address": receiver,
                        "topics": [REPLAY_REJECTED_TOPIC, "0x" + attempt_hash.hex()],
                    },
                )
            )
            if logs:
                return logs[-1]
            time.sleep(0.25)
        raise LocalTopologyError("timed out waiting for B0 replay rejection event")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def analyze_baseline_campaign(
    *,
    config_path: Path,
    profile_path: Path,
    deployment_path: Path,
    runner_state_path: Path,
    layerzero_state_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Reconcile 300 native B0 cases and freeze capability/result evidence."""

    config, config_sha = load_baseline_config(config_path)
    deployment = cast(dict[str, Any], json.loads(deployment_path.read_text(encoding="utf-8")))
    profile = cast(dict[str, Any], json.loads(profile_path.read_text(encoding="utf-8")))
    required_environment = str(config["required_environment_namespace"])
    environment_namespace_valid = deployment.get("namespace") == required_environment
    final_revision_binding_valid = final_revision_bindings_valid(deployment)
    final_revision_source_lock_valid = deployment.get("final_revision_source_sha256") == config.get(
        "final_revision_source_sha256"
    )
    plan = build_baseline_plan(config_path)
    expected = {item.entry.attempt.attempt_id: item for item in plan}
    runner = sqlite3.connect(runner_state_path)
    runner.row_factory = sqlite3.Row
    attempt_rows = {
        str(row["attempt_id"]): row for row in runner.execute("SELECT * FROM attempts").fetchall()
    }
    errors: list[dict[str, Any]] = []
    if not environment_namespace_valid:
        errors.append(
            {
                "environment_namespace": deployment.get("namespace"),
                "required_environment_namespace": required_environment,
            }
        )
    if not final_revision_binding_valid:
        errors.append({"final_revision_prior_binding_valid": False})
    if not final_revision_source_lock_valid:
        errors.append({"final_revision_source_lock_valid": False})
    missing = sorted(set(expected) - set(attempt_rows))
    unexpected = sorted(set(attempt_rows) - set(expected))
    incomplete = sorted(
        attempt_id for attempt_id, row in attempt_rows.items() if str(row["status"]) != "succeeded"
    )
    if missing:
        errors.append({"missing_attempts": missing})
    if unexpected:
        errors.append({"unexpected_attempts": unexpected})
    if incomplete:
        errors.append({"incomplete_attempts": incomplete})

    clients = {
        str(chain["route_role"]): qbft_web3(str(chain["rpc_url"])) for chain in profile["chains"]
    }
    onchain_prior_bindings = query_onchain_prior_verifier_bindings(
        clients["intermediate"], deployment
    )
    onchain_prior_binding_valid = onchain_prior_bindings == expected_prior_verifier_bindings(
        deployment
    )
    if not onchain_prior_binding_valid:
        errors.append({"onchain_prior_binding_valid": False})
    chain_role = {int(chain["chain_id"]): str(chain["route_role"]) for chain in profile["chains"]}
    first_block = min(
        int(bounds["first"]) for bounds in deployment["deployment_block_bounds"].values()
    )
    hyperlane_process: dict[tuple[str, str], str] = {}
    for role in ("intermediate", "destination"):
        logs = _query_logs(
            clients[role],
            address=deployment["infrastructure"][role]["mailbox"],
            topic=HYPERLANE_PROCESS_TOPIC,
            first=first_block,
            last=int(clients[role].eth.block_number),
        )
        for log in logs:
            topics = list(log["topics"])
            if len(topics) >= 2:
                hyperlane_process[(role, _hex(topics[1]).lower())] = _hex(
                    log["transactionHash"]
                ).lower()
    worker = sqlite3.connect(layerzero_state_path)
    worker.row_factory = sqlite3.Row
    layerzero_actions_by_guid = _index_layerzero_actions(worker)
    transaction_cache: dict[tuple[str, str], dict[str, Any]] = {}
    analyzer_transaction_read_retry_count = 0

    def transaction_metrics(role: str, transaction_hash: str) -> dict[str, Any]:
        nonlocal analyzer_transaction_read_retry_count
        tx_hash = transaction_hash.lower()
        key = (role, tx_hash)
        if key in transaction_cache:
            return transaction_cache[key]
        tx, tx_retries = _retry_rpc_read(lambda: clients[role].eth.get_transaction(HexStr(tx_hash)))
        receipt, receipt_retries = _retry_rpc_read(
            lambda: clients[role].eth.get_transaction_receipt(HexStr(tx_hash))
        )
        analyzer_transaction_read_retry_count += tx_retries + receipt_retries
        metrics = {
            "transaction_hash": tx_hash,
            "role": role,
            "chain_id": int(tx["chainId"]),
            "block_number": int(receipt["blockNumber"]),
            "block_hash": _hex(receipt["blockHash"]).lower(),
            "transaction_index": int(receipt["transactionIndex"]),
            "sender": str(tx["from"]).lower(),
            "target": None if tx["to"] is None else str(tx["to"]).lower(),
            "calldata_sha256": hashlib.sha256(bytes(tx["input"])).hexdigest(),
            "calldata_bytes": len(bytes(tx["input"])),
            "gas_used": int(receipt["gasUsed"]),
            "status": int(receipt["status"]),
        }
        transaction_cache[key] = metrics
        return metrics

    effect_logs = _query_logs(
        clients["destination"],
        address=deployment["chains"]["destination"]["ablation_receiver"],
        topic=EFFECT_TOPIC,
        first=first_block,
        last=int(clients["destination"].eth.block_number),
    )
    replay_logs = _query_logs(
        clients["destination"],
        address=deployment["chains"]["destination"]["ablation_receiver"],
        topic=REPLAY_REJECTED_TOPIC,
        first=first_block,
        last=int(clients["destination"].eth.block_number),
    )
    expected_hashes = {"0x" + keccak(text=attempt_id).hex(): attempt_id for attempt_id in expected}
    effects: dict[str, list[Any]] = {attempt_id: [] for attempt_id in expected}
    replays: dict[str, list[Any]] = {attempt_id: [] for attempt_id in expected}
    for log in effect_logs:
        topics = list(log["topics"])
        if len(topics) >= 2:
            attempt_id = expected_hashes.get(_hex(topics[1]).lower())
            if attempt_id is not None:
                effects[attempt_id].append(log)
    for log in replay_logs:
        topics = list(log["topics"])
        if len(topics) >= 2:
            attempt_id = expected_hashes.get(_hex(topics[1]).lower())
            if attempt_id is not None:
                replays[attempt_id].append(log)

    physical_rows: list[dict[str, Any]] = []
    result_rows: list[dict[str, Any]] = []
    coordinator_retry_count = 0
    required_common = {
        "case_materialized",
        "baseline_first_dispatch",
        "baseline_first_authenticated",
        "baseline_second_dispatch",
        "destination_effect",
        "baseline_complete",
    }
    for attempt_id, item in expected.items():
        row = attempt_rows.get(attempt_id)
        if row is None:
            continue
        stages = {
            str(stage["stage"]): stage
            for stage in runner.execute(
                "SELECT * FROM stages WHERE attempt_id=?", (attempt_id,)
            ).fetchall()
        }
        required = set(required_common)
        if item.case_name == "inactive_profile_unchecked":
            required.update(
                {
                    "profile_disable",
                    "inactive_profile_observed",
                    "profile_restore",
                    "profile_restored",
                }
            )
        if item.expected_replay_rejection:
            required.update({"replay_second_dispatch", "replay_rejected"})
        absent_stages = sorted(required - set(stages))
        invalid_stages = sorted(
            stage for stage in required & set(stages) if str(stages[stage]["state"]) != "succeeded"
        )
        if absent_stages or invalid_stages:
            errors.append(
                {
                    "attempt_id": attempt_id,
                    "missing_stages": absent_stages,
                    "invalid_stages": invalid_stages,
                }
            )
            continue
        dispatches = [
            ("baseline_first_dispatch", item.entry.attempt.route[0], "intermediate", 1),
            ("baseline_second_dispatch", item.entry.attempt.route[1], "destination", 2),
        ]
        if item.expected_replay_rejection:
            dispatches.append(
                ("replay_second_dispatch", item.entry.attempt.route[1], "destination", 2)
            )
        rows_for_attempt: list[dict[str, Any]] = []
        dispatch_digests: dict[str, str] = {}
        registry_blocks: dict[str, int] = {}
        registry_transactions: dict[str, str] = {}
        registry_states: dict[str, dict[str, Any]] = {}
        if item.case_name == "inactive_profile_unchecked":
            for registry_stage in ("profile_disable", "profile_restore"):
                stage = stages[registry_stage]
                if not stage["transaction_hash"]:
                    errors.append({"attempt_id": attempt_id, "missing_tx": registry_stage})
                    continue
                detail = cast(dict[str, Any], json.loads(str(stage["detail_json"])))
                registry_metrics = transaction_metrics(
                    "destination", str(stage["transaction_hash"])
                )
                dispatch_digests[registry_stage] = str(registry_metrics["calldata_sha256"])
                registry_blocks[registry_stage] = int(registry_metrics["block_number"])
                registry_transactions[registry_stage] = str(registry_metrics["transaction_hash"])
                registry_states[registry_stage] = cast(dict[str, Any], detail["profile_snapshot"])
                rows_for_attempt.append(
                    {
                        "attempt_id": attempt_id,
                        "route": item.entry.attempt.route,
                        "case_name": item.case_name,
                        "repetition": item.repetition,
                        "physical_stage": registry_stage,
                        "physical_kind": "registry_owner",
                        "native_message_id": "",
                        **registry_metrics,
                    }
                )
                expected_enabled = registry_stage == "profile_restore"
                if bool(detail["profile_snapshot"]["enabled"]) != expected_enabled:
                    errors.append(
                        {
                            "attempt_id": attempt_id,
                            "registry_stage_state_mismatch": registry_stage,
                        }
                    )
            restored_detail = cast(
                dict[str, Any],
                json.loads(str(stages["profile_restored"]["detail_json"])),
            )
            registry_states["profile_after_observed"] = cast(
                dict[str, Any], restored_detail["snapshot"]
            )
            disabled_detail = cast(
                dict[str, Any],
                json.loads(str(stages["inactive_profile_observed"]["detail_json"])),
            )
            registry_states["profile_disabled_observed"] = cast(
                dict[str, Any], disabled_detail["snapshot"]
            )
        for stage_name, protocol, destination_role, hop in dispatches:
            stage = stages[stage_name]
            if not stage["transaction_hash"]:
                errors.append({"attempt_id": attempt_id, "missing_tx": stage_name})
                continue
            detail = cast(dict[str, Any], json.loads(str(stage["detail_json"])))
            stage_retry_count = int(detail.get("retry_count", 0))
            coordinator_retry_count += stage_retry_count
            if stage_retry_count or detail.get("retry_lineage"):
                errors.append(
                    {
                        "attempt_id": attempt_id,
                        "physical_stage": stage_name,
                        "unaccounted_retry_count": stage_retry_count,
                    }
                )
            coordinator_role = str(detail["role"])
            coordinator_metrics = transaction_metrics(
                coordinator_role, str(stage["transaction_hash"])
            )
            dispatch_digests[stage_name] = str(coordinator_metrics["calldata_sha256"])
            rows_for_attempt.append(
                {
                    "attempt_id": attempt_id,
                    "route": item.entry.attempt.route,
                    "case_name": item.case_name,
                    "repetition": item.repetition,
                    "physical_stage": stage_name,
                    "physical_kind": "coordinator",
                    "native_message_id": _receipt_dispatch_id(detail, protocol).lower(),
                    **coordinator_metrics,
                }
            )
            native_id = _receipt_dispatch_id(detail, protocol).lower()
            if protocol == "H":
                process_hash = hyperlane_process.get((destination_role, native_id))
                if process_hash is None:
                    errors.append(
                        {
                            "attempt_id": attempt_id,
                            "missing_hyperlane_process": native_id,
                            "physical_stage": stage_name,
                        }
                    )
                    continue
                rows_for_attempt.append(
                    {
                        "attempt_id": attempt_id,
                        "route": item.entry.attempt.route,
                        "case_name": item.case_name,
                        "repetition": item.repetition,
                        "physical_stage": f"{stage_name}_hyperlane_process",
                        "physical_kind": "hyperlane_agent",
                        "native_message_id": native_id,
                        **transaction_metrics(destination_role, process_hash),
                    }
                )
            else:
                actions = layerzero_actions_by_guid.get(native_id, [])
                valid_actions = (
                    len(actions) == 3
                    and {str(action["stage"]) for action in actions}
                    == {"dvn_execute", "commit_verification", "executor_execute"}
                    and all(
                        str(action["status"]) == "succeeded"
                        and action["transaction_hash"]
                        and int(action["destination_chain_id"]) in chain_role
                        for action in actions
                    )
                )
                if not valid_actions:
                    errors.append(
                        {
                            "attempt_id": attempt_id,
                            "invalid_layerzero_lineage": native_id,
                            "physical_stage": stage_name,
                            "action_count": len(actions),
                        }
                    )
                    continue
                for action in actions:
                    action_role = chain_role[int(action["destination_chain_id"])]
                    rows_for_attempt.append(
                        {
                            "attempt_id": attempt_id,
                            "route": item.entry.attempt.route,
                            "case_name": item.case_name,
                            "repetition": item.repetition,
                            "physical_stage": f"{stage_name}_layerzero_{action['stage']}",
                            "physical_kind": "layerzero_worker",
                            "native_message_id": native_id,
                            **transaction_metrics(action_role, str(action["transaction_hash"])),
                        }
                    )
        tx_hashes = [str(physical["transaction_hash"]) for physical in rows_for_attempt]
        if len(tx_hashes) != len(set(tx_hashes)):
            errors.append({"attempt_id": attempt_id, "duplicate_physical_tx": True})
        if any(int(physical["status"]) != 1 for physical in rows_for_attempt):
            errors.append({"attempt_id": attempt_id, "failed_physical_tx": True})
        physical_rows.extend(rows_for_attempt)

        case_effects = effects[attempt_id]
        case_replays = replays[attempt_id]
        expected_replays = 1 if item.expected_replay_rejection else 0
        if len(case_effects) != 1 or len(case_replays) != expected_replays:
            errors.append(
                {
                    "attempt_id": attempt_id,
                    "effect_count": len(case_effects),
                    "replay_rejection_count": len(case_replays),
                    "expected_replay_rejections": expected_replays,
                }
            )
        material = cast(dict[str, Any], json.loads(str(stages["case_materialized"]["detail_json"])))
        seed = str(config["fixed_seed"])
        second_route_payload = build_case_route_payload(
            item,
            seed=seed,
            mutated_application=(item.case_name == "between_hop_payload_substitution"),
            substituted_route_label=(item.case_name == "route_label_substitution"),
        )
        decoded_route = cast(
            tuple[Any, ...], decode(["(bytes32,bytes2,uint64,bytes)"], second_route_payload)[0]
        )
        expected_route_label = bytes(decoded_route[1]).decode("ascii")
        expected_application_hash = "0x" + keccak(bytes(decoded_route[3])).hex()
        actual_route_label = ""
        actual_application_hash = ""
        effect_block = 0
        if case_effects:
            effect_block = int(case_effects[0]["blockNumber"])
            event_topics = list(case_effects[0]["topics"])
            actual_route_label = bytes(event_topics[2])[:2].decode("ascii")
            event_values = decode(
                ["uint64", "bytes32", "bytes32", "bytes32", "bytes32", "uint256"],
                bytes(case_effects[0]["data"]),
            )
            actual_application_hash = "0x" + bytes(event_values[2]).hex()
            if actual_route_label != expected_route_label:
                errors.append({"attempt_id": attempt_id, "route_label_mismatch": True})
            if actual_application_hash != expected_application_hash:
                errors.append({"attempt_id": attempt_id, "application_payload_hash_mismatch": True})
        if item.case_name == "inactive_profile_unchecked" and not (
            registry_blocks.get("profile_disable", 0)
            < effect_block
            < registry_blocks.get("profile_restore", 0)
        ):
            errors.append(
                {
                    "attempt_id": attempt_id,
                    "profile_mutation_effect_order_invalid": {
                        "disable": registry_blocks.get("profile_disable", 0),
                        "effect": effect_block,
                        "restore": registry_blocks.get("profile_restore", 0),
                    },
                }
            )
        result_rows.append(
            {
                "attempt_id": attempt_id,
                "route": item.entry.attempt.route,
                "case_name": item.case_name,
                "repetition": item.repetition,
                "expected_outcome": (
                    "DELIVERED_THEN_REPLAY_REJECTED"
                    if item.expected_replay_rejection
                    else "DELIVERED"
                ),
                "actual_outcome": (
                    "DELIVERED_THEN_REPLAY_REJECTED"
                    if len(case_effects) == 1 and len(case_replays) == 1
                    else "DELIVERED"
                    if len(case_effects) == 1
                    else "INVALID"
                ),
                "effect_count": len(case_effects),
                "replay_rejection_count": len(case_replays),
                "enforcement_stage": (
                    "destination_application_replay" if item.expected_replay_rejection else "none"
                ),
                "source_entrypoint": "sendBaselineSource(bytes32,bytes,bytes)",
                "intermediate_entrypoint": "sendBaselineSource(bytes32,bytes,bytes)",
                "destination_entrypoint": "baselineCarrierReceive(bytes32,bytes)",
                "source_calldata_sha256": dispatch_digests.get("baseline_first_dispatch", ""),
                "intermediate_calldata_sha256": dispatch_digests.get(
                    "baseline_second_dispatch", ""
                ),
                "replay_calldata_sha256": dispatch_digests.get("replay_second_dispatch", ""),
                "profile_disable_calldata_sha256": dispatch_digests.get("profile_disable", ""),
                "profile_restore_calldata_sha256": dispatch_digests.get("profile_restore", ""),
                "profile_disable_transaction_hash": registry_transactions.get(
                    "profile_disable", ""
                ),
                "profile_restore_transaction_hash": registry_transactions.get(
                    "profile_restore", ""
                ),
                "matched_xir_profile_hash": material["matched_xir_profile_hash"],
                "profile_enabled_during_delivery": (
                    False if item.case_name == "inactive_profile_unchecked" else ""
                ),
                "profile_restored": (
                    True if item.case_name == "inactive_profile_unchecked" else ""
                ),
                "profile_disable_block": registry_blocks.get("profile_disable", ""),
                "effect_block": effect_block,
                "profile_restore_block": registry_blocks.get("profile_restore", ""),
                "profile_before_state_json": (
                    ""
                    if material["original_profile"] is None
                    else json.dumps(
                        material["original_profile"], sort_keys=True, separators=(",", ":")
                    )
                ),
                "profile_disabled_state_json": (
                    ""
                    if "profile_disabled_observed" not in registry_states
                    else json.dumps(
                        registry_states["profile_disabled_observed"],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ),
                "profile_after_state_json": (
                    ""
                    if "profile_after_observed" not in registry_states
                    else json.dumps(
                        registry_states["profile_after_observed"],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ),
                "first_route_payload_sha256": material["first_route_payload_sha256"],
                "second_route_payload_sha256": material["second_route_payload_sha256"],
                "semantic_payload_changed": bool(material["semantic_payload_changed"]),
                "profile_or_history_field_present": False,
                "expected_route_label": expected_route_label,
                "actual_route_label": actual_route_label,
                "expected_application_payload_hash": expected_application_hash,
                "actual_application_payload_hash": actual_application_hash,
                "physical_transaction_count": len(rows_for_attempt),
            }
        )

    capabilities = capability_rows()
    case_summary: list[dict[str, Any]] = []
    for route in ROUTES:
        for case_name in CASES:
            rows = [
                result
                for result in result_rows
                if result["route"] == route and result["case_name"] == case_name
            ]
            case_summary.append(
                {
                    "route": route,
                    "case_name": case_name,
                    "n": len(rows),
                    "delivered": sum(int(result["effect_count"]) for result in rows),
                    "replay_rejected": sum(
                        int(result["replay_rejection_count"]) for result in rows
                    ),
                    "outcome_matches": sum(
                        result["actual_outcome"] == result["expected_outcome"] for result in rows
                    ),
                }
            )
    exact_case_counts = all(
        row["n"] == int(config["repetitions"])
        and row["outcome_matches"] == int(config["repetitions"])
        for row in case_summary
    )
    registry_contract = clients["destination"].eth.contract(
        address=deployment["chains"]["destination"]["registry"],
        abi=json.loads(
            (
                _repository_root() / "contracts" / "out" / "XIRRegistry.sol" / "XIRRegistry.json"
            ).read_text(encoding="utf-8")
        )["abi"],
    )
    for profile_hash in (PROFILE_HASHES["H_AB"], PROFILE_HASHES["L_AB"]):
        if not bool(registry_contract.functions.profileAt(profile_hash).call()[6]):
            errors.append(
                {
                    "profile_not_restored": "0x" + profile_hash.hex(),
                }
            )
    valid = (
        not errors
        and len(result_rows) == len(expected)
        and exact_case_counts
        and all(
            not row["expressible"]
            for row in capabilities
            if row["field"]
            in {
                "prior_hop_native_message_id",
                "verifier_profile_or_version",
                "registry_version_or_status",
                "ordered_receipt_history",
            }
        )
    )
    validation = {
        "schema_version": "xir-lab-native-security-baseline-v1-validation",
        "valid": valid,
        "expected_attempts": len(expected),
        "reconciled_attempts": len(result_rows),
        "case_counts": {f"{row['route']}_{row['case_name']}": row["n"] for row in case_summary},
        "effect_count": sum(len(logs) for logs in effects.values()),
        "replay_rejection_count": sum(len(logs) for logs in replays.values()),
        "coordinator_retry_count": coordinator_retry_count,
        "retry_free_complete_lineage": coordinator_retry_count == 0,
        "analyzer_transaction_read_retry_count": analyzer_transaction_read_retry_count,
        "environment_namespace_valid": environment_namespace_valid,
        "final_revision_prior_binding_valid": final_revision_binding_valid,
        "final_revision_source_lock_valid": final_revision_source_lock_valid,
        "onchain_prior_binding_valid": onchain_prior_binding_valid,
        "errors": errors,
    }
    _validate_schema(validation, "native-security-baseline-v1-validation.schema.json")
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "baseline-capability.csv", capabilities)
    _write_csv(output_root / "baseline-results.csv", result_rows)
    _write_csv(output_root / "case-summary.csv", case_summary)
    _write_csv(output_root / "physical-transactions.csv", physical_rows)
    (output_root / "validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    analysis: dict[str, Any] = {
        "schema_version": "xir-lab-native-security-baseline-v1-analysis",
        "namespace": "native-security-baseline-v1",
        "config_sha256": config_sha,
        "analysis_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
        "environment_namespace": deployment.get("namespace", ""),
        "base_deployment_sha256": deployment.get("base_deployment_sha256", ""),
        "final_revision_source_sha256": deployment.get("final_revision_source_sha256", {}),
        "prior_verifier_bindings": deployment.get("prior_verifier_bindings", {}),
        "onchain_prior_verifier_bindings": onchain_prior_bindings,
        "runner_state_sha256": hashlib.sha256(runner_state_path.read_bytes()).hexdigest(),
        "worker_state_sha256": hashlib.sha256(layerzero_state_path.read_bytes()).hexdigest(),
        "attempt_count": len(result_rows),
        "physical_transaction_count": len(physical_rows),
        "capability_rows": capabilities,
        "case_summary": case_summary,
        "validation": validation,
    }
    analysis["semantic_digest"] = hashlib.sha256(
        rfc8785.dumps(
            cast(
                dict[str, Any],
                {
                    "capability_rows": capabilities,
                    "result_rows": result_rows,
                    "case_summary": case_summary,
                    "physical_rows": physical_rows,
                    "validation": validation,
                },
            )
        )
    ).hexdigest()
    _validate_schema(analysis, "native-security-baseline-v1-analysis.schema.json")
    (output_root / "analysis.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_baseline_report(output_root, analysis)
    _write_baseline_manifest(output_root)
    runner.close()
    worker.close()
    return analysis


def _write_baseline_report(output_root: Path, analysis: dict[str, Any]) -> None:
    lines = [
        "# Native payload-only baseline capability v1",
        "",
        f"Reconciled attempts: {analysis['attempt_count']}.",
        f"Physical transactions: {analysis['physical_transaction_count']}.",
        f"Read-only transaction/receipt analyzer retries: "
        f"{analysis['validation']['analyzer_transaction_read_retry_count']}.",
        f"Validation: **{'PASS' if analysis['validation']['valid'] else 'FAIL'}**.",
        f"Analyzer source SHA-256: `{analysis['analysis_source_sha256']}`.",
        "",
        "Environment: administrator-bound final revision in `native-ablation-v2`. "
        f"Base deployment SHA-256: `{analysis['base_deployment_sha256']}`. "
        f"Ablation deployment SHA-256: `{analysis['deployment_sha256']}`.",
        "",
        "B0 executes and authenticates both native hops. The first authentication terminates at the intermediate ingress and is not bound into the final payload, so the destination sees only final-hop authentication. The carrier envelope contains no verifier-profile, registry-version/status, prior-native-message, or ordered-history field. Static absence appears only in `baseline-capability.csv`; it is not reported as a failed mutation.",
        "",
        "The inactive-profile case disables the same first-hop profile used by the matched XIR case: H_AB for HL and L_AB for LH. Each case records the owner transactions and observed before/disabled/restored states, and it runs serially while the registry is mutated.",
        "",
        "## Dynamic outcomes",
        "",
        "| Route | Case | n | Effects | Replay rejections | Matched |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in analysis["case_summary"]:
        lines.append(
            f"| {row['route']} | {row['case_name']} | {row['n']} | "
            f"{row['delivered']} | {row['replay_rejected']} | {row['outcome_matches']} |"
        )
    lines.extend(
        [
            "",
            "Each result row records the three entrypoints, coordinator calldata digests, enforcement stage, application effect, and complete native transaction lineage.",
            "",
            f"Semantic digest: `{analysis['semantic_digest']}`.",
        ]
    )
    (output_root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_baseline_manifest(output_root: Path) -> None:
    files = []
    for path in sorted(output_root.rglob("*")):
        if not path.is_file() or path.name in {"manifest.json", "manifest.sha256"}:
            continue
        files.append(
            {
                "path": str(path.relative_to(output_root)),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "schema_version": "xir-lab-native-security-baseline-v1-manifest",
        "namespace": "native-security-baseline-v1",
        "files": files,
    }
    _validate_schema(manifest, "native-security-baseline-v1-manifest.schema.json")
    path = output_root / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_root / "manifest.sha256").write_text(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  manifest.json\n",
        encoding="utf-8",
    )


def validate_baseline_publication(output_root: Path) -> dict[str, Any]:
    manifest_path = output_root / "manifest.json"
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
    mismatches: list[str] = []
    forbidden: list[str] = []
    for item in manifest["files"]:
        path = output_root / str(item["path"])
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            mismatches.append(str(item["path"]))
        if path.suffix.lower() in {".key", ".raw"} or "private-signed" in str(path):
            forbidden.append(str(item["path"]))
        if path.suffix.lower() in {".json", ".csv", ".md", ".txt"}:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for token in ("private_key", "raw_transaction_hex", "mnemonic"):
                if token in text:
                    forbidden.append(f"{item['path']}:{token}")
    expected_manifest_sha = (output_root / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    if expected_manifest_sha != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        mismatches.append("manifest.sha256")
    validation = cast(
        dict[str, Any],
        json.loads((output_root / "validation.json").read_text(encoding="utf-8")),
    )
    return {
        "valid": not mismatches and not forbidden and bool(validation["valid"]),
        "manifest_mismatches": mismatches,
        "forbidden_publishable_content": sorted(set(forbidden)),
        "experiment_validation": bool(validation["valid"]),
    }


def rebuild_baseline_publication(*, source_root: Path, output_root: Path) -> dict[str, Any]:
    """Rebuild the strict B0 tables from frozen normalized files only."""

    if output_root.exists() and any(output_root.iterdir()):
        raise LocalTopologyError(f"offline rebuild output is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    source_manifest = source_root / "manifest.json"
    if not source_manifest.is_file():
        raise LocalTopologyError("baseline rebuild source has no manifest")
    analysis = cast(
        dict[str, Any],
        json.loads((source_root / "analysis.json").read_text(encoding="utf-8")),
    )
    validation = cast(
        dict[str, Any],
        json.loads((source_root / "validation.json").read_text(encoding="utf-8")),
    )
    _validate_schema(analysis, "native-security-baseline-v1-analysis.schema.json")
    _validate_schema(validation, "native-security-baseline-v1-validation.schema.json")
    if analysis["validation"] != validation or not validation["valid"]:
        raise LocalTopologyError("baseline rebuild source validation mismatch")
    for name in (
        "analysis.json",
        "validation.json",
        "baseline-capability.csv",
        "baseline-results.csv",
        "case-summary.csv",
        "physical-transactions.csv",
    ):
        source = source_root / name
        if not source.is_file():
            raise LocalTopologyError(f"baseline rebuild source is missing {name}")
        (output_root / name).write_bytes(source.read_bytes())
    provenance = {
        "schema_version": "xir-lab-native-security-baseline-v1-offline-rebuild",
        "semantic_digest": analysis["semantic_digest"],
        "source_manifest_sha256": hashlib.sha256(source_manifest.read_bytes()).hexdigest(),
    }
    (output_root / "rebuild-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_baseline_report(output_root, analysis)
    _write_baseline_manifest(output_root)
    result = validate_baseline_publication(output_root)
    (output_root / "publication-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not result["valid"]:
        raise LocalTopologyError("offline baseline publication validation failed")
    return {
        "valid": True,
        "semantic_digest": analysis["semantic_digest"],
        "manifest_sha256": hashlib.sha256((output_root / "manifest.json").read_bytes()).hexdigest(),
    }
