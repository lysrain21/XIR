"""Benign negative-input conformance campaign for the isolated native stack.

The campaign prepares evidence through the deployed Hyperlane and LayerZero
stacks, mutates only the final XIR delivery input, and reconciles the destination
Gateway and application state.  It is an academic protocol-regression harness;
it does not probe public or third-party systems.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import jsonschema
from eth_abi.abi import encode
from eth_account import Account
from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import PROFILE_HASHES, gateway_typed_id
from xir_lab.native.runner import NativeExperimentRunner, PreparedXIRDelivery
from xir_lab.native.xir_trace import (
    XIRReceipt,
    bundle_commitment,
    message_id,
    next_prefix,
    receipt_tuple,
    transition_hash,
)

SECURITY_CASES = (
    "payload_tamper",
    "context_tamper",
    "profile_substitution",
    "profile_inactive",
    "receipt_delete",
    "receipt_reorder",
    "evidence_tamper",
    "wrong_registry_version",
    "cross_execution_splice",
    "sequential_replay",
    "concurrent_replay",
    "fake_verifier",
    "wrong_endpoint",
)

EXPECTED_ERROR = {
    "payload_tamper": "PayloadMismatch",
    "context_tamper": "InvalidRootSignature",
    "profile_substitution": "ProfileInactive",
    "profile_inactive": "ProfileInactive",
    "receipt_delete": "InvalidTrace",
    "receipt_reorder": "InvalidTrace",
    "evidence_tamper": "EvidenceRejected",
    "wrong_registry_version": "RootMismatch",
    "cross_execution_splice": "BundleRejected",
    "sequential_replay": "AlreadyConsumed",
    "concurrent_replay": "AlreadyConsumed",
    "fake_verifier": "UnapprovedPriorVerifier",
    "wrong_endpoint": "UnapprovedPriorVerifier",
}

ERROR_SIGNATURES = {
    "RootMismatch": "RootMismatch()",
    "RootInactive": "RootInactive()",
    "InvalidRootSignature": "InvalidRootSignature()",
    "InvalidTrace": "InvalidTrace(uint256)",
    "ProfileInactive": "ProfileInactive(uint256)",
    "PolicyRefused": "PolicyRefused(uint256)",
    "EvidenceRejected": "EvidenceRejected(uint256)",
    "BundleRejected": "BundleRejected()",
    "WrongDestination": "WrongDestination()",
    "PayloadMismatch": "PayloadMismatch()",
    "AlreadyConsumed": "AlreadyConsumed(bytes32)",
    "ReceiverCallFailed": "ReceiverCallFailed()",
    "ReceiverMismatch": "ReceiverMismatch()",
    "UnapprovedPriorVerifier": "UnapprovedPriorVerifier(uint256)",
}
SELECTOR_TO_ERROR = {
    "0x" + keccak(text=signature)[:4].hex(): name for name, signature in ERROR_SIGNATURES.items()
}
NATIVE_EFFECT_TOPIC = Web3.to_hex(
    keccak(
        text=(
            "NativeEffectApplied(bytes32,bytes2,uint64,bytes32,bytes32,bytes32,"
            "bytes32,bytes32,uint256,bool)"
        )
    )
).lower()


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_security_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    document = json.loads(raw)
    schema_version = document.get("schema_version")
    schema_name = {
        "xir-lab-native-security-v1-config-v1": "native-security-v1-config.schema.json",
        "xir-lab-native-security-v2-config-v1": "native-security-v2-config.schema.json",
    }.get(schema_version)
    if schema_name is None:
        raise LocalTopologyError(f"unsupported native-security schema: {schema_version}")
    schema = json.loads((repository_root() / f"schemas/{schema_name}").read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.path) or "<root>"
        raise LocalTopologyError(f"native-security config error at {location}: {error.message}")
    cases = cast(list[str], document["cases"])
    effects = cast(dict[str, int], document["expected_application_effects"])
    if set(cases) != set(effects) or not set(cases).issubset(SECURITY_CASES):
        raise LocalTopologyError("security cases and effect expectations differ")
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def case_attempt(*, campaign_id: str, route: str, case: str, repetition: int) -> NativeAttempt:
    material = f"{campaign_id}:{route}:{case}:{repetition}".encode()
    attempt_id = "security_" + hashlib.sha256(material).hexdigest()[:32]
    return NativeAttempt(
        attempt_id=attempt_id,
        phase="smoke",
        route=route,
        route_sequence=repetition,
        first_protocol="hyperlane" if route[0] == "H" else "layerzero-v2",
        second_protocol="hyperlane" if route[1] == "H" else "layerzero-v2",
        execution_class=f"{campaign_id}:{case}",
        xir=True,
        payload_bytes=64,
        payload_sha256=hashlib.sha256(material + b":payload").hexdigest(),
    )


def case_payload(attempt: NativeAttempt, fixed_seed: str) -> bytes:
    seed = bytes.fromhex(fixed_seed)
    application_payload = (
        hashlib.sha256(
            seed + attempt.attempt_id.encode() + attempt.route_sequence.to_bytes(8, "big")
        ).digest()
        * 2
    )
    return encode(
        ["(bytes32,bytes2,uint64,bytes)"],
        [
            (
                keccak(text=attempt.attempt_id),
                attempt.route.encode("ascii"),
                attempt.route_sequence,
                application_payload,
            )
        ],
    )


def extract_revert_data(value: Any) -> str | None:
    """Find EVM revert bytes in Web3/Besu exception or RPC response shapes."""

    if isinstance(value, BaseException):
        explicit = getattr(value, "data", None)
        found = extract_revert_data(explicit)
        if found is not None:
            return found
        return extract_revert_data(value.args)
    if isinstance(value, dict):
        for key in ("data", "return", "returnValue", "result", "originalError"):
            if key in value:
                found = extract_revert_data(value[key])
                if found is not None:
                    return found
        for item in value.values():
            found = extract_revert_data(item)
            if found is not None:
                return found
        return None
    if isinstance(value, (tuple, list)):
        for item in value:
            found = extract_revert_data(item)
            if found is not None:
                return found
        return None
    if isinstance(value, bytes) and len(value) >= 4:
        return "0x" + value.hex()
    if isinstance(value, str):
        candidates = re.findall(r"0x[0-9a-fA-F]{8,}", value)
        if candidates:
            known = [
                candidate for candidate in candidates if candidate[:10].lower() in SELECTOR_TO_ERROR
            ]
            return str(min(known or candidates, key=len)).lower()
    return None


def error_from_revert_data(data: str | None) -> tuple[str | None, str | None]:
    if data is None or len(data) < 10:
        return None, None
    selector = data[:10].lower()
    return selector, SELECTOR_TO_ERROR.get(selector)


class SecurityState:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS cases(
              case_key TEXT PRIMARY KEY,
              attempt_id TEXT NOT NULL UNIQUE,
              route TEXT NOT NULL,
              case_name TEXT NOT NULL,
              repetition INTEGER NOT NULL,
              status TEXT NOT NULL,
              planned_json TEXT NOT NULL,
              result_json TEXT,
              started_at REAL NOT NULL,
              finished_at REAL
            ) STRICT;
            """
        )
        self.connection.commit()

    def begin(self, attempt: NativeAttempt, case_name: str, repetition: int) -> bool:
        key = f"{attempt.route}:{case_name}:{repetition}"
        with self.lock:
            row = self.connection.execute(
                "SELECT status FROM cases WHERE case_key = ?", (key,)
            ).fetchone()
            if row is not None:
                return str(row["status"]) != "validated"
            self.connection.execute(
                """
                INSERT INTO cases(
                  case_key, attempt_id, route, case_name, repetition, status,
                  planned_json, started_at
                ) VALUES (?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    key,
                    attempt.attempt_id,
                    attempt.route,
                    case_name,
                    repetition,
                    json.dumps(asdict(attempt), sort_keys=True),
                    time.time(),
                ),
            )
            self.connection.commit()
            return True

    def finish(
        self, attempt: NativeAttempt, case_name: str, repetition: int, result: dict[str, Any]
    ) -> None:
        key = f"{attempt.route}:{case_name}:{repetition}"
        with self.lock:
            self.connection.execute(
                """
                UPDATE cases
                SET status = ?, result_json = ?, finished_at = ?
                WHERE case_key = ?
                """,
                (
                    "validated" if result["valid"] else "failed",
                    json.dumps(result, sort_keys=True),
                    time.time(),
                    key,
                ),
            )
            self.connection.commit()

    def rows(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM cases ORDER BY route, case_name, repetition"
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            value = dict(row)
            value["result"] = (
                json.loads(value.pop("result_json")) if value["result_json"] is not None else None
            )
            value["planned"] = json.loads(value.pop("planned_json"))
            output.append(value)
        return output


class NativeSecurityCampaign:
    def __init__(
        self,
        *,
        runner: NativeExperimentRunner,
        config_path: Path,
        deployment_path: Path,
        deployer_private_key: str,
        state_path: Path,
        output_root: Path,
        concurrency: int = 8,
        repetition_limit: int | None = None,
        attempt_namespace: str | None = None,
    ) -> None:
        self.runner = runner
        self.config, self.config_sha256 = load_security_config(config_path)
        campaign_version = "v2" if self.config["campaign_id"] == "native-security-v2" else "v1"
        self.case_schema_version = f"xir-lab-native-security-{campaign_version}-case-result-v1"
        self.summary_schema_version = f"xir-lab-native-security-{campaign_version}-summary-v1"
        self.report_title = f"Native security conformance {campaign_version}"
        self.deployment_path = deployment_path
        self.deployment_sha256 = hashlib.sha256(deployment_path.read_bytes()).hexdigest()
        self.state = SecurityState(state_path)
        self.output_root = output_root
        self.raw_root = output_root / "raw-receipts"
        self.private_root = output_root / "private-signed-transactions"
        self.publish_root = output_root / "publish"
        for path in (self.raw_root, self.private_root, self.publish_root):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.private_root, 0o700)
        self.concurrency = concurrency
        if concurrency <= 0:
            raise LocalTopologyError("security campaign concurrency must be positive")
        configured_repetitions = int(self.config["repetitions_per_route_case"])
        self.repetitions = configured_repetitions if repetition_limit is None else repetition_limit
        if self.repetitions <= 0 or self.repetitions > configured_repetitions:
            raise LocalTopologyError("security repetition limit exceeds the frozen config")
        if (
            attempt_namespace is not None
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", attempt_namespace) is None
        ):
            raise LocalTopologyError("invalid security attempt namespace")
        self.attempt_namespace = attempt_namespace
        self.gateway = runner._contract("destination", "gateway", "XIRGateway.sol", "XIRGateway")
        self.receiver = runner._contract(
            "destination",
            "receiver",
            "NativeExperimentReceiver.sol",
            "NativeExperimentReceiver",
        )
        self.registry = runner._contract(
            "destination", "registry", "XIRRegistry.sol", "XIRRegistry"
        )
        self.deployer = Account.from_key(deployer_private_key)
        self.deployer_key = deployer_private_key
        self.owner_nonce = int(
            runner.clients["destination"].eth.get_transaction_count(
                self.deployer.address, "pending"
            )
        )
        self.owner_lock = threading.Lock()

    def run(self) -> dict[str, Any]:
        campaign_id = str(self.config["campaign_id"])
        identity_campaign_id = (
            campaign_id
            if self.attempt_namespace is None
            else f"{campaign_id}:{self.attempt_namespace}"
        )
        repetitions = self.repetitions
        routes = cast(list[str], self.config["routes"])
        fixed_seed = str(self.config["fixed_seed"])
        for case_name in cast(list[str], self.config["cases"]):
            jobs = [(route, repetition) for route in routes for repetition in range(repetitions)]
            # Registry mutation is global; keep that case serial.  Every other
            # case has a unique message and can use bounded native concurrency.
            workers = 1 if case_name == "profile_inactive" else self.concurrency
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(
                        self._run_one,
                        case_attempt(
                            campaign_id=identity_campaign_id,
                            route=route,
                            case=case_name,
                            repetition=repetition,
                        ),
                        case_name,
                        repetition,
                        fixed_seed,
                    )
                    for route, repetition in jobs
                ]
                for future in futures:
                    future.result()
        return self.freeze()

    def _run_one(
        self,
        attempt: NativeAttempt,
        case_name: str,
        repetition: int,
        fixed_seed: str,
    ) -> None:
        if not self.state.begin(attempt, case_name, repetition):
            return
        if not self.runner.state.begin(attempt):
            # A resumed preparation is allowed; a fully delivered standard
            # attempt cannot share a native-security-v1 identifier.
            existing = self.runner.state.connection.execute(
                "SELECT status FROM attempts WHERE attempt_id = ?", (attempt.attempt_id,)
            ).fetchone()
            if existing is not None and str(existing["status"]) == "succeeded":
                row = next(
                    row for row in self.state.rows() if row["attempt_id"] == attempt.attempt_id
                )
                if row["status"] == "validated":
                    return
        payload = case_payload(attempt, fixed_seed)
        prepared = self.runner.prepare_heterogeneous(attempt, payload)
        result = self._execute_case(case_name, prepared)
        self.runner.state.finish(attempt.attempt_id)
        self.state.finish(attempt, case_name, repetition, result)
        if not result["valid"]:
            raise LocalTopologyError(
                f"security case failed: {attempt.route}/{case_name}/{repetition}"
            )

    def _snapshot(self, prepared: PreparedXIRDelivery) -> dict[str, Any]:
        mid = message_id(prepared.rid, prepared.record.destination_app)
        attempt_hash = keccak(text=prepared.attempt.attempt_id)
        return {
            "mid": "0x" + mid.hex(),
            "gateway_consumed": bool(self.gateway.functions.consumed(mid).call()),
            "receiver_delivery_count": int(self.receiver.functions.deliveryCount().call()),
            "receiver_attempt_consumed": bool(
                self.receiver.functions.consumedAttempts(attempt_hash).call()
            ),
            "receiver_effect_class": Web3.to_hex(
                self.receiver.functions.effectClassForAttempt(attempt_hash).call()
            ),
            "receiver_state_hash": Web3.to_hex(self.receiver.functions.effectStateHash().call()),
        }

    def _execute_case(self, case_name: str, prepared: PreparedXIRDelivery) -> dict[str, Any]:
        before = self._snapshot(prepared)
        expected_error = EXPECTED_ERROR[case_name]
        transactions: list[dict[str, Any]] = []

        if case_name == "sequential_replay":
            transactions.append(
                self._submit_delivery(
                    prepared.envelope, prepared.payload, prepared.receiver_address, 1
                )
            )
            transactions.append(
                self._submit_delivery(
                    prepared.envelope,
                    prepared.payload,
                    prepared.receiver_address,
                    0,
                    expected_error,
                )
            )
        elif case_name == "concurrent_replay":
            transactions.extend(self._submit_competing_deliveries(prepared))
        elif case_name == "profile_inactive":
            receipt = prepared.receipts[0]
            current = tuple(self.registry.functions.profileAt(receipt.profile_hash).call())
            disabled = (*current[:-1], False)
            self._owner_profile(receipt.profile_hash, disabled, "disable")
            try:
                transactions.append(
                    self._submit_delivery(
                        prepared.envelope,
                        prepared.payload,
                        prepared.receiver_address,
                        0,
                        expected_error,
                    )
                )
            finally:
                self._owner_profile(receipt.profile_hash, current, "restore")
        else:
            envelope, payload = self._mutate(case_name, prepared)
            transactions.append(
                self._submit_delivery(
                    envelope,
                    payload,
                    prepared.receiver_address,
                    0,
                    expected_error,
                )
            )

        after = self._snapshot(prepared)
        expected_attempt_topic = Web3.to_hex(keccak(text=prepared.attempt.attempt_id)).lower()
        effect_topics = [
            topic
            for transaction in transactions
            for topic in cast(list[str], transaction["native_effect_attempt_ids"])
        ]
        effect_delta = len(effect_topics)
        expected_effects = int(
            cast(dict[str, int], self.config["expected_application_effects"])[case_name]
        )
        rejected_transactions = [item for item in transactions if item["status"] == 0]
        successful_transactions = [item for item in transactions if item["status"] == 1]
        rejection_effect_delta = sum(
            len(cast(list[str], item["native_effect_attempt_ids"]))
            for item in rejected_transactions
        )
        actual_errors = [item.get("revert_error") for item in rejected_transactions]
        valid = (
            effect_delta == expected_effects
            and all(topic == expected_attempt_topic for topic in effect_topics)
            and len(rejected_transactions) == 1
            and all(error == expected_error for error in actual_errors)
            and (
                len(successful_transactions) == 1
                if case_name in {"sequential_replay", "concurrent_replay"}
                else len(successful_transactions) == 0
            )
            and (
                case_name not in {"sequential_replay", "concurrent_replay"}
                or after["gateway_consumed"]
            )
            and (
                case_name in {"sequential_replay", "concurrent_replay"}
                or not after["gateway_consumed"]
            )
            and rejection_effect_delta == 0
        )
        return {
            "schema_version": self.case_schema_version,
            "case": case_name,
            "route": prepared.attempt.route,
            "repetition": prepared.attempt.route_sequence,
            "attempt_id": prepared.attempt.attempt_id,
            "expected_rejection": expected_error,
            "actual_rejections": actual_errors,
            "expected_application_effects": expected_effects,
            "application_effect_delta": effect_delta,
            "rejection_application_effect_delta": rejection_effect_delta,
            "effect_attempt_ids": effect_topics,
            "before": before,
            "after": after,
            "transactions": transactions,
            "root_signer_separated": (
                str(self.runner.deployment.get("root_signer", "")).lower()
                != self.runner.account.address.lower()
            ),
            "valid": valid,
        }

    def _mutate(
        self, case_name: str, prepared: PreparedXIRDelivery
    ) -> tuple[tuple[Any, ...], bytes]:
        record, context, certificate, receipt_values = copy.deepcopy(prepared.envelope)
        receipts = list(receipt_values)
        payload = prepared.payload
        if case_name == "payload_tamper":
            payload = prepared.payload + b"\x00"
        elif case_name == "context_tamper":
            context = (int(context[0]) + 1, context[1])
        elif case_name == "profile_substitution":
            receipt = list(receipts[0])
            receipt[2] = keccak(
                text=f"native-security-v1-unregistered:{prepared.attempt.attempt_id}"
            )
            receipts[0] = tuple(receipt)
        elif case_name == "receipt_delete":
            receipts = receipts[1:]
            receipts = self._recompute_prefixes(prepared, receipts)
        elif case_name == "receipt_reorder":
            receipts = list(reversed(receipts))
            receipts = self._recompute_prefixes(prepared, receipts)
        elif case_name == "evidence_tamper":
            receipt = list(receipts[0])
            receipt[3] = keccak(text=f"native-security-v1-evidence:{prepared.attempt.attempt_id}")
            receipts[0] = tuple(receipt)
        elif case_name == "wrong_registry_version":
            certificate = (int(certificate[0]) + 1, certificate[1])
        elif case_name == "cross_execution_splice":
            receipts = [
                receipt_tuple(prepared.receipts[0]),
                receipt_tuple(self._alternate_second_receipt(prepared)),
            ]
            receipts = self._recompute_prefixes(prepared, receipts)
        else:
            raise LocalTopologyError(f"unsupported security mutation: {case_name}")
        return (record, context, certificate, receipts), payload

    def _recompute_prefixes(
        self, prepared: PreparedXIRDelivery, receipts: list[Any]
    ) -> list[tuple[Any, ...]]:
        prefix = prepared.receipts[0].prior_prefix
        rebuilt: list[tuple[Any, ...]] = []
        for value in receipts:
            receipt = XIRReceipt(
                source_gateway=value[0],
                destination_gateway=value[1],
                profile_hash=bytes(value[2]),
                evidence_hash=bytes(value[3]),
                transition_hash=bytes(value[4]),
                prior_prefix=prefix,
            )
            rebuilt.append(receipt_tuple(receipt))
            prefix = next_prefix(receipt)
        return rebuilt

    def _alternate_second_receipt(self, prepared: PreparedXIRDelivery) -> XIRReceipt:
        base = prepared.attempt
        alternate = NativeAttempt(
            **{
                **asdict(base),
                "attempt_id": base.attempt_id + "_alternate",
                "execution_class": "native-security-v1:splice-transport",
            }
        )
        self.runner.state.begin(alternate)
        first = base.route[0]
        second = base.route[1]
        first_profile = PROFILE_HASHES[f"{first}_AB"]
        second_profile = PROFILE_HASHES[f"{second}_BC"]
        source_id = prepared.record.source_gateway
        intermediate_id = gateway_typed_id(
            int(self.runner.chain_by_role["intermediate"]["chain_id"])
        )
        destination_id = gateway_typed_id(int(self.runner.chain_by_role["destination"]["chain_id"]))
        transition_one = transition_hash(
            prepared.record, prepared.context, source_id, intermediate_id
        )
        evidence_one = self.runner._dispatch_first_xir(
            alternate, first, first_profile, transition_one
        )
        self.runner._wait_verify(
            role="intermediate",
            adapter_role=f"{first.lower()}_in",
            protocol=first,
            profile_hash=first_profile,
            evidence_hash=evidence_one,
            transition=transition_one,
        )
        first_receipt = XIRReceipt(
            source_id,
            intermediate_id,
            first_profile,
            evidence_one,
            transition_one,
            prepared.receipts[0].prior_prefix,
        )
        transition_two = transition_hash(
            prepared.record, prepared.context, intermediate_id, destination_id
        )
        evidence_two = self.runner._dispatch_second_xir(
            alternate,
            second,
            first_profile,
            evidence_one,
            transition_one,
            second_profile,
            transition_two,
        )
        adapter_role = f"{second.lower()}_xir_in"
        for profile, evidence, transition in (
            (first_profile, evidence_one, transition_one),
            (second_profile, evidence_two, transition_two),
        ):
            self.runner._wait_verify(
                role="destination",
                adapter_role=adapter_role,
                protocol=second,
                profile_hash=profile,
                evidence_hash=evidence,
                transition=transition,
            )
        second_receipt = XIRReceipt(
            intermediate_id,
            destination_id,
            second_profile,
            evidence_two,
            transition_two,
            next_prefix(first_receipt),
        )
        adapter = self.runner._contract(
            "destination",
            adapter_role,
            "HyperlaneAdapter.sol" if second == "H" else "LayerZeroAdapter.sol",
            "HyperlaneAdapter" if second == "H" else "LayerZeroAdapter",
        )
        if not adapter.functions.verifyBundle(
            bundle_commitment((first_receipt, second_receipt))
        ).call():
            raise LocalTopologyError("alternate native bundle was not authenticated")
        spliced_second = XIRReceipt(
            second_receipt.source_gateway,
            second_receipt.destination_gateway,
            second_receipt.profile_hash,
            second_receipt.evidence_hash,
            second_receipt.transition_hash,
            next_prefix(prepared.receipts[0]),
        )
        if adapter.functions.verifyBundle(
            bundle_commitment((prepared.receipts[0], spliced_second))
        ).call():
            raise LocalTopologyError("splice fixture accidentally produced an accepted bundle")
        self.runner.state.finish(alternate.attempt_id)
        return spliced_second

    def _call_error(self, function: Any, sender: str) -> tuple[str | None, str | None]:
        try:
            function.call({"from": sender, "gas": 8_000_000})
        except Exception as exc:  # Web3 exposes provider-specific revert wrappers.
            return error_from_revert_data(extract_revert_data(exc))
        return None, None

    def _runner_nonces(self, count: int = 1) -> tuple[int, ...]:
        if count <= 0:
            raise ValueError("nonce count must be positive")
        with self.runner.nonce_locks["destination"]:
            start = self.runner.nonces["destination"]
            self.runner.nonces["destination"] += count
            return tuple(range(start, start + count))

    def _built_transaction(self, function: Any, sender: str, nonce: int) -> dict[str, Any]:
        client = self.runner.clients["destination"]
        return cast(
            dict[str, Any],
            function.build_transaction(
                {
                    "from": sender,
                    "chainId": int(self.runner.chain_by_role["destination"]["chain_id"]),
                    "nonce": nonce,
                    "maxFeePerGas": max(int(client.eth.gas_price) * 2, 1),
                    "maxPriorityFeePerGas": 0,
                    "type": 2,
                    "gas": 8_000_000,
                }
            ),
        )

    def _broadcast(self, built: dict[str, Any], key: str, expected_status: int) -> dict[str, Any]:
        client = self.runner.clients["destination"]
        signed = Account.sign_transaction(built, key)
        tx_hash = Web3.to_hex(signed.hash).lower()
        raw_path = self.private_root / f"{tx_hash}.raw"
        raw_path.write_bytes(signed.raw_transaction)
        os.chmod(raw_path, 0o600)
        client.eth.send_raw_transaction(signed.raw_transaction)
        receipt = client.eth.wait_for_transaction_receipt(
            HexStr(tx_hash), timeout=self.runner.timeout_seconds
        )
        status = int(receipt["status"])
        receipt_document = cast(
            dict[str, Any], json.loads(Web3.to_json(cast(dict[Any, Any], receipt)))
        )
        receipt_path = self.raw_root / f"{tx_hash}.json"
        receipt_path.write_text(
            json.dumps(receipt_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if status != expected_status:
            raise LocalTopologyError(
                f"security transaction status {status}, expected {expected_status}: {tx_hash}"
            )
        return {
            "transaction_hash": tx_hash,
            "status": status,
            "nonce": int(built["nonce"]),
            "block_number": int(receipt["blockNumber"]),
            "gas_used": int(receipt["gasUsed"]),
            "calldata_bytes": len(bytes.fromhex(str(built["data"])[2:])),
            "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "native_effect_attempt_ids": self._effect_attempt_ids(receipt),
        }

    def _effect_attempt_ids(self, receipt: Any) -> list[str]:
        """Return indexed attempt IDs from this transaction's application effects."""

        receiver_address = str(self.receiver.address).lower()
        output: list[str] = []
        for log in receipt["logs"]:
            topics = log["topics"]
            if (
                str(log["address"]).lower() == receiver_address
                and len(topics) >= 2
                and Web3.to_hex(topics[0]).lower() == NATIVE_EFFECT_TOPIC
            ):
                output.append(Web3.to_hex(topics[1]).lower())
        return output

    def _submit_delivery(
        self,
        envelope: tuple[Any, ...],
        payload: bytes,
        receiver: str,
        expected_status: int,
        expected_error: str | None = None,
    ) -> dict[str, Any]:
        function = self.gateway.functions.deliver(envelope, payload, receiver)
        selector, error = self._call_error(function, self.runner.account.address)
        if expected_status == 0 and error != expected_error:
            raise LocalTopologyError(
                f"delivery preflight rejected at {error or selector}, expected {expected_error}"
            )
        if expected_status == 1 and (selector is not None or error is not None):
            raise LocalTopologyError(f"valid delivery preflight failed at {error or selector}")
        built = self._built_transaction(
            function, self.runner.account.address, self._runner_nonces()[0]
        )
        result = self._broadcast(built, self.runner.private_key, expected_status)
        result.update({"revert_selector": selector, "revert_error": error})
        return result

    def _submit_competing_deliveries(self, prepared: PreparedXIRDelivery) -> list[dict[str, Any]]:
        function = self.gateway.functions.deliver(
            prepared.envelope, prepared.payload, prepared.receiver_address
        )
        first_nonce, second_nonce = self._runner_nonces(2)
        first = self._built_transaction(function, self.runner.account.address, first_nonce)
        second = self._built_transaction(function, self.runner.account.address, second_nonce)
        client = self.runner.clients["destination"]
        signed_first = Account.sign_transaction(first, self.runner.private_key)
        signed_second = Account.sign_transaction(second, self.runner.private_key)
        hashes = [Web3.to_hex(signed_first.hash).lower(), Web3.to_hex(signed_second.hash).lower()]
        for tx_hash, signed in zip(hashes, (signed_first, signed_second), strict=True):
            raw_path = self.private_root / f"{tx_hash}.raw"
            raw_path.write_bytes(signed.raw_transaction)
            os.chmod(raw_path, 0o600)
        client.eth.send_raw_transaction(signed_first.raw_transaction)
        client.eth.send_raw_transaction(signed_second.raw_transaction)
        results: list[dict[str, Any]] = []
        for tx_hash, built in zip(hashes, (first, second), strict=True):
            receipt = client.eth.wait_for_transaction_receipt(
                HexStr(tx_hash), timeout=self.runner.timeout_seconds
            )
            receipt_path = self.raw_root / f"{tx_hash}.json"
            receipt_path.write_text(
                json.dumps(
                    json.loads(Web3.to_json(cast(dict[Any, Any], receipt))),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            results.append(
                {
                    "transaction_hash": tx_hash,
                    "status": int(receipt["status"]),
                    "nonce": int(built["nonce"]),
                    "block_number": int(receipt["blockNumber"]),
                    "gas_used": int(receipt["gasUsed"]),
                    "calldata_bytes": len(bytes.fromhex(str(built["data"])[2:])),
                    "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                    "native_effect_attempt_ids": self._effect_attempt_ids(receipt),
                    "revert_selector": None,
                    "revert_error": None,
                }
            )
        if sorted(item["status"] for item in results) != [0, 1]:
            raise LocalTopologyError("competing replay did not yield exactly one success")
        selector, error = self._call_error(function, self.runner.account.address)
        for item in results:
            if item["status"] == 0:
                item["revert_selector"] = selector
                item["revert_error"] = error
        if error != EXPECTED_ERROR["concurrent_replay"]:
            raise LocalTopologyError("competing replay did not reconcile to AlreadyConsumed")
        return results

    def _owner_profile(
        self, profile_hash: bytes, snapshot: tuple[Any, ...], action: str
    ) -> dict[str, Any]:
        with self.owner_lock:
            nonce = self.owner_nonce
            self.owner_nonce += 1
        function = self.registry.functions.setProfile(profile_hash, snapshot)
        built = self._built_transaction(function, self.deployer.address, nonce)
        result = self._broadcast(built, self.deployer_key, 1)
        result["registry_action"] = action
        return result

    def freeze(self) -> dict[str, Any]:
        rows = self.state.rows()
        expected = (
            len(cast(list[str], self.config["routes"]))
            * len(cast(list[str], self.config["cases"]))
            * self.repetitions
        )
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            key = (str(row["route"]), str(row["case_name"]))
            group = groups.setdefault(
                key,
                {
                    "route": key[0],
                    "case": key[1],
                    "repetitions": 0,
                    "validated": 0,
                    "expected_rejection": EXPECTED_ERROR[key[1]],
                    "actual_rejection_matches": 0,
                    "application_effects": 0,
                },
            )
            group["repetitions"] += 1
            result = row["result"]
            if row["status"] == "validated" and result is not None:
                group["validated"] += 1
                group["actual_rejection_matches"] += int(
                    result["actual_rejections"] == [group["expected_rejection"]]
                )
                group["application_effects"] += int(result["application_effect_delta"])
        summary = {
            "schema_version": self.summary_schema_version,
            "campaign_id": self.config["campaign_id"],
            "attempt_namespace": self.attempt_namespace,
            "config_sha256": self.config_sha256,
            "deployment_sha256": self.deployment_sha256,
            "expected_case_runs": expected,
            "observed_case_runs": len(rows),
            "validated_case_runs": sum(row["status"] == "validated" for row in rows),
            "failed_case_runs": sum(row["status"] == "failed" for row in rows),
            "root_signer": self.runner.deployment.get("root_signer"),
            "runner": self.runner.account.address.lower(),
            "root_signer_separated": (
                str(self.runner.deployment.get("root_signer", "")).lower()
                != self.runner.account.address.lower()
            ),
            "groups": [groups[key] for key in sorted(groups)],
        }
        summary["valid"] = (
            summary["observed_case_runs"] == expected
            and summary["validated_case_runs"] == expected
            and summary["failed_case_runs"] == 0
            and summary["root_signer_separated"]
            and all(
                group["validated"] == self.repetitions
                and group["actual_rejection_matches"] == self.repetitions
                for group in summary["groups"]
            )
        )
        results_path = self.publish_root / "case-results.json"
        summary_path = self.publish_root / "summary.json"
        csv_path = self.publish_root / "paper-table.csv"
        results_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with csv_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=(
                    "route",
                    "case",
                    "repetitions",
                    "expected_rejection",
                    "actual_rejection_matches",
                    "application_effects",
                    "validated",
                ),
            )
            writer.writeheader()
            writer.writerows(summary["groups"])
        report_path = self.publish_root / "REPORT.md"
        report_lines = [
            f"# {self.report_title}",
            "",
            f"- Case runs: {summary['validated_case_runs']}/{expected}",
            f"- Distinct runner/root signer: {summary['root_signer_separated']}",
            f"- Final validation: {summary['valid']}",
            "",
            "Each negative case was prepared through the deployed native carrier stacks. "
            "The recorded rejection transaction changed neither Gateway consumption state "
            "nor application state. Replay cases produced one initial effect and no duplicate effect.",
            "",
            "| Route | Case | Repetitions | Rejection matches | Effects |",
            "|---|---|---:|---:|---:|",
        ]
        for group in summary["groups"]:
            report_lines.append(
                f"| {group['route']} | {group['case']} | {group['repetitions']} | "
                f"{group['actual_rejection_matches']} | {group['application_effects']} |"
            )
        report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
        self._write_manifest()
        return summary

    def _write_manifest(self) -> None:
        manifest_path = self.publish_root / "SHA256SUMS"
        entries = []
        for path in sorted(self.publish_root.rglob("*")):
            if path.is_file() and path != manifest_path:
                entries.append(
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.publish_root)}"
                )
        manifest_path.write_text("\n".join(entries) + "\n", encoding="utf-8")
