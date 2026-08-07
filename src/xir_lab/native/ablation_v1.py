"""Matched native-carrier B0--B3 mechanism ablation.

The module creates a deterministic interleaved plan, deploys an isolated
application layer over the existing native Hyperlane/LayerZero infrastructure,
executes both heterogeneous carrier orders, and reconciles every logical and
physical transaction before analysis.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import sqlite3
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Literal, TypeVar, cast

import jsonschema
import numpy as np
import rfc8785
from eth_abi.abi import encode
from eth_typing import HexStr
from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3
from web3.exceptions import Web3RPCError

from xir_lab.localnet.native_profile import (
    NativeAttempt,
    native_application_payload,
)
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import (
    PROFILE_HASHES,
    NativeApplicationDeployer,
    gateway_typed_id,
    typed_id_hash,
)
from xir_lab.native.layerzero import executor_lz_receive_options
from xir_lab.native.rpc import is_transient_rpc_error, qbft_web3
from xir_lab.native.runner import NativeExperimentRunner
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

AblationLayer = Literal["B0", "B1", "B2", "B3"]
AblationPhase = Literal["smoke", "scale"]
AblationNamespace = Literal["native-ablation-v1", "native-ablation-v2"]
LAYERS: tuple[AblationLayer, ...] = ("B0", "B1", "B2", "B3")
ROUTES = ("HL", "LH")
LAYERZERO_MESSAGE_LIMIT_BYTES = 1_000
LAYERZERO_BASELINE_WRAPPER_BYTES = 160
MECHANISMS: dict[AblationLayer, tuple[str, ...]] = {
    "B0": (
        "native_two_hop_execution",
        "destination_visible_final_hop_authentication",
        "application_replay",
    ),
    "B1": (
        "native_two_hop_execution",
        "destination_visible_final_hop_authentication",
        "application_replay",
        "canonical_record",
        "rid_mid",
    ),
    "B2": (
        "native_two_hop_execution",
        "destination_visible_final_hop_authentication",
        "application_replay",
        "canonical_record",
        "rid_mid",
        "prefix_linked_receipts",
        "adapter_evidence",
        "ordered_bundle_lineage",
    ),
    "B3": (
        "native_two_hop_execution",
        "destination_visible_final_hop_authentication",
        "application_replay",
        "canonical_record",
        "rid_mid",
        "prefix_linked_receipts",
        "adapter_evidence",
        "ordered_bundle_lineage",
        "registry_resolution",
        "security_threshold",
        "atomic_mid_delivery",
    ),
}
PRIOR_VERIFIER_GETTER_ABI = [
    {
        "type": "function",
        "name": "approvedPriorVerifiers",
        "stateMutability": "view",
        "inputs": [{"name": "profileHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "address"}],
    }
]
ReadResult = TypeVar("ReadResult")


@dataclass(frozen=True)
class AblationAttempt:
    attempt: NativeAttempt
    layer: AblationLayer
    pair_id: str
    interleave_block: int
    interleave_slot: int
    logical_nonce: int

    def document(self) -> dict[str, Any]:
        return {
            **asdict(self.attempt),
            "layer": self.layer,
            "pair_id": self.pair_id,
            "interleave_block": self.interleave_block,
            "interleave_slot": self.interleave_slot,
            "logical_nonce": self.logical_nonce,
            "mechanisms": list(MECHANISMS[self.layer]),
        }


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def ablation_version(namespace: str) -> int:
    versions = {"native-ablation-v1": 1, "native-ablation-v2": 2}
    try:
        return versions[namespace]
    except KeyError as exc:
        raise LocalTopologyError(f"unsupported ablation namespace: {namespace}") from exc


def _ablation_schema(namespace: str, artifact: str) -> str:
    version = ablation_version(namespace)
    return f"native-ablation-v{version}-{artifact}.schema.json"


def expected_prior_verifier_bindings(document: dict[str, Any]) -> dict[str, dict[str, str]]:
    intermediate = cast(dict[str, str], document["chains"]["intermediate"])
    return {
        outbound: {
            "H_AB": str(intermediate["h_in"]).lower(),
            "L_AB": str(intermediate["l_in"]).lower(),
        }
        for outbound in ("h_xir_out", "l_xir_out")
    }


def final_revision_bindings_valid(document: dict[str, Any]) -> bool:
    return document.get("prior_verifier_bindings") == expected_prior_verifier_bindings(document)


def query_onchain_prior_verifier_bindings(
    client: Web3, document: dict[str, Any]
) -> dict[str, dict[str, str]]:
    intermediate = cast(dict[str, str], document["chains"]["intermediate"])
    observed: dict[str, dict[str, str]] = {}
    for outbound in ("h_xir_out", "l_xir_out"):
        contract = client.eth.contract(
            address=Web3.to_checksum_address(intermediate[outbound]),
            abi=PRIOR_VERIFIER_GETTER_ABI,
        )
        observed[outbound] = {
            profile_name: str(
                contract.functions.approvedPriorVerifiers(PROFILE_HASHES[profile_name]).call()
            ).lower()
            for profile_name in ("H_AB", "L_AB")
        }
    return observed


def _transient_ablation_read_error(error: Web3RPCError) -> bool:
    message = str(error).lower()
    return is_transient_rpc_error(error) or ("-32603" in message and "internal error" in message)


def _retry_rpc_read(
    operation: Callable[[], ReadResult], *, timeout_seconds: float = 180.0
) -> tuple[ReadResult, int]:
    deadline = time.monotonic() + timeout_seconds
    retries = 0
    while True:
        try:
            return operation(), retries
        except Web3RPCError as error:
            if not _transient_ablation_read_error(error) or time.monotonic() >= deadline:
                raise
            retries += 1
            time.sleep(min(0.2 * (2 ** min(retries, 4)), 2.0))


def _index_layerzero_actions(
    worker: sqlite3.Connection,
) -> dict[str, list[sqlite3.Row]]:
    """Index frozen LayerZero lineage with one ordered database scan.

    Reconciliation previously applied ``lower(guid)`` in one SQL query per
    attempt.  SQLite cannot use the direct ``guid`` index for that expression,
    so a large campaign repeatedly scanned the same immutable table.  Loading
    the ordered rows once preserves the exact lookup semantics and makes
    offline rebuild time linear in the worker database size.
    """

    indexed: dict[str, list[sqlite3.Row]] = {}
    for action in worker.execute(
        """
        SELECT guid, stage, destination_chain_id, transaction_hash, status
        FROM actions ORDER BY guid, stage
        """
    ).fetchall():
        indexed.setdefault(str(action["guid"]).lower(), []).append(action)
    return indexed


def load_ablation_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    document = cast(dict[str, Any], json.loads(raw))
    namespace = str(document.get("namespace", ""))
    schema = json.loads(
        (_repository_root() / "schemas" / _ablation_schema(namespace, "config")).read_text(
            encoding="utf-8"
        )
    )
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise LocalTopologyError(f"{namespace} config violation at {location}: {errors[0].message}")
    return document, hashlib.sha256(raw).hexdigest()


def load_operational_incidents(path: Path | None, *, phase: AblationPhase) -> list[dict[str, Any]]:
    incidents, _ = load_operational_incident_document(path, phase=phase)
    return incidents


def load_operational_incident_document(
    path: Path | None, *, phase: AblationPhase
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if path is None:
        return [], None
    document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    namespace = str(document.get("namespace", ""))
    _validate_schema(document, _ablation_schema(namespace, "operational-incidents"))
    incidents = [
        cast(dict[str, Any], item) for item in document["incidents"] if item["phase"] == phase
    ]
    sensitivity = cast(dict[str, Any] | None, document.get("latency_sensitivity"))
    return incidents, sensitivity


def _validate_schema(document: dict[str, Any], schema_name: str) -> None:
    schema = json.loads((_repository_root() / "schemas" / schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise LocalTopologyError(f"{schema_name} violation at {location}: {errors[0].message}")


def ablation_route_id(route: str, layer: AblationLayer, *, version: int = 1) -> bytes:
    if route not in ROUTES or layer not in {"B0", "B1"}:
        raise LocalTopologyError("baseline ablation route id requires HL/LH and B0/B1")
    if version not in {1, 2}:
        raise LocalTopologyError(f"unsupported ablation route version: {version}")
    return keccak(text=f"XIR_NATIVE_ABLATION_V{version}:{route}:{layer}")


def _application_payload(*, profile_path: Path, phase: AblationPhase, sequence: int) -> bytes:
    native_phase = "smoke" if phase == "smoke" else "scale"
    return native_application_payload(
        profile_path=profile_path, phase=cast(Any, native_phase), sequence=sequence
    )


def encode_b1_wire_payload(
    *,
    payload: bytes,
    record: XIRRecord,
    context: XIRContext,
    rid: bytes,
    mid: bytes,
) -> bytes:
    """Encode the fixed-width B1 wire object reconstructed by the receiver."""

    return encode(
        [
            "uint8",
            "bytes",
            "address",
            "address",
            "address",
            "uint64",
            "bytes32",
            "uint8",
            "bytes32",
            "uint32",
            "bytes32",
            "bytes32",
        ],
        [
            1,
            payload,
            record.source_gateway[1],
            record.source_app[1],
            record.destination_app[1],
            record.nonce,
            record.payload_hash,
            context.required_security,
            context.policy_hash,
            1,
            rid,
            mid,
        ],
    )


def build_ablation_plan(*, config_path: Path, phase: AblationPhase) -> tuple[AblationAttempt, ...]:
    config, _ = load_ablation_config(config_path)
    version = ablation_version(str(config["namespace"]))
    repository = _repository_root()
    profile_path = repository / str(config["profile"])
    per_cell = int(config[f"{phase}_attempts_per_cell"])
    seed = str(config["fixed_seed"])
    plan: list[AblationAttempt] = []
    for sequence in range(per_cell):
        payload = _application_payload(profile_path=profile_path, phase=phase, sequence=sequence)
        payload_sha = hashlib.sha256(payload).hexdigest()
        layer_rotation = sequence % len(LAYERS)
        layer_order = LAYERS[layer_rotation:] + LAYERS[:layer_rotation]
        route_order = ROUTES if sequence % 2 == 0 else tuple(reversed(ROUTES))
        slot = 0
        pair_id = (
            "abpair_"
            + hashlib.sha256(
                rfc8785.dumps(
                    {
                        "namespace": config["namespace"],
                        "phase": phase,
                        "sequence": sequence,
                        "payload_sha256": payload_sha,
                        "seed": seed,
                    }
                )
            ).hexdigest()[:24]
        )
        for layer in layer_order:
            for route in route_order:
                attempt_id = (
                    f"ablv{version}_"
                    + hashlib.sha256(
                        rfc8785.dumps(
                            {
                                "pair_id": pair_id,
                                "route": route,
                                "layer": layer,
                            }
                        )
                    ).hexdigest()[:32]
                )
                native = NativeAttempt(
                    attempt_id=attempt_id,
                    phase=cast(Any, "smoke" if phase == "smoke" else "scale"),
                    route=route,
                    route_sequence=sequence,
                    first_protocol=route[0],
                    second_protocol=route[1],
                    execution_class=f"native_ablation_v{version}",
                    xir=layer in {"B2", "B3"},
                    payload_bytes=len(payload),
                    payload_sha256=payload_sha,
                )
                plan.append(
                    AblationAttempt(
                        attempt=native,
                        layer=layer,
                        pair_id=pair_id,
                        interleave_block=sequence,
                        interleave_slot=slot,
                        logical_nonce=sequence * 8 + LAYERS.index(layer) * 2 + ROUTES.index(route),
                    )
                )
                slot += 1
    validate_ablation_plan(plan, expected_per_cell=per_cell)
    return tuple(plan)


def validate_ablation_plan(
    plan: list[AblationAttempt] | tuple[AblationAttempt, ...],
    *,
    expected_per_cell: int,
) -> None:
    expected_cells = {(route, layer) for route in ROUTES for layer in LAYERS}
    cell_counts = {cell: 0 for cell in expected_cells}
    ids: set[str] = set()
    by_block: dict[int, list[AblationAttempt]] = {}
    for entry in plan:
        key = (entry.attempt.route, entry.layer)
        if key not in expected_cells:
            raise LocalTopologyError(f"unexpected ablation cell: {key}")
        if entry.attempt.attempt_id in ids:
            raise LocalTopologyError("duplicate ablation attempt id")
        ids.add(entry.attempt.attempt_id)
        cell_counts[key] += 1
        by_block.setdefault(entry.interleave_block, []).append(entry)
    if set(cell_counts.values()) != {expected_per_cell}:
        raise LocalTopologyError(f"unbalanced ablation cells: {cell_counts}")
    if len(by_block) != expected_per_cell:
        raise LocalTopologyError("ablation interleave block count mismatch")
    for sequence, block in by_block.items():
        if {(item.attempt.route, item.layer) for item in block} != expected_cells:
            raise LocalTopologyError(f"block {sequence} does not contain all cells")
        if sorted(item.interleave_slot for item in block) != list(range(8)):
            raise LocalTopologyError(f"block {sequence} has invalid slots")
        payloads = {item.attempt.payload_sha256 for item in block}
        if len(payloads) != 1:
            raise LocalTopologyError(f"block {sequence} does not share one payload")
    previous: set[str] = set()
    for layer in LAYERS:
        current = set(MECHANISMS[layer])
        if not previous.issubset(current):
            raise LocalTopologyError(f"{layer} does not retain prior mechanisms")
        previous = current


class NativeAblationDeployer:
    """Deploy only the isolated ablation contracts and carrier peers."""

    def __init__(
        self,
        *,
        repository_root: Path,
        runtime_root: Path,
        profile_path: Path,
        base_deployment_path: Path,
        deployer_private_key: str,
        runner_address: str,
        namespace: AblationNamespace = "native-ablation-v1",
        expected_source_sha256: dict[str, str] | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.repository_root = repository_root
        self.runtime_root = runtime_root
        self.profile_path = profile_path
        self.base_path = base_deployment_path
        self.base = json.loads(base_deployment_path.read_text(encoding="utf-8"))
        self.namespace = namespace
        self.version = ablation_version(namespace)
        self.source_sha256 = {
            relative: hashlib.sha256((repository_root / relative).read_bytes()).hexdigest()
            for relative in (expected_source_sha256 or {})
        }
        if self.version >= 2 and (
            not expected_source_sha256 or self.source_sha256 != expected_source_sha256
        ):
            raise LocalTopologyError("native-ablation-v2 source lock mismatch")
        self.runner_address = Web3.to_checksum_address(runner_address)
        self.helper = NativeApplicationDeployer(
            repository_root=repository_root,
            runtime_root=runtime_root,
            profile_path=profile_path,
            private_key=deployer_private_key,
            runner_address=runner_address,
        )
        output = runtime_root / namespace / "deployment"
        self.helper.output_root = output
        self.helper.raw_root = output / "receipts"
        self.helper.signed_root = output / "private-signed-transactions"
        self.helper.raw_root.mkdir(parents=True, exist_ok=True)
        self.helper.signed_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.helper.signed_root, 0o700)
        self.helper.journal_path = output / "deployment-journal.jsonl"
        self.helper.manifest = {
            role: dict(contracts)
            for role, contracts in cast(dict[str, dict[str, str]], self.base["chains"]).items()
        }
        self.output_root = output

    def _peer(self, role: str, local: str, remote_role: str, remote: str, protocol: str) -> None:
        remote_bytes = bytes.fromhex("00" * 12 + self.helper.manifest[remote_role][remote][2:])
        self.helper.call(
            role,
            local,
            "HyperlaneAdapter.sol" if protocol == "h" else "LayerZeroAdapter.sol",
            "HyperlaneAdapter" if protocol == "h" else "LayerZeroAdapter",
            "setRemoteAdapter" if protocol == "h" else "setRemotePeer",
            [remote_bytes],
        )

    def run(self) -> dict[str, Any]:
        h_out = self.helper._deploy_hyperlane_adapter  # noqa: SLF001
        l_out = self.helper._deploy_layerzero_adapter  # noqa: SLF001
        h_out("intermediate", "h_ablation_out", "destination", self.runner_address)
        h_out("destination", "h_ablation_in", "intermediate", self.runner_address)
        l_out("intermediate", "l_ablation_out", "destination", self.runner_address)
        l_out("destination", "l_ablation_in", "intermediate", self.runner_address)
        self._peer("intermediate", "h_ablation_out", "destination", "h_ablation_in", "h")
        self._peer("destination", "h_ablation_in", "intermediate", "h_ablation_out", "h")
        self._peer("intermediate", "l_ablation_out", "destination", "l_ablation_in", "l")
        self._peer("destination", "l_ablation_in", "intermediate", "l_ablation_out", "l")
        options = executor_lz_receive_options(1_500_000)
        for role, adapter in (
            ("intermediate", "l_ablation_out"),
            ("destination", "l_ablation_in"),
        ):
            self.helper.call(
                role,
                adapter,
                "LayerZeroAdapter.sol",
                "LayerZeroAdapter",
                "setEnforcedOptions",
                [options],
            )

        prior_bindings = cast(
            dict[str, dict[str, str]], self.base.get("prior_verifier_bindings", {})
        )
        if self.version >= 2 and not final_revision_bindings_valid(self.base):
            raise LocalTopologyError(
                "native-ablation-v2 requires final-revision prior-verifier bindings"
            )

        ingress = self.helper.deploy(
            "intermediate",
            "ablation_ingress",
            "NativeAblationV1.sol",
            "NativeAblationIngressV1",
            [
                self.helper.manifest["intermediate"]["h_in"],
                self.helper.manifest["intermediate"]["l_in"],
            ],
        )
        source_id = gateway_typed_id(self.helper.chains["source"].chain_id)
        self.helper.deploy(
            "source",
            "ablation_root",
            "NativeAblationV1.sol",
            "NativeAblationRootV1",
            [source_id],
        )
        hashes = [
            typed_id_hash(gateway_typed_id(self.helper.chains[role].chain_id))
            for role in ("source", "intermediate", "destination")
        ]
        profiles = [PROFILE_HASHES[name] for name in ("H_AB", "L_AB", "H_BC", "L_BC")]
        old_receiver = self.helper.manifest["destination"]["receiver"]
        receiver = self.helper.deploy(
            "destination",
            "ablation_receiver",
            "NativeAblationV1.sol",
            "NativeAblationReceiverV1",
            [
                self.runner_address,
                self.helper.manifest["destination"]["h_ablation_in"],
                self.helper.manifest["destination"]["l_ablation_in"],
                self.helper.manifest["destination"]["gateway"],
                self.helper.manifest["destination"]["h_xir_in"],
                self.helper.manifest["destination"]["l_xir_in"],
                hashes,
                profiles,
            ],
        )
        self.helper.deploy(
            "intermediate",
            "ablation_transition",
            "NativeAblationV1.sol",
            "NativeAblationTransitionV1",
            [
                self.runner_address,
                self.helper.manifest["intermediate"]["h_in"],
                self.helper.manifest["intermediate"]["l_in"],
                hashes[0],
                hashes[1],
                PROFILE_HASHES["H_AB"],
                PROFILE_HASHES["L_AB"],
            ],
        )
        for route in ROUTES:
            first = route[0].lower()
            second = route[1].lower()
            for layer in cast(tuple[AblationLayer, ...], ("B0", "B1")):
                route_id = ablation_route_id(route, layer, version=self.version)
                self.helper.call(
                    "intermediate",
                    f"{first}_in",
                    "HyperlaneAdapter.sol" if first == "h" else "LayerZeroAdapter.sol",
                    "HyperlaneAdapter" if first == "h" else "LayerZeroAdapter",
                    "setBaselineReceiver",
                    [route_id, ingress],
                )
                self.helper.call(
                    "destination",
                    f"{second}_ablation_in",
                    "HyperlaneAdapter.sol" if second == "h" else "LayerZeroAdapter.sol",
                    "HyperlaneAdapter" if second == "h" else "LayerZeroAdapter",
                    "setBaselineReceiver",
                    [route_id, receiver],
                )
        self.helper.manifest["destination"]["base_receiver"] = old_receiver
        self.helper.manifest["destination"]["receiver"] = receiver
        successful = [
            json.loads(line)
            for line in self.helper.journal_path.read_text(encoding="utf-8").splitlines()
            if json.loads(line).get("record") == "succeeded"
        ]
        bounds = {
            role: {
                "first": min(
                    int(item["block_number"]) for item in successful if item["role"] == role
                ),
                "last": max(
                    int(item["block_number"]) for item in successful if item["role"] == role
                ),
            }
            for role in ("source", "intermediate", "destination")
        }
        document = {
            "schema_version": f"xir-lab-native-ablation-v{self.version}-deployment",
            "namespace": self.namespace,
            "base_deployment": str(self.base_path),
            "base_deployment_sha256": hashlib.sha256(self.base_path.read_bytes()).hexdigest(),
            "deployer": self.helper.account.address.lower(),
            "runner": self.runner_address.lower(),
            "deployment_block_bounds": bounds,
            "ablation_route_ids": {
                f"{route}_{layer}": "0x"
                + ablation_route_id(route, layer, version=self.version).hex()
                for route in ROUTES
                for layer in cast(tuple[AblationLayer, ...], ("B0", "B1"))
            },
            "profile_hashes": {key: "0x" + value.hex() for key, value in PROFILE_HASHES.items()},
            "prior_verifier_bindings": prior_bindings,
            "final_revision_source_sha256": self.source_sha256,
            "infrastructure": self.base["infrastructure"],
            "chains": self.helper.manifest,
        }
        path = self.output_root / "deployment.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return document


class NativeAblationRunner(NativeExperimentRunner):
    def __init__(self, *, config_path: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.config_path = config_path
        self.ablation_config, _ = load_ablation_config(config_path)
        self.ablation_version = ablation_version(str(self.ablation_config["namespace"]))
        self.ingress = self._contract(
            "intermediate",
            "ablation_ingress",
            "NativeAblationV1.sol",
            "NativeAblationIngressV1",
        )
        self.ablation_root = self._contract(
            "source", "ablation_root", "NativeAblationV1.sol", "NativeAblationRootV1"
        )
        self.ablation_transition = self._contract(
            "intermediate",
            "ablation_transition",
            "NativeAblationV1.sol",
            "NativeAblationTransitionV1",
        )
        self.ablation_receiver = self._contract(
            "destination",
            "ablation_receiver",
            "NativeAblationV1.sol",
            "NativeAblationReceiverV1",
        )

    def run_ablation_phase(self, phase: AblationPhase) -> None:
        entries = build_ablation_plan(config_path=self.config_path, phase=phase)
        sequences = int(self.ablation_config["interleave_block_sequences"])
        batch_size = sequences * 8
        for offset in range(0, len(entries), batch_size):
            batch = entries[offset : offset + batch_size]
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = [pool.submit(self._run_entry, entry) for entry in batch]
                for future in futures:
                    future.result()

    def _run_entry(self, entry: AblationAttempt) -> None:
        attempt = entry.attempt
        if not self.state.begin(attempt):
            return
        started = time.time()
        retry_deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self._execute_entry(entry, started=started)
                return
            except Web3RPCError as exc:
                if not _transient_ablation_read_error(exc) or time.monotonic() >= retry_deadline:
                    raise
                time.sleep(0.5)

    def _execute_entry(self, entry: AblationAttempt, *, started: float) -> None:
        attempt = entry.attempt
        payload = self._route_payload(entry)
        if entry.layer in {"B0", "B1"}:
            self._run_baseline_layer(entry, payload)
        elif entry.layer == "B2":
            self._run_b2(entry, payload)
        else:
            prepared = self.prepare_heterogeneous(attempt, payload)
            gateway = self._contract("destination", "gateway", "XIRGateway.sol", "XIRGateway")
            self._transact(
                attempt_id=attempt.attempt_id,
                stage="destination_deliver",
                role="destination",
                function=gateway.functions.deliver(
                    prepared.envelope, prepared.payload, prepared.receiver_address
                ),
                detail={
                    "ablation_layer": "B3",
                    "pair_id": entry.pair_id,
                    "rid": "0x" + prepared.rid.hex(),
                    "receipt_count": 2,
                    "carrier_change_records": 1,
                },
            )
        self.state.record_stage(
            attempt.attempt_id,
            "ablation_complete",
            "succeeded",
            {
                "ablation_layer": entry.layer,
                "pair_id": entry.pair_id,
                "interleave_block": entry.interleave_block,
                "interleave_slot": entry.interleave_slot,
                "mechanisms": list(MECHANISMS[entry.layer]),
                "elapsed_seconds": time.time() - started,
            },
        )
        self.state.finish(attempt.attempt_id)

    def _route_payload(self, entry: AblationAttempt) -> bytes:
        phase: AblationPhase = "smoke" if entry.attempt.phase == "smoke" else "scale"
        application = _application_payload(
            profile_path=self.profile_path,
            phase=phase,
            sequence=entry.attempt.route_sequence,
        )
        return encode(
            ["(bytes32,bytes2,uint64,bytes)"],
            [
                (
                    keccak(text=entry.attempt.attempt_id),
                    entry.attempt.route.encode("ascii"),
                    entry.attempt.route_sequence,
                    application,
                )
            ],
        )

    def _logical_objects(
        self, entry: AblationAttempt, payload: bytes
    ) -> tuple[XIRRecord, XIRContext, bytes, bytes]:
        destination = self.contracts["destination"]["ablation_receiver"]
        record = XIRRecord(
            source_gateway=gateway_typed_id(int(self.chain_by_role["source"]["chain_id"])),
            source_app=(1, bytes.fromhex(self.account.address[2:])),
            destination_app=(1, bytes.fromhex(destination[2:])),
            nonce=entry.logical_nonce,
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
        rid = root_id(record, context, 1)
        mid = message_id(rid, record.destination_app)
        return record, context, rid, mid

    def _create_logical_record(
        self, entry: AblationAttempt, payload: bytes
    ) -> tuple[XIRRecord, XIRContext, bytes, bytes]:
        record, context, rid, mid = self._logical_objects(entry, payload)
        existing = self.state.stage(entry.attempt.attempt_id, "logical_record")
        if existing is None:
            preview = self.ablation_root.functions.create(
                record.nonce,
                record.destination_app,
                payload,
                (context.required_security, context.policy_hash),
                1,
            ).call({"from": self.account.address})
            if bytes(preview[1]) != rid or bytes(preview[2]) != mid:
                raise LocalTopologyError("B1/B2 logical preview differs from exact encoding")
        self._transact(
            attempt_id=entry.attempt.attempt_id,
            stage="logical_record",
            role="source",
            function=self.ablation_root.functions.create(
                record.nonce,
                record.destination_app,
                payload,
                (context.required_security, context.policy_hash),
                1,
            ),
            detail={
                "ablation_layer": entry.layer,
                "pair_id": entry.pair_id,
                "rid": "0x" + rid.hex(),
                "mid": "0x" + mid.hex(),
                "record_nonce": record.nonce,
            },
        )
        return record, context, rid, mid

    def _run_baseline_layer(self, entry: AblationAttempt, payload: bytes) -> None:
        if entry.layer == "B0":
            carrier_payload = encode(["uint8", "bytes"], [0, payload])
        else:
            record, context, rid, mid = self._create_logical_record(entry, payload)
            carrier_payload = encode_b1_wire_payload(
                payload=payload,
                record=record,
                context=context,
                rid=rid,
                mid=mid,
            )
        self.dispatch_baseline_first(entry, carrier_payload)
        self.dispatch_baseline_second(entry, carrier_payload)
        self.wait_ablation_effect(entry)

    def dispatch_baseline_first(
        self,
        entry: AblationAttempt,
        carrier_payload: bytes,
        *,
        stage: str = "source_dispatch",
        authentication_stage: str = "first_hop_authenticated",
    ) -> bytes:
        """Execute and reconcile one native-authenticated first baseline hop.

        The separate boundary lets the security-capability campaign replace the
        second-hop semantic payload while preserving the first-hop evidence.
        """

        attempt = entry.attempt
        route_id = ablation_route_id(attempt.route, entry.layer, version=self.ablation_version)
        first = attempt.route[0]
        first_adapter = self._contract(
            "source",
            f"{first.lower()}_source",
            "HyperlaneAdapter.sol" if first == "H" else "LayerZeroAdapter.sol",
            "HyperlaneAdapter" if first == "H" else "LayerZeroAdapter",
        )
        first_options = b"" if first == "H" else self.options
        first_fee = int(
            first_adapter.functions.quoteBaseline(route_id, carrier_payload, first_options).call()
        )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage=stage,
            role="source",
            function=first_adapter.functions.sendBaselineSource(
                route_id, carrier_payload, first_options
            ),
            value=first_fee,
            detail={
                "ablation_layer": entry.layer,
                "pair_id": entry.pair_id,
                "protocol": first,
                "native_fee": first_fee,
                "carrier_payload_bytes": len(carrier_payload),
            },
        )
        payload_hash = keccak(carrier_payload)
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            native_message_id = bytes(
                self.ingress.functions.firstMessageForPayload(payload_hash).call()
            )
            if native_message_id != bytes(32):
                break
            time.sleep(0.25)
        else:
            raise LocalTopologyError("timed out waiting for ablation first-hop ingress")
        self.state.record_stage(
            attempt.attempt_id,
            authentication_stage,
            "succeeded",
            {
                "payload_hash": "0x" + payload_hash.hex(),
                "protocol": first,
                "native_message_id": "0x" + native_message_id.hex(),
            },
        )
        return native_message_id

    def dispatch_baseline_second(
        self,
        entry: AblationAttempt,
        carrier_payload: bytes,
        *,
        stage: str = "intermediate_forward",
    ) -> dict[str, Any]:
        """Submit the second native baseline hop without waiting for an effect."""

        attempt = entry.attempt
        route_id = ablation_route_id(attempt.route, entry.layer, version=self.ablation_version)
        second = attempt.route[1]
        second_adapter = self._contract(
            "intermediate",
            f"{second.lower()}_ablation_out",
            "HyperlaneAdapter.sol" if second == "H" else "LayerZeroAdapter.sol",
            "HyperlaneAdapter" if second == "H" else "LayerZeroAdapter",
        )
        second_options = b"" if second == "H" else self.options
        second_fee = int(
            second_adapter.functions.quoteBaseline(route_id, carrier_payload, second_options).call()
        )
        return self._transact(
            attempt_id=attempt.attempt_id,
            stage=stage,
            role="intermediate",
            function=second_adapter.functions.sendBaselineSource(
                route_id, carrier_payload, second_options
            ),
            value=second_fee,
            detail={
                "ablation_layer": entry.layer,
                "pair_id": entry.pair_id,
                "protocol": second,
                "native_fee": second_fee,
                "carrier_payload_bytes": len(carrier_payload),
            },
        )

    def wait_ablation_effect(
        self,
        entry: AblationAttempt,
        *,
        effect_attempt_hash: bytes | None = None,
        stage: str = "destination_effect",
    ) -> None:
        """Wait for exactly the application attempt named by the route payload."""

        attempt = entry.attempt
        attempt_hash = effect_attempt_hash or keccak(text=attempt.attempt_id)
        deadline = time.monotonic() + self.timeout_seconds
        rpc_poll_errors = 0
        while time.monotonic() < deadline:
            try:
                consumed = bool(
                    self.ablation_receiver.functions.consumedAttempts(attempt_hash).call()
                )
            except Web3RPCError:
                rpc_poll_errors += 1
                time.sleep(0.25)
                continue
            if consumed:
                self.state.record_stage(
                    attempt.attempt_id,
                    stage,
                    "succeeded",
                    {
                        "ablation_layer": entry.layer,
                        "pair_id": entry.pair_id,
                        "attempt_hash": "0x" + attempt_hash.hex(),
                        "rpc_poll_errors": rpc_poll_errors,
                    },
                )
                return
            time.sleep(0.25)
        raise LocalTopologyError("timed out waiting for B0/B1 destination effect")

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
        """Poll adapter evidence while tolerating transient JSON-RPC internal errors."""

        source = "HyperlaneAdapter.sol" if protocol == "H" else "LayerZeroAdapter.sol"
        contract = "HyperlaneAdapter" if protocol == "H" else "LayerZeroAdapter"
        adapter = self._contract(role, adapter_role, source, contract)
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            try:
                if adapter.functions.verify(profile_hash, evidence_hash, transition).call():
                    return
            except Web3RPCError:
                time.sleep(0.5)
                continue
            time.sleep(0.5)
        raise LocalTopologyError(
            f"timed out waiting for {protocol} evidence at {role}:{adapter_role}"
        )

    def _run_b2(self, entry: AblationAttempt, payload: bytes) -> None:
        attempt = entry.attempt
        record, context, rid, _ = self._create_logical_record(entry, payload)
        source_id = record.source_gateway
        intermediate_id = gateway_typed_id(int(self.chain_by_role["intermediate"]["chain_id"]))
        destination_id = gateway_typed_id(int(self.chain_by_role["destination"]["chain_id"]))
        first, second = attempt.route[0], attempt.route[1]
        first_profile = PROFILE_HASHES[f"{first}_AB"]
        second_profile = PROFILE_HASHES[f"{second}_BC"]
        transition_one = transition_hash(record, context, source_id, intermediate_id)
        evidence_one = self._dispatch_first_xir(attempt, first, first_profile, transition_one)
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
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="b2_transition",
            role="intermediate",
            function=self.ablation_transition.functions.record(
                payload,
                record_tuple(record),
                (context.required_security, context.policy_hash),
                receipt_tuple(receipt_one),
                1,
            ),
            detail={
                "ablation_layer": "B2",
                "pair_id": entry.pair_id,
                "outbound_profile": "0x" + second_profile.hex(),
            },
        )
        transition_two = transition_hash(record, context, intermediate_id, destination_id)
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
        for profile, evidence, transition in (
            (first_profile, evidence_one, transition_one),
            (second_profile, evidence_two, transition_two),
        ):
            self._wait_verify(
                role="destination",
                adapter_role=destination_adapter,
                protocol=second,
                profile_hash=profile,
                evidence_hash=evidence,
                transition=transition,
            )
        receipt_two = XIRReceipt(
            intermediate_id,
            destination_id,
            second_profile,
            evidence_two,
            transition_two,
            next_prefix(receipt_one),
        )
        self._transact(
            attempt_id=attempt.attempt_id,
            stage="b2_deliver",
            role="destination",
            function=self.ablation_receiver.functions.deliverB2(
                payload,
                record_tuple(record),
                (context.required_security, context.policy_hash),
                1,
                [receipt_tuple(receipt_one), receipt_tuple(receipt_two)],
            ),
            detail={
                "ablation_layer": "B2",
                "pair_id": entry.pair_id,
                "rid": "0x" + rid.hex(),
                "receipt_count": 2,
                "carrier_change_records": 1,
            },
        )


def write_plan(
    path: Path,
    entries: tuple[AblationAttempt, ...],
    *,
    namespace: AblationNamespace | None = None,
) -> str:
    if not entries:
        raise LocalTopologyError("ablation plan cannot be empty")
    if namespace is None:
        execution_class = entries[0].attempt.execution_class
        inferred = {
            "native_ablation_v1": "native-ablation-v1",
            "native_ablation_v2": "native-ablation-v2",
        }.get(execution_class)
        if inferred is None:
            raise LocalTopologyError(f"cannot infer namespace from {execution_class}")
        namespace = cast(AblationNamespace, inferred)
    version = ablation_version(namespace)
    document = {
        "schema_version": f"xir-lab-native-ablation-v{version}-plan",
        "namespace": namespace,
        "attempt_count": len(entries),
        "cells": {
            f"{route}_{layer}": sum(
                1 for entry in entries if entry.attempt.route == route and entry.layer == layer
            )
            for route in ROUTES
            for layer in LAYERS
        },
        "mechanisms": {layer: list(MECHANISMS[layer]) for layer in LAYERS},
        "attempts": [entry.document() for entry in entries],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


HYPERLANE_DISPATCH_TOPIC = (
    "0x" + keccak(text="HyperlaneDispatched(bytes32,uint32,bytes32,uint256)").hex()
)
LAYERZERO_BASELINE_TOPIC = "0x" + keccak(text="BaselineDispatched(bytes32,uint64,uint256)").hex()
LAYERZERO_XIR_TOPIC = "0x" + keccak(text="VerifiedEvidenceForwarded(bytes32,uint64,uint256)").hex()
HYPERLANE_PROCESS_TOPIC = "0x" + keccak(text="ProcessId(bytes32)").hex()
ABLATION_EFFECT_TOPIC = (
    "0x"
    + keccak(
        text=(
            "AblationEffectApplied(bytes32,bytes2,uint8,uint64,bytes32,bytes32,"
            "bytes32,bytes32,uint256)"
        )
    ).hex()
)


def _hex(value: Any) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return text if text.startswith("0x") else "0x" + text


def _receipt_dispatch_id(detail: dict[str, Any], protocol: str) -> str:
    receipt = json.loads(Path(str(detail["receipt"])).read_text(encoding="utf-8"))
    wanted = {
        HYPERLANE_DISPATCH_TOPIC.lower() if protocol == "H" else LAYERZERO_BASELINE_TOPIC.lower(),
        HYPERLANE_DISPATCH_TOPIC.lower() if protocol == "H" else LAYERZERO_XIR_TOPIC.lower(),
    }
    for log in receipt["logs"]:
        topics = [str(value).lower() for value in log.get("topics", [])]
        if len(topics) >= 2 and topics[0] in wanted:
            return topics[1]
    raise LocalTopologyError(
        f"{protocol} dispatch receipt has no native message identifier: {detail['receipt']}"
    )


def _query_logs(
    client: Web3,
    *,
    address: str,
    topic: str,
    first: int,
    last: int,
    chunk: int = 2_000,
) -> list[Any]:
    result: list[Any] = []
    for start in range(first, last + 1, chunk):
        logs, _ = _retry_rpc_read(
            lambda: client.eth.get_logs(
                {
                    "fromBlock": start,
                    "toBlock": min(start + chunk - 1, last),
                    "address": Web3.to_checksum_address(address),
                    "topics": [topic],
                }
            )
        )
        result.extend(logs)
    return result


def _moving_block_interval(
    values: list[float],
    *,
    repetitions: int,
    block_length: int,
    confidence: float,
    seed: int,
    statistic: Literal["mean", "median"],
) -> tuple[float, float, float]:
    if not values:
        raise LocalTopologyError("bootstrap input is empty")
    data = np.asarray(values, dtype=float)
    n = len(data)
    block = min(block_length, n)
    rng = np.random.default_rng(seed)
    estimates = np.empty(repetitions, dtype=float)
    blocks = math.ceil(n / block)
    for index in range(repetitions):
        starts = rng.integers(0, n, size=blocks)
        selected = np.concatenate([np.arange(start, start + block) % n for start in starts])[:n]
        sample = data[selected]
        estimates[index] = (
            float(np.mean(sample)) if statistic == "mean" else float(np.median(sample))
        )
    alpha = (1.0 - confidence) / 2.0
    point = float(np.mean(data)) if statistic == "mean" else float(np.median(data))
    return (
        point,
        float(np.quantile(estimates, alpha)),
        float(np.quantile(estimates, 1.0 - alpha)),
    )


def _paired_metric_rows(
    attempt_metrics: list[dict[str, Any]],
    *,
    bootstrap: dict[str, Any],
    metric_names: tuple[str, ...],
    seed_suffix: str = "",
) -> list[dict[str, Any]]:
    lookup = {
        (str(item["route"]), str(item["layer"]), int(item["sequence"])): item
        for item in attempt_metrics
    }
    increments = (("B0", "B1"), ("B1", "B2"), ("B2", "B3"))
    rows: list[dict[str, Any]] = []
    for route in ROUTES:
        for lower, upper in increments:
            sequences = sorted(
                sequence
                for route_value, layer, sequence in lookup
                if route_value == route and layer == lower and (route, upper, sequence) in lookup
            )
            for metric_name in metric_names:
                deltas = [
                    float(lookup[(route, upper, sequence)][metric_name])
                    - float(lookup[(route, lower, sequence)][metric_name])
                    for sequence in sequences
                ]
                for statistic_name in cast(
                    tuple[Literal["mean", "median"], ...], ("mean", "median")
                ):
                    seed_material = (
                        f"{bootstrap['seed']}:{route}:{lower}:{upper}:{metric_name}:"
                        f"{statistic_name}{seed_suffix}"
                    )
                    seed = int.from_bytes(
                        hashlib.sha256(seed_material.encode()).digest()[:8], "big"
                    )
                    point, low, high = _moving_block_interval(
                        deltas,
                        repetitions=int(bootstrap["repetitions"]),
                        block_length=int(bootstrap["block_length"]),
                        confidence=float(bootstrap["confidence"]),
                        seed=seed,
                        statistic=statistic_name,
                    )
                    rows.append(
                        {
                            "route": route,
                            "increment": f"{lower}->{upper}",
                            "metric": metric_name,
                            "statistic": statistic_name,
                            "n_pairs": len(deltas),
                            "estimate": point,
                            "ci_low": low,
                            "ci_high": high,
                            "confidence": bootstrap["confidence"],
                            "bootstrap_repetitions": bootstrap["repetitions"],
                            "block_length": min(int(bootstrap["block_length"]), len(deltas)),
                        }
                    )
    return rows


def _incident_free_latency_analysis(
    attempt_metrics: list[dict[str, Any]],
    *,
    phase: AblationPhase,
    incidents: list[dict[str, Any]],
    rule: dict[str, Any] | None,
    bootstrap: dict[str, Any],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    required = rule is not None and str(rule.get("phase")) == phase
    excluded_sequences = (
        {int(value) for value in cast(list[int], rule["excluded_route_sequences"])}
        if required and rule is not None
        else set()
    )
    audit_rows = [
        {
            "attempt_id": str(item["attempt_id"]),
            "route": str(item["route"]),
            "layer": str(item["layer"]),
            "pair_id": str(item["pair_id"]),
            "sequence": int(item["sequence"]),
            "interleave_block": int(item["interleave_block"]),
            "interleave_slot": int(item["interleave_slot"]),
            "latency_seconds": float(item["latency_seconds"]),
            "included": int(item["sequence"]) not in excluded_sequences,
            "exclusion_rule_id": (
                str(rule["rule_id"])
                if required and int(item["sequence"]) in excluded_sequences and rule is not None
                else ""
            ),
        }
        for item in sorted(
            attempt_metrics,
            key=lambda row: (int(row["sequence"]), int(row["interleave_slot"])),
        )
    ]
    included_metrics = [
        item for item in attempt_metrics if int(item["sequence"]) not in excluded_sequences
    ]
    excluded_rows = [row for row in audit_rows if not bool(row["included"])]
    cell_rows: list[dict[str, Any]] = []
    included_cell_counts: dict[str, int] = {}
    excluded_cell_counts: dict[str, int] = {}
    for route in ROUTES:
        for layer in LAYERS:
            cell = [
                item
                for item in included_metrics
                if item["route"] == route and item["layer"] == layer
            ]
            excluded_cell = [
                item
                for item in attempt_metrics
                if item["route"] == route
                and item["layer"] == layer
                and int(item["sequence"]) in excluded_sequences
            ]
            key = f"{route}_{layer}"
            included_cell_counts[key] = len(cell)
            excluded_cell_counts[key] = len(excluded_cell)
            values = [float(item["latency_seconds"]) for item in cell]
            cell_rows.append(
                {
                    "route": route,
                    "layer": layer,
                    "n": len(values),
                    "latency_seconds_mean": statistics.mean(values) if values else None,
                    "latency_seconds_median": statistics.median(values) if values else None,
                    "latency_seconds_p95": float(np.quantile(values, 0.95)) if values else None,
                }
            )
    paired_rows = _paired_metric_rows(
        included_metrics,
        bootstrap=bootstrap,
        metric_names=("latency_seconds",),
        seed_suffix=(f":incident-free:{rule['rule_id']}" if required and rule is not None else ""),
    )
    paired_counts = {
        f"{route}_{increment}": next(
            (
                int(row["n_pairs"])
                for row in paired_rows
                if row["route"] == route and row["increment"] == increment
            ),
            0,
        )
        for route in ROUTES
        for increment in ("B0->B1", "B1->B2", "B2->B3")
    }
    full_blocks = len({int(item["sequence"]) for item in attempt_metrics})
    included_blocks = len({int(item["sequence"]) for item in included_metrics})
    excluded_blocks = len(excluded_sequences)
    incident_sequences = {int(item["route_sequence"]) for item in incidents}
    expected_cells = {(route, layer) for route in ROUTES for layer in LAYERS}
    block_cells_valid = all(
        {
            (str(item["route"]), str(item["layer"]))
            for item in attempt_metrics
            if int(item["sequence"]) == sequence
        }
        == expected_cells
        for sequence in excluded_sequences
    )
    expectations_valid = True
    if required and rule is not None:
        expected_per_cell = int(rule["expected_included_per_cell"])
        expectations_valid = all(
            (
                full_blocks == int(rule["full_matched_blocks"]),
                included_blocks == int(rule["expected_included_blocks"]),
                excluded_blocks == int(rule["expected_excluded_blocks"]),
                len(included_metrics) == int(rule["expected_included_attempts"]),
                len(excluded_rows) == int(rule["expected_excluded_attempts"]),
                incident_sequences == excluded_sequences,
                block_cells_valid,
                all(value == expected_per_cell for value in included_cell_counts.values()),
                all(value == len(excluded_sequences) for value in excluded_cell_counts.values()),
                all(value == expected_per_cell for value in paired_counts.values()),
            )
        )
    summary = {
        "required": required,
        "valid": expectations_valid,
        "rule_id": str(rule["rule_id"]) if required and rule is not None else "none",
        "selection_unit": (
            str(rule["selection_unit"]) if required and rule is not None else "none"
        ),
        "exclusion_reason": (
            str(rule["exclusion_reason"]) if required and rule is not None else "none"
        ),
        "excluded_route_sequences": sorted(excluded_sequences),
        "incident_overlap_attempts": [
            {
                "incident_id": str(item["incident_id"]),
                "attempt_id": str(item["affected_attempt_id"]),
                "route": str(item["route"]),
                "layer": str(item["layer"]),
                "sequence": int(item["route_sequence"]),
            }
            for item in incidents
        ],
        "full_attempts": len(attempt_metrics),
        "included_attempts": len(included_metrics),
        "excluded_attempts": len(excluded_rows),
        "full_matched_blocks": full_blocks,
        "included_matched_blocks": included_blocks,
        "excluded_matched_blocks": excluded_blocks,
        "included_cell_counts": included_cell_counts,
        "excluded_cell_counts": excluded_cell_counts,
        "paired_increment_counts": paired_counts,
        "ordering": str(rule["ordering"]) if required and rule is not None else "unchanged",
        "interval_method": (
            str(rule["interval_method"]) if required and rule is not None else "unchanged"
        ),
        "bootstrap_seed": str(bootstrap["seed"]),
        "bootstrap_repetitions": int(bootstrap["repetitions"]),
        "bootstrap_block_length": int(bootstrap["block_length"]),
        "bootstrap_confidence": float(bootstrap["confidence"]),
    }
    return summary, audit_rows, cell_rows, paired_rows


def analyze_ablation_phase(
    *,
    phase: AblationPhase,
    config_path: Path,
    profile_path: Path,
    deployment_path: Path,
    runner_state_path: Path,
    layerzero_state_path: Path,
    output_root: Path,
    operational_incidents_path: Path | None = None,
) -> dict[str, Any]:
    """Reconcile one phase and emit deterministic publication artifacts."""

    config, config_sha = load_ablation_config(config_path)
    namespace = str(config["namespace"])
    version = ablation_version(namespace)
    result_role = "revision_evidence_only" if version == 1 else "final_mechanism_cost_estimate"
    deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if str(deployment.get("namespace")) != namespace:
        raise LocalTopologyError(
            f"ablation deployment namespace mismatch: {deployment.get('namespace')} != {namespace}"
        )
    prior_bindings_valid = version < 2 or final_revision_bindings_valid(deployment)
    if not prior_bindings_valid:
        raise LocalTopologyError("final-revision prior-verifier bindings do not match ingress")
    source_lock_valid = version < 2 or deployment.get("final_revision_source_sha256") == config.get(
        "final_revision_source_sha256"
    )
    if not source_lock_valid:
        raise LocalTopologyError("final-revision deployment source lock mismatch")
    entries = build_ablation_plan(config_path=config_path, phase=phase)
    operational_incidents, latency_sensitivity_rule = load_operational_incident_document(
        operational_incidents_path, phase=phase
    )
    expected = {entry.attempt.attempt_id: entry for entry in entries}
    connection = sqlite3.connect(runner_state_path)
    connection.row_factory = sqlite3.Row
    attempt_rows = {
        str(row["attempt_id"]): row
        for row in connection.execute("SELECT * FROM attempts").fetchall()
    }
    missing_attempts = sorted(set(expected) - set(attempt_rows))
    unexpected_attempts = sorted(set(attempt_rows) - set(expected))
    incomplete_attempts = sorted(
        attempt_id for attempt_id, row in attempt_rows.items() if str(row["status"]) != "succeeded"
    )
    clients = {
        str(chain["route_role"]): qbft_web3(str(chain["rpc_url"])) for chain in profile["chains"]
    }
    onchain_prior_bindings = (
        query_onchain_prior_verifier_bindings(clients["intermediate"], deployment)
        if version >= 2
        else {}
    )
    onchain_prior_bindings_valid = (
        version < 2 or onchain_prior_bindings == expected_prior_verifier_bindings(deployment)
    )
    chain_role = {int(chain["chain_id"]): str(chain["route_role"]) for chain in profile["chains"]}
    first_block = min(
        int(bounds["first"]) for bounds in deployment["deployment_block_bounds"].values()
    )
    hyperlane_process: dict[tuple[str, str], str] = {}
    for role in ("intermediate", "destination"):
        last = int(clients[role].eth.block_number)
        mailbox = deployment["infrastructure"][role]["mailbox"]
        for log in _query_logs(
            clients[role],
            address=mailbox,
            topic=HYPERLANE_PROCESS_TOPIC,
            first=first_block,
            last=last,
        ):
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

    def metrics(role: str, transaction_hash: str) -> dict[str, Any]:
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
        result = {
            "transaction_hash": tx_hash,
            "role": role,
            "chain_id": int(tx["chainId"]),
            "block_number": int(receipt["blockNumber"]),
            "block_hash": _hex(receipt["blockHash"]).lower(),
            "transaction_index": int(receipt["transactionIndex"]),
            "sender": str(tx["from"]).lower(),
            "target": None if tx["to"] is None else str(tx["to"]).lower(),
            "calldata_sha256": hashlib.sha256(bytes(tx["input"])).hexdigest(),
            "gas_used": int(receipt["gasUsed"]),
            "calldata_bytes": len(bytes(tx["input"])),
            "status": int(receipt["status"]),
        }
        transaction_cache[key] = result
        return result

    physical_rows: list[dict[str, Any]] = []
    attempt_metrics: list[dict[str, Any]] = []
    reconciliation_errors: list[dict[str, Any]] = []
    b1_exact_wire_checks = 0
    b1_layerzero_size_checks = 0
    coordinator_retry_count = 0
    required_by_layer = {
        "B0": {"source_dispatch", "intermediate_forward"},
        "B1": {"logical_record", "source_dispatch", "intermediate_forward"},
        "B2": {
            "logical_record",
            "first_protocol_dispatch",
            "b2_transition",
            "second_protocol_dispatch",
            "b2_deliver",
        },
        "B3": {
            "xir_root_record",
            "first_protocol_dispatch",
            "xir_transition",
            "second_protocol_dispatch",
            "destination_deliver",
        },
    }
    dispatch_stage = {
        "B0": ("source_dispatch", "intermediate_forward"),
        "B1": ("source_dispatch", "intermediate_forward"),
        "B2": ("first_protocol_dispatch", "second_protocol_dispatch"),
        "B3": ("first_protocol_dispatch", "second_protocol_dispatch"),
    }
    for attempt_id, entry in expected.items():
        row = attempt_rows.get(attempt_id)
        if row is None:
            continue
        stages = {
            str(stage["stage"]): stage
            for stage in connection.execute(
                "SELECT * FROM stages WHERE attempt_id=?", (attempt_id,)
            ).fetchall()
        }
        missing_stages = sorted(required_by_layer[entry.layer] - set(stages))
        if missing_stages:
            reconciliation_errors.append(
                {"attempt_id": attempt_id, "missing_stages": missing_stages}
            )
            continue
        if entry.layer == "B1":
            application = _application_payload(
                profile_path=profile_path,
                phase=phase,
                sequence=entry.attempt.route_sequence,
            )
            route_payload = encode(
                ["(bytes32,bytes2,uint64,bytes)"],
                [
                    (
                        keccak(text=attempt_id),
                        entry.attempt.route.encode("ascii"),
                        entry.attempt.route_sequence,
                        application,
                    )
                ],
            )
            source_chain_id = next(
                int(chain["chain_id"])
                for chain in profile["chains"]
                if chain["route_role"] == "source"
            )
            destination_address = str(deployment["chains"]["destination"]["ablation_receiver"])
            record = XIRRecord(
                source_gateway=gateway_typed_id(source_chain_id),
                source_app=(1, bytes.fromhex(str(deployment["runner"])[2:])),
                destination_app=(1, bytes.fromhex(destination_address[2:])),
                nonce=entry.logical_nonce,
                payload_hash=keccak(route_payload),
            )
            context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
            expected_rid = root_id(record, context, 1)
            expected_mid = message_id(expected_rid, record.destination_app)
            wire_payload = encode_b1_wire_payload(
                payload=route_payload,
                record=record,
                context=context,
                rid=expected_rid,
                mid=expected_mid,
            )
            logical_detail = json.loads(str(stages["logical_record"]["detail_json"]))
            authentication = stages.get("first_hop_authenticated")
            authentication_detail = (
                json.loads(str(authentication["detail_json"])) if authentication is not None else {}
            )
            dispatch_details = [
                json.loads(str(stages[name]["detail_json"]))
                for name in ("source_dispatch", "intermediate_forward")
            ]
            exact = (
                logical_detail.get("rid", "").lower() == "0x" + expected_rid.hex()
                and logical_detail.get("mid", "").lower() == "0x" + expected_mid.hex()
                and int(logical_detail.get("record_nonce", -1)) == record.nonce
                and authentication_detail.get("payload_hash", "").lower()
                == "0x" + keccak(wire_payload).hex()
                and all(
                    int(detail.get("carrier_payload_bytes", -1)) == len(wire_payload)
                    for detail in dispatch_details
                )
            )
            if exact:
                b1_exact_wire_checks += 1
            else:
                reconciliation_errors.append(
                    {"attempt_id": attempt_id, "invalid_b1_exact_wire_rebuild": True}
                )
            if (
                len(wire_payload) + LAYERZERO_BASELINE_WRAPPER_BYTES
                <= LAYERZERO_MESSAGE_LIMIT_BYTES
            ):
                b1_layerzero_size_checks += 1
            else:
                reconciliation_errors.append(
                    {
                        "attempt_id": attempt_id,
                        "b1_layerzero_message_bytes": len(wire_payload)
                        + LAYERZERO_BASELINE_WRAPPER_BYTES,
                    }
                )
        rows_for_attempt: list[dict[str, Any]] = []
        for stage_name in sorted(required_by_layer[entry.layer]):
            stage = stages[stage_name]
            if str(stage["state"]) != "succeeded" or not stage["transaction_hash"]:
                reconciliation_errors.append(
                    {"attempt_id": attempt_id, "invalid_stage": stage_name}
                )
                continue
            detail = json.loads(str(stage["detail_json"]))
            stage_retry_count = int(detail.get("retry_count", 0))
            coordinator_retry_count += stage_retry_count
            if stage_retry_count or detail.get("retry_lineage"):
                reconciliation_errors.append(
                    {
                        "attempt_id": attempt_id,
                        "physical_stage": stage_name,
                        "unaccounted_retry_count": stage_retry_count,
                    }
                )
            role = str(detail["role"])
            item = {
                "attempt_id": attempt_id,
                "route": entry.attempt.route,
                "layer": entry.layer,
                "pair_id": entry.pair_id,
                "physical_stage": stage_name,
                "physical_kind": "coordinator",
                "hop_index": 0,
                "native_message_id": "",
                **metrics(role, str(stage["transaction_hash"])),
            }
            rows_for_attempt.append(item)
        for hop, stage_name in enumerate(dispatch_stage[entry.layer]):
            protocol = entry.attempt.route[hop]
            stage = stages[stage_name]
            detail = json.loads(str(stage["detail_json"]))
            native_id = _receipt_dispatch_id(detail, protocol).lower()
            coordinator_dispatch = next(
                (item for item in rows_for_attempt if item["physical_stage"] == stage_name),
                None,
            )
            if coordinator_dispatch is None:
                continue
            coordinator_dispatch["hop_index"] = hop + 1
            coordinator_dispatch["native_message_id"] = native_id
            destination_role = "intermediate" if hop == 0 else "destination"
            if protocol == "H":
                native_hash = hyperlane_process.get((destination_role, native_id))
                if native_hash is None:
                    reconciliation_errors.append(
                        {
                            "attempt_id": attempt_id,
                            "missing_hyperlane_process": native_id,
                            "hop": hop + 1,
                        }
                    )
                    continue
                rows_for_attempt.append(
                    {
                        "attempt_id": attempt_id,
                        "route": entry.attempt.route,
                        "layer": entry.layer,
                        "pair_id": entry.pair_id,
                        "physical_stage": f"hop_{hop + 1}_hyperlane_process",
                        "physical_kind": "hyperlane_agent",
                        "hop_index": hop + 1,
                        "native_message_id": native_id,
                        **metrics(destination_role, native_hash),
                    }
                )
            else:
                actions = layerzero_actions_by_guid.get(native_id, [])
                if (
                    len(actions) != 3
                    or any(
                        str(action["status"]) != "succeeded"
                        or not action["transaction_hash"]
                        or int(action["destination_chain_id"]) not in chain_role
                        for action in actions
                    )
                    or {str(action["stage"]) for action in actions}
                    != {
                        "dvn_execute",
                        "commit_verification",
                        "executor_execute",
                    }
                ):
                    reconciliation_errors.append(
                        {
                            "attempt_id": attempt_id,
                            "invalid_layerzero_lineage": native_id,
                            "action_count": len(actions),
                            "hop": hop + 1,
                        }
                    )
                    continue
                for action in actions:
                    role = chain_role[int(action["destination_chain_id"])]
                    rows_for_attempt.append(
                        {
                            "attempt_id": attempt_id,
                            "route": entry.attempt.route,
                            "layer": entry.layer,
                            "pair_id": entry.pair_id,
                            "physical_stage": f"hop_{hop + 1}_layerzero_{action['stage']}",
                            "physical_kind": "layerzero_worker",
                            "hop_index": hop + 1,
                            "native_message_id": native_id,
                            **metrics(role, str(action["transaction_hash"])),
                        }
                    )
        hashes = [item["transaction_hash"] for item in rows_for_attempt]
        if len(hashes) != len(set(hashes)):
            reconciliation_errors.append(
                {"attempt_id": attempt_id, "duplicate_physical_transaction": True}
            )
        if any(int(item["status"]) != 1 for item in rows_for_attempt):
            reconciliation_errors.append(
                {"attempt_id": attempt_id, "failed_physical_transaction": True}
            )
        physical_rows.extend(rows_for_attempt)
        coordinator = [item for item in rows_for_attempt if item["physical_kind"] == "coordinator"]
        attempt_metrics.append(
            {
                "attempt_id": attempt_id,
                "route": entry.attempt.route,
                "layer": entry.layer,
                "pair_id": entry.pair_id,
                "sequence": entry.attempt.route_sequence,
                "interleave_block": entry.interleave_block,
                "interleave_slot": entry.interleave_slot,
                "payload_bytes": entry.attempt.payload_bytes,
                "payload_sha256": entry.attempt.payload_sha256,
                "started_at_unix": float(row["started_at"]),
                "finished_at_unix": float(row["finished_at"]),
                "latency_seconds": float(row["finished_at"]) - float(row["started_at"]),
                "physical_transactions": len(rows_for_attempt),
                "complete_gas": sum(int(item["gas_used"]) for item in rows_for_attempt),
                "complete_calldata": sum(int(item["calldata_bytes"]) for item in rows_for_attempt),
                "coordinator_transactions": len(coordinator),
                "coordinator_gas": sum(int(item["gas_used"]) for item in coordinator),
                "coordinator_calldata": sum(int(item["calldata_bytes"]) for item in coordinator),
            }
        )

    destination_last = int(clients["destination"].eth.block_number)
    effect_logs = _query_logs(
        clients["destination"],
        address=deployment["chains"]["destination"]["ablation_receiver"],
        topic=ABLATION_EFFECT_TOPIC,
        first=first_block,
        last=destination_last,
    )
    effect_counts: dict[str, int] = {}
    expected_hash_to_id = {
        "0x" + keccak(text=attempt_id).hex(): attempt_id for attempt_id in expected
    }
    for log in effect_logs:
        topics = list(log["topics"])
        if len(topics) < 2:
            continue
        attempt_hash = _hex(topics[1]).lower()
        effect_attempt_id = expected_hash_to_id.get(attempt_hash)
        if effect_attempt_id is not None:
            effect_counts[effect_attempt_id] = effect_counts.get(effect_attempt_id, 0) + 1
    missing_effects = sorted(set(expected) - set(effect_counts))
    duplicate_effects = sorted(
        attempt_id for attempt_id, count in effect_counts.items() if count != 1
    )

    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "attempt-metrics.csv", attempt_metrics)
    _write_csv(output_root / "physical-transactions.csv", physical_rows)
    cell_summary: list[dict[str, Any]] = []
    for route in ROUTES:
        for layer in LAYERS:
            cell = [
                item
                for item in attempt_metrics
                if item["route"] == route and item["layer"] == layer
            ]
            summary: dict[str, Any] = {
                "route": route,
                "layer": layer,
                "n": len(cell),
            }
            for metric_name in (
                "latency_seconds",
                "complete_gas",
                "complete_calldata",
                "coordinator_gas",
                "coordinator_calldata",
                "physical_transactions",
            ):
                values = [float(item[metric_name]) for item in cell]
                summary[f"{metric_name}_mean"] = statistics.mean(values) if values else None
                summary[f"{metric_name}_median"] = statistics.median(values) if values else None
                summary[f"{metric_name}_p95"] = float(np.quantile(values, 0.95)) if values else None
            cell_summary.append(summary)
    _write_csv(output_root / "cell-summary.csv", cell_summary)

    bootstrap = cast(dict[str, Any], config["bootstrap"])
    paired_rows = _paired_metric_rows(
        attempt_metrics,
        bootstrap=bootstrap,
        metric_names=(
            "latency_seconds",
            "complete_gas",
            "complete_calldata",
            "coordinator_gas",
            "coordinator_calldata",
        ),
    )
    _write_csv(output_root / "paired-deltas.csv", paired_rows)
    (
        incident_latency_sensitivity,
        latency_sensitivity_audit_rows,
        incident_free_latency_summary,
        incident_free_latency_deltas,
    ) = _incident_free_latency_analysis(
        attempt_metrics,
        phase=phase,
        incidents=operational_incidents,
        rule=latency_sensitivity_rule,
        bootstrap=bootstrap,
    )
    _write_csv(output_root / "latency-sensitivity-attempts.csv", latency_sensitivity_audit_rows)
    _write_csv(output_root / "incident-free-latency-summary.csv", incident_free_latency_summary)
    _write_csv(output_root / "incident-free-latency-deltas.csv", incident_free_latency_deltas)

    stage_summary: list[dict[str, Any]] = []
    coordinator_stages = sorted(
        {
            str(item["physical_stage"])
            for item in physical_rows
            if item["physical_kind"] == "coordinator"
        }
    )
    for route in ROUTES:
        for layer in LAYERS:
            for stage in coordinator_stages:
                rows = [
                    item
                    for item in physical_rows
                    if item["route"] == route
                    and item["layer"] == layer
                    and item["physical_stage"] == stage
                ]
                if rows:
                    stage_summary.append(
                        {
                            "route": route,
                            "layer": layer,
                            "stage": stage,
                            "n": len(rows),
                            "gas_mean": statistics.mean(int(item["gas_used"]) for item in rows),
                            "gas_median": statistics.median(int(item["gas_used"]) for item in rows),
                            "calldata_mean": statistics.mean(
                                int(item["calldata_bytes"]) for item in rows
                            ),
                            "calldata_median": statistics.median(
                                int(item["calldata_bytes"]) for item in rows
                            ),
                        }
                    )
    _write_csv(output_root / "stage-costs.csv", stage_summary)
    cell_counts = {
        f"{route}_{layer}": sum(
            item["route"] == route and item["layer"] == layer for item in attempt_metrics
        )
        for route in ROUTES
        for layer in LAYERS
    }
    mechanism_deltas = {
        layer: sorted(
            set(MECHANISMS[layer]) - (set() if index == 0 else set(MECHANISMS[LAYERS[index - 1]]))
        )
        for index, layer in enumerate(LAYERS)
    }
    paired_increment_counts = {
        f"{route}_{increment}": next(
            (
                int(row["n_pairs"])
                for row in paired_rows
                if row["route"] == route and row["increment"] == increment
            ),
            0,
        )
        for route in ROUTES
        for increment in ("B0->B1", "B1->B2", "B2->B3")
    }
    scale_minimum_satisfied = phase != "scale" or min(cell_counts.values()) >= 1_000
    expected_b1_checks = sum(entry.layer == "B1" for entry in entries)
    runtime_root = deployment_path.parents[2]
    incident_logs_valid = all(
        (runtime_root / str(incident["runner_log_relative_path"])).is_file()
        and hashlib.sha256(
            (runtime_root / str(incident["runner_log_relative_path"])).read_bytes()
        ).hexdigest()
        == incident["runner_log_sha256"]
        for incident in operational_incidents
    )
    incident_source_snapshots_valid = all(
        not incident.get(f"{prefix}_source_relative_path")
        or (
            (runtime_root / str(incident[f"{prefix}_source_relative_path"])).is_file()
            and hashlib.sha256(
                (runtime_root / str(incident[f"{prefix}_source_relative_path"])).read_bytes()
            ).hexdigest()
            == incident[f"{prefix}_source_sha256"]
        )
        for incident in operational_incidents
        for prefix in ("pre_retry", "resume")
    )
    incident_resume_audits_valid = all(
        not incident.get(f"{prefix}_relative_path")
        or (
            (runtime_root / str(incident[f"{prefix}_relative_path"])).is_file()
            and hashlib.sha256(
                (runtime_root / str(incident[f"{prefix}_relative_path"])).read_bytes()
            ).hexdigest()
            == incident[f"{prefix}_sha256"]
        )
        for incident in operational_incidents
        for prefix in ("pre_resume_audit", "post_resume_audit")
    )
    incident_recovery_valid = (
        incident_logs_valid
        and incident_source_snapshots_valid
        and incident_resume_audits_valid
        and all(
            incident["status"] == "recovered"
            and not incident["treatment_changed"]
            and incident["attempt_in_final_denominator"]
            and incident["affected_attempt_id"] in expected
            and expected[incident["affected_attempt_id"]].attempt.route == incident["route"]
            and expected[incident["affected_attempt_id"]].layer == incident["layer"]
            and expected[incident["affected_attempt_id"]].attempt.route_sequence
            == incident["route_sequence"]
            for incident in operational_incidents
        )
    )
    valid = not (
        missing_attempts
        or unexpected_attempts
        or incomplete_attempts
        or reconciliation_errors
        or missing_effects
        or duplicate_effects
        or len(attempt_metrics) != len(expected)
        or not scale_minimum_satisfied
        or not incident_recovery_valid
        or not incident_latency_sensitivity["valid"]
        or not onchain_prior_bindings_valid
    )
    validation = {
        "schema_version": f"xir-lab-native-ablation-v{version}-validation",
        "valid": valid,
        "phase": phase,
        "expected_attempts": len(expected),
        "reconciled_attempts": len(attempt_metrics),
        "application_effects": sum(effect_counts.values()),
        "missing_attempts": missing_attempts,
        "unexpected_attempts": unexpected_attempts,
        "incomplete_attempts": incomplete_attempts,
        "missing_effects": missing_effects,
        "duplicate_effects": duplicate_effects,
        "reconciliation_errors": reconciliation_errors,
        "cell_counts": cell_counts,
        "mechanism_matrix": {layer: list(MECHANISMS[layer]) for layer in LAYERS},
        "mechanism_deltas": mechanism_deltas,
        "mechanism_nesting_valid": all(
            set(MECHANISMS[LAYERS[index - 1]]).issubset(MECHANISMS[layer])
            for index, layer in enumerate(LAYERS[1:], start=1)
        ),
        "matched_payload_blocks": len({item["pair_id"] for item in attempt_metrics}),
        "paired_increment_counts": paired_increment_counts,
        "scale_minimum_satisfied": scale_minimum_satisfied,
        "physical_lineage_complete": not reconciliation_errors,
        "complete_physical_transactions": len(physical_rows),
        "coordinator_retry_count": coordinator_retry_count,
        "retry_free_complete_lineage": coordinator_retry_count == 0,
        "analyzer_transaction_read_retry_count": analyzer_transaction_read_retry_count,
        "operational_incident_count": len(operational_incidents),
        "operational_incident_logs_valid": incident_logs_valid,
        "operational_incident_source_snapshots_valid": incident_source_snapshots_valid,
        "operational_incidents_recovered": incident_recovery_valid,
        "incident_latency_sensitivity_required": incident_latency_sensitivity["required"],
        "incident_latency_sensitivity_valid": incident_latency_sensitivity["valid"],
        "incident_latency_sensitivity_included_attempts": incident_latency_sensitivity[
            "included_attempts"
        ],
        "incident_latency_sensitivity_excluded_attempts": incident_latency_sensitivity[
            "excluded_attempts"
        ],
        "incident_latency_sensitivity_included_blocks": incident_latency_sensitivity[
            "included_matched_blocks"
        ],
        "incident_latency_sensitivity_excluded_blocks": incident_latency_sensitivity[
            "excluded_matched_blocks"
        ],
        "incident_latency_sensitivity_cell_counts": incident_latency_sensitivity[
            "included_cell_counts"
        ],
        "incident_latency_sensitivity_paired_counts": incident_latency_sensitivity[
            "paired_increment_counts"
        ],
        "administrator_prior_binding_required": version >= 2,
        "administrator_prior_binding_valid": prior_bindings_valid,
        "final_revision_source_lock_required": version >= 2,
        "final_revision_source_lock_valid": source_lock_valid,
        "onchain_prior_binding_valid": onchain_prior_bindings_valid,
        "b1_exact_wire_checks": b1_exact_wire_checks,
        "b1_exact_wire_rebuild_valid": b1_exact_wire_checks == expected_b1_checks,
        "b1_layerzero_size_checks": b1_layerzero_size_checks,
        "b1_layerzero_size_valid": b1_layerzero_size_checks == expected_b1_checks,
    }
    _validate_schema(validation, _ablation_schema(namespace, "validation"))
    (output_root / "validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    analysis = {
        "schema_version": f"xir-lab-native-ablation-v{version}-analysis",
        "namespace": namespace,
        "result_role": result_role,
        "phase": phase,
        "config_sha256": config_sha,
        "analysis_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "operational_incidents_sha256": (
            hashlib.sha256(operational_incidents_path.read_bytes()).hexdigest()
            if operational_incidents_path is not None
            else ""
        ),
        "deployment_sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest(),
        "base_deployment_sha256": deployment.get("base_deployment_sha256", ""),
        "final_revision_source_sha256": deployment.get("final_revision_source_sha256", {}),
        "prior_verifier_bindings": deployment.get("prior_verifier_bindings", {}),
        "onchain_prior_verifier_bindings": onchain_prior_bindings,
        "runner_state_sha256": hashlib.sha256(runner_state_path.read_bytes()).hexdigest(),
        "layerzero_state_sha256": hashlib.sha256(layerzero_state_path.read_bytes()).hexdigest(),
        "attempt_count": len(attempt_metrics),
        "physical_transaction_count": len(physical_rows),
        "cell_summary": cell_summary,
        "paired_deltas": paired_rows,
        "stage_costs": stage_summary,
        "incident_latency_sensitivity": incident_latency_sensitivity,
        "incident_free_latency_summary": incident_free_latency_summary,
        "incident_free_latency_deltas": incident_free_latency_deltas,
        "prepublication_exclusions": config["prepublication_exclusions"],
        "operational_incidents": operational_incidents,
        "validation": validation,
    }
    analysis["semantic_digest"] = hashlib.sha256(
        rfc8785.dumps(
            cast(
                dict[str, Any],
                {
                    "namespace": namespace,
                    "result_role": result_role,
                    "phase": phase,
                    "attempt_metrics": attempt_metrics,
                    "physical_rows": physical_rows,
                    "cell_summary": cell_summary,
                    "paired_deltas": paired_rows,
                    "stage_costs": stage_summary,
                    "latency_sensitivity_audit_rows": latency_sensitivity_audit_rows,
                    "incident_latency_sensitivity": incident_latency_sensitivity,
                    "incident_free_latency_summary": incident_free_latency_summary,
                    "incident_free_latency_deltas": incident_free_latency_deltas,
                    "validation": validation,
                    "operational_incidents": operational_incidents,
                },
            )
        )
    ).hexdigest()
    _validate_schema(analysis, _ablation_schema(namespace, "analysis"))
    (output_root / "analysis.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _render_waterfall(output_root, cell_summary, paired_rows, namespace=namespace)
    _write_report(output_root, analysis)
    _write_manifest(output_root, namespace=namespace)
    return analysis


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _render_waterfall(
    output_root: Path,
    cell_summary: list[dict[str, Any]],
    paired_rows: list[dict[str, Any]],
    *,
    namespace: str = "native-ablation-v1",
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    # Matplotlib otherwise seeds SVG element identifiers randomly on each save.
    # A stable salt makes independent publication rebuilds byte-identical.
    matplotlib.rcParams["svg.hashsalt"] = f"xir-{namespace}"
    import matplotlib.pyplot as plt

    # The paper figure uses one neutral family plus one color per route.  Font
    # sizes are limited to three roles (11, 9, and 8 pt), and the generous top
    # mechanism band keeps the occupied visual area close to the manuscript's
    # 61.8% target while making the nested treatments readable without prose.
    neutral = "#344054"
    neutral_light = "#D9DEE7"
    palette = {"HL": "#2563A6", "LH": "#C7792D"}
    metrics = (
        ("complete_gas", "Gas · complete route"),
        ("complete_calldata", "Calldata · complete route (bytes)"),
        ("latency_seconds", "Latency · logical attempt (s)"),
    )
    figure, axes = plt.subplots(1, 3, figsize=(11.4, 4.4))
    figure.subplots_adjust(left=0.065, right=0.985, bottom=0.19, top=0.68, wspace=0.34)

    figure.suptitle(
        "Matched mechanism cost from B0 to B3",
        x=0.065,
        y=0.965,
        ha="left",
        color=neutral,
        fontsize=11,
        fontweight="bold",
    )
    figure.text(
        0.065,
        0.905,
        "Each column adds only the mechanism named below; HL and LH remain separate.",
        ha="left",
        color=neutral,
        fontsize=9,
    )
    mechanism_labels = (
        ("B0", "Native two-hop\nreceiver replay"),
        ("B1", "+ exact R / rid / mid"),
        ("B2", "+ receipts / evidence\n+ ordered lineage"),
        ("B3", "+ registry / threshold\n+ atomic delivery"),
    )
    mechanism_x = (0.135, 0.375, 0.625, 0.865)
    for x_position, (layer, description) in zip(mechanism_x, mechanism_labels, strict=True):
        figure.text(
            x_position,
            0.842,
            layer,
            ha="center",
            va="center",
            color=neutral,
            fontsize=9,
            fontweight="bold",
        )
        figure.text(
            x_position,
            0.785,
            description,
            ha="center",
            va="center",
            color=neutral,
            fontsize=8,
            linespacing=1.25,
        )
    x = np.arange(4)
    for axis, (metric, title) in zip(axes, metrics, strict=True):
        for route, shift in (("HL", -0.18), ("LH", 0.18)):
            totals = [
                next(
                    float(item[f"{metric}_mean"])
                    for item in cell_summary
                    if item["route"] == route and item["layer"] == layer
                )
                for layer in LAYERS
            ]
            changes = [totals[0]]
            errors_low: list[float] = [0.0]
            errors_high: list[float] = [0.0]
            for lower, upper in (("B0", "B1"), ("B1", "B2"), ("B2", "B3")):
                row = next(
                    item
                    for item in paired_rows
                    if item["route"] == route
                    and item["increment"] == f"{lower}->{upper}"
                    and item["metric"] == metric
                    and item["statistic"] == "mean"
                )
                changes.append(float(row["estimate"]))
                errors_low.append(float(row["estimate"]) - float(row["ci_low"]))
                errors_high.append(float(row["ci_high"]) - float(row["estimate"]))
            starts = [0.0, *totals[:-1]]
            bottoms = [min(start, start + change) for start, change in zip(starts, changes)]
            heights = [abs(change) for change in changes]
            axis.bar(
                x + shift,
                heights,
                bottom=bottoms,
                width=0.28,
                color=palette[route],
                edgecolor=palette[route],
                alpha=0.20,
                linewidth=1.0,
            )
            axis.errorbar(
                x + shift,
                totals,
                yerr=np.asarray([errors_low, errors_high]),
                marker="o",
                linewidth=1.2,
                markersize=4,
                capsize=2,
                color=palette[route],
                label=route if axis is axes[0] else "_nolegend_",
            )
        axis.set_title(title, fontsize=9, color=neutral, pad=8)
        axis.set_xticks(x, LAYERS)
        axis.grid(axis="y", color=neutral_light, linewidth=0.6)
        axis.spines[["top", "right"]].set_visible(False)
        axis.spines[["bottom", "left"]].set_color(neutral)
        axis.tick_params(labelsize=8, colors=neutral)
        axis.set_axisbelow(True)
    axes[0].legend(
        frameon=False,
        fontsize=8,
        loc="upper left",
        ncols=2,
        handlelength=1.4,
    )
    figure.text(
        0.065,
        0.065,
        "Bars start at the preceding layer total; dots mark the upper-layer mean and whiskers "
        "the 95% moving-block paired interval. Complete route = coordinator + Hyperlane "
        "process + all LayerZero worker actions.",
        ha="left",
        va="bottom",
        color=neutral,
        fontsize=8,
    )
    figure.savefig(
        output_root / "mechanism-waterfall.pdf",
        bbox_inches="tight",
        metadata={"Creator": f"XIR {namespace}", "CreationDate": None},
    )
    figure.savefig(
        output_root / "mechanism-waterfall.svg",
        bbox_inches="tight",
        metadata={"Creator": f"XIR {namespace}", "Date": None},
    )
    plt.close(figure)


def _write_report(output_root: Path, analysis: dict[str, Any]) -> None:
    validation = analysis["validation"]
    version = ablation_version(str(analysis["namespace"]))
    lines = [
        f"# Native B0--B3 mechanism ablation v{version}",
        "",
        f"Phase: `{analysis['phase']}`.",
        f"Result role: `{analysis['result_role']}`.",
        f"Reconciled attempts: {analysis['attempt_count']}.",
        f"Complete physical transactions: {analysis['physical_transaction_count']}.",
        f"Matched payload blocks: {validation['matched_payload_blocks']}.",
        "Read-only transaction/receipt analyzer retries: "
        f"{validation['analyzer_transaction_read_retry_count']}.",
        f"Validation: **{'PASS' if validation['valid'] else 'FAIL'}**.",
        "",
        "B0 executes and authenticates both native carrier hops, exposes only the final-hop "
        "authentication to the destination, and retains application replay protection. The "
        "first-hop authentication is neither carried to nor bound at the destination. "
        "B1 adds the exact Record, rid, and mid encodings. B2 adds prefix-linked hop receipts, "
        "adapter-authenticated evidence, and ordered bundle lineage. B3 adds current-state registry "
        "resolution, the security threshold, and Gateway-level atomic mid consumption.",
        "",
        "HL and LH use the same payload at each sequence. All four layers are interleaved inside "
        "each deterministic sequence block. Complete-route totals include coordinator transactions, "
        "Hyperlane process transactions, and all three LayerZero worker actions.",
        "",
        *(
            [
                "The final-revision deployment binds each H_AB/L_AB prior-hop profile to the "
                "administrator-approved intermediate inbound adapter before B2/B3 dispatch.",
                "",
            ]
            if version >= 2
            else []
        ),
        "## Operational incidents",
        "",
    ]
    if analysis.get("operational_incidents"):
        for incident in analysis["operational_incidents"]:
            committed = "; ".join(str(value) for value in incident["committed_stage_summary"])
            destination_state = (
                "The destination application effect had committed before the failed read."
                if incident["destination_effect_observed_before_resume"]
                else "The destination application effect had not started before the failed read."
            )
            lines.append(
                f"- `{incident['incident_id']}`: {incident['exception_class']} "
                f"{incident['exception_code']} during {incident['operation']}; durable resume used "
                f"the same plan, database, raw root, deployment, and frozen configuration. The "
                f"committed stages were: {committed}. {destination_state} The RPC failure occurred "
                f"on a read-only poll. The retry path preserved the treatment, configuration, seed, "
                f"and denominator, and the affected attempt appears exactly once in the complete "
                f"analysis. The retained traceback is `{incident['runner_log_relative_path']}` (SHA-256 "
                f"`{incident['runner_log_sha256']}`)."
            )
            if incident.get("pre_retry_source_relative_path"):
                lines.append(
                    f"  The pre-retry analyzer/runner module is retained at "
                    f"`{incident['pre_retry_source_relative_path']}` (SHA-256 "
                    f"`{incident['pre_retry_source_sha256']}`)."
                )
            if incident.get("resume_source_relative_path"):
                lines.append(
                    f"  The resume execution module is retained at "
                    f"`{incident['resume_source_relative_path']}` (SHA-256 "
                    f"`{incident['resume_source_sha256']}`)."
                )
            if incident.get("pre_resume_audit_relative_path"):
                lines.append(
                    f"  The pre-resume chain-state audit is retained at "
                    f"`{incident['pre_resume_audit_relative_path']}` (SHA-256 "
                    f"`{incident['pre_resume_audit_sha256']}`)."
                )
            if incident.get("post_resume_audit_relative_path"):
                lines.append(
                    f"  The post-resume exactly-once audit is retained at "
                    f"`{incident['post_resume_audit_relative_path']}` (SHA-256 "
                    f"`{incident['post_resume_audit_sha256']}`)."
                )
    else:
        lines.append("No operational incident occurred in this phase.")
    lines.extend(
        [
            "",
            "## Prepublication smoke exclusions",
            "",
            "The following diagnostic smokes are retained for audit and excluded from every "
            "published denominator:",
            "",
        ]
    )
    for item in analysis.get("prepublication_exclusions", []):
        lines.append(f"- `{item['id']}`: {item['reason']}.")
    lines.extend(
        [
            "",
            "## Cell means",
            "",
            "| Route | Layer | n | Gas | Calldata (B) | Latency (s) | Physical tx |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for cell in analysis["cell_summary"]:
        lines.append(
            f"| {cell['route']} | {cell['layer']} | {cell['n']} | "
            f"{float(cell['complete_gas_mean']):.1f} | "
            f"{float(cell['complete_calldata_mean']):.1f} | "
            f"{float(cell['latency_seconds_mean']):.4f} | "
            f"{float(cell['physical_transactions_mean']):.2f} |"
        )
    lines.extend(
        [
            "",
            "## Paired mean mechanism increments",
            "",
            "| Route | Increment | Metric | n | Estimate | 95% interval |",
            "|---|---|---|---:|---:|---:|",
        ]
    )
    for row in analysis["paired_deltas"]:
        if row["statistic"] == "mean" and row["metric"] in {
            "complete_gas",
            "complete_calldata",
            "latency_seconds",
        }:
            lines.append(
                f"| {row['route']} | {row['increment']} | {row['metric']} | {row['n_pairs']} | "
                f"{float(row['estimate']):.4f} | "
                f"[{float(row['ci_low']):.4f}, {float(row['ci_high']):.4f}] |"
            )
    sensitivity = analysis.get("incident_latency_sensitivity")
    if sensitivity and sensitivity["required"]:
        excluded = ", ".join(str(value) for value in sensitivity["excluded_route_sequences"])
        lines.extend(
            [
                "",
                "## Incident-free matched-block latency sensitivity",
                "",
                f"The primary latency analysis retains all {sensitivity['full_attempts']} attempts. "
                f"The frozen sensitivity rule `{sensitivity['rule_id']}` excludes complete "
                f"deterministic interleave blocks {excluded}. Each block contains one interrupted "
                f"attempt and its seven matched cells. This produces "
                f"{sensitivity['included_attempts']} included attempts and "
                f"{sensitivity['excluded_attempts']} explicitly listed exclusions across "
                f"{sensitivity['included_matched_blocks']} matched blocks. Every route-layer cell "
                f"contains {next(iter(sensitivity['included_cell_counts'].values()))} attempts. "
                "`latency-sensitivity-attempts.csv` marks every included and excluded attempt.",
                "",
                "| Route | Increment | Statistic | n | Latency delta (s) | 95% interval |",
                "|---|---|---|---:|---:|---:|",
            ]
        )
        for row in analysis["incident_free_latency_deltas"]:
            lines.append(
                f"| {row['route']} | {row['increment']} | {row['statistic']} | "
                f"{row['n_pairs']} | {float(row['estimate']):.4f} | "
                f"[{float(row['ci_low']):.4f}, {float(row['ci_high']):.4f}] |"
            )
    lines.extend(
        [
            "",
            "## Directly measured XIR coordinator stages",
            "",
            "| Route | Stage | n | Mean gas | Mean calldata (B) |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for row in analysis["stage_costs"]:
        if row.get("layer") == "B3" and row.get("stage") in {
            "xir_root_record",
            "xir_transition",
        }:
            lines.append(
                f"| {row['route']} | {row['stage']} | {row['n']} | "
                f"{float(row['gas_mean']):.1f} | {float(row['calldata_mean']):.1f} |"
            )
    lines.extend(
        [
            "",
            "Directly measured coordinator stages are in `stage-costs.csv`, and every physical "
            "transaction is linked in `physical-transactions.csv`.",
            "",
            f"Semantic digest: `{analysis['semantic_digest']}`.",
            f"Analyzer source SHA-256: `{analysis.get('analysis_source_sha256', 'unrecorded')}`.",
        ]
    )
    (output_root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_manifest(output_root: Path, *, namespace: str = "native-ablation-v1") -> None:
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
    version = ablation_version(namespace)
    manifest = {
        "schema_version": f"xir-lab-native-ablation-v{version}-manifest",
        "namespace": namespace,
        "files": files,
    }
    _validate_schema(manifest, _ablation_schema(namespace, "manifest"))
    path = output_root / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_root / "manifest.sha256").write_text(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  manifest.json\n",
        encoding="utf-8",
    )


def validate_publication_tree(output_root: Path) -> dict[str, Any]:
    manifest_path = output_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
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
    sha_line = (output_root / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    if sha_line != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        mismatches.append("manifest.sha256")
    validation = json.loads((output_root / "validation.json").read_text(encoding="utf-8"))
    result = {
        "valid": not mismatches and not forbidden and bool(validation["valid"]),
        "manifest_mismatches": mismatches,
        "forbidden_publishable_content": sorted(set(forbidden)),
        "experiment_validation": bool(validation["valid"]),
    }
    return result


def rebuild_ablation_publication(*, source_root: Path, output_root: Path) -> dict[str, Any]:
    """Rebuild every publication artifact from frozen normalized source files.

    This path performs no RPC or database access. Two clean invocations over
    the same source tree must yield identical files and semantic digests.
    """

    if output_root.exists() and any(output_root.iterdir()):
        raise LocalTopologyError(f"offline rebuild output is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    source_manifest = source_root / "manifest.json"
    if not source_manifest.is_file():
        raise LocalTopologyError("offline rebuild source has no manifest")
    analysis = cast(
        dict[str, Any],
        json.loads((source_root / "analysis.json").read_text(encoding="utf-8")),
    )
    validation = cast(
        dict[str, Any],
        json.loads((source_root / "validation.json").read_text(encoding="utf-8")),
    )
    namespace = str(analysis.get("namespace", ""))
    version = ablation_version(namespace)
    _validate_schema(analysis, _ablation_schema(namespace, "analysis"))
    _validate_schema(validation, _ablation_schema(namespace, "validation"))
    if analysis["validation"] != validation or not validation["valid"]:
        raise LocalTopologyError("offline rebuild source validation mismatch")
    source_files = [
        "analysis.json",
        "validation.json",
        "attempt-metrics.csv",
        "physical-transactions.csv",
        "cell-summary.csv",
        "paired-deltas.csv",
        "stage-costs.csv",
    ]
    if "incident_latency_sensitivity" in analysis:
        source_files.extend(
            [
                "latency-sensitivity-attempts.csv",
                "incident-free-latency-summary.csv",
                "incident-free-latency-deltas.csv",
            ]
        )
    for name in source_files:
        source = source_root / name
        if not source.is_file():
            raise LocalTopologyError(f"offline rebuild source is missing {name}")
        (output_root / name).write_bytes(source.read_bytes())
    provenance = {
        "schema_version": f"xir-lab-native-ablation-v{version}-offline-rebuild",
        "semantic_digest": analysis["semantic_digest"],
        "source_manifest_sha256": hashlib.sha256(source_manifest.read_bytes()).hexdigest(),
    }
    (output_root / "rebuild-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _render_waterfall(
        output_root,
        cast(list[dict[str, Any]], analysis["cell_summary"]),
        cast(list[dict[str, Any]], analysis["paired_deltas"]),
        namespace=namespace,
    )
    _write_report(output_root, analysis)
    _write_manifest(output_root, namespace=namespace)
    result = validate_publication_tree(output_root)
    (output_root / "publication-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not result["valid"]:
        raise LocalTopologyError("offline ablation publication validation failed")
    return {
        "valid": True,
        "semantic_digest": analysis["semantic_digest"],
        "manifest_sha256": hashlib.sha256((output_root / "manifest.json").read_bytes()).hexdigest(),
        "figure_pdf_sha256": hashlib.sha256(
            (output_root / "mechanism-waterfall.pdf").read_bytes()
        ).hexdigest(),
        "figure_svg_sha256": hashlib.sha256(
            (output_root / "mechanism-waterfall.svg").read_bytes()
        ).hexdigest(),
    }
