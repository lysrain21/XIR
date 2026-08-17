"""Fresh route-specific application deployment for five-chain multihop runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, cast

import yaml
from eth_account import Account
from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import DeploymentChain, NativeApplicationDeployer, typed_id_hash
from xir_lab.native.layerzero import executor_lz_receive_options
from xir_lab.native.multihop_scalability import ROUTE_ORDER, load_multihop_profile
from xir_lab.native.rpc import qbft_web3

CHAIN_ROLES = ("a", "b", "c", "d", "e")
REGISTRY_VERSION = 1


def multihop_gateway_typed_id(chain_id: int) -> tuple[int, bytes]:
    return (1, keccak(text=f"XIR_NATIVE_MULTIHOP_GATEWAY_ID_V1:{chain_id}")[-20:])


def multihop_profile_hash(route: str, hop_index: int) -> bytes:
    if route not in ROUTE_ORDER or hop_index < 1 or hop_index > len(route):
        raise LocalTopologyError("multihop profile coordinates are invalid")
    protocol = route[hop_index - 1]
    return keccak(text=f"XIR_NATIVE_MULTIHOP_PROFILE_V1:{route}:{hop_index}:{protocol}")


def adapter_key(route: str, hop_index: int, direction: str) -> str:
    if direction not in {"out", "in"}:
        raise LocalTopologyError("multihop adapter direction is invalid")
    if route not in ROUTE_ORDER or not 1 <= hop_index <= len(route):
        raise LocalTopologyError("multihop adapter coordinates are invalid")
    return f"route_{route.lower()}_hop_{hop_index}_{direction}"


def classify_multihop_deployment_costs(
    successes: list[dict[str, Any]],
) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    """Classify experiment application costs without charging reused carriers."""

    component_gas: dict[str, list[int]] = {}
    classified_gas: dict[str, list[int]] = {
        "xir_only_contract_deployment": [],
        "xir_profile_root_peer_binding_initialization": [],
    }
    for item in successes:
        action = str(item["action"])
        gas_used = int(item["gas_used"])
        if action.startswith("deploy:"):
            component = action.rsplit(":", 1)[-1]
            classification = "xir_only_contract_deployment"
        else:
            component = "configuration_call"
            classification = "xir_profile_root_peer_binding_initialization"
        component_gas.setdefault(component, []).append(gas_used)
        classified_gas[classification].append(gas_used)
        item["cost_classification"] = classification
    if not all(classified_gas.values()):
        raise LocalTopologyError("multihop deployment cost classes are incomplete")
    return component_gas, classified_gas


class NativeMultihopDeployer(NativeApplicationDeployer):
    """Deploy a fresh, route-specific verifier-bound A--E application."""

    def __init__(
        self,
        *,
        repository_root: Path,
        runtime_root: Path,
        profile_path: Path,
        private_key: str,
        runner_address: str,
        root_signer_address: str,
        output_directory: str = "native-multihop-switching-v1/deployment",
    ) -> None:
        self.repository_root = repository_root
        self.runtime_root = runtime_root
        self.profile, self.profile_sha256 = load_multihop_profile(profile_path)
        self.account = Account.from_key(private_key)
        self.private_key = private_key
        self.runner_address = Web3.to_checksum_address(runner_address)
        self.root_signer_address = Web3.to_checksum_address(root_signer_address)
        if self.runner_address.lower() == self.root_signer_address.lower():
            raise LocalTopologyError("multihop runner and root signer must be distinct")
        self.include_security_v2_fixture = False
        self.artifact_root = repository_root / "contracts" / "out"
        if re.fullmatch(r"[a-z0-9][a-z0-9/-]{0,127}", output_directory) is None:
            raise LocalTopologyError("invalid multihop application output directory")
        self.output_root = runtime_root / output_directory
        self.raw_root = self.output_root / "receipts"
        self.signed_root = self.output_root / "private-signed-transactions"
        self.raw_root.mkdir(parents=True, exist_ok=False)
        self.signed_root.mkdir(parents=True, exist_ok=False)
        os.chmod(self.signed_root, 0o700)
        self.journal_path = self.output_root / "deployment-journal.jsonl"
        self.chains = self._load_multihop_chains()
        self.clients = {
            role: qbft_web3(chain.rpc_url) for role, chain in self.chains.items()
        }
        self.nonces = {
            role: int(client.eth.get_transaction_count(self.account.address, "pending"))
            for role, client in self.clients.items()
        }
        self.manifest: dict[str, dict[str, str]] = {
            role: {} for role in CHAIN_ROLES
        }
        self.profile_hashes = {
            route: {
                str(hop): multihop_profile_hash(route, hop)
                for hop in range(1, len(route) + 1)
            }
            for route in ROUTE_ORDER
        }

    def _load_multihop_chains(self) -> dict[str, DeploymentChain]:
        result: dict[str, DeploymentChain] = {}
        for index, item in enumerate(cast(list[dict[str, Any]], self.profile["chains"])):
            role = CHAIN_ROLES[index]
            chain_name = f"xirlocalchain{role}"
            registry = (
                self.runtime_root
                / "hyperlane"
                / "registry"
                / "chains"
                / chain_name
                / "addresses.yaml"
            )
            try:
                hyperlane = yaml.safe_load(registry.read_text(encoding="utf-8"))
                layerzero = json.loads(
                    (
                        self.runtime_root
                        / "layerzero"
                        / "deployments"
                        / f"{item['chain_id']}.json"
                    ).read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
                raise LocalTopologyError(
                    f"multihop native infrastructure is missing for chain {role.upper()}"
                ) from exc
            result[role] = DeploymentChain(
                role=role,
                chain_id=int(item["chain_id"]),
                hyperlane_domain=int(item["hyperlane_domain"]),
                layerzero_eid=int(item["layerzero_eid"]),
                rpc_url=cast(str, item["rpc_url"]),
                mailbox=Web3.to_checksum_address(hyperlane["mailbox"]),
                endpoint=Web3.to_checksum_address(
                    layerzero["contracts"]["endpoint_v2"]
                ),
            )
        if tuple(result) != CHAIN_ROLES:
            raise LocalTopologyError("multihop infrastructure must contain A through E")
        return result

    def run(self) -> dict[str, Any]:
        self._deploy_gateways_and_receivers()
        self._deploy_route_adapters()
        self._configure_route_adapters()
        self._configure_route_registries()
        document = self._deployment_document()
        output = self.output_root / "deployment.json"
        output.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        document["deployment_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
        return document

    def _deploy_gateways_and_receivers(self) -> None:
        for role, chain in self.chains.items():
            registry = self.deploy(
                role, "registry", "XIRRegistry.sol", "XIRRegistry", [self.account.address]
            )
            gateway = self.deploy(
                role,
                "gateway",
                "XIRGateway.sol",
                "XIRGateway",
                [registry, multihop_gateway_typed_id(chain.chain_id)],
            )
            if role != "a":
                self.deploy(
                    role,
                    "receiver",
                    "NativeMultihopReceiver.sol",
                    "NativeMultihopReceiver",
                    [gateway, keccak(text=f"XIR_NATIVE_MULTIHOP_INITIAL_STATE_V1:{role}")],
                )
            if role in {"b", "c", "d"}:
                self.deploy(
                    role,
                    "transition_recorder",
                    "NativeMultihopTransitionRecorder.sol",
                    "NativeMultihopTransitionRecorder",
                    [gateway, self.runner_address],
                )

    def _deploy_route_adapters(self) -> None:
        placeholder = bytes.fromhex("00" * 12 + self.account.address[2:])
        for route in ROUTE_ORDER:
            for hop_index, protocol in enumerate(route, start=1):
                source_role = CHAIN_ROLES[hop_index - 1]
                destination_role = CHAIN_ROLES[hop_index]
                source_key = adapter_key(route, hop_index, "out")
                destination_key = adapter_key(route, hop_index, "in")
                if protocol == "H":
                    source_args = [
                        self.chains[source_role].mailbox,
                        self.chains[destination_role].hyperlane_domain,
                        placeholder,
                        self.account.address,
                        self.runner_address,
                    ]
                    destination_args = [
                        self.chains[destination_role].mailbox,
                        self.chains[source_role].hyperlane_domain,
                        placeholder,
                        self.account.address,
                        self.runner_address,
                    ]
                    source_file = "HyperlaneAdapter.sol"
                    contract = "HyperlaneAdapter"
                else:
                    source_args = [
                        self.chains[source_role].endpoint,
                        self.chains[destination_role].layerzero_eid,
                        placeholder,
                        self.account.address,
                        self.runner_address,
                    ]
                    destination_args = [
                        self.chains[destination_role].endpoint,
                        self.chains[source_role].layerzero_eid,
                        placeholder,
                        self.account.address,
                        self.runner_address,
                    ]
                    source_file = "LayerZeroAdapter.sol"
                    contract = "LayerZeroAdapter"
                self.deploy(
                    source_role, source_key, source_file, contract, source_args
                )
                self.deploy(
                    destination_role,
                    destination_key,
                    source_file,
                    contract,
                    destination_args,
                )

    def _configure_route_adapters(self) -> None:
        options = executor_lz_receive_options(1_500_000)
        for route in ROUTE_ORDER:
            for hop_index, protocol in enumerate(route, start=1):
                source_role = CHAIN_ROLES[hop_index - 1]
                destination_role = CHAIN_ROLES[hop_index]
                source_key = adapter_key(route, hop_index, "out")
                destination_key = adapter_key(route, hop_index, "in")
                source_file = (
                    "HyperlaneAdapter.sol" if protocol == "H" else "LayerZeroAdapter.sol"
                )
                contract = "HyperlaneAdapter" if protocol == "H" else "LayerZeroAdapter"
                remote_in = bytes.fromhex(
                    "00" * 12 + self.manifest[destination_role][destination_key][2:]
                )
                remote_out = bytes.fromhex(
                    "00" * 12 + self.manifest[source_role][source_key][2:]
                )
                setter = "setRemoteAdapter" if protocol == "H" else "setRemotePeer"
                self.call(
                    source_role, source_key, source_file, contract, setter, [remote_in]
                )
                self.call(
                    destination_role,
                    destination_key,
                    source_file,
                    contract,
                    setter,
                    [remote_out],
                )
                if protocol == "L":
                    self.call(
                        source_role,
                        source_key,
                        source_file,
                        contract,
                        "setEnforcedOptions",
                        [options],
                    )
                    self.call(
                        destination_role,
                        destination_key,
                        source_file,
                        contract,
                        "setEnforcedOptions",
                        [options],
                    )
                if hop_index > 1:
                    verifier = self.manifest[source_role][
                        adapter_key(route, hop_index - 1, "in")
                    ]
                    for prior_hop in range(1, hop_index):
                        self.call(
                            source_role,
                            source_key,
                            source_file,
                            contract,
                            "setPriorVerifier",
                            [self.profile_hashes[route][str(prior_hop)], verifier],
                        )

    def _set_root(self, role: str, source_hash: bytes) -> None:
        self.call(
            role,
            "registry",
            "XIRRegistry.sol",
            "XIRRegistry",
            "setRoot",
            [
                REGISTRY_VERSION,
                (source_hash, self.root_signer_address, 0, 0, True),
            ],
        )

    def _set_multihop_profile(
        self,
        *,
        role: str,
        profile_hash: bytes,
        source_hash: bytes,
        destination_hash: bytes,
        adapter: str,
    ) -> None:
        self.call(
            role,
            "registry",
            "XIRRegistry.sol",
            "XIRRegistry",
            "setProfile",
            [
                profile_hash,
                (source_hash, destination_hash, adapter, 1, 0, 0, True),
            ],
        )

    def _configure_route_registries(self) -> None:
        gateway_hashes = {
            role: typed_id_hash(multihop_gateway_typed_id(chain.chain_id))
            for role, chain in self.chains.items()
        }
        for role in CHAIN_ROLES[1:]:
            self._set_root(role, gateway_hashes["a"])
        for route in ROUTE_ORDER:
            for completed_hops in range(1, len(route) + 1):
                role = CHAIN_ROLES[completed_hops]
                verifier = self.manifest[role][
                    adapter_key(route, completed_hops, "in")
                ]
                for receipt_index in range(1, completed_hops + 1):
                    self._set_multihop_profile(
                        role=role,
                        profile_hash=self.profile_hashes[route][str(receipt_index)],
                        source_hash=gateway_hashes[CHAIN_ROLES[receipt_index - 1]],
                        destination_hash=gateway_hashes[CHAIN_ROLES[receipt_index]],
                        adapter=verifier,
                    )

    def _deployment_document(self) -> dict[str, Any]:
        journal = [
            json.loads(line)
            for line in self.journal_path.read_text(encoding="utf-8").splitlines()
        ]
        intents = {
            str(item["action_id"]): item
            for item in journal
            if item.get("record") == "intent"
        }
        signed = {
            str(item["action_id"]): item
            for item in journal
            if item.get("record") == "signed"
        }
        successes = [
            {**item, "action": intents[str(item["action_id"])]["action"]}
            for item in journal
            if item.get("record") == "succeeded"
        ]
        if len(successes) != len(intents):
            raise LocalTopologyError("multihop deployment journal is incomplete")
        component_gas, classified_gas = classify_multihop_deployment_costs(successes)
        receipt_provenance: list[dict[str, Any]] = []
        for item in successes:
            action_id = str(item["action_id"])
            intent = intents[action_id]
            signed_row = signed.get(action_id)
            if signed_row is None:
                raise LocalTopologyError("deployment action lacks signed provenance")
            transaction_hash = str(item["transaction_hash"])
            receipt_path = self.raw_root / f"{transaction_hash}.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            target = receipt.get("contractAddress") or intent.get("target")
            if not isinstance(target, str) or not target.startswith("0x"):
                raise LocalTopologyError("deployment receipt target is unavailable")
            client = self.clients[str(item["role"])]
            runtime_code = bytes(client.eth.get_code(Web3.to_checksum_address(target)))
            if not runtime_code:
                raise LocalTopologyError("deployment provenance target has no runtime code")
            block = client.eth.get_block(int(item["block_number"]))
            contract_name = (
                str(item["action"]).rsplit(":", 1)[-1]
                if str(item["action"]).startswith("deploy:")
                else None
            )
            artifact_sha256 = None
            if contract_name is not None:
                candidates = sorted(
                    self.artifact_root.glob(f"*/{contract_name}.json")
                )
                if len(candidates) != 1:
                    raise LocalTopologyError(
                        f"deployment artifact provenance is ambiguous: {contract_name}"
                    )
                artifact_sha256 = hashlib.sha256(candidates[0].read_bytes()).hexdigest()
            receipt_provenance.append(
                {
                    "role": item["role"],
                    "chain_id": int(intent["chain_id"]),
                    "action": item["action"],
                    "action_id": action_id,
                    "nonce": int(intent["nonce"]),
                    "transaction_hash": transaction_hash,
                    "raw_sha256": str(signed_row["raw_sha256"]),
                    "target_or_created_address": target.lower(),
                    "calldata_sha256": str(intent["calldata_sha256"]),
                    "status": int(receipt["status"], 16)
                    if isinstance(receipt["status"], str)
                    else int(receipt["status"]),
                    "gas_used": int(item["gas_used"]),
                    "block_number": int(item["block_number"]),
                    "block_timestamp_utc_seconds": int(block["timestamp"]),
                    "receipt_sha256": str(item["receipt_sha256"]),
                    "runtime_code_sha256": hashlib.sha256(runtime_code).hexdigest(),
                    "compiled_artifact_sha256": artifact_sha256,
                    "cost_classification": item["cost_classification"],
                }
            )
        route_manifest: dict[str, Any] = {}
        for route in ROUTE_ORDER:
            hops: list[dict[str, Any]] = []
            for hop_index, protocol in enumerate(route, start=1):
                source_role = CHAIN_ROLES[hop_index - 1]
                destination_role = CHAIN_ROLES[hop_index]
                hops.append(
                    {
                        "hop_index": hop_index,
                        "protocol": protocol,
                        "source_chain": source_role.upper(),
                        "destination_chain": destination_role.upper(),
                        "profile_hash": "0x"
                        + self.profile_hashes[route][str(hop_index)].hex(),
                        "outbound_adapter": self.manifest[source_role][
                            adapter_key(route, hop_index, "out")
                        ].lower(),
                        "inbound_adapter": self.manifest[destination_role][
                            adapter_key(route, hop_index, "in")
                        ].lower(),
                    }
                )
            route_manifest[route] = {
                "destination_chain": CHAIN_ROLES[len(route)].upper(),
                "receiver": self.manifest[CHAIN_ROLES[len(route)]]["receiver"].lower(),
                "hops": hops,
            }
        return {
            "schema_version": "xir-lab-native-multihop-deployment-v1",
            "namespace": "native-multihop-switching-v1",
            "profile_sha256": self.profile_sha256,
            "deployer": self.account.address.lower(),
            "runner": self.runner_address.lower(),
            "root_signer": self.root_signer_address.lower(),
            "registry_version": REGISTRY_VERSION,
            "gateway_typed_ids": {
                role.upper(): {
                    "kind": identifier[0],
                    "value": "0x" + identifier[1].hex(),
                    "hash": "0x" + typed_id_hash(identifier).hex(),
                }
                for role, identifier in (
                    (role, multihop_gateway_typed_id(chain.chain_id))
                    for role, chain in self.chains.items()
                )
            },
            "routes": route_manifest,
            "chains": self.manifest,
            "deployment_gas": {
                "transaction_count": len(successes),
                "gas_used": sum(int(item["gas_used"]) for item in successes),
                "scope": "experiment_route_isolation_total_not_single_gateway_cost",
                "reused_native_carrier_gas_included": False,
                "reused_native_carrier_components": [
                    "Hyperlane Mailbox/ISM/validator/relayer",
                    "LayerZero Endpoint/ULN/DVN/Executor/worker",
                ],
                "classified_totals": [
                    {
                        "classification": classification,
                        "transaction_count": len(values),
                        "gas_used": sum(values),
                    }
                    for classification, values in sorted(classified_gas.items())
                ],
                "component_unit_observations": [
                    {
                        "component": component,
                        "observation_count": len(values),
                        "minimum_gas": min(values),
                        "maximum_gas": max(values),
                        "mean_gas": sum(values) / len(values),
                    }
                    for component, values in sorted(component_gas.items())
                ],
                "receipts": receipt_provenance,
            },
        }
