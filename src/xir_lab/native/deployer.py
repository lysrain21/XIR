"""Deployment/configuration of the three-chain native route application."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from eth_account import Account
from eth_typing import ChecksumAddress
from eth_utils import keccak  # type: ignore[attr-defined]
from hexbytes import HexBytes
from web3 import Web3
from web3.types import TxParams

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import executor_lz_receive_options
from xir_lab.native.rpc import qbft_web3

ROUTE_IDS = {
    "HH": keccak(text="XIR_NATIVE_ROUTE_HH_V1"),
    "HL": keccak(text="XIR_NATIVE_ROUTE_HL_V1"),
    "LH": keccak(text="XIR_NATIVE_ROUTE_LH_V1"),
    "LL": keccak(text="XIR_NATIVE_ROUTE_LL_V1"),
}
PROFILE_HASHES = {
    "H_AB": keccak(text="XIR_NATIVE_PROFILE_HYPERLANE_AB_V1"),
    "L_AB": keccak(text="XIR_NATIVE_PROFILE_LAYERZERO_AB_V1"),
    "H_BC": keccak(text="XIR_NATIVE_PROFILE_HYPERLANE_BC_V1"),
    "L_BC": keccak(text="XIR_NATIVE_PROFILE_LAYERZERO_BC_V1"),
}


@dataclass(frozen=True)
class DeploymentChain:
    role: str
    chain_id: int
    hyperlane_domain: int
    layerzero_eid: int
    rpc_url: str
    mailbox: ChecksumAddress
    endpoint: ChecksumAddress


def gateway_typed_id(chain_id: int) -> tuple[int, bytes]:
    value = keccak(text=f"XIR_NATIVE_GATEWAY_ID_V1:{chain_id}")[-20:]
    return (1, value)


def typed_id_hash(identifier: tuple[int, bytes]) -> bytes:
    return keccak(
        identifier[0].to_bytes(1, "big") + len(identifier[1]).to_bytes(1, "big") + identifier[1]
    )


class NativeApplicationDeployer:
    """Broadcasts only after a durable intent and captures every receipt."""

    def __init__(
        self,
        *,
        repository_root: Path,
        runtime_root: Path,
        profile_path: Path,
        private_key: str,
        runner_address: str,
        root_signer_address: str | None = None,
        output_directory: str = "native-application",
        include_security_v2_fixture: bool = False,
    ) -> None:
        self.repository_root = repository_root
        self.runtime_root = runtime_root
        self.profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.account = Account.from_key(private_key)
        self.private_key = private_key
        self.runner_address = Web3.to_checksum_address(runner_address)
        self.root_signer_address = Web3.to_checksum_address(root_signer_address or runner_address)
        self.include_security_v2_fixture = include_security_v2_fixture
        self.artifact_root = repository_root / "contracts" / "out"
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", output_directory) is None:
            raise LocalTopologyError("invalid native application output directory")
        self.output_root = runtime_root / output_directory
        self.raw_root = self.output_root / "receipts"
        self.signed_root = self.output_root / "private-signed-transactions"
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self.signed_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.signed_root, 0o700)
        self.journal_path = self.output_root / "deployment-journal.jsonl"
        self.chains = self._load_chains()
        self.clients = {role: qbft_web3(chain.rpc_url) for role, chain in self.chains.items()}
        self.nonces = {
            role: int(client.eth.get_transaction_count(self.account.address, "pending"))
            for role, client in self.clients.items()
        }
        self.manifest: dict[str, dict[str, str]] = {
            "source": {},
            "intermediate": {},
            "destination": {},
        }

    def _load_chains(self) -> dict[str, DeploymentChain]:
        result: dict[str, DeploymentChain] = {}
        for item in self.profile["chains"]:
            role = str(item["route_role"])
            registry = (
                self.runtime_root
                / "hyperlane"
                / "registry"
                / "chains"
                / {
                    "source": "xirlocalsource",
                    "intermediate": "xirlocalintermediate",
                    "destination": "xirlocaldestination",
                }[role]
                / "addresses.yaml"
            )
            import yaml

            hyperlane = yaml.safe_load(registry.read_text(encoding="utf-8"))
            layerzero = json.loads(
                (
                    self.runtime_root / "layerzero" / "deployments" / f"{item['chain_id']}.json"
                ).read_text(encoding="utf-8")
            )
            result[role] = DeploymentChain(
                role=role,
                chain_id=int(item["chain_id"]),
                hyperlane_domain=int(item["hyperlane_domain"]),
                layerzero_eid=int(item["layerzero_eid"]),
                rpc_url=str(item["rpc_url"]),
                mailbox=Web3.to_checksum_address(hyperlane["mailbox"]),
                endpoint=Web3.to_checksum_address(layerzero["contracts"]["endpoint_v2"]),
            )
        if set(result) != {"source", "intermediate", "destination"}:
            raise LocalTopologyError("native application requires source/intermediate/destination")
        return result

    def _artifact(self, source: str, contract: str) -> dict[str, Any]:
        path = self.artifact_root / source / f"{contract}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        if not document.get("bytecode", {}).get("object"):
            raise LocalTopologyError(f"missing deployable artifact: {contract}")
        return cast(dict[str, Any], document)

    def _append_journal(self, document: dict[str, Any]) -> None:
        with self.journal_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(document, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def _send(
        self,
        *,
        role: str,
        action: str,
        transaction: dict[str, Any],
    ) -> dict[str, Any]:
        client = self.clients[role]
        chain = self.chains[role]
        nonce = self.nonces[role]
        transaction.update(
            {
                "chainId": chain.chain_id,
                "nonce": nonce,
                "maxFeePerGas": max(int(client.eth.gas_price) * 2, 1),
                "maxPriorityFeePerGas": 0,
                "type": 2,
                "from": self.account.address,
            }
        )
        try:
            estimated = int(client.eth.estimate_gas(cast(TxParams, transaction)))
            transaction["gas"] = min(max(estimated * 13 // 10, 100_000), 29_000_000)
        except ValueError:
            transaction["gas"] = 29_000_000
        data = HexBytes(transaction.get("data", b""))
        action_id = hashlib.sha256(
            f"{role}:{nonce}:{action}:{hashlib.sha256(data).hexdigest()}".encode()
        ).hexdigest()
        self._append_journal(
            {
                "record": "intent",
                "action_id": action_id,
                "role": role,
                "chain_id": chain.chain_id,
                "nonce": nonce,
                "action": action,
                "target": transaction.get("to"),
                "calldata_sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        signed = self.account.sign_transaction(transaction)
        raw = bytes(signed.raw_transaction)
        signed_path = self.signed_root / f"{signed.hash.hex()}.raw"
        signed_path.write_bytes(raw)
        os.chmod(signed_path, 0o600)
        self._append_journal(
            {
                "record": "signed",
                "action_id": action_id,
                "transaction_hash": signed.hash.hex(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        tx_hash = client.eth.send_raw_transaction(raw)
        self._append_journal(
            {
                "record": "submitted",
                "action_id": action_id,
                "transaction_hash": tx_hash.hex(),
            }
        )
        receipt = client.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        receipt_document = json.loads(Web3.to_json(cast(dict[Any, Any], receipt)))
        receipt_path = self.raw_root / f"{tx_hash.hex()}.json"
        receipt_path.write_text(
            json.dumps(receipt_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if int(receipt["status"]) != 1:
            raise LocalTopologyError(f"native application action reverted: {action}")
        self._append_journal(
            {
                "record": "succeeded",
                "action_id": action_id,
                "role": role,
                "transaction_hash": tx_hash.hex(),
                "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "gas_used": int(receipt["gasUsed"]),
                "block_number": int(receipt["blockNumber"]),
            }
        )
        self.nonces[role] += 1
        return cast(dict[str, Any], receipt_document)

    def deploy(
        self, role: str, manifest_role: str, source: str, contract: str, args: list[Any]
    ) -> ChecksumAddress:
        artifact = self._artifact(source, contract)
        client = self.clients[role]
        factory = client.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
        built = factory.constructor(*args).build_transaction({"from": self.account.address})
        receipt = self._send(
            role=role,
            action=f"deploy:{manifest_role}:{contract}",
            transaction={"data": built["data"], "value": 0},
        )
        address = Web3.to_checksum_address(receipt["contractAddress"])
        self.manifest[role][manifest_role] = address
        return address

    def call(
        self,
        role: str,
        manifest_role: str,
        source: str,
        contract: str,
        function: str,
        args: list[Any],
        *,
        value: int = 0,
    ) -> None:
        address = Web3.to_checksum_address(self.manifest[role][manifest_role])
        artifact = self._artifact(source, contract)
        instance = self.clients[role].eth.contract(address=address, abi=artifact["abi"])
        built = getattr(instance.functions, function)(*args).build_transaction(
            {"from": self.account.address, "value": value}
        )
        self._send(
            role=role,
            action=f"call:{manifest_role}:{function}",
            transaction={"to": address, "data": built["data"], "value": value},
        )

    def run(self) -> dict[str, Any]:
        self._deploy_gateways()
        self._deploy_adapters()
        if self.include_security_v2_fixture:
            self.deploy(
                "intermediate",
                "security_v2_always_true_prior_verifier",
                "NativeSecurityPriorVerifierFixture.sol",
                "NativeSecurityPriorVerifierFixture",
                [],
            )
        self._deploy_route_contracts()
        self._configure_peers_and_routes()
        self._configure_registries()
        successful_records = [
            json.loads(line)
            for line in self.journal_path.read_text(encoding="utf-8").splitlines()
            if json.loads(line).get("record") == "succeeded"
        ]
        block_bounds = {
            role: {
                "first": min(
                    int(item["block_number"]) for item in successful_records if item["role"] == role
                ),
                "last": max(
                    int(item["block_number"]) for item in successful_records if item["role"] == role
                ),
            }
            for role in self.chains
        }
        document: dict[str, Any] = {
            "schema_version": "xir-lab-native-application-deployment-v1",
            "deployer": self.account.address.lower(),
            "runner": self.runner_address.lower(),
            "root_signer": self.root_signer_address.lower(),
            "gateway_typed_ids": {
                role: {
                    "kind": identifier[0],
                    "value": "0x" + identifier[1].hex(),
                    "hash": "0x" + typed_id_hash(identifier).hex(),
                }
                for role, identifier in (
                    (role, gateway_typed_id(chain.chain_id)) for role, chain in self.chains.items()
                )
            },
            "profile_hashes": {key: "0x" + value.hex() for key, value in PROFILE_HASHES.items()},
            "route_ids": {key: "0x" + value.hex() for key, value in ROUTE_IDS.items()},
            "prior_verifier_bindings": {
                outbound: {
                    "H_AB": self.manifest["intermediate"]["h_in"].lower(),
                    "L_AB": self.manifest["intermediate"]["l_in"].lower(),
                }
                for outbound in ("h_xir_out", "l_xir_out")
            },
            "security_v2_fixtures": (
                {
                    "always_true_prior_verifier": self.manifest["intermediate"][
                        "security_v2_always_true_prior_verifier"
                    ].lower()
                }
                if self.include_security_v2_fixture
                else {}
            ),
            "deployment_block_bounds": block_bounds,
            "infrastructure": {
                role: {
                    "mailbox": chain.mailbox,
                    "layerzero_endpoint_v2": chain.endpoint,
                }
                for role, chain in self.chains.items()
            },
            "chains": self.manifest,
        }
        manifest_path = self.output_root / "deployment.json"
        manifest_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return document

    def _deploy_gateways(self) -> None:
        for role, chain in self.chains.items():
            registry = self.deploy(
                role,
                "registry",
                "XIRRegistry.sol",
                "XIRRegistry",
                [self.account.address],
            )
            self.deploy(
                role,
                "gateway",
                "XIRGateway.sol",
                "XIRGateway",
                [registry, gateway_typed_id(chain.chain_id)],
            )

    def _peer_placeholder(self) -> bytes:
        return bytes.fromhex("00" * 12 + self.account.address[2:])

    def _deploy_hyperlane_adapter(
        self,
        role: str,
        manifest_role: str,
        remote_role: str,
        runner: str,
    ) -> None:
        self.deploy(
            role,
            manifest_role,
            "HyperlaneAdapter.sol",
            "HyperlaneAdapter",
            [
                self.chains[role].mailbox,
                self.chains[remote_role].hyperlane_domain,
                self._peer_placeholder(),
                self.account.address,
                runner,
            ],
        )

    def _deploy_layerzero_adapter(
        self,
        role: str,
        manifest_role: str,
        remote_role: str,
        runner: str,
    ) -> None:
        self.deploy(
            role,
            manifest_role,
            "LayerZeroAdapter.sol",
            "LayerZeroAdapter",
            [
                self.chains[role].endpoint,
                self.chains[remote_role].layerzero_eid,
                self._peer_placeholder(),
                self.account.address,
                runner,
            ],
        )

    def _deploy_adapters(self) -> None:
        for protocol in ("h", "l"):
            deploy = (
                self._deploy_hyperlane_adapter
                if protocol == "h"
                else self._deploy_layerzero_adapter
            )
            deploy("source", f"{protocol}_source", "intermediate", self.runner_address)
            deploy("intermediate", f"{protocol}_in", "source", self.runner_address)
            deploy("intermediate", f"{protocol}_hom_out", "destination", self.runner_address)
            deploy("intermediate", f"{protocol}_xir_out", "destination", self.runner_address)
            deploy("destination", f"{protocol}_hom_in", "intermediate", self.runner_address)
            deploy("destination", f"{protocol}_xir_in", "intermediate", self.runner_address)

    def _deploy_route_contracts(self) -> None:
        options = executor_lz_receive_options(1_500_000)
        forwarder = self.deploy(
            "intermediate",
            "homogeneous_forwarder",
            "NativeHomogeneousForwarder.sol",
            "NativeHomogeneousForwarder",
            [
                self.account.address,
                self.manifest["intermediate"]["h_in"],
                self.manifest["intermediate"]["h_hom_out"],
                self.manifest["intermediate"]["l_in"],
                self.manifest["intermediate"]["l_hom_out"],
                options,
            ],
        )
        self._send(
            role="intermediate",
            action="fund:homogeneous_forwarder",
            transaction={"to": forwarder, "data": b"", "value": Web3.to_wei(100, "ether")},
        )
        self.deploy(
            "intermediate",
            "xir_transition_recorder",
            "NativeXIRTransitionRecorder.sol",
            "NativeXIRTransitionRecorder",
            [
                self.manifest["intermediate"]["gateway"],
                self.runner_address,
            ],
        )
        self.deploy(
            "destination",
            "receiver",
            "NativeExperimentReceiver.sol",
            "NativeExperimentReceiver",
            [
                self.manifest["destination"]["h_hom_in"],
                self.manifest["destination"]["l_hom_in"],
                self.manifest["destination"]["gateway"],
                keccak(text="XIR_NATIVE_INITIAL_EFFECT_STATE_V1"),
            ],
        )
        for adapter in ("h_hom_out", "l_hom_out"):
            source = "HyperlaneAdapter.sol" if adapter.startswith("h_") else "LayerZeroAdapter.sol"
            contract = "HyperlaneAdapter" if adapter.startswith("h_") else "LayerZeroAdapter"
            self.call(
                "intermediate",
                adapter,
                source,
                contract,
                "setRunner",
                [forwarder],
            )

    def _set_peer(
        self,
        role: str,
        local: str,
        remote_role: str,
        remote: str,
        protocol: str,
    ) -> None:
        remote_bytes32 = bytes.fromhex("00" * 12 + self.manifest[remote_role][remote][2:])
        self.call(
            role,
            local,
            "HyperlaneAdapter.sol" if protocol == "h" else "LayerZeroAdapter.sol",
            "HyperlaneAdapter" if protocol == "h" else "LayerZeroAdapter",
            "setRemoteAdapter" if protocol == "h" else "setRemotePeer",
            [remote_bytes32],
        )

    def _configure_peers_and_routes(self) -> None:
        for protocol in ("h", "l"):
            self._set_peer(
                "source", f"{protocol}_source", "intermediate", f"{protocol}_in", protocol
            )
            self._set_peer(
                "intermediate", f"{protocol}_in", "source", f"{protocol}_source", protocol
            )
            for path in ("hom", "xir"):
                self._set_peer(
                    "intermediate",
                    f"{protocol}_{path}_out",
                    "destination",
                    f"{protocol}_{path}_in",
                    protocol,
                )
                self._set_peer(
                    "destination",
                    f"{protocol}_{path}_in",
                    "intermediate",
                    f"{protocol}_{path}_out",
                    protocol,
                )
        options = executor_lz_receive_options(1_500_000)
        for role, contracts in self.manifest.items():
            for adapter in [name for name in contracts if name.startswith("l_")]:
                self.call(
                    role,
                    adapter,
                    "LayerZeroAdapter.sol",
                    "LayerZeroAdapter",
                    "setEnforcedOptions",
                    [options],
                )
        for outbound in ("h_xir_out", "l_xir_out"):
            outbound_protocol = "h" if outbound.startswith("h_") else "l"
            for profile, inbound in (("H_AB", "h_in"), ("L_AB", "l_in")):
                self.call(
                    "intermediate",
                    outbound,
                    (
                        "HyperlaneAdapter.sol"
                        if outbound_protocol == "h"
                        else "LayerZeroAdapter.sol"
                    ),
                    "HyperlaneAdapter" if outbound_protocol == "h" else "LayerZeroAdapter",
                    "setPriorVerifier",
                    [PROFILE_HASHES[profile], self.manifest["intermediate"][inbound]],
                )
        self.call(
            "intermediate",
            "h_in",
            "HyperlaneAdapter.sol",
            "HyperlaneAdapter",
            "setBaselineReceiver",
            [ROUTE_IDS["HH"], self.manifest["intermediate"]["homogeneous_forwarder"]],
        )
        self.call(
            "intermediate",
            "l_in",
            "LayerZeroAdapter.sol",
            "LayerZeroAdapter",
            "setBaselineReceiver",
            [ROUTE_IDS["LL"], self.manifest["intermediate"]["homogeneous_forwarder"]],
        )
        self.call(
            "destination",
            "h_hom_in",
            "HyperlaneAdapter.sol",
            "HyperlaneAdapter",
            "setBaselineReceiver",
            [ROUTE_IDS["HH"], self.manifest["destination"]["receiver"]],
        )
        self.call(
            "destination",
            "l_hom_in",
            "LayerZeroAdapter.sol",
            "LayerZeroAdapter",
            "setBaselineReceiver",
            [ROUTE_IDS["LL"], self.manifest["destination"]["receiver"]],
        )

    def _set_root(self, role: str, source_gateway_hash: bytes) -> None:
        self.call(
            role,
            "registry",
            "XIRRegistry.sol",
            "XIRRegistry",
            "setRoot",
            [1, (source_gateway_hash, self.root_signer_address, 0, 0, True)],
        )

    def _set_profile(
        self,
        role: str,
        profile: str,
        src_hash: bytes,
        dst_hash: bytes,
        adapter: str,
    ) -> None:
        self.call(
            role,
            "registry",
            "XIRRegistry.sol",
            "XIRRegistry",
            "setProfile",
            [
                PROFILE_HASHES[profile],
                (
                    src_hash,
                    dst_hash,
                    self.manifest[role][adapter],
                    1,
                    0,
                    0,
                    True,
                ),
            ],
        )

    def _configure_registries(self) -> None:
        hashes = {
            role: typed_id_hash(gateway_typed_id(chain.chain_id))
            for role, chain in self.chains.items()
        }
        self._set_root("intermediate", hashes["source"])
        self._set_root("destination", hashes["source"])
        self._set_profile("intermediate", "H_AB", hashes["source"], hashes["intermediate"], "h_in")
        self._set_profile("intermediate", "L_AB", hashes["source"], hashes["intermediate"], "l_in")
        self._set_profile(
            "destination", "H_AB", hashes["source"], hashes["intermediate"], "l_xir_in"
        )
        self._set_profile(
            "destination", "L_AB", hashes["source"], hashes["intermediate"], "h_xir_in"
        )
        self._set_profile(
            "destination",
            "H_BC",
            hashes["intermediate"],
            hashes["destination"],
            "h_xir_in",
        )
        self._set_profile(
            "destination",
            "L_BC",
            hashes["intermediate"],
            hashes["destination"],
            "l_xir_in",
        )
