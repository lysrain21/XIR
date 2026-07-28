from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore
from xir_lab.preflight.carrier_discovery import (
    HYPERLANE_REGISTRY_ROOT,
    LAYERZERO_DEPLOYMENTS_URL,
    NETWORKS,
    OfficialRegistryDiscovery,
    build_registry_candidates,
    discover_official_deployments,
    freeze_official_discovery,
)
from xir_lab.preflight.carriers import CarrierPreflightError


class FixtureFetcher:
    def __init__(self) -> None:
        self.responses: dict[str, bytes] = {}
        for network_id, metadata in NETWORKS.items():
            key = metadata["hyperlane_key"]
            self.responses[f"{HYPERLANE_REGISTRY_ROOT}/{key}/metadata.yaml"] = (
                (
                    f"chainId: {metadata['chain_id']}\n"
                    f"domainId: {metadata['chain_id']}\n"
                    "protocol: ethereum\n"
                    "isTestnet: true\n"
                ).encode()
            )
            offset = list(NETWORKS).index(network_id) * 4
            self.responses[f"{HYPERLANE_REGISTRY_ROOT}/{key}/addresses.yaml"] = (
                (
                    f'mailbox: "0x{offset + 1:040x}"\n'
                    f'interchainSecurityModule: "0x{offset + 2:040x}"\n'
                    f'merkleTreeHook: "0x{offset + 3:040x}"\n'
                    f'interchainGasPaymaster: "0x{offset + 4:040x}"\n'
                ).encode()
            )
        layerzero: dict[str, object] = {}
        for index, (network_id, metadata) in enumerate(NETWORKS.items()):
            base = 100 + index * 4
            layerzero[network_id] = {
                "chainDetails": {"nativeChainId": metadata["chain_id"]},
                "deployments": [
                    {
                        "version": 2,
                        "stage": "testnet",
                        "eid": str(40_200 + index),
                        "endpointV2": {"address": f"0x{base + 1:040x}"},
                        "sendUln302": {"address": f"0x{base + 2:040x}"},
                        "receiveUln302": {"address": f"0x{base + 3:040x}"},
                        "executor": {"address": f"0x{base + 4:040x}"},
                    }
                ],
            }
        self.responses[LAYERZERO_DEPLOYMENTS_URL] = json.dumps(layerzero).encode()

    def fetch(self, url: str) -> bytes:
        return self.responses[url]


def _discovery() -> OfficialRegistryDiscovery:
    return discover_official_deployments(
        fetcher=FixtureFetcher(),
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
    )


def test_official_discovery_resolves_both_protocols_on_all_three_networks() -> None:
    discovery = _discovery()
    assert len(discovery.deployments) == 6
    assert len(discovery.discovery_sha256) == 64
    assert discovery.as_dict()["effects"] == {
        "signing_operations": 0,
        "deployments": 0,
        "configurations": 0,
        "broadcasts": 0,
    }

    route_keys = (
        ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
        ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
        ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
        ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
    )
    local = {key: f"0x{index + 201:040x}" for index, key in enumerate(route_keys)}
    remote = {key: f"0x{index + 211:040x}" for index, key in enumerate(route_keys)}
    candidates = build_registry_candidates(
        discovery=discovery,
        local_adapters=local,
        remote_peers=remote,
    )
    assert len(candidates) == 4
    assert candidates[0].local_adapter_address == local[route_keys[0]]
    assert candidates[0].peer_address == remote[route_keys[0]]


def test_registry_cannot_substitute_for_missing_planned_adapter_or_identity() -> None:
    discovery = _discovery()
    route = ("op-sepolia", "arbitrum-sepolia", "hyperlane")
    with pytest.raises(CarrierPreflightError, match="deployment plan"):
        build_registry_candidates(
            discovery=discovery,
            local_adapters={route: "0x" + "11" * 20},
            remote_peers={route: "0x" + "12" * 20},
        )
    deployments = list(discovery.deployments)
    deployments[0] = replace(deployments[0], chain_id=1)
    changed = replace(discovery, deployments=tuple(deployments))
    with pytest.raises(CarrierPreflightError, match="identity changed"):
        build_registry_candidates(
            discovery=changed,
            local_adapters={route: "0x" + "11" * 20},
            remote_peers={route: "0x" + "12" * 20},
        )


def test_official_discovery_freeze_is_expiring_and_content_addressed(
    tmp_path: Path,
) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    document, digest = freeze_official_discovery(
        _discovery(),
        validity_seconds=300,
        store=store,
    )
    assert document["valid_until"] == "2026-07-28T00:05:00+00:00"
    assert hashlib.sha256(store.read_raw(digest)).hexdigest() == digest
