"""Official carrier registry discovery for the fixed three-testnet route.

Registry documents are discovery inputs only.  Application adapter addresses
come from the separately frozen deployment plan and are never inferred from a
carrier registry.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import rfc8785
import yaml

from xir_lab.evidence.store import EvidenceStore
from xir_lab.preflight.carriers import (
    FIXED_CARRIER_ROUTES,
    CarrierPreflightError,
    ProtocolName,
    RegistryCandidate,
)

HYPERLANE_REGISTRY_ROOT = (
    "https://raw.githubusercontent.com/hyperlane-xyz/"
    "hyperlane-registry/main/chains"
)
LAYERZERO_DEPLOYMENTS_URL = (
    "https://metadata.layerzero-api.com/v1/metadata/deployments"
)

NETWORKS = {
    "op-sepolia": {
        "chain_id": 11_155_420,
        "hyperlane_key": "optimismsepolia",
    },
    "arbitrum-sepolia": {
        "chain_id": 421_614,
        "hyperlane_key": "arbitrumsepolia",
    },
    "base-sepolia": {
        "chain_id": 84_532,
        "hyperlane_key": "basesepolia",
    },
}


class RegistryFetcher(Protocol):
    def fetch(self, url: str) -> bytes:
        """Fetch one public official registry object."""


class HttpsRegistryFetcher:
    """Fetch only the exact official registry locations used by this lab."""

    def __init__(self, *, timeout_seconds: int = 20) -> None:
        self.timeout_seconds = timeout_seconds

    def fetch(self, url: str) -> bytes:
        allowed = url == LAYERZERO_DEPLOYMENTS_URL or url.startswith(
            HYPERLANE_REGISTRY_ROOT + "/"
        )
        if not allowed or not url.startswith("https://"):
            raise CarrierPreflightError("registry URL is outside the exact official allowlist")
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "xir-testnet-lab/0.1 registry-discovery"},
            )
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                body = cast(bytes, response.read())
        except (OSError, urllib.error.URLError) as exc:
            raise CarrierPreflightError("official registry fetch failed") from exc
        if not body:
            raise CarrierPreflightError("official registry response is empty")
        return body


@dataclass(frozen=True)
class OfficialDeployment:
    protocol: ProtocolName
    network_id: str
    chain_id: int
    local_selector: int
    endpoint_address: str
    security_addresses: tuple[tuple[str, str], ...]
    source_url: str
    source_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "local_selector": self.local_selector,
            "endpoint_address": self.endpoint_address,
            "security_addresses": dict(self.security_addresses),
            "source_url": self.source_url,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class OfficialRegistryDiscovery:
    observed_at: str
    deployments: tuple[OfficialDeployment, ...]
    discovery_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "xir-lab-carrier-discovery-v1",
            "observed_at": self.observed_at,
            "deployments": [item.as_dict() for item in self.deployments],
            "discovery_sha256": self.discovery_sha256,
            "effects": {
                "signing_operations": 0,
                "deployments": 0,
                "configurations": 0,
                "broadcasts": 0,
            },
        }


def _address(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise CarrierPreflightError(f"{label} is not an EVM address")
    try:
        valid = len(value) == 42 and value.startswith("0x") and int(value, 16) != 0
    except ValueError:
        valid = False
    if not valid:
        raise CarrierPreflightError(f"{label} is not a nonzero EVM address")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CarrierPreflightError(f"{label} is not an object")
    return cast(dict[str, Any], value)


def _hyperlane_deployment(
    *,
    network_id: str,
    metadata_raw: bytes,
    addresses_raw: bytes,
    metadata_url: str,
    addresses_url: str,
) -> OfficialDeployment:
    try:
        metadata = _mapping(yaml.safe_load(metadata_raw), "Hyperlane metadata")
        addresses = _mapping(yaml.safe_load(addresses_raw), "Hyperlane addresses")
    except yaml.YAMLError as exc:
        raise CarrierPreflightError("Hyperlane registry YAML is invalid") from exc
    expected = NETWORKS[network_id]
    chain_id = metadata.get("chainId")
    domain = metadata.get("domainId")
    if (
        chain_id != expected["chain_id"]
        or domain != expected["chain_id"]
        or metadata.get("protocol") != "ethereum"
        or metadata.get("isTestnet") is not True
    ):
        raise CarrierPreflightError("Hyperlane registry identity differs from fixed route")
    source_sha256 = hashlib.sha256(
        rfc8785.dumps(
            {
                "metadata": {
                    "url": metadata_url,
                    "sha256": hashlib.sha256(metadata_raw).hexdigest(),
                },
                "addresses": {
                    "url": addresses_url,
                    "sha256": hashlib.sha256(addresses_raw).hexdigest(),
                },
            }
        )
    ).hexdigest()
    return OfficialDeployment(
        protocol="hyperlane",
        network_id=network_id,
        chain_id=cast(int, chain_id),
        local_selector=cast(int, domain),
        endpoint_address=_address(addresses.get("mailbox"), "Hyperlane Mailbox"),
        security_addresses=tuple(
            sorted(
                {
                    "registryIsm": _address(
                        addresses.get("interchainSecurityModule"),
                        "Hyperlane registry ISM",
                    ),
                    "merkleTreeHook": _address(
                        addresses.get("merkleTreeHook"),
                        "Hyperlane Merkle tree hook",
                    ),
                    "interchainGasPaymaster": _address(
                        addresses.get("interchainGasPaymaster"),
                        "Hyperlane gas paymaster",
                    ),
                }.items()
            )
        ),
        source_url=addresses_url,
        source_sha256=source_sha256,
    )


def _layerzero_deployments(raw: bytes) -> tuple[OfficialDeployment, ...]:
    try:
        document = _mapping(json.loads(raw), "LayerZero deployments")
    except json.JSONDecodeError as exc:
        raise CarrierPreflightError("LayerZero registry JSON is invalid") from exc
    by_chain_id = {
        cast(int, _mapping(value, "LayerZero network").get("chainDetails", {}).get("nativeChainId")):
        _mapping(value, "LayerZero network")
        for value in document.values()
        if isinstance(value, dict)
        and isinstance(value.get("chainDetails"), dict)
        and isinstance(value["chainDetails"].get("nativeChainId"), int)
    }
    result: list[OfficialDeployment] = []
    source_sha256 = hashlib.sha256(raw).hexdigest()
    for network_id, expected in NETWORKS.items():
        network = by_chain_id.get(cast(int, expected["chain_id"]))
        if network is None:
            raise CarrierPreflightError("LayerZero registry lacks a fixed-route network")
        deployments = network.get("deployments")
        if not isinstance(deployments, list):
            raise CarrierPreflightError("LayerZero deployments list is invalid")
        matches = [
            _mapping(item, "LayerZero deployment")
            for item in deployments
            if isinstance(item, dict)
            and item.get("version") == 2
            and item.get("stage") == "testnet"
        ]
        if len(matches) != 1:
            raise CarrierPreflightError("LayerZero V2 testnet deployment is ambiguous")
        deployment = matches[0]
        endpoint = _mapping(deployment.get("endpointV2"), "LayerZero Endpoint V2")
        send = _mapping(deployment.get("sendUln302"), "LayerZero send ULN")
        receive = _mapping(deployment.get("receiveUln302"), "LayerZero receive ULN")
        executor = _mapping(deployment.get("executor"), "LayerZero executor")
        try:
            eid = int(cast(str, deployment["eid"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise CarrierPreflightError("LayerZero EID is invalid") from exc
        result.append(
            OfficialDeployment(
                protocol="layerzero-v2",
                network_id=network_id,
                chain_id=cast(int, expected["chain_id"]),
                local_selector=eid,
                endpoint_address=_address(
                    endpoint.get("address"), "LayerZero Endpoint V2"
                ),
                security_addresses=tuple(
                    sorted(
                        {
                            "sendUln302": _address(
                                send.get("address"), "LayerZero send ULN"
                            ),
                            "receiveUln302": _address(
                                receive.get("address"), "LayerZero receive ULN"
                            ),
                            "executor": _address(
                                executor.get("address"), "LayerZero executor"
                            ),
                        }.items()
                    )
                ),
                source_url=LAYERZERO_DEPLOYMENTS_URL,
                source_sha256=source_sha256,
            )
        )
    return tuple(result)


def discover_official_deployments(
    *,
    fetcher: RegistryFetcher,
    observed_at: datetime,
) -> OfficialRegistryDiscovery:
    """Resolve all current official deployment candidates with attributable bytes."""

    deployments: list[OfficialDeployment] = []
    for network_id, expected in NETWORKS.items():
        key = expected["hyperlane_key"]
        metadata_url = f"{HYPERLANE_REGISTRY_ROOT}/{key}/metadata.yaml"
        addresses_url = f"{HYPERLANE_REGISTRY_ROOT}/{key}/addresses.yaml"
        deployments.append(
            _hyperlane_deployment(
                network_id=network_id,
                metadata_raw=fetcher.fetch(metadata_url),
                addresses_raw=fetcher.fetch(addresses_url),
                metadata_url=metadata_url,
                addresses_url=addresses_url,
            )
        )
    deployments.extend(_layerzero_deployments(fetcher.fetch(LAYERZERO_DEPLOYMENTS_URL)))
    ordered = tuple(
        sorted(deployments, key=lambda item: (item.network_id, item.protocol))
    )
    expected_keys = {
        (network_id, protocol)
        for network_id in NETWORKS
        for protocol in ("hyperlane", "layerzero-v2")
    }
    if {(item.network_id, item.protocol) for item in ordered} != expected_keys:
        raise CarrierPreflightError("official discovery lacks complete carrier coverage")
    body = [item.as_dict() for item in ordered]
    return OfficialRegistryDiscovery(
        observed_at=observed_at.astimezone(UTC).isoformat(),
        deployments=ordered,
        discovery_sha256=hashlib.sha256(rfc8785.dumps(body)).hexdigest(),
    )


def validate_official_discovery(
    discovery: OfficialRegistryDiscovery,
) -> OfficialRegistryDiscovery:
    expected_keys = {
        (network_id, protocol)
        for network_id in NETWORKS
        for protocol in ("hyperlane", "layerzero-v2")
    }
    if (
        len(discovery.deployments) != 6
        or {(item.network_id, item.protocol) for item in discovery.deployments}
        != expected_keys
    ):
        raise CarrierPreflightError("official discovery lacks complete carrier coverage")
    for deployment in discovery.deployments:
        expected_chain = NETWORKS[deployment.network_id]["chain_id"]
        if deployment.chain_id != expected_chain or deployment.local_selector <= 0:
            raise CarrierPreflightError("official discovery network identity changed")
        _address(deployment.endpoint_address, "carrier endpoint")
        for label, address in deployment.security_addresses:
            _address(address, label)
    body = [
        item.as_dict()
        for item in sorted(
            discovery.deployments, key=lambda item: (item.network_id, item.protocol)
        )
    ]
    if hashlib.sha256(rfc8785.dumps(body)).hexdigest() != discovery.discovery_sha256:
        raise CarrierPreflightError("official discovery digest mismatch")
    return discovery


def freeze_official_discovery(
    discovery: OfficialRegistryDiscovery,
    *,
    validity_seconds: int,
    store: EvidenceStore | None = None,
) -> tuple[dict[str, Any], str]:
    validate_official_discovery(discovery)
    if validity_seconds <= 0:
        raise CarrierPreflightError("official discovery validity must be positive")
    try:
        observed_at = datetime.fromisoformat(discovery.observed_at).astimezone(UTC)
    except ValueError as exc:
        raise CarrierPreflightError("official discovery observation time is invalid") from exc
    document = discovery.as_dict()
    document["valid_until"] = datetime.fromtimestamp(
        observed_at.timestamp() + validity_seconds,
        tz=UTC,
    ).isoformat()
    raw = rfc8785.dumps(document)
    digest = hashlib.sha256(raw).hexdigest()
    if store is not None:
        stored = store.put_raw(
            raw,
            media_type="application/json",
            metadata={
                "kind": "carrier-official-discovery",
                "public_facts_only": True,
            },
        )
        if stored != digest:
            raise CarrierPreflightError("official discovery digest changed during storage")
    return document, digest


def build_registry_candidates(
    *,
    discovery: OfficialRegistryDiscovery,
    local_adapters: dict[tuple[str, str, str], str],
    remote_peers: dict[tuple[str, str, str], str],
) -> tuple[RegistryCandidate, ...]:
    """Join official endpoints with separately planned local/remote adapters."""

    validate_official_discovery(discovery)
    deployments = {
        (item.network_id, item.protocol): item for item in discovery.deployments
    }
    candidates: list[RegistryCandidate] = []
    for local, remote, protocol_raw in FIXED_CARRIER_ROUTES:
        protocol = cast(ProtocolName, protocol_raw)
        key = (local, remote, protocol)
        try:
            local_deployment = deployments[(local, protocol)]
            remote_deployment = deployments[(remote, protocol)]
            local_adapter = local_adapters[key]
            remote_peer = remote_peers[key]
        except KeyError as exc:
            raise CarrierPreflightError(
                "deployment plan lacks a fixed-route adapter address"
            ) from exc
        candidates.append(
            RegistryCandidate(
                protocol=protocol,
                local_network=local,
                remote_network=remote,
                endpoint_address=local_deployment.endpoint_address,
                remote_selector=remote_deployment.local_selector,
                peer_address=remote_peer,
                local_adapter_address=local_adapter,
                source_url=local_deployment.source_url,
                source_sha256=local_deployment.source_sha256,
            )
        )
    return tuple(candidates)
