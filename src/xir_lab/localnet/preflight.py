"""Read-only host and optional twelve-node health preflight."""

from __future__ import annotations

import json
import os
import shutil
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from xir_lab.localnet.topology import (
    LocalIdentityManifest,
    LocalTopology,
    LocalTopologyError,
    ResourceThresholds,
)

PreflightMode = Literal["render", "smoke", "scale"]


@dataclass(frozen=True)
class HostSnapshot:
    logical_cpus: int
    memory_bytes: int
    disk_available_bytes: int
    storage_filesystem_path: str

    @classmethod
    def collect(cls, path: Path) -> HostSnapshot:
        memory_bytes = 0
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    memory_bytes = int(line.split()[1]) * 1024
                    break
        except OSError:
            memory_bytes = 0
        return cls(
            logical_cpus=os.cpu_count() or 0,
            memory_bytes=memory_bytes,
            disk_available_bytes=shutil.disk_usage(path).free,
            storage_filesystem_path=str(path.resolve()),
        )


@dataclass(frozen=True)
class NodeObservation:
    network_id: str
    validator_id: str
    chain_id: int
    reachable: bool
    peer_count: int
    head_block: int
    checkpoint_block: int
    checkpoint_hash: str
    block_advanced: bool


class LocalHealthError(LocalTopologyError):
    """Raised when a private local validator RPC cannot be observed."""


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Host": "localhost",
            "User-Agent": "xir-local-scale-health/0.1",
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=5) as response:
            document = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalHealthError(f"local validator RPC failed: {url} {method}") from exc
    if not isinstance(document, dict) or "result" not in document:
        raise LocalHealthError(f"local validator RPC returned no result: {url} {method}")
    return document["result"]


def collect_node_observations(
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
    wait_seconds: float | None = None,
) -> tuple[NodeObservation, ...]:
    """Collect private-bridge RPC agreement without using public endpoints."""

    endpoints: list[tuple[str, str, int, str]] = []
    network_map = {item.network_id: item for item in topology.networks}
    for identity in manifest.networks:
        network = network_map[identity.network_id]
        subnet_prefix = network.subnet.removesuffix("0/24")
        for validator in identity.validators:
            ip_address = validator.enode.rsplit("@", 1)[1].split(":", 1)[0]
            if not ip_address.startswith(subnet_prefix):
                raise LocalHealthError("validator enode escaped its private topology subnet")
            endpoints.append(
                (
                    identity.network_id,
                    validator.validator_id,
                    identity.chain_id,
                    f"http://{ip_address}:8545",
                )
            )
    first_heads = {
        (network_id, validator_id): int(_rpc(url, "eth_blockNumber", []), 16)
        for network_id, validator_id, _, url in endpoints
    }
    delay = wait_seconds
    if delay is None:
        delay = float(max(item.block_period_seconds for item in topology.networks) + 1)
    if delay > 0:
        time.sleep(delay)
    raw: list[dict[str, Any]] = []
    for network_id, validator_id, expected_chain_id, url in endpoints:
        chain_id = int(_rpc(url, "eth_chainId", []), 16)
        peer_count = int(_rpc(url, "net_peerCount", []), 16)
        head_block = int(_rpc(url, "eth_blockNumber", []), 16)
        raw.append(
            {
                "network_id": network_id,
                "validator_id": validator_id,
                "expected_chain_id": expected_chain_id,
                "chain_id": chain_id,
                "peer_count": peer_count,
                "head_block": head_block,
                "url": url,
            }
        )
    observations: list[NodeObservation] = []
    for network in topology.networks:
        rows = [item for item in raw if item["network_id"] == network.network_id]
        checkpoint = min(int(item["head_block"]) for item in rows)
        for item in rows:
            block = _rpc(
                str(item["url"]),
                "eth_getBlockByNumber",
                [hex(checkpoint), False],
            )
            if not isinstance(block, dict) or not isinstance(block.get("hash"), str):
                raise LocalHealthError("local validator returned an invalid checkpoint block")
            key = (str(item["network_id"]), str(item["validator_id"]))
            observations.append(
                NodeObservation(
                    network_id=key[0],
                    validator_id=key[1],
                    chain_id=int(item["chain_id"]),
                    reachable=True,
                    peer_count=int(item["peer_count"]),
                    head_block=int(item["head_block"]),
                    checkpoint_block=checkpoint,
                    checkpoint_hash=str(block["hash"]),
                    block_advanced=int(item["head_block"]) > first_heads[key],
                )
            )
    return tuple(observations)


def _check(
    check_id: str,
    observed: Any,
    required: Any,
    passed: bool,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "status": "pass" if passed else "fail",
        "observed": observed,
        "required": required,
        "reason_code": "ok" if passed else reason_code,
    }


def _threshold(topology: LocalTopology, mode: PreflightMode) -> ResourceThresholds:
    return {
        "render": topology.resource_policy.render,
        "smoke": topology.resource_policy.smoke,
        "scale": topology.resource_policy.scale,
    }[mode]


def build_local_preflight(
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest | None,
    mode: PreflightMode,
    host: HostSnapshot,
    observations: tuple[NodeObservation, ...] = (),
) -> dict[str, Any]:
    """Build a zero-container-start preflight report."""

    threshold = _threshold(topology, mode)
    checks = [
        _check(
            "logical_cpus",
            host.logical_cpus,
            threshold.minimum_logical_cpus,
            host.logical_cpus >= threshold.minimum_logical_cpus,
            "insufficient_logical_cpus",
        ),
        _check(
            "memory_bytes",
            host.memory_bytes,
            threshold.minimum_memory_bytes,
            host.memory_bytes >= threshold.minimum_memory_bytes,
            "insufficient_memory",
        ),
        _check(
            "disk_available_bytes",
            host.disk_available_bytes,
            threshold.minimum_disk_available_bytes,
            host.disk_available_bytes >= threshold.minimum_disk_available_bytes,
            "insufficient_disk",
        ),
        _check(
            "identity_manifest",
            manifest is not None,
            True,
            manifest is not None,
            "identity_manifest_required",
        ),
    ]
    if mode != "render":
        expected = {
            (network.network_id, f"v{index}")
            for network in topology.networks
            for index in range(1, 5)
        }
        observed_ids = {
            (item.network_id, item.validator_id) for item in observations
        }
        checks.append(
            _check(
                "twelve_node_observations",
                len(observed_ids),
                12,
                observed_ids == expected,
                "node_observations_incomplete",
            )
        )
        network_map = {item.network_id: item for item in topology.networks}
        for network in topology.networks:
            items = [item for item in observations if item.network_id == network.network_id]
            checks.extend(
                (
                    _check(
                        f"{network.network_id}:reachable",
                        sum(item.reachable for item in items),
                        4,
                        len(items) == 4 and all(item.reachable for item in items),
                        "validator_unreachable",
                    ),
                    _check(
                        f"{network.network_id}:chain_id",
                        sorted({item.chain_id for item in items}),
                        [network.chain_id],
                        len(items) == 4
                        and {item.chain_id for item in items} == {network.chain_id},
                        "chain_id_mismatch",
                    ),
                    _check(
                        f"{network.network_id}:peer_count",
                        min((item.peer_count for item in items), default=-1),
                        3,
                        len(items) == 4 and all(item.peer_count >= 3 for item in items),
                        "peer_count_insufficient",
                    ),
                    _check(
                        f"{network.network_id}:block_progress",
                        sum(item.block_advanced for item in items),
                        4,
                        len(items) == 4 and all(item.block_advanced for item in items),
                        "block_progress_missing",
                    ),
                    _check(
                        f"{network.network_id}:checkpoint_agreement",
                        sorted({item.checkpoint_hash for item in items}),
                        "one common hash",
                        len(items) == 4
                        and len({item.checkpoint_block for item in items}) == 1
                        and len({item.checkpoint_hash for item in items}) == 1,
                        "checkpoint_disagreement",
                    ),
                )
            )
        unknown = sorted(
            {
                item.network_id
                for item in observations
                if item.network_id not in network_map
            }
        )
        checks.append(
            _check(
                "unknown_networks",
                unknown,
                [],
                not unknown,
                "unknown_network_observation",
            )
        )
    return {
        "schema_version": "xir-lab-local-preflight-v1",
        "mode": mode,
        "topology_sha256": topology.source_sha256,
        "identity_manifest_sha256": (
            manifest.payload_sha256 if manifest is not None else None
        ),
        "eligible": all(item["status"] == "pass" for item in checks),
        "checks": checks,
        "effects": {
            "public_network_calls": 0,
            "public_signatures": 0,
            "public_broadcasts": 0,
            "containers_started": 0,
        },
        "host": asdict(host),
    }
