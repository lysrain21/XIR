"""Repository-external initialization for local QBFT identities."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from eth_utils import keccak, to_checksum_address  # type: ignore[attr-defined]
from rlp import encode as rlp_encode  # type: ignore[import-untyped]

from xir_lab.localnet.topology import LocalTopology


class LocalIdentityError(RuntimeError):
    """Raised when local private material cannot be created safely."""


@dataclass(frozen=True)
class _GeneratedKey:
    private_bytes: bytes
    public_bytes: bytes
    address: str


def _private_key() -> _GeneratedKey:
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_value = private_key.private_numbers().private_value.to_bytes(32, "big")
    uncompressed = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    public_bytes = uncompressed[1:]
    return _GeneratedKey(
        private_bytes=private_value,
        public_bytes=public_bytes,
        address=str(to_checksum_address(keccak(public_bytes)[-20:])),
    )


def _write_private(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value)
    path.chmod(0o600)


def _genesis(
    *,
    chain_id: int,
    gas_limit: str,
    block_period_seconds: int,
    request_timeout_seconds: int,
    validator_addresses: list[str],
    funded_addresses: Sequence[str],
) -> dict[str, Any]:
    extra_data = "0x" + rlp_encode(
        [
            bytes(32),
            [bytes.fromhex(address.removeprefix("0x")) for address in validator_addresses],
            [],
            0,
            [],
        ]
    ).hex()
    return {
        "config": {
            "chainId": chain_id,
            "londonBlock": 0,
            "zeroBaseFee": True,
            "qbft": {
                "blockperiodseconds": block_period_seconds,
                "epochlength": 30000,
                "requesttimeoutseconds": request_timeout_seconds,
            },
        },
        "nonce": "0x0",
        "timestamp": "0x0",
        "extraData": extra_data,
        "gasLimit": gas_limit,
        "difficulty": "0x1",
        "mixHash": "0x63746963616c2062797a616e74696e65207768616c6521000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {
            address.removeprefix("0x").lower(): {
                "balance": "0x204fce5e3e25026110000000"
            }
            for address in funded_addresses
        },
    }


def initialize_local_identities(
    topology: LocalTopology,
    *,
    runtime_root: Path,
    repository_root: Path,
    created_at: datetime | None = None,
) -> Path:
    """Create fresh local-only keys and freeze their public manifest."""

    resolved_runtime = runtime_root.resolve()
    resolved_repository = repository_root.resolve()
    if resolved_runtime == resolved_repository or resolved_repository in resolved_runtime.parents:
        raise LocalIdentityError("local identity runtime root must stay outside the repository")
    if resolved_runtime.exists() and any(resolved_runtime.iterdir()):
        raise LocalIdentityError("local identity runtime root must be empty")
    resolved_runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_runtime.chmod(0o700)

    deployer_key = _private_key()
    runner_key = _private_key()
    _write_private(
        resolved_runtime / "private" / "accounts" / "deployer.key",
        deployer_key.private_bytes.hex().encode("ascii"),
    )
    _write_private(
        resolved_runtime / "private" / "accounts" / "runner.key",
        runner_key.private_bytes.hex().encode("ascii"),
    )
    funded_addresses = [
        deployer_key.address,
        runner_key.address,
    ]

    manifest_networks: list[dict[str, Any]] = []
    for network in topology.networks:
        subnet = ipaddress.ip_network(network.subnet)
        validator_rows: list[dict[str, Any]] = []
        validator_addresses: list[str] = []
        for index in range(1, network.validator_count + 1):
            private_key = _private_key()
            public_key = private_key.public_bytes.hex()
            address = private_key.address
            relative_key = (
                Path("private")
                / "validators"
                / network.network_id
                / f"v{index}"
                / "key"
            )
            _write_private(
                resolved_runtime / relative_key,
                private_key.private_bytes.hex().encode("ascii"),
            )
            ip_address = str(subnet.network_address + 10 + index)
            validator_rows.append(
                {
                    "validator_id": f"v{index}",
                    "address": address,
                    "public_key": public_key,
                    "enode": f"enode://{public_key}@{ip_address}:30303",
                    "private_key_path": relative_key.as_posix(),
                }
            )
            validator_addresses.append(address)
            data_path = (
                resolved_runtime
                / "data"
                / network.network_id
                / f"v{index}"
            )
            data_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            data_path.chmod(0o700)
        genesis = _genesis(
            chain_id=network.chain_id,
            gas_limit=network.gas_limit,
            block_period_seconds=network.block_period_seconds,
            request_timeout_seconds=network.request_timeout_seconds,
            validator_addresses=validator_addresses,
            funded_addresses=funded_addresses,
        )
        genesis_bytes = rfc8785.dumps(genesis) + b"\n"
        relative_genesis = Path("networks") / network.network_id / "genesis.json"
        genesis_path = resolved_runtime / relative_genesis
        genesis_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        genesis_path.write_bytes(genesis_bytes)
        manifest_networks.append(
            {
                "network_id": network.network_id,
                "chain_id": network.chain_id,
                "genesis_path": relative_genesis.as_posix(),
                "genesis_sha256": hashlib.sha256(genesis_bytes).hexdigest(),
                "validators": validator_rows,
            }
        )
    payload = {
        "domain": "xir-lab-local-identity-manifest-v1",
        "topology_sha256": topology.source_sha256,
        "created_at": (created_at or datetime.now(UTC)).astimezone(UTC).isoformat(),
        "development_only": True,
        "accounts": {
            "deployer": funded_addresses[0],
            "runner": funded_addresses[1],
        },
        "networks": manifest_networks,
    }
    document = {
        "schema_version": "xir-lab-local-identity-manifest-v1",
        "payload_sha256": hashlib.sha256(
            rfc8785.dumps(payload)  # type: ignore[arg-type]
        ).hexdigest(),
        "payload": payload,
    }
    manifest_path = resolved_runtime / "identity-manifest.json"
    manifest_path.write_bytes(
        rfc8785.dumps(document) + b"\n"  # type: ignore[arg-type]
    )
    os.chmod(manifest_path, 0o644)
    return manifest_path
