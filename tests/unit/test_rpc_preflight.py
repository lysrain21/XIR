from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from xir_lab.config.loaders import load_lab_config
from xir_lab.evidence.store import EvidenceStore
from xir_lab.preflight.rpc import (
    EndpointPair,
    ReadOnlyRpcGuard,
    RpcPreflightError,
    RpcReferenceResolver,
    collect_rpc_preflight,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tests" / "fixtures" / "config" / "lab-config.json"
SCHEMA = ROOT / "schemas" / "lab-config-v1.schema.json"
OBSERVED_AT = datetime(2026, 7, 28, 12, tzinfo=UTC)


class FixtureRpc:
    def __init__(
        self,
        *,
        chain_id: int,
        checkpoint_number: int,
        checkpoint_hash: str,
        latest_timestamp: int,
        balance: int = 100_000,
        confirmed_nonce: int = 4,
        pending_nonce: int = 4,
        archive: bool = True,
    ) -> None:
        self.chain_id = chain_id
        self.checkpoint_number = checkpoint_number
        self.checkpoint_hash = checkpoint_hash
        self.latest_timestamp = latest_timestamp
        self.balance = balance
        self.confirmed_nonce = confirmed_nonce
        self.pending_nonce = pending_nonce
        self.archive = archive
        self.methods: list[str] = []

    def call(self, method: str, params: list[Any]) -> Any:
        self.methods.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            if params[0] == "latest":
                return {
                    "number": hex(self.checkpoint_number + 100),
                    "hash": "0x" + "ab" * 32,
                    "timestamp": hex(self.latest_timestamp),
                    "baseFeePerGas": hex(10),
                }
            return {
                "number": params[0],
                "hash": self.checkpoint_hash,
                "timestamp": hex(self.latest_timestamp - 100),
                "baseFeePerGas": hex(9),
            }
        if method == "eth_gasPrice":
            return hex(12)
        if method == "eth_maxPriorityFeePerGas":
            return hex(2)
        if method == "eth_getBalance":
            if params[1] != "latest" and not self.archive:
                raise ConnectionError("fixture archive unavailable")
            return hex(self.balance)
        if method == "eth_getTransactionCount":
            return hex(self.pending_nonce if params[1] == "pending" else self.confirmed_nonce)
        raise AssertionError(f"unexpected method: {method}")


def _endpoints(
    *,
    latest_timestamp: int | None = None,
) -> dict[str, EndpointPair]:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    timestamp = latest_timestamp or int(OBSERVED_AT.timestamp()) - 5
    return {
        network.network_id: EndpointPair(
            read=FixtureRpc(
                chain_id=network.chain_id,
                checkpoint_number=network.checkpoint.block_number,
                checkpoint_hash=network.checkpoint.block_hash,
                latest_timestamp=timestamp,
            ),
            write=FixtureRpc(
                chain_id=network.chain_id,
                checkpoint_number=network.checkpoint.block_number,
                checkpoint_hash=network.checkpoint.block_hash,
                latest_timestamp=timestamp,
            ),
        )
        for network in config.networks
    }


def test_read_only_guard_rejects_every_write_method() -> None:
    client = FixtureRpc(
        chain_id=1,
        checkpoint_number=1,
        checkpoint_hash="0x" + "11" * 32,
        latest_timestamp=1,
    )
    guarded = ReadOnlyRpcGuard(client)
    with pytest.raises(RpcPreflightError, match="read-only"):
        guarded.call("eth_sendRawTransaction", ["0x00"])
    assert client.methods == []


def test_external_rpc_reference_file_permissions_and_location(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    external = tmp_path / "custody" / "rpc-references.json"
    external.parent.mkdir()
    authenticated = "https://" + "user:token@" + "example.test"
    external.write_text(json.dumps({"rpc.op.read": authenticated}))
    os.chmod(external, 0o600)
    resolver = RpcReferenceResolver(external, forbidden_roots=(checkout,))
    assert isinstance(resolver.resolve("rpc.op.read"), ReadOnlyRpcGuard)

    os.chmod(external, 0o644)
    with pytest.raises(RpcPreflightError, match="permissions"):
        RpcReferenceResolver(external, forbidden_roots=(checkout,))
    inside = checkout / "rpc.json"
    inside.write_text("{}")
    os.chmod(inside, 0o600)
    with pytest.raises(RpcPreflightError, match="outside"):
        RpcReferenceResolver(inside, forbidden_roots=(checkout,))


def test_complete_rpc_suite_is_schema_valid_content_addressed_and_zero_write(
    tmp_path: Path,
) -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    suite, digest = collect_rpc_preflight(
        config=config,
        endpoints=_endpoints(),
        observed_at=OBSERVED_AT,
        maximum_block_age_seconds=30,
        store=store,
    )
    assert suite.outcome == "pass"
    assert digest is not None
    assert store.read_raw(digest) == __import__("rfc8785").dumps(suite.as_dict())
    assert set(suite.effects.values()) == {0}


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ("wrong_chain", "chain_id_mismatch"),
        ("stale", "stale_or_future_block"),
        ("disagreement", "read_write_disagreement"),
        ("no_archive", "archive_view_unavailable"),
        ("nonce", "pending_nonce_conflict"),
        ("balance", "balance_below_floor"),
    ),
)
def test_wrong_network_stale_archive_nonce_balance_and_disagreement_block(
    change: str,
    reason: str,
) -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    endpoints = _endpoints(
        latest_timestamp=(
            int(OBSERVED_AT.timestamp()) - 3600
            if change == "stale"
            else None
        )
    )
    first = endpoints["op-sepolia"]
    read = first.read
    write = first.write
    assert isinstance(read, FixtureRpc)
    assert isinstance(write, FixtureRpc)
    if change == "wrong_chain":
        read.chain_id = 1
    elif change == "disagreement":
        write.checkpoint_hash = "0x" + "ff" * 32
    elif change == "no_archive":
        read.archive = False
    elif change == "nonce":
        read.pending_nonce += 1
    elif change == "balance":
        read.balance = 0

    suite, _ = collect_rpc_preflight(
        config=config,
        endpoints=endpoints,
        observed_at=OBSERVED_AT,
        maximum_block_age_seconds=30,
    )
    assert suite.outcome == "blocked"
    assert reason in suite.observations[0].reason_codes
    assert all(
        method != "eth_sendRawTransaction"
        for endpoint in endpoints.values()
        for client in (endpoint.read, endpoint.write)
        for method in cast(FixtureRpc, client).methods
    )
