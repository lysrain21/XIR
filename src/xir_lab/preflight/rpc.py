"""Credential-isolated, read-only JSON-RPC collection for the fixed testnet route."""

from __future__ import annotations

import hashlib
import json
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import jsonschema
import rfc8785

from xir_lab.config.loaders import EXPECTED_NETWORKS, LabConfig, Network
from xir_lab.evidence.store import EvidenceStore

READ_ONLY_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_getBalance",
        "eth_getBlockByNumber",
        "eth_getTransactionCount",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
    }
)


class RpcPreflightError(RuntimeError):
    """Raised when an RPC reference or required public fact is unsafe or unknown."""


class RpcClient(Protocol):
    def call(self, method: str, params: list[Any]) -> Any:
        """Perform one JSON-RPC call."""


@dataclass(frozen=True)
class EndpointPair:
    read: RpcClient
    write: RpcClient


@dataclass(frozen=True)
class AccountObservation:
    role: str
    address: str
    balance_wei: int | None
    confirmed_nonce: int | None
    pending_nonce: int | None
    minimum_balance_wei: int
    status: str
    reason_code: str


@dataclass(frozen=True)
class NetworkRpcObservation:
    network_id: str
    chain_id: int | None
    expected_chain_id: int
    latest_block_number: int | None
    latest_block_hash: str | None
    latest_block_timestamp: int | None
    checkpoint_block_number: int
    checkpoint_hash: str | None
    write_checkpoint_hash: str | None
    base_fee_per_gas_wei: int | None
    gas_price_wei: int | None
    max_priority_fee_per_gas_wei: int | None
    archive_capable: bool | None
    read_write_agree: bool | None
    block_age_seconds: int | None
    accounts: tuple[AccountObservation, ...]
    status: str
    reason_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "network_id": self.network_id,
            "chain_id": self.chain_id,
            "expected_chain_id": self.expected_chain_id,
            "latest_block_number": self.latest_block_number,
            "latest_block_hash": self.latest_block_hash,
            "latest_block_timestamp": self.latest_block_timestamp,
            "checkpoint_block_number": self.checkpoint_block_number,
            "checkpoint_hash": self.checkpoint_hash,
            "write_checkpoint_hash": self.write_checkpoint_hash,
            "base_fee_per_gas_wei": self.base_fee_per_gas_wei,
            "gas_price_wei": self.gas_price_wei,
            "max_priority_fee_per_gas_wei": self.max_priority_fee_per_gas_wei,
            "archive_capable": self.archive_capable,
            "read_write_agree": self.read_write_agree,
            "block_age_seconds": self.block_age_seconds,
            "accounts": [
                {
                    "role": item.role,
                    "address": item.address,
                    "balance_wei": item.balance_wei,
                    "confirmed_nonce": item.confirmed_nonce,
                    "pending_nonce": item.pending_nonce,
                    "minimum_balance_wei": item.minimum_balance_wei,
                    "status": item.status,
                    "reason_code": item.reason_code,
                }
                for item in self.accounts
            ],
            "status": self.status,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class RpcPreflightSuite:
    observed_at: str
    maximum_block_age_seconds: int
    observations: tuple[NetworkRpcObservation, ...]
    outcome: str
    effects: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "xir-lab-rpc-preflight-v1",
            "observed_at": self.observed_at,
            "maximum_block_age_seconds": self.maximum_block_age_seconds,
            "observations": [item.as_dict() for item in self.observations],
            "outcome": self.outcome,
            "effects": self.effects,
        }


class ReadOnlyRpcGuard:
    """Reject every method that could write public state."""

    def __init__(self, client: RpcClient) -> None:
        self.client = client

    def call(self, method: str, params: list[Any]) -> Any:
        if method not in READ_ONLY_METHODS:
            raise RpcPreflightError("JSON-RPC method is outside read-only allowlist")
        return self.client.call(method, params)


class HttpJsonRpcClient:
    """Small JSON-RPC client whose errors never include its endpoint URL."""

    def __init__(self, endpoint: str, *, timeout_seconds: int = 20) -> None:
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds

    def call(self, method: str, params: list[Any]) -> Any:
        request = urllib.request.Request(
            self._endpoint,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": method,
                    "params": params,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds
            ) as response:
                document = json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RpcPreflightError("RPC request failed") from exc
        if not isinstance(document, dict) or "error" in document or "result" not in document:
            raise RpcPreflightError("RPC returned an invalid or error response")
        return document["result"]


class RpcReferenceResolver:
    """Resolve URL-bearing references only from a restrictive external file."""

    def __init__(
        self,
        reference_file: Path,
        *,
        forbidden_roots: tuple[Path, ...],
    ) -> None:
        self.reference_file = reference_file
        resolved = reference_file.resolve()
        for root in forbidden_roots:
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                continue
            raise RpcPreflightError("RPC reference file must remain outside forbidden roots")
        try:
            mode = stat.S_IMODE(reference_file.stat().st_mode)
        except OSError as exc:
            raise RpcPreflightError("RPC reference file is unavailable") from exc
        if mode & 0o077:
            raise RpcPreflightError("RPC reference file permissions must exclude group/other")
        try:
            document = json.loads(reference_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RpcPreflightError("RPC reference file is invalid") from exc
        if not isinstance(document, dict):
            raise RpcPreflightError("RPC reference file root must be an object")
        self._references = cast(dict[str, Any], document)

    def resolve(self, reference: str) -> ReadOnlyRpcGuard:
        if not reference or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in reference):
            raise RpcPreflightError("RPC reference name is invalid")
        endpoint = self._references.get(reference)
        if not isinstance(endpoint, str):
            raise RpcPreflightError("RPC reference is missing")
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None or parsed.fragment:
            raise RpcPreflightError("RPC reference does not resolve to an HTTP endpoint")
        return ReadOnlyRpcGuard(HttpJsonRpcClient(endpoint))


def _quantity(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RpcPreflightError(f"{label} is not a JSON-RPC quantity")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise RpcPreflightError(f"{label} is not hexadecimal") from exc
    if parsed < 0:
        raise RpcPreflightError(f"{label} is negative")
    return parsed


def _block(client: RpcClient, tag: str) -> dict[str, Any]:
    value = client.call("eth_getBlockByNumber", [tag, False])
    if not isinstance(value, dict):
        raise RpcPreflightError("required block is unavailable")
    return cast(dict[str, Any], value)


def _account(
    *,
    client: RpcClient,
    role: str,
    address: str,
    minimum_balance_wei: int,
) -> AccountObservation:
    try:
        balance = _quantity(
            client.call("eth_getBalance", [address, "latest"]),
            "balance",
        )
        confirmed = _quantity(
            client.call("eth_getTransactionCount", [address, "latest"]),
            "confirmed nonce",
        )
        pending = _quantity(
            client.call("eth_getTransactionCount", [address, "pending"]),
            "pending nonce",
        )
    except Exception:
        return AccountObservation(
            role, address, None, None, None, minimum_balance_wei,
            "unknown", "account_fact_unavailable",
        )
    if pending != confirmed:
        status, reason = "fail", "pending_nonce_conflict"
    elif balance < minimum_balance_wei:
        status, reason = "fail", "balance_below_floor"
    else:
        status, reason = "pass", "account_ready"
    return AccountObservation(
        role, address, balance, confirmed, pending, minimum_balance_wei,
        status, reason,
    )


def probe_network(
    *,
    network: Network,
    endpoints: EndpointPair,
    deployer_address: str,
    runner_address: str,
    deployer_balance_floor_wei: int,
    runner_balance_floor_wei: int,
    observed_at: datetime,
    maximum_block_age_seconds: int,
) -> NetworkRpcObservation:
    """Collect one network's required read facts and fail closed on unknowns."""

    read = ReadOnlyRpcGuard(endpoints.read)
    write = ReadOnlyRpcGuard(endpoints.write)
    reasons: list[str] = []
    accounts: tuple[AccountObservation, ...] = ()
    chain_id: int | None = None
    latest_number: int | None = None
    latest_hash: str | None = None
    latest_timestamp: int | None = None
    checkpoint_hash: str | None = None
    write_checkpoint_hash: str | None = None
    base_fee: int | None = None
    gas_price: int | None = None
    priority_fee: int | None = None
    archive_capable: bool | None = None
    agreement: bool | None = None
    age: int | None = None
    expected_chain_id = EXPECTED_NETWORKS[network.network_id][0]
    try:
        chain_id = _quantity(read.call("eth_chainId", []), "chain ID")
        write_chain_id = _quantity(write.call("eth_chainId", []), "write chain ID")
        if chain_id != expected_chain_id or write_chain_id != expected_chain_id:
            reasons.append("chain_id_mismatch")
        latest = _block(read, "latest")
        latest_number = _quantity(latest.get("number"), "latest block number")
        latest_timestamp = _quantity(latest.get("timestamp"), "latest block timestamp")
        latest_hash = cast(str | None, latest.get("hash"))
        if latest_hash is None:
            reasons.append("latest_block_hash_unknown")
        age = int(observed_at.astimezone(UTC).timestamp()) - latest_timestamp
        if age < 0 or age > maximum_block_age_seconds:
            reasons.append("stale_or_future_block")
        checkpoint_tag = hex(network.checkpoint.block_number)
        checkpoint_hash = cast(str | None, _block(read, checkpoint_tag).get("hash"))
        write_checkpoint_hash = cast(str | None, _block(write, checkpoint_tag).get("hash"))
        agreement = (
            checkpoint_hash is not None
            and write_checkpoint_hash is not None
            and checkpoint_hash.lower() == write_checkpoint_hash.lower()
        )
        if checkpoint_hash is None or checkpoint_hash.lower() != network.checkpoint.block_hash.lower():
            reasons.append("checkpoint_mismatch")
        if not agreement:
            reasons.append("read_write_disagreement")
        base_fee_value = latest.get("baseFeePerGas")
        if base_fee_value is None:
            reasons.append("base_fee_unknown")
        else:
            base_fee = _quantity(base_fee_value, "base fee")
        gas_price = _quantity(read.call("eth_gasPrice", []), "gas price")
        priority_fee = _quantity(
            read.call("eth_maxPriorityFeePerGas", []),
            "priority fee",
        )
        try:
            read.call(
                "eth_getBalance",
                [runner_address, checkpoint_tag],
            )
        except Exception:
            archive_capable = False
            reasons.append("archive_view_unavailable")
        else:
            archive_capable = True
        accounts = (
            _account(
                client=read,
                role="deployer",
                address=deployer_address,
                minimum_balance_wei=deployer_balance_floor_wei,
            ),
            _account(
                client=read,
                role="runner",
                address=runner_address,
                minimum_balance_wei=runner_balance_floor_wei,
            ),
        )
        reasons.extend(
            item.reason_code for item in accounts if item.status != "pass"
        )
    except Exception:
        reasons.append("required_rpc_fact_unknown")
    unique_reasons = tuple(sorted(set(reasons)))
    return NetworkRpcObservation(
        network_id=network.network_id,
        chain_id=chain_id,
        expected_chain_id=expected_chain_id,
        latest_block_number=latest_number,
        latest_block_hash=latest_hash,
        latest_block_timestamp=latest_timestamp,
        checkpoint_block_number=network.checkpoint.block_number,
        checkpoint_hash=checkpoint_hash,
        write_checkpoint_hash=write_checkpoint_hash,
        base_fee_per_gas_wei=base_fee,
        gas_price_wei=gas_price,
        max_priority_fee_per_gas_wei=priority_fee,
        archive_capable=archive_capable,
        read_write_agree=agreement,
        block_age_seconds=age,
        accounts=accounts,
        status="pass" if not unique_reasons else "fail",
        reason_codes=unique_reasons or ("rpc_network_ready",),
    )


def collect_rpc_preflight(
    *,
    config: LabConfig,
    endpoints: dict[str, EndpointPair],
    observed_at: datetime,
    maximum_block_age_seconds: int,
    store: EvidenceStore | None = None,
) -> tuple[RpcPreflightSuite, str | None]:
    if set(endpoints) != set(EXPECTED_NETWORKS):
        raise RpcPreflightError("RPC endpoint pairs must cover exactly the fixed route")
    signers = {item.role: item.public_identity for item in config.signers}
    budgets = {item.chain_id: item for item in config.budgets}
    observations = tuple(
        probe_network(
            network=network,
            endpoints=endpoints[network.network_id],
            deployer_address=signers["deployer"],
            runner_address=signers["runner"],
            deployer_balance_floor_wei=budgets[network.chain_id].max_run_wei,
            runner_balance_floor_wei=budgets[network.chain_id].minimum_runner_balance_wei,
            observed_at=observed_at,
            maximum_block_age_seconds=maximum_block_age_seconds,
        )
        for network in config.networks
    )
    suite = RpcPreflightSuite(
        observed_at=observed_at.astimezone(UTC).isoformat(),
        maximum_block_age_seconds=maximum_block_age_seconds,
        observations=observations,
        outcome="pass" if all(item.status == "pass" for item in observations) else "blocked",
        effects={
            "signing_operations": 0,
            "funding_operations": 0,
            "deployments": 0,
            "broadcasts": 0,
        },
    )
    document = suite.as_dict()
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "rpc-preflight-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)
    raw = rfc8785.dumps(document)
    digest = hashlib.sha256(raw).hexdigest()
    if store is not None:
        stored = store.put_raw(
            raw,
            media_type="application/json",
            metadata={
                "kind": "rpc-preflight",
                "contains_authenticated_url": False,
            },
        )
        if stored != digest:
            raise RpcPreflightError("raw RPC preflight digest changed during storage")
    return suite, digest


def resolve_configured_endpoints(
    config: LabConfig,
    resolver: RpcReferenceResolver,
) -> dict[str, EndpointPair]:
    return {
        network.network_id: EndpointPair(
            read=resolver.resolve(network.read_rpc_ref),
            write=resolver.resolve(network.write_rpc_ref),
        )
        for network in config.networks
    }
