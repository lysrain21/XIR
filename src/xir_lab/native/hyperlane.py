"""Render and verify the pinned official Hyperlane local deployment."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, cast

import rfc8785
import yaml
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.native_profile import load_native_profile
from xir_lab.localnet.topology import LocalTopologyError

CHAIN_NAMES = (
    "xirlocalsource",
    "xirlocalintermediate",
    "xirlocaldestination",
)
REQUIRED_ADDRESS_FIELDS = (
    "mailbox",
    "validatorAnnounce",
    "merkleTreeHook",
    "interchainGasPaymaster",
)
EVENT_TOPICS = {
    "dispatch": "0x" + keccak(text="Dispatch(address,uint32,bytes32,bytes)").hex(),
    "dispatch_id": "0x" + keccak(text="DispatchId(bytes32)").hex(),
    "process": "0x" + keccak(text="Process(uint32,bytes32,address)").hex(),
    "process_id": "0x" + keccak(text="ProcessId(bytes32)").hex(),
    "inserted": "0x" + keccak(text="InsertedIntoTree(bytes32,uint32)").hex(),
}


@dataclass(frozen=True)
class HyperlanePublicIdentities:
    owner_address: str
    validator_address: str
    relayer_address: str


@dataclass(frozen=True)
class HyperlaneMessageEvidence:
    message_id: str
    dispatch_transaction: str
    dispatch_log_index: int
    inserted_log_index: int
    checkpoint_sha256: str
    validator_signature_sha256: str
    relayer_decision_sha256: str
    process_transaction: str
    process_log_index: int


def _address(value: str, label: str) -> str:
    if len(value) != 42 or not value.startswith("0x"):
        raise LocalTopologyError(f"invalid Hyperlane {label} address")
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise LocalTopologyError(f"invalid Hyperlane {label} address") from exc
    if int(value[2:], 16) == 0:
        raise LocalTopologyError(f"zero Hyperlane {label} address")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def render_hyperlane_deployment_inputs(
    *,
    profile_path: Path,
    identities: HyperlanePublicIdentities,
    runtime_root: Path,
) -> dict[str, Any]:
    """Render secret-free registry metadata and core configs."""

    profile, profile_sha256 = load_native_profile(profile_path)
    owner = _address(identities.owner_address, "owner")
    validator = _address(identities.validator_address, "validator")
    _address(identities.relayer_address, "relayer")
    hyperlane_root = runtime_root / "hyperlane"
    registry_root = hyperlane_root / "registry"
    chains = cast(list[dict[str, Any]], profile["chains"])
    rendered: list[dict[str, Any]] = []
    for name, chain in zip(CHAIN_NAMES, chains, strict=True):
        metadata = {
            "chainId": chain["chain_id"],
            "domainId": chain["hyperlane_domain"],
            "name": name,
            "displayName": f"XIR {chain['route_role'].title()} Local",
            "protocol": "ethereum",
            "isTestnet": True,
            "rpcUrls": [{"http": chain["rpc_url"]}],
            "blocks": {
                "confirmations": 1,
                "estimateBlockTime": 1,
                "reorgPeriod": 0,
            },
            "index": {"from": 0, "chunk": 1000, "interval": 1},
            "nativeToken": {"name": "Local Ether", "symbol": "ETH", "decimals": 18},
        }
        core = {
            "owner": owner,
            "defaultIsm": {
                "type": "messageIdMultisigIsm",
                "threshold": 1,
                "validators": [validator],
            },
            "defaultHook": {
                "type": "protocolFee",
                "maxProtocolFee": "0",
                "protocolFee": "0",
                "beneficiary": owner,
                "owner": owner,
            },
            "requiredHook": {"type": "merkleTreeHook"},
        }
        metadata_path = registry_root / "chains" / name / "metadata.yaml"
        core_path = hyperlane_root / "core" / f"{name}.yaml"
        _write_yaml(metadata_path, metadata)
        _write_yaml(core_path, core)
        rendered.append(
            {
                "chain_name": name,
                "metadata_path": str(metadata_path.relative_to(runtime_root)),
                "core_path": str(core_path.relative_to(runtime_root)),
                "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
                "core_sha256": hashlib.sha256(core_path.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "schema_version": "xir-lab-hyperlane-deployment-inputs-v1",
        "profile_sha256": profile_sha256,
        "cli_package": "@hyperlane-xyz/cli@39.0.0",
        "identities": {
            "owner_address": owner.lower(),
            "validator_address": validator.lower(),
            "relayer_address": identities.relayer_address.lower(),
        },
        "rendered": rendered,
    }
    manifest["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(manifest)  # type: ignore[arg-type]
    ).hexdigest()
    _write_json(hyperlane_root / "deployment-inputs.json", manifest)
    return cast(dict[str, Any], manifest)


def load_hyperlane_addresses(
    *, registry_root: Path, chain_name: str
) -> dict[str, str]:
    path = registry_root / "chains" / chain_name / "addresses.yaml"
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LocalTopologyError(f"cannot read Hyperlane addresses: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("Hyperlane addresses root must be an object")
    result: dict[str, str] = {}
    for field in REQUIRED_ADDRESS_FIELDS:
        raw = document.get(field)
        if not isinstance(raw, str):
            raise LocalTopologyError(f"Hyperlane deployment lacks {field}")
        result[field] = _address(raw, field)
    return result


def render_hyperlane_agent_configs(
    *,
    profile_path: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    """Render public agent configs after official core deployment."""

    profile, profile_sha256 = load_native_profile(profile_path)
    hyperlane_root = runtime_root / "hyperlane"
    registry_root = hyperlane_root / "registry"
    chains = cast(list[dict[str, Any]], profile["chains"])
    chain_config: dict[str, Any] = {}
    for name, chain in zip(CHAIN_NAMES, chains, strict=True):
        addresses = load_hyperlane_addresses(
            registry_root=registry_root, chain_name=name
        )
        chain_config[name] = {
            "name": name,
            "protocol": "ethereum",
            "chainId": chain["chain_id"],
            "domainId": chain["hyperlane_domain"],
            "rpcUrls": [{"http": chain["rpc_url"]}],
            "blocks": {
                "confirmations": 1,
                "estimateBlockTime": 1,
                "reorgPeriod": 0,
            },
            "index": {"from": 0, "chunk": 1000, "interval": 1},
            "nativeToken": {"symbol": "ETH", "decimals": 18},
            **addresses,
        }
    config_root = hyperlane_root / "agents" / "config"
    rendered: list[dict[str, str]] = []
    for index, name in enumerate(CHAIN_NAMES):
        checkpoint_path = hyperlane_root / "checkpoints" / name
        validator_config = {
            "chains": chain_config,
            "originChainName": name,
            "db": str(hyperlane_root / "agents" / "db" / f"validator-{name}"),
            "checkpointSyncer": {
                "type": "localStorage",
                "path": str(checkpoint_path),
            },
            "interval": 1,
            "metricsPort": 19100 + index,
            "maxSignConcurrency": 16,
            "allowPublicRpcs": False,
            "skipAnnounce": False,
        }
        path = config_root / f"validator-{name}.json"
        _write_json(path, validator_config)
        rendered.append(
            {
                "kind": "validator",
                "chain": name,
                "path": str(path.relative_to(runtime_root)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    relayer_config = {
        "chains": chain_config,
        "relayChains": ",".join(CHAIN_NAMES),
        "db": str(hyperlane_root / "agents" / "db" / "relayer"),
        "allowLocalCheckpointSyncers": True,
        "gasPaymentEnforcement": [{"type": "none"}],
        "metricsPort": 19200,
        "maxMessageRetries": 20,
        "transactionGasLimit": "30000000",
    }
    relayer_path = config_root / "relayer.json"
    _write_json(relayer_path, relayer_config)
    rendered.append(
        {
            "kind": "relayer",
            "chain": "*",
            "path": str(relayer_path.relative_to(runtime_root)),
            "sha256": hashlib.sha256(relayer_path.read_bytes()).hexdigest(),
        }
    )
    manifest = {
        "schema_version": "xir-lab-hyperlane-agent-configs-v1",
        "profile_sha256": profile_sha256,
        "secret_free": True,
        "rendered": rendered,
    }
    manifest["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(manifest)  # type: ignore[arg-type]
    ).hexdigest()
    _write_json(hyperlane_root / "agents" / "config-manifest.json", manifest)
    return cast(dict[str, Any], manifest)


def classify_hyperlane_receipt_logs(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    """Classify official Hyperlane event logs without discarding raw fields."""

    transaction_hash = str(receipt.get("transactionHash", ""))
    classified: list[dict[str, Any]] = []
    topics_to_name = {value.lower(): key for key, value in EVENT_TOPICS.items()}
    logs = receipt.get("logs", [])
    if not isinstance(logs, list):
        raise LocalTopologyError("Hyperlane receipt logs must be a list")
    for log in logs:
        if not isinstance(log, dict):
            raise LocalTopologyError("Hyperlane receipt log must be an object")
        topics = log.get("topics", [])
        if not isinstance(topics, list) or not topics:
            continue
        event_name = topics_to_name.get(str(topics[0]).lower())
        if event_name is None:
            continue
        classified.append(
            {
                "event": event_name,
                "transaction_hash": transaction_hash.lower(),
                "log_index": int(str(log["logIndex"]), 16),
                "address": str(log["address"]).lower(),
                "topics": [str(topic).lower() for topic in topics],
                "data": str(log.get("data", "0x")).lower(),
            }
        )
    return classified


def reconcile_hyperlane_message(evidence: HyperlaneMessageEvidence) -> None:
    missing = [
        field
        for field, value in evidence.__dict__.items()
        if value == "" or value is None
    ]
    if missing:
        raise LocalTopologyError(
            "Hyperlane message evidence is incomplete: " + ",".join(missing)
        )
    for field in (
        "checkpoint_sha256",
        "validator_signature_sha256",
        "relayer_decision_sha256",
    ):
        if len(cast(str, getattr(evidence, field))) != 64:
            raise LocalTopologyError(f"Hyperlane {field} is not SHA-256")


def _rpc_call(url: str, method: str, params: list[Any]) -> Any:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        url, data=payload, headers={"content-type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"Hyperlane deployment RPC failed: {method}") from exc
    if not isinstance(document, dict) or document.get("error") is not None:
        raise LocalTopologyError(f"Hyperlane deployment RPC error: {method}")
    return document.get("result")


def capture_hyperlane_deployment_evidence(
    *,
    profile_path: Path,
    runtime_root: Path,
    owner_address: str,
    start_blocks: dict[str, int],
    end_blocks: dict[str, int] | None = None,
    rpc_call: Callable[[str, str, list[Any]], Any] = _rpc_call,
) -> dict[str, Any]:
    """Capture all deployer transactions and verify effective Mailbox state."""

    profile, profile_sha256 = load_native_profile(profile_path)
    owner = _address(owner_address, "owner").lower()
    hyperlane_root = runtime_root / "hyperlane"
    registry_root = hyperlane_root / "registry"
    receipt_root = hyperlane_root / "deployment-receipts"
    chains = cast(list[dict[str, Any]], profile["chains"])
    chain_evidence: list[dict[str, Any]] = []
    for name, chain in zip(CHAIN_NAMES, chains, strict=True):
        if name not in start_blocks or start_blocks[name] < 0:
            raise LocalTopologyError(f"Hyperlane start block is missing: {name}")
        rpc_url = cast(str, chain["rpc_url"])
        addresses = load_hyperlane_addresses(
            registry_root=registry_root, chain_name=name
        )
        head_raw = rpc_call(rpc_url, "eth_blockNumber", [])
        if not isinstance(head_raw, str):
            raise LocalTopologyError("Hyperlane block head is invalid")
        end_block = (
            int(head_raw, 16)
            if end_blocks is None
            else int(end_blocks[name])
        )
        transactions: list[dict[str, Any]] = []
        for block_number in range(start_blocks[name], end_block + 1):
            block = rpc_call(
                rpc_url, "eth_getBlockByNumber", [hex(block_number), True]
            )
            if not isinstance(block, dict):
                raise LocalTopologyError("Hyperlane deployment block is unavailable")
            raw_transactions = block.get("transactions", [])
            if not isinstance(raw_transactions, list):
                raise LocalTopologyError("Hyperlane deployment transaction list is invalid")
            for transaction in raw_transactions:
                if not isinstance(transaction, dict):
                    raise LocalTopologyError("Hyperlane deployment transaction is invalid")
                if str(transaction.get("from", "")).lower() != owner:
                    continue
                transaction_hash = str(transaction.get("hash", "")).lower()
                receipt = rpc_call(
                    rpc_url, "eth_getTransactionReceipt", [transaction_hash]
                )
                if not isinstance(receipt, dict):
                    raise LocalTopologyError("Hyperlane deployment receipt is unavailable")
                exact = {"transaction": transaction, "receipt": receipt}
                path = receipt_root / name / f"{transaction_hash}.json"
                _write_json(path, exact)
                transactions.append(
                    {
                        "transaction_hash": transaction_hash,
                        "block_number": int(str(receipt["blockNumber"]), 16),
                        "status": int(str(receipt["status"]), 16),
                        "contract_address": receipt.get("contractAddress"),
                        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        if not transactions or any(item["status"] != 1 for item in transactions):
            raise LocalTopologyError(
                f"Hyperlane deployment transactions are missing or failed: {name}"
            )
        verified_addresses: dict[str, dict[str, str]] = {}
        for field, address in addresses.items():
            code = rpc_call(rpc_url, "eth_getCode", [address, "latest"])
            if not isinstance(code, str) or code in {"0x", "0x0"}:
                raise LocalTopologyError(
                    f"Hyperlane {field} has no runtime code on {name}"
                )
            verified_addresses[field] = {
                "address": address.lower(),
                "runtime_code_sha256": hashlib.sha256(
                    bytes.fromhex(code.removeprefix("0x"))
                ).hexdigest(),
            }
        domain_call = "0x" + keccak(text="localDomain()")[:4].hex()
        domain_result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": addresses["mailbox"], "data": domain_call}, "latest"],
        )
        if not isinstance(domain_result, str) or int(domain_result, 16) != int(
            chain["hyperlane_domain"]
        ):
            raise LocalTopologyError(f"Hyperlane Mailbox domain mismatch: {name}")
        chain_evidence.append(
            {
                "chain_name": name,
                "chain_id": chain["chain_id"],
                "domain_id": chain["hyperlane_domain"],
                "start_block": start_blocks[name],
                "end_block": end_block,
                "addresses": verified_addresses,
                "transactions": transactions,
            }
        )
    manifest = {
        "schema_version": "xir-lab-hyperlane-deployment-evidence-v1",
        "profile_sha256": profile_sha256,
        "owner_address": owner,
        "chains": chain_evidence,
    }
    manifest["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(manifest)  # type: ignore[arg-type]
    ).hexdigest()
    _write_json(hyperlane_root / "deployment-evidence.json", manifest)
    return cast(dict[str, Any], manifest)
