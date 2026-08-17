"""Hyperlane rendering for the versioned A--E multihop stack."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any, Callable, cast

import rfc8785
import yaml
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.hyperlane import HyperlanePublicIdentities, load_hyperlane_addresses
from xir_lab.native.multihop_scalability import load_multihop_profile

MULTIHOP_HYPERLANE_NAMES = tuple(f"xirlocalchain{label}" for label in "abcde")
REQUIRED_ADDRESS_FIELDS = (
    "mailbox",
    "validatorAnnounce",
    "merkleTreeHook",
    "interchainGasPaymaster",
)


def _address(value: str, label: str) -> str:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except ValueError as exc:
        raise LocalTopologyError(f"invalid multihop Hyperlane {label} address") from exc
    if len(raw) != 20 or not any(raw):
        raise LocalTopologyError(f"invalid multihop Hyperlane {label} address")
    return "0x" + raw.hex()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


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
        raise LocalTopologyError(f"multihop Hyperlane RPC failed: {method}") from exc
    if not isinstance(document, dict) or document.get("error") is not None:
        raise LocalTopologyError(f"multihop Hyperlane RPC error: {method}")
    return document.get("result")


def render_multihop_hyperlane_deployment_inputs(
    *,
    profile_path: Path,
    identities: HyperlanePublicIdentities,
    runtime_root: Path,
) -> dict[str, Any]:
    profile, profile_sha256 = load_multihop_profile(profile_path)
    owner = _address(identities.owner_address, "owner")
    validator = _address(identities.validator_address, "validator")
    relayer = _address(identities.relayer_address, "relayer")
    root = runtime_root / "hyperlane"
    rendered: list[dict[str, str]] = []
    chains = cast(list[dict[str, Any]], profile["chains"])
    for name, chain in zip(MULTIHOP_HYPERLANE_NAMES, chains, strict=True):
        metadata = {
            "chainId": chain["chain_id"],
            "domainId": chain["hyperlane_domain"],
            "name": name,
            "displayName": f"XIR Local Chain {chain['label']}",
            "protocol": "ethereum",
            "isTestnet": True,
            "rpcUrls": [{"http": chain["rpc_url"]}],
            "blocks": {"confirmations": 1, "estimateBlockTime": 1, "reorgPeriod": 0},
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
        metadata_path = root / "registry" / "chains" / name / "metadata.yaml"
        core_path = root / "core" / f"{name}.yaml"
        _write_yaml(metadata_path, metadata)
        _write_yaml(core_path, core)
        rendered.append(
            {
                "chain_name": name,
                "metadata_path": str(metadata_path.relative_to(runtime_root)),
                "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
                "core_path": str(core_path.relative_to(runtime_root)),
                "core_sha256": hashlib.sha256(core_path.read_bytes()).hexdigest(),
            }
        )
    document: dict[str, Any] = {
        "schema_version": "xir-lab-multihop-hyperlane-deployment-inputs-v1",
        "profile_sha256": profile_sha256,
        "cli_package": "@hyperlane-xyz/cli@39.0.0",
        "identities": {
            "owner_address": owner,
            "validator_address": validator,
            "relayer_address": relayer,
        },
        "rendered": rendered,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    _write_json(root / "deployment-inputs.json", document)
    return document


def materialize_multihop_hyperlane_registry(
    *, profile_path: Path, runtime_root: Path
) -> dict[str, Any]:
    profile, profile_sha256 = load_multihop_profile(profile_path)
    chains = cast(list[dict[str, Any]], profile["chains"])
    rendered: list[dict[str, str]] = []
    for name, chain in zip(MULTIHOP_HYPERLANE_NAMES, chains, strict=True):
        source = (
            runtime_root
            / "hyperlane"
            / "native-deployments"
            / f"{chain['chain_id']}.json"
        )
        try:
            deployment = json.loads(source.read_text(encoding="utf-8"))
            contracts = cast(dict[str, str], deployment["contracts"])
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            raise LocalTopologyError(f"missing Hyperlane deployment for {name}") from exc
        addresses = {
            "mailbox": _address(contracts["mailbox"], "mailbox"),
            "merkleTreeHook": _address(contracts["merkleTreeHook"], "merkleTreeHook"),
            "validatorAnnounce": _address(contracts["validatorAnnounce"], "validatorAnnounce"),
            "defaultIsm": _address(contracts["defaultIsm"], "defaultIsm"),
            "staticMessageIdMultisigIsmFactory": _address(
                contracts["staticMessageIdMultisigIsmFactory"], "ISM factory"
            ),
            "protocolFee": _address(contracts["protocolFee"], "protocolFee"),
            "interchainGasPaymaster": _address(contracts["protocolFee"], "IGP alias"),
        }
        path = runtime_root / "hyperlane" / "registry" / "chains" / name / "addresses.yaml"
        _write_yaml(path, addresses)
        rendered.append(
            {
                "chain_name": name,
                "path": str(path.relative_to(runtime_root)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    document: dict[str, Any] = {
        "schema_version": "xir-lab-multihop-hyperlane-registry-v1",
        "profile_sha256": profile_sha256,
        "rendered": rendered,
        "igp_deployed": False,
        "igp_called_by_formal_workload": False,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    _write_json(runtime_root / "hyperlane" / "registry-manifest.json", document)
    return document


def render_multihop_hyperlane_agent_configs(
    *, profile_path: Path, runtime_root: Path
) -> dict[str, Any]:
    profile, profile_sha256 = load_multihop_profile(profile_path)
    root = runtime_root / "hyperlane"
    chains = cast(list[dict[str, Any]], profile["chains"])
    configs: dict[str, Any] = {}
    for name, chain in zip(MULTIHOP_HYPERLANE_NAMES, chains, strict=True):
        path = root / "registry" / "chains" / name / "addresses.yaml"
        addresses = yaml.safe_load(path.read_text(encoding="utf-8"))
        for field in REQUIRED_ADDRESS_FIELDS:
            _address(cast(str, addresses[field]), field)
        configs[name] = {
            "name": name,
            "protocol": "ethereum",
            "chainId": chain["chain_id"],
            "domainId": chain["hyperlane_domain"],
            "rpcUrls": [{"http": chain["rpc_url"]}],
            "blocks": {"confirmations": 1, "estimateBlockTime": 1, "reorgPeriod": 0},
            "index": {"from": 0, "chunk": 1000, "interval": 1},
            "nativeToken": {"symbol": "ETH", "decimals": 18},
            **addresses,
        }
    output_root = root / "agents" / "config"
    rendered: list[dict[str, str]] = []
    for index, name in enumerate(MULTIHOP_HYPERLANE_NAMES):
        validator_document = {
            "chains": configs,
            "originChainName": name,
            "db": str(root / "agents" / "db" / f"validator-{name}"),
            "checkpointSyncer": {
                "type": "localStorage",
                "path": str(root / "checkpoints" / name),
            },
            "interval": 1,
            "metricsPort": 19300 + index,
            "maxSignConcurrency": 16,
            "allowPublicRpcs": False,
            "skipAnnounce": False,
        }
        path = output_root / f"validator-{name}.json"
        _write_json(path, validator_document)
        rendered.append(
            {"kind": "validator", "chain": name, "path": str(path.relative_to(runtime_root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
    relayer = {
        "chains": configs,
        "relayChains": ",".join(MULTIHOP_HYPERLANE_NAMES),
        "db": str(root / "agents" / "db" / "relayer"),
        "allowLocalCheckpointSyncers": True,
        "gasPaymentEnforcement": [{"type": "none"}],
        "metricsPort": 19400,
        "maxMessageRetries": 20,
        "transactionGasLimit": "30000000",
    }
    relayer_path = output_root / "relayer.json"
    _write_json(relayer_path, relayer)
    rendered.append(
        {"kind": "relayer", "chain": "*", "path": str(relayer_path.relative_to(runtime_root)), "sha256": hashlib.sha256(relayer_path.read_bytes()).hexdigest()}
    )
    manifest: dict[str, Any] = {
        "schema_version": "xir-lab-multihop-hyperlane-agent-configs-v1",
        "profile_sha256": profile_sha256,
        "secret_free": True,
        "rendered": rendered,
    }
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write_json(root / "agents" / "config-manifest.json", manifest)
    return manifest


def capture_multihop_hyperlane_deployment_evidence(
    *,
    profile_path: Path,
    runtime_root: Path,
    owner_address: str,
    start_blocks: dict[str, int],
    end_blocks: dict[str, int] | None = None,
    rpc_call: Callable[[str, str, list[Any]], Any] = _rpc_call,
) -> dict[str, Any]:
    """Capture receipts and effective bytecode for all five Hyperlane domains."""

    profile, profile_sha256 = load_multihop_profile(profile_path)
    owner = _address(owner_address, "owner").lower()
    root = runtime_root / "hyperlane"
    chains = cast(list[dict[str, Any]], profile["chains"])
    evidence: list[dict[str, Any]] = []
    for name, chain in zip(MULTIHOP_HYPERLANE_NAMES, chains, strict=True):
        if name not in start_blocks or start_blocks[name] < 0:
            raise LocalTopologyError(f"multihop Hyperlane start block missing: {name}")
        rpc_url = cast(str, chain["rpc_url"])
        addresses = load_hyperlane_addresses(
            registry_root=root / "registry", chain_name=name
        )
        head = rpc_call(rpc_url, "eth_blockNumber", [])
        if not isinstance(head, str):
            raise LocalTopologyError("multihop Hyperlane block head is invalid")
        terminal = int(head, 16) if end_blocks is None else int(end_blocks[name])
        transactions: list[dict[str, Any]] = []
        for block_number in range(start_blocks[name], terminal + 1):
            block = rpc_call(
                rpc_url, "eth_getBlockByNumber", [hex(block_number), True]
            )
            if not isinstance(block, dict) or not isinstance(
                block.get("transactions"), list
            ):
                raise LocalTopologyError("multihop Hyperlane block is unavailable")
            for transaction in cast(list[Any], block["transactions"]):
                if not isinstance(transaction, dict):
                    raise LocalTopologyError("multihop Hyperlane transaction is invalid")
                if str(transaction.get("from", "")).lower() != owner:
                    continue
                transaction_hash = str(transaction.get("hash", "")).lower()
                receipt = rpc_call(
                    rpc_url, "eth_getTransactionReceipt", [transaction_hash]
                )
                if not isinstance(receipt, dict):
                    raise LocalTopologyError("multihop Hyperlane receipt is unavailable")
                raw_path = root / "deployment-receipts" / name / f"{transaction_hash}.json"
                _write_json(raw_path, {"transaction": transaction, "receipt": receipt})
                transactions.append(
                    {
                        "transaction_hash": transaction_hash,
                        "block_number": int(str(receipt["blockNumber"]), 16),
                        "status": int(str(receipt["status"]), 16),
                        "gas_used": int(str(receipt["gasUsed"]), 16),
                        "contract_address": receipt.get("contractAddress"),
                        "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                    }
                )
        if not transactions or any(row["status"] != 1 for row in transactions):
            raise LocalTopologyError(f"multihop Hyperlane receipts failed: {name}")
        verified: dict[str, dict[str, str]] = {}
        for field, address in addresses.items():
            code = rpc_call(rpc_url, "eth_getCode", [address, "latest"])
            if not isinstance(code, str) or code in {"0x", "0x0"}:
                raise LocalTopologyError(f"multihop Hyperlane code missing: {name}:{field}")
            verified[field] = {
                "address": address.lower(),
                "runtime_code_sha256": hashlib.sha256(
                    bytes.fromhex(code.removeprefix("0x"))
                ).hexdigest(),
            }
        local_domain = "0x" + keccak(text="localDomain()")[:4].hex()
        result = rpc_call(
            rpc_url,
            "eth_call",
            [{"to": addresses["mailbox"], "data": local_domain}, "latest"],
        )
        if not isinstance(result, str) or int(result, 16) != int(
            chain["hyperlane_domain"]
        ):
            raise LocalTopologyError(f"multihop Hyperlane domain mismatch: {name}")
        evidence.append(
            {
                "chain_name": name,
                "chain_id": chain["chain_id"],
                "domain_id": chain["hyperlane_domain"],
                "start_block": start_blocks[name],
                "end_block": terminal,
                "addresses": verified,
                "transactions": transactions,
            }
        )
    manifest: dict[str, Any] = {
        "schema_version": "xir-lab-multihop-hyperlane-deployment-evidence-v1",
        "profile_sha256": profile_sha256,
        "owner_address": owner,
        "chains": evidence,
    }
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write_json(root / "deployment-evidence.json", manifest)
    return manifest
