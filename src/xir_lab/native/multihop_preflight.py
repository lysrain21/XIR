"""Fail-closed review-bound preflight for the five-chain multihop campaign."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import time
from pathlib import Path
from typing import Any, cast

import rfc8785
from eth_account import Account
from web3 import Web3
from web3.types import RPCEndpoint

from xir_lab.localnet.multihop_topology import (
    load_multihop_identity_manifest,
    load_multihop_topology,
)
from xir_lab.localnet.multihop_volume_bootstrap import (
    build_validator_volume_plan,
    verify_existing_validator_volumes,
)
from xir_lab.localnet.toolchain_preflight import verify_toolchain_preflight
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import (
    executor_lz_receive_options,
    inspect_layerzero_effective_configuration,
)
from xir_lab.native.multihop_deployer import (
    CHAIN_ROLES,
    REGISTRY_VERSION,
    adapter_key,
)
from xir_lab.native.multihop_identity import (
    DEPLOYMENT_NAMESPACE,
    config_identity,
    evidence_namespace,
)
from xir_lab.native.multihop_scalability import ROUTE_ORDER, load_multihop_config
from xir_lab.native.rpc import (
    BESU_RAW_TRANSACTION_RPC_METHOD,
    decode_besu_raw_transaction_result,
    qbft_web3,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_transaction_hash(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x")


def _validate_trace_probe(response: Any, *, role: str) -> None:
    if not isinstance(response, dict) or response.get("error") is not None:
        raise LocalTopologyError(f"Besu TRACE unavailable: {role}")
    result = response.get("result")
    if not isinstance(result, list) or not result:
        raise LocalTopologyError(f"Besu TRACE returned an empty result: {role}")
    roots = [
        row
        for row in result
        if isinstance(row, dict) and row.get("traceAddress") == []
    ]
    if len(roots) != 1:
        raise LocalTopologyError(f"Besu TRACE lacks one root trace: {role}")
    root_result = roots[0].get("result")
    if not isinstance(root_result, dict) or "gasUsed" not in root_result:
        raise LocalTopologyError(f"Besu TRACE root gas is unavailable: {role}")
    gas_used = root_result["gasUsed"]
    try:
        if isinstance(gas_used, int):
            parsed_gas = gas_used
        elif isinstance(gas_used, str):
            parsed_gas = int(gas_used, 16) if gas_used.startswith("0x") else int(gas_used)
        else:
            raise TypeError("unsupported gas quantity")
    except (TypeError, ValueError) as exc:
        raise LocalTopologyError(f"Besu TRACE root gas is invalid: {role}") from exc
    if parsed_gas < 0:
        raise LocalTopologyError(f"Besu TRACE root gas is invalid: {role}")


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"preflight input is unavailable: {path}") from exc
    if not isinstance(value, dict):
        raise LocalTopologyError("preflight JSON root must be an object")
    return cast(dict[str, Any], value)


def _key_address(path: Path) -> str:
    value = path.read_text(encoding="ascii").strip()
    if not value.startswith("0x"):
        value = "0x" + value
    return str(Account.from_key(value).address).lower()


def _alive(pid_path: Path) -> bool:
    try:
        pid = int(pid_path.read_text(encoding="ascii").strip())
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def _host_snapshot(runtime_root: Path) -> dict[str, Any]:
    memory: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        key, raw = line.split(":", 1)
        if key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(raw.strip().split()[0]) * 1024
    if set(memory) != {"MemTotal", "MemAvailable"}:
        raise LocalTopologyError("host memory inventory is incomplete")
    disk = shutil.disk_usage(runtime_root)
    return {
        "captured_utc_ns": time.time_ns(),
        "captured_monotonic_ns": time.monotonic_ns(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "logical_cpus": os.cpu_count(),
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_bytes": memory["MemAvailable"],
        "runtime_disk": {
            "path": str(runtime_root.resolve()),
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "available_bytes": disk.free,
        },
        "load_average": list(os.getloadavg()),
    }


def _artifact(repository_root: Path, source: str, contract: str) -> dict[str, Any]:
    return _load(repository_root / "contracts/out" / source / f"{contract}.json")


def _require_review_closure(
    *, workspace_root: Path, preregistration: dict[str, Any]
) -> dict[str, Any]:
    gate = cast(dict[str, Any], preregistration["review_gate"])
    relative = gate.get("closure_audit_path")
    expected = gate.get("closure_audit_sha256")
    if (
        preregistration.get("status") != "review_closed_formal_execution_allowed"
        or preregistration.get("formal_execution_allowed") is not True
        or not isinstance(relative, str)
        or not isinstance(expected, str)
    ):
        raise LocalTopologyError("independent review closure has not enabled execution")
    path = (workspace_root / relative).resolve()
    if workspace_root.resolve() not in path.parents or not path.is_file() or _sha(path) != expected:
        raise LocalTopologyError("independent review closure digest is invalid")
    closure = _load(path)
    if (
        closure.get("verdict") != "PASS"
        or int(closure.get("blockers", -1)) != 0
        or int(closure.get("majors", -1)) != 0
    ):
        raise LocalTopologyError("independent review closure is not PASS")
    return closure


def preregistration_review_payload_sha256(preregistration: dict[str, Any]) -> str:
    """Hash the preregistration while normalizing only closure-controlled fields."""

    payload = json.loads(json.dumps(preregistration))
    payload["status"] = "preregistered_local_implementation_pending_review"
    payload["formal_execution_allowed"] = False
    gate = cast(dict[str, Any], payload["review_gate"])
    gate["closure_audit_path"] = None
    gate["closure_audit_sha256"] = None
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _verified_manifest(*, root: Path, manifest: dict[str, str], label: str) -> str:
    if not manifest:
        raise LocalTopologyError(f"reviewed {label} manifest is absent")
    for relative, expected in manifest.items():
        path = (root / relative).resolve()
        if root.resolve() not in path.parents or not path.is_file() or _sha(path) != expected:
            raise LocalTopologyError(f"reviewed {label} digest drift: {relative}")
    return hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()


def _verified_complete_source_manifest(
    *, root: Path, manifest: dict[str, str], policy: dict[str, Any]
) -> str:
    """Require the reviewed manifest to equal the declared source-tree closure."""

    include_globs = policy.get("include_globs")
    if (
        policy.get("schema_version") != "xir-lab-native-multihop-implementation-source-policy-v1"
        or policy.get("exact_file_set") is not True
        or not isinstance(include_globs, list)
        or not include_globs
        or any(not isinstance(pattern, str) or not pattern for pattern in include_globs)
    ):
        raise LocalTopologyError("implementation source policy is invalid")
    discovered: set[str] = set()
    for pattern in cast(list[str], include_globs):
        matched = {
            path.relative_to(root).as_posix() for path in root.glob(pattern) if path.is_file()
        }
        if not matched:
            raise LocalTopologyError(f"implementation source policy glob is empty: {pattern}")
        discovered.update(matched)
    if set(manifest) != discovered:
        missing = sorted(discovered - set(manifest))
        unexpected = sorted(set(manifest) - discovered)
        raise LocalTopologyError(
            "implementation source manifest is not the exact policy closure: "
            f"missing={missing[:5]}, unexpected={unexpected[:5]}"
        )
    return _verified_manifest(root=root, manifest=manifest, label="implementation source")


def verify_multihop_review_gate(
    *, workspace_root: Path, repository_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    """Verify the independent closure and reviewed source tree before deployment."""

    preregistration = _load(preregistration_path)
    closure = _require_review_closure(
        workspace_root=workspace_root, preregistration=preregistration
    )
    source_manifest = cast(dict[str, str], preregistration.get("implementation_source_sha256", {}))
    source_manifest_digest = _verified_complete_source_manifest(
        root=repository_root,
        manifest=source_manifest,
        policy=cast(dict[str, Any], preregistration.get("implementation_source_policy", {})),
    )
    context_manifest = cast(dict[str, str], preregistration.get("review_context_sha256", {}))
    context_manifest_digest = _verified_manifest(
        root=workspace_root,
        manifest=context_manifest,
        label="design/runbook context",
    )
    prereg_payload_digest = preregistration_review_payload_sha256(preregistration)
    if (
        closure.get("implementation_source_manifest_sha256") != source_manifest_digest
        or closure.get("review_context_manifest_sha256") != context_manifest_digest
        or closure.get("preregistration_review_payload_sha256") != prereg_payload_digest
    ):
        raise LocalTopologyError("independent closure is not bound to the full review handoff")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-predeployment-review-gate-v1",
        "valid": True,
        "preregistration_sha256": _sha(preregistration_path),
        "closure_sha256": _sha(
            workspace_root / str(preregistration["review_gate"]["closure_audit_path"])
        ),
        "implementation_source_manifest_sha256": source_manifest_digest,
        "review_context_manifest_sha256": context_manifest_digest,
        "preregistration_review_payload_sha256": prereg_payload_digest,
        "source_file_count": len(source_manifest),
        "review_context_file_count": len(context_manifest),
    }
    document["semantic_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return document


def run_multihop_preflight(
    *,
    workspace_root: Path,
    repository_root: Path,
    runtime_root: Path,
    topology_path: Path,
    identity_path: Path,
    config_path: Path,
    deployment_path: Path,
    preregistration_path: Path,
    review_gate_path: Path,
    validator_volume_attestation_path: Path,
    validator_volume_journal_path: Path,
) -> dict[str, Any]:
    preregistration = _load(preregistration_path)
    review_gate = verify_multihop_review_gate(
        workspace_root=workspace_root,
        repository_root=repository_root,
        preregistration_path=preregistration_path,
    )
    persisted_review_gate = _load(review_gate_path)
    if persisted_review_gate != review_gate:
        raise LocalTopologyError("persisted review gate differs from current review state")
    topology = load_multihop_topology(topology_path)
    host_snapshot = _host_snapshot(runtime_root)
    thresholds = topology.resource_policy.scale
    if (
        int(host_snapshot["logical_cpus"] or 0) < thresholds.minimum_logical_cpus
        or int(host_snapshot["memory_available_bytes"]) < thresholds.minimum_memory_bytes
        or int(cast(dict[str, Any], host_snapshot["runtime_disk"])["available_bytes"])
        < thresholds.minimum_disk_available_bytes
    ):
        raise LocalTopologyError("host resources are below the frozen scale threshold")
    identity = load_multihop_identity_manifest(identity_path, topology=topology)
    volume_plan = build_validator_volume_plan(
        runtime_root=runtime_root,
        topology_path=topology_path,
        identity_manifest_path=identity_path,
        compose_path=runtime_root / "compose.yaml",
    )
    volume_attestation = verify_existing_validator_volumes(
        plan=volume_plan,
        runtime_root=runtime_root,
        attestation_path=validator_volume_attestation_path,
        journal_path=validator_volume_journal_path,
    )
    toolchain_path = runtime_root / "provenance/toolchain-preflight.json"
    toolchain = verify_toolchain_preflight(toolchain_path, require_library=True)
    config, config_sha = load_multihop_config(config_path)
    profile_path = repository_root / str(config["profile"])
    profile = _load(profile_path)
    deployment = _load(deployment_path)
    if tuple(topology.rpc_http_apis) != (
        "ETH",
        "NET",
        "QBFT",
        "WEB3",
        "DEBUG",
        "TRACE",
    ):
        raise LocalTopologyError("five-chain topology does not expose frozen trace APIs")
    prereg_config = cast(dict[str, Any], preregistration["inputs"])["config"]
    prereg_profile = cast(dict[str, Any], preregistration["inputs"])["profile"]
    if config_sha != prereg_config["sha256"] or _sha(profile_path) != prereg_profile["sha256"]:
        raise LocalTopologyError("preflight config/profile differs from preregistration")
    source_manifest = cast(dict[str, str], preregistration["implementation_source_sha256"])
    if (
        deployment.get("namespace") != DEPLOYMENT_NAMESPACE
        or deployment.get("profile_sha256") != _sha(profile_path)
        or deployment.get("runner") == deployment.get("root_signer")
    ):
        raise LocalTopologyError("multihop deployment identity is invalid")
    key_roles = {
        "deployer": runtime_root / "private/accounts/deployer.key",
        "runner": runtime_root / "private/accounts/runner.key",
        "root_signer": runtime_root / "private/accounts/root-signer.key",
        "hyperlane_validator": runtime_root / "private/accounts/hyperlane-validator.key",
        "hyperlane_relayer": runtime_root / "private/accounts/hyperlane-relayer.key",
        "layerzero_worker": runtime_root / "private/accounts/layerzero-worker.key",
    }
    key_addresses = {role: _key_address(path) for role, path in key_roles.items()}
    if len(set(key_addresses.values())) != len(key_addresses):
        raise LocalTopologyError("multihop operational signers are not distinct")
    if (
        key_addresses["deployer"] != str(deployment["deployer"]).lower()
        or key_addresses["runner"] != str(deployment["runner"]).lower()
        or key_addresses["root_signer"] != str(deployment["root_signer"]).lower()
    ):
        raise LocalTopologyError("multihop deployment signers differ from keys")
    hyperlane_evidence = _load(runtime_root / "hyperlane/deployment-evidence.json")
    layerzero_evidence = _load(runtime_root / "layerzero/deployment-evidence.json")
    worker_roles = _load(runtime_root / "layerzero/worker-role-configuration/verification.json")
    if (
        hyperlane_evidence.get("schema_version")
        != "xir-lab-multihop-hyperlane-deployment-evidence-v1"
        or len(cast(list[Any], hyperlane_evidence.get("chains", []))) != 5
        or layerzero_evidence.get("schema_version") != "xir-lab-layerzero-deployment-evidence-v1"
        or layerzero_evidence.get("official_chain_components") is not True
        or len(cast(list[Any], layerzero_evidence.get("chains", []))) != 5
        or worker_roles.get("schema_version") != "xir-lab-layerzero-worker-role-configuration-v1"
        or str(worker_roles.get("worker", "")).lower() != key_addresses["layerzero_worker"]
        or len(cast(list[Any], worker_roles.get("verified", []))) != 10
        or not all(
            row.get("effective") is True
            for row in cast(list[dict[str, Any]], worker_roles.get("verified", []))
        )
    ):
        raise LocalTopologyError("native carrier deployment evidence is incomplete")
    chains = cast(list[dict[str, Any]], profile["chains"])
    clients = {
        role: qbft_web3(str(chain["rpc_url"]))
        for role, chain in zip(CHAIN_ROLES, chains, strict=True)
    }
    chain_checks: list[dict[str, Any]] = []
    receipts = cast(list[dict[str, Any]], deployment["deployment_gas"]["receipts"])
    for role, chain in zip(CHAIN_ROLES, chains, strict=True):
        client = clients[role]
        validators = client.provider.make_request(
            RPCEndpoint("qbft_getValidatorsByBlockNumber"), ["latest"]
        )
        peers = client.provider.make_request(RPCEndpoint("net_peerCount"), [])
        if (
            int(client.eth.chain_id) != int(chain["chain_id"])
            or validators.get("error") is not None
            or len(cast(list[Any], validators.get("result"))) != 4
            or peers.get("error") is not None
            or int(cast(str, peers["result"]), 16) < 3
        ):
            raise LocalTopologyError(f"QBFT chain health failed: {role}")
        missing_code = [
            name
            for name, address in cast(dict[str, str], deployment["chains"][role]).items()
            if len(client.eth.get_code(Web3.to_checksum_address(address))) == 0
        ]
        if missing_code:
            raise LocalTopologyError(f"deployment runtime code missing: {role}:{missing_code[0]}")
        sample = next(row for row in receipts if row["role"] == role)
        trace = client.provider.make_request(
            RPCEndpoint("trace_transaction"), [str(sample["transaction_hash"])]
        )
        _validate_trace_probe(trace, role=role)
        raw_response = client.provider.make_request(
            RPCEndpoint(BESU_RAW_TRANSACTION_RPC_METHOD),
            [str(sample["transaction_hash"])],
        )
        if raw_response.get("error") is not None:
            raise LocalTopologyError(f"Besu raw transaction retrieval unavailable: {role}")
        try:
            raw = decode_besu_raw_transaction_result(raw_response.get("result"))
        except LocalTopologyError as exc:
            raise LocalTopologyError(f"Besu raw transaction retrieval unavailable: {role}") from exc
        if (
            _canonical_transaction_hash(Web3.keccak(raw).hex())
            != _canonical_transaction_hash(str(sample["transaction_hash"]))
        ):
            raise LocalTopologyError(f"Besu raw transaction retrieval mismatch: {role}")
        chain_checks.append(
            {
                "role": role,
                "chain_id": int(chain["chain_id"]),
                "validator_count": 4,
                "peer_count_minimum": 3,
                "runtime_component_count": len(deployment["chains"][role]),
                "trace_transaction_available": True,
                "raw_transaction_retrieval_available": True,
            }
        )
    h_abi = _artifact(repository_root, "HyperlaneAdapter.sol", "HyperlaneAdapter")["abi"]
    l_abi = _artifact(repository_root, "LayerZeroAdapter.sol", "LayerZeroAdapter")["abi"]
    registry_abi = _artifact(repository_root, "XIRRegistry.sol", "XIRRegistry")["abi"]
    route_checks = 0
    layerzero_path_checks = 0
    for route in ROUTE_ORDER:
        for hop in cast(list[dict[str, Any]], deployment["routes"][route]["hops"]):
            hop_index = int(hop["hop_index"])
            protocol = str(hop["protocol"])
            source_role = CHAIN_ROLES[hop_index - 1]
            destination_role = CHAIN_ROLES[hop_index]
            abi = h_abi if protocol == "H" else l_abi
            outbound = clients[source_role].eth.contract(
                address=Web3.to_checksum_address(str(hop["outbound_adapter"])), abi=abi
            )
            inbound = clients[destination_role].eth.contract(
                address=Web3.to_checksum_address(str(hop["inbound_adapter"])), abi=abi
            )
            if (
                str(outbound.functions.administrator().call()).lower()
                != str(deployment["deployer"]).lower()
                or str(outbound.functions.runner().call()).lower()
                != str(deployment["runner"]).lower()
                or str(inbound.functions.administrator().call()).lower()
                != str(deployment["deployer"]).lower()
                or str(inbound.functions.runner().call()).lower()
                != str(deployment["runner"]).lower()
            ):
                raise LocalTopologyError("adapter authority binding is invalid")
            source_chain = chains[CHAIN_ROLES.index(source_role)]
            destination_chain = chains[CHAIN_ROLES.index(destination_role)]
            if protocol == "H":
                expected_remote = bytes.fromhex("00" * 12 + str(hop["inbound_adapter"])[2:])
                expected_reverse = bytes.fromhex("00" * 12 + str(hop["outbound_adapter"])[2:])
                source_hyperlane = cast(
                    dict[str, str],
                    _load(
                        runtime_root
                        / "hyperlane/native-deployments"
                        / f"{source_chain['chain_id']}.json"
                    )["contracts"],
                )
                destination_hyperlane = cast(
                    dict[str, str],
                    _load(
                        runtime_root
                        / "hyperlane/native-deployments"
                        / f"{destination_chain['chain_id']}.json"
                    )["contracts"],
                )
                if (
                    bytes(outbound.functions.remoteAdapter().call()) != expected_remote
                    or bytes(inbound.functions.remoteAdapter().call()) != expected_reverse
                    or int(outbound.functions.remoteDomain().call())
                    != int(destination_chain["hyperlane_domain"])
                    or int(inbound.functions.remoteDomain().call())
                    != int(source_chain["hyperlane_domain"])
                    or str(outbound.functions.mailbox().call()).lower()
                    != str(source_hyperlane["mailbox"]).lower()
                    or str(inbound.functions.mailbox().call()).lower()
                    != str(destination_hyperlane["mailbox"]).lower()
                ):
                    raise LocalTopologyError("Hyperlane bidirectional receive path mismatch")
            else:
                expected_remote = bytes.fromhex("00" * 12 + str(hop["inbound_adapter"])[2:])
                expected_reverse = bytes.fromhex("00" * 12 + str(hop["outbound_adapter"])[2:])
                source_lz = cast(
                    dict[str, str],
                    _load(
                        runtime_root / "layerzero/deployments" / f"{source_chain['chain_id']}.json"
                    )["contracts"],
                )
                destination_lz = cast(
                    dict[str, str],
                    _load(
                        runtime_root
                        / "layerzero/deployments"
                        / f"{destination_chain['chain_id']}.json"
                    )["contracts"],
                )
                options_hash = Web3.keccak(executor_lz_receive_options(1_500_000))
                if (
                    bytes(outbound.functions.remotePeer().call()) != expected_remote
                    or bytes(inbound.functions.remotePeer().call()) != expected_reverse
                    or bytes(outbound.functions.enforcedOptionsHash().call()) != options_hash
                    or bytes(inbound.functions.enforcedOptionsHash().call()) != options_hash
                    or int(outbound.functions.remoteEid().call())
                    != int(destination_chain["layerzero_eid"])
                    or int(inbound.functions.remoteEid().call())
                    != int(source_chain["layerzero_eid"])
                    or str(outbound.functions.endpoint().call()).lower()
                    != str(source_lz["endpoint_v2"]).lower()
                    or str(inbound.functions.endpoint().call()).lower()
                    != str(destination_lz["endpoint_v2"]).lower()
                ):
                    raise LocalTopologyError("LayerZero bidirectional receive path mismatch")
                for local_chain, remote_chain, subject, contracts in (
                    (source_chain, destination_chain, hop["outbound_adapter"], source_lz),
                    (destination_chain, source_chain, hop["inbound_adapter"], destination_lz),
                ):
                    effective = inspect_layerzero_effective_configuration(
                        rpc_url=str(local_chain["rpc_url"]),
                        local_eid=int(local_chain["layerzero_eid"]),
                        remote_eids=[int(remote_chain["layerzero_eid"])],
                        subject_address=str(subject),
                        contracts=contracts,
                    )
                    if (
                        effective["dvn_signers"] != [key_addresses["layerzero_worker"]]
                        or int(effective["dvn_quorum"]) != 1
                    ):
                        raise LocalTopologyError(
                            "LayerZero bidirectional DVN signer binding mismatch"
                        )
                    layerzero_path_checks += 1
            if hop_index > 1:
                prior_inbound = deployment["chains"][source_role][
                    adapter_key(route, hop_index - 1, "in")
                ]
                for prior in cast(list[dict[str, Any]], deployment["routes"][route]["hops"])[
                    : hop_index - 1
                ]:
                    approved = outbound.functions.approvedPriorVerifiers(
                        prior["profile_hash"]
                    ).call()
                    if str(approved).lower() != str(prior_inbound).lower():
                        raise LocalTopologyError("approved prior verifier mismatch")
            registry = clients[destination_role].eth.contract(
                address=Web3.to_checksum_address(
                    deployment["chains"][destination_role]["registry"]
                ),
                abi=registry_abi,
            )
            for prior in cast(list[dict[str, Any]], deployment["routes"][route]["hops"])[
                :hop_index
            ]:
                profile_snapshot = registry.functions.profileAt(prior["profile_hash"]).call()
                if (
                    str(profile_snapshot[2]).lower() != str(hop["inbound_adapter"]).lower()
                    or int(profile_snapshot[3]) != 1
                    or profile_snapshot[6] is not True
                ):
                    raise LocalTopologyError("registry profile binding mismatch")
            root = registry.functions.rootAt(REGISTRY_VERSION).call()
            if (
                str(root[1]).lower() != str(deployment["root_signer"]).lower()
                or root[4] is not True
            ):
                raise LocalTopologyError("registry root signer mismatch")
            route_checks += 1
    process_names = [
        *(f"validator-xirlocalchain{role}" for role in CHAIN_ROLES),
        "relayer",
    ]
    process_checks = {
        name: _alive(runtime_root / "hyperlane/agents/pids" / f"{name}.pid")
        for name in process_names
    }
    process_checks["layerzero-worker"] = _alive(runtime_root / "pids/layerzero-worker.pid")
    if not all(process_checks.values()):
        raise LocalTopologyError("native carrier processes are not all alive")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-preflight-v1",
        "namespace": config_identity(config).evidence_namespace,
        "valid": True,
        "credentials_included": False,
        "topology_sha256": topology.source_sha256,
        "identity_manifest_sha256": identity.source_sha256,
        "validator_volume_attestation_sha256": _sha(
            validator_volume_attestation_path
        ),
        "validator_volume_attestation_semantic_sha256": volume_attestation[
            "semantic_sha256"
        ],
        "validator_volume_journal_sha256": _sha(validator_volume_journal_path),
        "validator_volume_journal_semantic_sha256": _load(
            validator_volume_journal_path
        )["semantic_sha256"],
        "validator_volume_count": volume_attestation["validator_volume_count"],
        "toolchain_preflight_sha256": _sha(toolchain_path),
        "toolchain_preflight_semantic_sha256": toolchain["semantic_sha256"],
        "config_sha256": config_sha,
        "profile_sha256": _sha(profile_path),
        "deployment_sha256": _sha(deployment_path),
        "preregistration_sha256": _sha(preregistration_path),
        "review_closure_sha256": review_gate["closure_sha256"],
        "review_gate_sha256": _sha(review_gate_path),
        "review_closure_source_manifest_sha256": review_gate[
            "implementation_source_manifest_sha256"
        ],
        "chain_checks": chain_checks,
        "route_hop_checks": route_checks,
        "layerzero_effective_path_checks": layerzero_path_checks,
        "hyperlane_deployment_evidence_sha256": _sha(
            runtime_root / "hyperlane/deployment-evidence.json"
        ),
        "layerzero_deployment_evidence_sha256": _sha(
            runtime_root / "layerzero/deployment-evidence.json"
        ),
        "layerzero_worker_roles_sha256": _sha(
            runtime_root / "layerzero/worker-role-configuration/verification.json"
        ),
        "process_checks": process_checks,
        "host_snapshot": host_snapshot,
        "scale_resource_thresholds": {
            "minimum_logical_cpus": thresholds.minimum_logical_cpus,
            "minimum_memory_bytes": thresholds.minimum_memory_bytes,
            "minimum_disk_available_bytes": thresholds.minimum_disk_available_bytes,
        },
        "signer_roles_distinct": True,
        "source_file_count": len(source_manifest),
    }
    document["semantic_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return document


def _semantic_sha256(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("semantic_sha256", None)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_multihop_preflight_document(
    *,
    workspace_root: Path,
    repository_root: Path,
    runtime_root: Path,
    topology_path: Path,
    identity_path: Path,
    config_path: Path,
    deployment_path: Path,
    preregistration_path: Path,
    review_gate_path: Path,
    preflight_path: Path,
    validator_volume_attestation_path: Path,
    validator_volume_journal_path: Path,
) -> dict[str, Any]:
    """Recompute every immutable preflight identity before a writer is constructed."""

    document = _load(preflight_path)
    review_gate = verify_multihop_review_gate(
        workspace_root=workspace_root,
        repository_root=repository_root,
        preregistration_path=preregistration_path,
    )
    persisted_review_gate = _load(review_gate_path)
    if persisted_review_gate != review_gate:
        raise LocalTopologyError("persisted review gate differs from current review state")
    topology = load_multihop_topology(topology_path)
    identity = load_multihop_identity_manifest(identity_path, topology=topology)
    config, config_sha = load_multihop_config(config_path)
    profile_path = repository_root / str(config["profile"])
    deployment = _load(deployment_path)
    toolchain_path = runtime_root / "provenance/toolchain-preflight.json"
    toolchain = verify_toolchain_preflight(toolchain_path, require_library=True)
    expected_processes = {
        *(f"validator-xirlocalchain{role}" for role in CHAIN_ROLES),
        "relayer",
        "layerzero-worker",
    }
    process_checks = document.get("process_checks")
    chain_checks = document.get("chain_checks")
    routes = cast(dict[str, dict[str, Any]], deployment.get("routes", {}))
    expected_hops = sum(len(cast(list[Any], routes[route]["hops"])) for route in ROUTE_ORDER)
    expected_lz_paths = 2 * sum(
        1
        for route in ROUTE_ORDER
        for hop in cast(list[dict[str, Any]], routes[route]["hops"])
        if hop.get("protocol") == "L"
    )
    host = cast(dict[str, Any], document.get("host_snapshot", {}))
    runtime_disk = cast(dict[str, Any], host.get("runtime_disk", {}))
    expected: dict[str, bool] = {
        "schema": document.get("schema_version") == "xir-lab-native-multihop-preflight-v1",
        "namespace": document.get("namespace") == evidence_namespace(config),
        "valid": document.get("valid") is True,
        "credentials_excluded": document.get("credentials_included") is False,
        "semantic": document.get("semantic_sha256") == _semantic_sha256(document),
        "topology": document.get("topology_sha256") == topology.source_sha256,
        "identity": document.get("identity_manifest_sha256") == identity.source_sha256,
        "validator_volume_attestation": document.get(
            "validator_volume_attestation_sha256"
        )
        == _sha(validator_volume_attestation_path),
        "validator_volume_attestation_semantic": document.get(
            "validator_volume_attestation_semantic_sha256"
        )
        == _load(validator_volume_attestation_path).get("semantic_sha256"),
        "validator_volume_journal": document.get("validator_volume_journal_sha256")
        == _sha(validator_volume_journal_path),
        "validator_volume_journal_semantic": document.get(
            "validator_volume_journal_semantic_sha256"
        )
        == _load(validator_volume_journal_path).get("semantic_sha256"),
        "validator_volume_count": int(document.get("validator_volume_count", -1)) == 20,
        "toolchain_preflight": document.get("toolchain_preflight_sha256")
        == _sha(toolchain_path),
        "toolchain_preflight_semantic": document.get(
            "toolchain_preflight_semantic_sha256"
        )
        == toolchain.get("semantic_sha256"),
        "config": document.get("config_sha256") == config_sha,
        "profile": document.get("profile_sha256") == _sha(profile_path),
        "deployment": document.get("deployment_sha256") == _sha(deployment_path),
        "preregistration": document.get("preregistration_sha256") == _sha(preregistration_path),
        "review_gate": document.get("review_gate_sha256") == _sha(review_gate_path),
        "review_closure": document.get("review_closure_sha256") == review_gate["closure_sha256"],
        "review_source_manifest": document.get("review_closure_source_manifest_sha256")
        == review_gate["implementation_source_manifest_sha256"],
        "source_count": int(document.get("source_file_count", -1))
        == int(review_gate["source_file_count"]),
        "deployment_namespace": deployment.get("namespace") == DEPLOYMENT_NAMESPACE,
        "signer_separation": document.get("signer_roles_distinct") is True
        and deployment.get("runner") != deployment.get("root_signer"),
        "route_hops": int(document.get("route_hop_checks", -1)) == expected_hops,
        "layerzero_paths": int(document.get("layerzero_effective_path_checks", -1))
        == expected_lz_paths,
        "chain_rows": isinstance(chain_checks, list)
        and [row.get("role") for row in chain_checks] == list(CHAIN_ROLES)
        and all(
            row.get("validator_count") == 4
            and row.get("trace_transaction_available") is True
            and row.get("raw_transaction_retrieval_available") is True
            for row in chain_checks
        ),
        "process_rows": isinstance(process_checks, dict)
        and set(process_checks) == expected_processes
        and all(value is True for value in process_checks.values()),
        "host": host.get("hostname") == platform.node()
        and host.get("boot_id")
        == Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
        "runtime": runtime_disk.get("path") == str(runtime_root.resolve()),
    }
    failed = sorted(key for key, valid in expected.items() if not valid)
    if failed:
        raise LocalTopologyError("multihop preflight document invalid: " + ", ".join(failed))
    live_document = run_multihop_preflight(
        workspace_root=workspace_root,
        repository_root=repository_root,
        runtime_root=runtime_root,
        topology_path=topology_path,
        identity_path=identity_path,
        config_path=config_path,
        deployment_path=deployment_path,
        preregistration_path=preregistration_path,
        review_gate_path=review_gate_path,
        validator_volume_attestation_path=validator_volume_attestation_path,
        validator_volume_journal_path=validator_volume_journal_path,
    )
    persisted_stable = dict(document)
    live_stable = dict(live_document)
    persisted_host = cast(dict[str, Any], persisted_stable.pop("host_snapshot", {}))
    live_host = cast(dict[str, Any], live_stable.pop("host_snapshot", {}))
    persisted_stable.pop("semantic_sha256", None)
    live_stable.pop("semantic_sha256", None)
    if persisted_stable != live_stable:
        raise LocalTopologyError(
            "multihop preflight live recomputation differs from persisted authority"
        )
    persisted_disk = cast(dict[str, Any], persisted_host.get("runtime_disk", {}))
    live_disk = cast(dict[str, Any], live_host.get("runtime_disk", {}))
    if (
        persisted_host.get("hostname") != live_host.get("hostname")
        or persisted_host.get("boot_id") != live_host.get("boot_id")
        or persisted_disk.get("path") != live_disk.get("path")
    ):
        raise LocalTopologyError("multihop preflight live host identity drift")
    return {
        "preflight_sha256": _sha(preflight_path),
        "preflight_semantic_sha256": str(document["semantic_sha256"]),
        "topology_sha256": topology.source_sha256,
        "identity_manifest_sha256": identity.source_sha256,
        "config_sha256": config_sha,
        "profile_sha256": _sha(profile_path),
        "deployment_sha256": _sha(deployment_path),
        "preregistration_sha256": _sha(preregistration_path),
        "review_gate_sha256": _sha(review_gate_path),
        "review_closure_sha256": review_gate["closure_sha256"],
        "toolchain_preflight_sha256": _sha(toolchain_path),
        "toolchain_preflight_semantic_sha256": str(toolchain["semantic_sha256"]),
    }
