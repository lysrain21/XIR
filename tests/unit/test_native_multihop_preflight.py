from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_deployer import CHAIN_ROLES
from xir_lab.native.multihop_preflight import (
    _require_review_closure,
    _semantic_sha256,
    _validate_trace_probe,
    preregistration_review_payload_sha256,
    verify_multihop_preflight_document,
    verify_multihop_review_gate,
)
from xir_lab.native.multihop_scalability import ROUTE_ORDER


def _write(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_trace_probe_requires_nonempty_root_with_gas() -> None:
    valid = {
        "result": [
            {
                "action": {"callType": "call"},
                "result": {"gasUsed": "0x5208"},
                "traceAddress": [],
                "type": "call",
            }
        ]
    }
    _validate_trace_probe(valid, role="a")

    with pytest.raises(LocalTopologyError, match="empty result"):
        _validate_trace_probe({"result": []}, role="a")
    with pytest.raises(LocalTopologyError, match="one root trace"):
        _validate_trace_probe(
            {"result": [{"result": {"gasUsed": "0x1"}, "traceAddress": [0]}]},
            role="a",
        )
    with pytest.raises(LocalTopologyError, match="root gas"):
        _validate_trace_probe(
            {"result": [{"result": {}, "traceAddress": []}]}, role="a"
        )


def test_review_gate_fails_closed_until_pass_digest_exists(tmp_path: Path) -> None:
    preregistration = {
        "status": "preregistered_local_implementation_pending_review",
        "formal_execution_allowed": False,
        "review_gate": {"closure_audit_path": None, "closure_audit_sha256": None},
    }
    with pytest.raises(LocalTopologyError, match="has not enabled"):
        _require_review_closure(workspace_root=tmp_path, preregistration=preregistration)

    closure_path = tmp_path / "openspec/review-closure.json"
    digest = _write(
        closure_path,
        {
            "verdict": "PASS",
            "blockers": 0,
            "majors": 0,
            "implementation_source_manifest_sha256": "ab" * 32,
        },
    )
    preregistration = {
        "status": "review_closed_formal_execution_allowed",
        "formal_execution_allowed": True,
        "review_gate": {
            "closure_audit_path": "openspec/review-closure.json",
            "closure_audit_sha256": digest,
        },
    }
    closure = _require_review_closure(workspace_root=tmp_path, preregistration=preregistration)
    assert closure["verdict"] == "PASS"


def test_review_gate_rejects_major_findings(tmp_path: Path) -> None:
    closure_path = tmp_path / "review.json"
    digest = _write(closure_path, {"verdict": "FAIL", "blockers": 0, "majors": 1})
    with pytest.raises(LocalTopologyError, match="not PASS"):
        _require_review_closure(
            workspace_root=tmp_path,
            preregistration={
                "status": "review_closed_formal_execution_allowed",
                "formal_execution_allowed": True,
                "review_gate": {
                    "closure_audit_path": "review.json",
                    "closure_audit_sha256": digest,
                },
            },
        )


def test_predeployment_gate_binds_reviewed_source_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "src/reviewed.py"
    source_digest = _write(source, {"reviewed": True})
    deploy_script = repository / "scripts/deploy.sh"
    deploy_digest = _write(deploy_script, {"reviewed": "deployment"})
    contract = repository / "contracts/src/Reviewed.sol"
    contract_digest = _write(contract, {"reviewed": "solidity"})
    protocol_foundry = repository / "protocol-projects/hyperlane-native/foundry.toml"
    protocol_foundry_digest = _write(protocol_foundry, {"profile": "default"})
    protocol_source = repository / "protocol-projects/hyperlane-native/src/Mailbox.sol"
    protocol_source_digest = _write(protocol_source, {"reviewed": "carrier"})
    source_manifest = {
        "contracts/src/Reviewed.sol": contract_digest,
        "protocol-projects/hyperlane-native/foundry.toml": protocol_foundry_digest,
        "protocol-projects/hyperlane-native/src/Mailbox.sol": protocol_source_digest,
        "scripts/deploy.sh": deploy_digest,
        "src/reviewed.py": source_digest,
    }
    source_manifest_digest = hashlib.sha256(rfc8785.dumps(source_manifest)).hexdigest()
    context = tmp_path / "openspec/design.md"
    context_digest = _write(context, {"reviewed": "design and runbook"})
    context_manifest = {"openspec/design.md": context_digest}
    context_manifest_digest = hashlib.sha256(rfc8785.dumps(context_manifest)).hexdigest()
    preregistration_path = tmp_path / "preregistration.json"
    preregistration = {
        "status": "preregistered_local_implementation_pending_review",
        "formal_execution_allowed": False,
        "review_gate": {
            "closure_audit_path": None,
            "closure_audit_sha256": None,
        },
        "implementation_source_sha256": source_manifest,
        "implementation_source_policy": {
            "schema_version": "xir-lab-native-multihop-implementation-source-policy-v1",
            "exact_file_set": True,
            "include_globs": [
                "contracts/src/**/*.sol",
                "protocol-projects/*-native/foundry.toml",
                "protocol-projects/*-native/**/*.sol",
                "scripts/**/*.sh",
                "src/**/*.py",
            ],
        },
        "review_context_sha256": context_manifest,
    }
    preregistration_payload_digest = preregistration_review_payload_sha256(preregistration)
    closure_path = tmp_path / "review.json"
    closure_digest = _write(
        closure_path,
        {
            "verdict": "PASS",
            "blockers": 0,
            "majors": 0,
            "implementation_source_manifest_sha256": source_manifest_digest,
            "review_context_manifest_sha256": context_manifest_digest,
            "preregistration_review_payload_sha256": preregistration_payload_digest,
        },
    )
    preregistration.update(
        {
            "status": "review_closed_formal_execution_allowed",
            "formal_execution_allowed": True,
            "review_gate": {
                "closure_audit_path": "review.json",
                "closure_audit_sha256": closure_digest,
            },
        }
    )
    _write(
        preregistration_path,
        preregistration,
    )
    gate = verify_multihop_review_gate(
        workspace_root=tmp_path,
        repository_root=repository,
        preregistration_path=preregistration_path,
    )
    assert gate["valid"] is True
    source.write_text("drift\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="source digest drift"):
        verify_multihop_review_gate(
            workspace_root=tmp_path,
            repository_root=repository,
            preregistration_path=preregistration_path,
        )
    _write(source, {"reviewed": True})
    unlisted = repository / "src/shared_dependency.py"
    _write(unlisted, {"new": "semantic dependency"})
    with pytest.raises(LocalTopologyError, match="exact policy closure"):
        verify_multihop_review_gate(
            workspace_root=tmp_path,
            repository_root=repository,
            preregistration_path=preregistration_path,
        )
    unlisted.unlink()
    contract.write_text("drift\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="source digest drift"):
        verify_multihop_review_gate(
            workspace_root=tmp_path,
            repository_root=repository,
            preregistration_path=preregistration_path,
        )
    _write(contract, {"reviewed": "solidity"})
    protocol_source.write_text("drift\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="source digest drift"):
        verify_multihop_review_gate(
            workspace_root=tmp_path,
            repository_root=repository,
            preregistration_path=preregistration_path,
        )
    _write(protocol_source, {"reviewed": "carrier"})
    context.write_text("drift\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="design/runbook context digest drift"):
        verify_multihop_review_gate(
            workspace_root=tmp_path,
            repository_root=repository,
            preregistration_path=preregistration_path,
        )


def _offline_preflight_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    repository = tmp_path / "repository"
    repository.mkdir()
    profile = repository / "profile.json"
    _write(profile, {"chains": []})
    config = tmp_path / "config.json"
    _write(config, {"profile": "profile.json"})
    preregistration = tmp_path / "preregistration.json"
    _write(preregistration, {"review_gate": {"closure_audit_sha256": "11" * 32}})
    review_gate = tmp_path / "review-gate.json"
    review_gate_document = {
        "closure_sha256": "11" * 32,
        "implementation_source_manifest_sha256": "22" * 32,
        "source_file_count": 82,
    }
    _write(review_gate, review_gate_document)
    deployment = tmp_path / "deployment.json"
    routes = {
        route: {"hops": [{"protocol": protocol} for protocol in route]} for route in ROUTE_ORDER
    }
    _write(
        deployment,
        {
            "namespace": "native-multihop-switching-v1",
            "runner": "0x" + "11" * 20,
            "root_signer": "0x" + "22" * 20,
            "routes": routes,
        },
    )
    topology = tmp_path / "topology.json"
    identity = tmp_path / "identity.json"
    _write(topology, {})
    _write(identity, {})
    validator_volume_attestation = tmp_path / "validator-volume-bootstrap.json"
    _write(
        validator_volume_attestation,
        {"schema_version": "test", "semantic_sha256": "66" * 32},
    )
    validator_volume_journal = tmp_path / "validator-volume-transaction.json"
    _write(
        validator_volume_journal,
        {"schema_version": "test", "semantic_sha256": "67" * 32},
    )
    toolchain = tmp_path / "runtime/provenance/toolchain-preflight.json"
    toolchain_document = {
        "schema_version": "xir-lab-native-multihop-toolchain-preflight-v1",
        "valid": True,
        "libclang_path": "/lib/libclang-18.so.18",
        "libclang_directory": "/lib",
        "libclang_sha256": "68" * 32,
        "semantic_sha256": "69" * 32,
    }
    _write(toolchain, toolchain_document)
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.verify_toolchain_preflight",
        lambda _path, **_kwargs: toolchain_document,
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.load_multihop_topology",
        lambda _path: SimpleNamespace(source_sha256="33" * 32),
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.load_multihop_identity_manifest",
        lambda _path, topology: SimpleNamespace(source_sha256="44" * 32),
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.load_multihop_config",
        lambda _path: ({"profile": "profile.json"}, "55" * 32),
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.verify_multihop_review_gate",
        lambda **_kwargs: review_gate_document,
    )
    process_names = {
        *(f"validator-xirlocalchain{role}" for role in CHAIN_ROLES),
        "relayer",
        "layerzero-worker",
    }
    document = {
        "schema_version": "xir-lab-native-multihop-preflight-v1",
        "namespace": "native-multihop-switching-v1",
        "valid": True,
        "credentials_included": False,
        "topology_sha256": "33" * 32,
        "identity_manifest_sha256": "44" * 32,
        "validator_volume_attestation_sha256": hashlib.sha256(
            validator_volume_attestation.read_bytes()
        ).hexdigest(),
        "validator_volume_attestation_semantic_sha256": "66" * 32,
        "validator_volume_journal_sha256": hashlib.sha256(
            validator_volume_journal.read_bytes()
        ).hexdigest(),
        "validator_volume_journal_semantic_sha256": "67" * 32,
        "validator_volume_count": 20,
        "toolchain_preflight_sha256": hashlib.sha256(toolchain.read_bytes()).hexdigest(),
        "toolchain_preflight_semantic_sha256": "69" * 32,
        "config_sha256": "55" * 32,
        "profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(deployment.read_bytes()).hexdigest(),
        "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        "review_gate_sha256": hashlib.sha256(review_gate.read_bytes()).hexdigest(),
        "review_closure_sha256": "11" * 32,
        "review_closure_source_manifest_sha256": "22" * 32,
        "source_file_count": 82,
        "route_hop_checks": sum(len(route) for route in ROUTE_ORDER),
        "layerzero_effective_path_checks": 2 * sum(route.count("L") for route in ROUTE_ORDER),
        "chain_checks": [
            {
                "role": role,
                "validator_count": 4,
                "trace_transaction_available": True,
                "raw_transaction_retrieval_available": True,
            }
            for role in CHAIN_ROLES
        ],
        "process_checks": {name: True for name in process_names},
        "host_snapshot": {
            "hostname": platform.node(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
            "runtime_disk": {"path": str((tmp_path / "runtime").resolve())},
        },
        "signer_roles_distinct": True,
    }
    document["semantic_sha256"] = _semantic_sha256(document)
    preflight = tmp_path / "preflight.json"
    _write(preflight, document)
    live_document = json.loads(json.dumps(document))
    monkeypatch.setattr(
        "xir_lab.native.multihop_preflight.run_multihop_preflight",
        lambda **_kwargs: live_document,
    )
    return {
        "workspace_root": tmp_path,
        "repository_root": repository,
        "runtime_root": tmp_path / "runtime",
        "topology_path": topology,
        "identity_path": identity,
        "config_path": config,
        "deployment_path": deployment,
        "preregistration_path": preregistration,
        "review_gate_path": review_gate,
        "preflight_path": preflight,
        "validator_volume_attestation_path": validator_volume_attestation,
        "validator_volume_journal_path": validator_volume_journal,
    }


def test_offline_preflight_verifier_rejects_forged_and_stale_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _offline_preflight_fixture(tmp_path, monkeypatch)
    verified = verify_multihop_preflight_document(**arguments)
    assert verified["config_sha256"] == "55" * 32
    preflight = arguments["preflight_path"]
    original = json.loads(preflight.read_text(encoding="utf-8"))
    for key, value, expected in (
        ("semantic_sha256", "00" * 32, "semantic"),
        ("deployment_sha256", "00" * 32, "deployment"),
        ("config_sha256", "00" * 32, "config"),
    ):
        tampered = dict(original)
        tampered[key] = value
        if key != "semantic_sha256":
            tampered["semantic_sha256"] = _semantic_sha256(tampered)
        _write(preflight, tampered)
        with pytest.raises(LocalTopologyError, match=expected):
            verify_multihop_preflight_document(**arguments)
    _write(preflight, {"valid": True, "review_closure_sha256": "11" * 32})
    with pytest.raises(LocalTopologyError, match="preflight document invalid"):
        verify_multihop_preflight_document(**arguments)


def test_preflight_verifier_requires_fresh_live_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _offline_preflight_fixture(tmp_path, monkeypatch)

    def unavailable(**_kwargs: object) -> dict[str, object]:
        raise LocalTopologyError("native carrier processes are not all alive")

    monkeypatch.setattr("xir_lab.native.multihop_preflight.run_multihop_preflight", unavailable)
    with pytest.raises(LocalTopologyError, match="processes are not all alive"):
        verify_multihop_preflight_document(**arguments)
