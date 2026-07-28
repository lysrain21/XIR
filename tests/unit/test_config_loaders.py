from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from xir_lab.config import (
    ConfigError,
    load_approval_envelope,
    load_lab_config,
    load_run_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests/fixtures/config"


def _load_fixture() -> dict[str, Any]:
    value = json.loads((FIXTURES / "lab-config.json").read_text())
    assert isinstance(value, dict)
    return value


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(json.dumps(value))
    return path


def test_lab_config_loads_as_typed_fixed_route() -> None:
    config = load_lab_config(
        FIXTURES / "lab-config.json",
        schema_path=SCHEMAS / "lab-config-v1.schema.json",
    )
    assert config.config_id == "fixture-lab-config"
    assert [network.chain_id for network in config.networks] == [11155420, 421614, 84532]
    assert {
        (endpoint.local_network, endpoint.remote_network, endpoint.protocol)
        for endpoint in config.deployment.carrier_endpoints
    } == {
        ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
        ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
        ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
        ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
    }
    assert len(config.source_sha256) == 64


def test_wrong_chain_identity_is_rejected(tmp_path: Path) -> None:
    document = _load_fixture()
    document["networks"][0]["chain_id"] = 1
    path = _write_json(tmp_path / "config.json", document)
    with pytest.raises(ConfigError, match="network identity"):
        load_lab_config(path, schema_path=SCHEMAS / "lab-config-v1.schema.json")


def test_deployer_and_runner_must_be_distinct(tmp_path: Path) -> None:
    document = _load_fixture()
    document["signers"][1]["public_identity"] = document["signers"][0]["public_identity"]
    path = _write_json(tmp_path / "config.json", document)
    with pytest.raises(ConfigError, match="must be distinct"):
        load_lab_config(path, schema_path=SCHEMAS / "lab-config-v1.schema.json")


def test_payload_digest_is_verified(tmp_path: Path) -> None:
    document = _load_fixture()
    document["payload_effect"]["payload_sha256"] = "0" * 64
    path = _write_json(tmp_path / "config.json", document)
    with pytest.raises(ConfigError, match="payload_sha256"):
        load_lab_config(path, schema_path=SCHEMAS / "lab-config-v1.schema.json")


def test_all_six_approval_operations_are_required(tmp_path: Path) -> None:
    document = _load_fixture()
    document["approval_requirements"][-1] = copy.deepcopy(document["approval_requirements"][0])
    path = _write_json(tmp_path / "config.json", document)
    with pytest.raises(ConfigError, match="all six operation types"):
        load_lab_config(path, schema_path=SCHEMAS / "lab-config-v1.schema.json")


def test_approval_loader_checks_canonical_payload_digest(tmp_path: Path) -> None:
    digest = "1" * 64
    payload: dict[str, Any] = {
        "approval_id": "fixture-approval",
        "issuer_id": "fixture-issuer",
        "approval_key_id": "fixture-key",
        "issuer_sequence": 1,
        "operation_type": "pilot",
        "operation_id": "fixture-operation",
        "run_id": "fixture-run",
        "issued_at": "2026-07-25T00:00:00Z",
        "valid_from": "2026-07-25T00:00:00Z",
        "valid_until": "2026-07-25T01:00:00Z",
        "expected_pre_state_sha256": digest,
        "authorized_transition_sha256": digest,
        "config_sha256": digest,
        "profile_sha256": digest,
        "code_sha256": digest,
        "schema_sha256": digest,
        "deployment_sha256": digest,
        "signer_identity_sha256": digest,
        "network_identity_sha256": digest,
        "addresses": {
            "deployer_administrator": "0x" + "22" * 20,
            "runner": "0x" + "33" * 20,
        },
        "networks": [
            {
                "network_id": network,
                "chain_id": chain_id,
                "checkpoint_sha256": digest,
            }
            for network, chain_id in (
                ("op-sepolia", 11_155_420),
                ("arbitrum-sepolia", 421_614),
                ("base-sepolia", 84_532),
            )
        ],
        "deployment_ids": ["deployment-1"],
        "condition_scope": ["HH", "HL", "LH", "LL"],
        "planned_counts": {
            "pair_slots": 20,
            "designated_attempts": 40,
            "warmup_attempts": 0,
        },
        "max_retries_per_lineage": 1,
        "max_concurrency": 2,
        "allow_partial_conditions": False,
        "stop_policy_sha256": digest,
        "per_chain_limits": {"11155420": 1000},
    }
    payload_digest = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    envelope = {
        "schema_version": "xir-lab-approval-envelope-v1",
        "payload": payload,
        "payload_sha256": payload_digest,
        "signature": "2" * 128,
    }
    path = _write_json(tmp_path / "approval.json", envelope)

    approval = load_approval_envelope(
        path,
        schema_path=SCHEMAS / "approval-envelope-v1.schema.json",
    )
    assert approval.operation_type == "pilot"
    assert approval.payload_sha256 == payload_digest

    envelope["payload_sha256"] = "0" * 64
    _write_json(path, envelope)
    with pytest.raises(ConfigError, match="RFC 8785"):
        load_approval_envelope(
            path,
            schema_path=SCHEMAS / "approval-envelope-v1.schema.json",
        )


def test_run_manifest_loader_requires_all_conditions() -> None:
    manifest = load_run_manifest(
        FIXTURES / "run-manifest.json",
        schema_path=SCHEMAS / "run-manifest-v1.schema.json",
    )
    assert manifest.run_id == "fixture-run"
    assert manifest.profile_id == "fixture-profile"
