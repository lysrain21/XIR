from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xir_lab.cli import run
from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.approvals import (
    APPROVAL_DOMAIN,
    REVOCATION_DOMAIN,
    ApprovalVerifier,
    PinnedApprovalKey,
    canonical_payload_digest,
    signature_message,
)
from xir_lab.execute.live_commands import (
    LiveCommandPaths,
    LiveDispatchResult,
    dispatch_live,
    load_live_context,
)
from xir_lab.live import LIVE_DISABLE_ENV, LIVE_FEATURE_ENV, LIVE_FEATURE_VERSION

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_CONFIG = ROOT / "tests" / "fixtures" / "config" / "lab-config.json"
DIGEST = "11" * 32
NETWORKS = (
    ("op-sepolia", 11_155_420),
    ("arbitrum-sepolia", 421_614),
    ("base-sepolia", 84_532),
)


def _write(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _profile() -> dict[str, Any]:
    return {
        "schema_version": "xir-lab-execution-profile-v1",
        "profile_id": "live-pilot-fixture",
        "profile_version": 1,
        "profile_mode": "live",
        "profile_kind": "pilot",
        "approval_operation_type": "pilot",
        "fixed_seed": "12" * 32,
        "conditions": ["HH", "HL", "LH", "LL"],
        "counts": {
            "pair_slots_per_condition": 5,
            "planned_pair_slots": 20,
            "designated_attempt_kind": "pilot",
            "planned_designated_attempts": 40,
            "warmups_per_condition_arm": 0,
            "planned_warmup_attempts": 0,
            "planned_total_non_retry_attempts": 40,
            "retry_attempts_in_designated_count": False,
        },
        "live_limits": {
            "max_retries_per_lineage": 1,
            "max_batch_attempts": 4,
            "max_duration_seconds": 3600,
            "max_in_flight_attempts": 2,
            "chain_budget_wei": {
                "11155420": 1000,
                "421614": 2000,
                "84532": 3000,
            },
            "stop_policy": {
                "consecutive_failures": 3,
                "rolling_window": 10,
                "rolling_failure_rate": 0.3,
                "timeout_count": 3,
                "collector_backlog": 10,
                "collector_heartbeat_seconds": 30,
                "disk_floor_bytes": 1_073_741_824,
            },
            "allow_partial_conditions": False,
        },
        "derived_from": {
            "kind": "none",
            "run_id": None,
            "freeze_sha256": None,
            "reconciled": None,
        },
    }


def _preflight() -> dict[str, Any]:
    return {
        "schema_version": "xir-lab-preflight-experiment-v1",
        "operation_type": "pilot",
        "operation_id": "pilot-operation-1",
        "approval_id": "pilot-approval-1",
        "network_identity_sha256": "21" * 32,
        "deployment_sha256": "22" * 32,
        "profile_sha256": "",
        "contracts": [
            {
                "contract_id": f"gateway-{network}",
                "network_id": network,
                "address": f"0x{index + 1:040x}",
                "runtime_code_sha256": "23" * 32,
                "administrator": "0x" + "aa" * 20,
                "active_runner": "0x" + "bb" * 20,
                "outbound_paused": False,
                "route_profile_state_sha256": "24" * 32,
            }
            for index, (network, _) in enumerate(NETWORKS)
        ],
        "carrier_routes": [
            {
                "route_id": f"{protocol}-{local}-{remote}",
                "protocol": protocol,
                "local_network": local,
                "remote_network": remote,
                "endpoint_address": f"0x{index + 10:040x}",
                "peer_address": f"0x{index + 20:040x}",
                "remote_selector": index + 1,
                "security_config_sha256": "25" * 32,
            }
            for index, (local, remote, protocol) in enumerate(
                (
                    ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
                    ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
                    ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
                    ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
                )
            )
        ],
    }


def _approval_payload(
    *,
    config_sha256: str,
    profile_sha256: str,
    operation_type: str = "pilot",
    operation_id: str = "pilot-operation-1",
    valid: bool = True,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    valid_from = now - timedelta(minutes=5)
    valid_until = now + timedelta(hours=1) if valid else now - timedelta(minutes=1)
    issued_at = valid_from - timedelta(minutes=1)
    return {
        "approval_id": "pilot-approval-1",
        "issuer_id": "fixture-issuer",
        "approval_key_id": "fixture-approval-key",
        "issuer_sequence": 1,
        "operation_type": operation_type,
        "operation_id": operation_id,
        "run_id": "fixture-live-run",
        "issued_at": issued_at.isoformat(),
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat(),
        "expected_pre_state_sha256": "33" * 32,
        "authorized_transition_sha256": "43" + "33" * 31,
        "config_sha256": config_sha256,
        "profile_sha256": profile_sha256,
        "code_sha256": DIGEST,
        "schema_sha256": DIGEST,
        "deployment_sha256": "22" * 32,
        "signer_identity_sha256": DIGEST,
        "network_identity_sha256": "21" * 32,
        "addresses": {
            "deployer_administrator": "0x" + "aa" * 20,
            "runner": "0x" + "bb" * 20,
        },
        "networks": [
            {
                "network_id": network,
                "chain_id": chain_id,
                "checkpoint_sha256": DIGEST,
            }
            for network, chain_id in NETWORKS
        ],
        "deployment_ids": ["fixture-deployment"],
        "condition_scope": ["HH", "HL", "LH", "LL"],
        "planned_counts": {
            "pair_slots": 20,
            "designated_attempts": 40,
            "warmup_attempts": 0,
        },
        "max_retries_per_lineage": 1,
        "max_concurrency": 2,
        "allow_partial_conditions": False,
        "stop_policy_sha256": DIGEST,
        "per_chain_limits": {
            "11155420": 1000,
            "421614": 2000,
            "84532": 3000,
        },
    }


def _sign(
    private: Ed25519PrivateKey,
    payload: dict[str, Any],
) -> dict[str, Any]:
    digest = canonical_payload_digest(payload)
    return {
        "schema_version": "xir-lab-approval-envelope-v1",
        "payload": payload,
        "payload_sha256": digest,
        "signature": private.sign(signature_message(APPROVAL_DOMAIN, digest)).hex(),
    }


def _fixture(
    tmp_path: Path,
) -> tuple[list[str], Ed25519PrivateKey, PinnedApprovalKey, EvidenceStore, dict[str, Path]]:
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    config = json.loads(FIXTURE_CONFIG.read_text(encoding="utf-8"))
    config["signers"][2]["public_identity"] = f"ed25519:{public_hex}"
    config_path = _write(tmp_path / "config.json", config)

    profile_path = _write(tmp_path / "profile.json", _profile())
    profile_sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    preflight = _preflight()
    preflight["profile_sha256"] = profile_sha256
    preflight_path = _write(tmp_path / "preflight.json", preflight)

    config_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()
    approval_path = _write(
        tmp_path / "approval.json",
        _sign(
            private,
            _approval_payload(
                config_sha256=config_sha256,
                profile_sha256=profile_sha256,
            ),
        ),
    )
    run_dir = tmp_path / "run"
    store = EvidenceStore(run_dir / "evidence.sqlite", run_dir / "raw")
    store.initialize()
    paths = {
        "config": config_path,
        "profile": profile_path,
        "preflight": preflight_path,
        "approval": approval_path,
        "run_dir": run_dir,
    }
    args = [
        "pilot-run",
        "--live",
        "--config",
        str(config_path),
        "--profile",
        str(profile_path),
        "--run-dir",
        str(run_dir),
        "--preflight",
        str(preflight_path),
        "--approval",
        str(approval_path),
    ]
    return (
        args,
        private,
        PinnedApprovalKey("fixture-issuer", "fixture-approval-key", public_hex),
        store,
        paths,
    )


@pytest.fixture(autouse=True)
def _enable_live_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(LIVE_DISABLE_ENV, raising=False)
    monkeypatch.setenv(LIVE_FEATURE_ENV, LIVE_FEATURE_VERSION)


def test_first_invocation_emits_exact_zero_signature_confirmation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, _, _, store, _ = _fixture(tmp_path)
    assert run(args) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "confirmation_required"
    assert result["confirmation_id"].startswith("confirm_")
    confirmation = result["confirmation"]
    assert confirmation["operation_id"] == "pilot-operation-1"
    assert confirmation["transaction_count_bound"] == {"minimum": 40, "maximum": 80}
    assert set(confirmation["signers"]) == {"deployer", "runner"}
    assert len(confirmation["chains"]) == 3
    assert confirmation["effects"] == {"signatures": 0, "broadcasts": 0}
    with store.connect(read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM approval_consumptions").fetchone()[0] == 0


def test_repeated_invocation_requires_exact_confirmation_and_reaches_only_boundary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, _, _, _, _ = _fixture(tmp_path)
    assert run(args) == 3
    first = json.loads(capsys.readouterr().out)
    assert run([*args, "--confirmation-id", "confirm_" + "0" * 64]) == 2
    stale = json.loads(capsys.readouterr().out)
    assert "stale" in stale["reason_code"]
    assert run([*args, "--confirmation-id", first["confirmation_id"]]) == 2
    confirmed = json.loads(capsys.readouterr().out)
    assert confirmed["implementation_status"] == "confirmed_dispatch_boundary"
    assert confirmed["reason_code"] == "operation_backend_not_implemented"
    assert set(confirmed["effects"].values()) == {0}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("wrong_type", "operation type"),
        ("unknown_operation", "operation IDs differ"),
        ("expired", "currently valid"),
        ("changed_profile", "profile digest"),
    ),
)
def test_changed_unknown_expired_and_cross_type_inputs_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
    reason: str,
) -> None:
    args, private, _, _, paths = _fixture(tmp_path)
    approval = json.loads(paths["approval"].read_text(encoding="utf-8"))
    payload = approval["payload"]
    if mutation == "wrong_type":
        payload["operation_type"] = "configuration"
    elif mutation == "unknown_operation":
        payload["operation_id"] = "unknown-operation"
    elif mutation == "expired":
        payload["valid_until"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    else:
        profile = json.loads(paths["profile"].read_text(encoding="utf-8"))
        profile["fixed_seed"] = "99" * 32
        _write(paths["profile"], profile)
    if mutation != "changed_profile":
        _write(paths["approval"], _sign(private, payload))

    assert run(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert reason in result["reason_code"]
    assert set(result["effects"].values()) == {0}


def test_revoked_and_consumed_approvals_fail_before_dispatch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, private, pinned, store, paths = _fixture(tmp_path)
    verifier = ApprovalVerifier(store=store, pinned_keys=(pinned,))
    revocation_payload = {
        "revocation_id": "fixture-revocation-2",
        "approval_id": "pilot-approval-1",
        "issuer_id": "fixture-issuer",
        "approval_key_id": "fixture-approval-key",
        "issuer_sequence": 2,
        "revoked_at": datetime.now(UTC).isoformat(),
        "reason": "fixture revocation",
    }
    revocation_digest = hashlib.sha256(rfc8785.dumps(revocation_payload)).hexdigest()
    verifier.verify_and_record_revocation(
        {
            "schema_version": "xir-lab-revocation-record-v1",
            "payload": revocation_payload,
            "payload_sha256": revocation_digest,
            "signature": private.sign(
                signature_message(REVOCATION_DOMAIN, revocation_digest)
            ).hex(),
        }
    )
    assert run(args) == 2
    revoked = json.loads(capsys.readouterr().out)
    assert "revoked" in revoked["reason_code"]

    second_root = tmp_path / "consumed"
    args, _, pinned, store, paths = _fixture(second_root)
    verifier = ApprovalVerifier(store=store, pinned_keys=(pinned,))
    verifier.verify_and_consume(
        json.loads(paths["approval"].read_text(encoding="utf-8"))
    )
    assert run(args) == 2
    consumed = json.loads(capsys.readouterr().out)
    assert "consumed" in consumed["reason_code"]


@pytest.mark.parametrize("command", ("deploy", "configure", "pilot-run", "closeout"))
def test_every_state_backend_is_unreachable_until_exact_confirmation(
    tmp_path: Path,
    command: str,
) -> None:
    _, _, _, _, paths = _fixture(tmp_path)
    context = load_live_context(
        "pilot-run",
        LiveCommandPaths(
            config=paths["config"],
            profile=paths["profile"],
            run_dir=paths["run_dir"],
            preflight=paths["preflight"],
            approval=paths["approval"],
        ),
    )

    class Backend:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, context) -> LiveDispatchResult:
            self.calls += 1
            return LiveDispatchResult("started", "fixture", "mock-backend")

    backend = Backend()
    first = dispatch_live(
        replace(context, command=command),
        confirmation_id=None,
        state_change_backend=backend,
    )
    assert first.outcome == "confirmation_required"
    assert backend.calls == 0
    if command != "pilot-run":
        return
    confirmed = dispatch_live(
        context,
        confirmation_id=context.confirmation_id,
        state_change_backend=backend,
    )
    assert confirmed.outcome == "started"
    assert backend.calls == 1
