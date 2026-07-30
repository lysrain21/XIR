from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.hyperlane import (
    CHAIN_NAMES,
    EVENT_TOPICS,
    HyperlaneMessageEvidence,
    HyperlanePublicIdentities,
    capture_hyperlane_deployment_evidence,
    classify_hyperlane_receipt_logs,
    reconcile_hyperlane_message,
    render_hyperlane_agent_configs,
    render_hyperlane_deployment_inputs,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs" / "profiles" / "native-protocol-stack-v1.json"
ADDRESS = "0x1111111111111111111111111111111111111111"
DIGEST = "ab" * 32


def _identities() -> HyperlanePublicIdentities:
    return HyperlanePublicIdentities(ADDRESS, ADDRESS, ADDRESS)


def test_hyperlane_deployment_inputs_are_deterministic_and_secret_free(
    tmp_path: Path,
) -> None:
    first = render_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=_identities(), runtime_root=tmp_path
    )
    second = render_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=_identities(), runtime_root=tmp_path
    )
    assert first == second
    assert first["semantic_sha256"] == second["semantic_sha256"]
    for name in CHAIN_NAMES:
        core = yaml.safe_load(
            (tmp_path / "hyperlane" / "core" / f"{name}.yaml").read_text()
        )
        assert core["defaultIsm"]["type"] == "messageIdMultisigIsm"
        assert core["defaultIsm"]["threshold"] == 1
        assert core["defaultHook"]["protocolFee"] == "0"
        assert core["requiredHook"]["type"] == "merkleTreeHook"
    assert "private" not in json.dumps(first).lower()


def test_hyperlane_agent_configs_require_official_deployment_addresses(
    tmp_path: Path,
) -> None:
    render_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=_identities(), runtime_root=tmp_path
    )
    registry = tmp_path / "hyperlane" / "registry"
    for name in CHAIN_NAMES:
        path = registry / "chains" / name / "addresses.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "mailbox": ADDRESS,
                    "interchainGasPaymaster": ADDRESS,
                    "validatorAnnounce": ADDRESS,
                    "merkleTreeHook": ADDRESS,
                }
            )
        )
    manifest = render_hyperlane_agent_configs(
        profile_path=PROFILE, runtime_root=tmp_path
    )
    assert manifest["secret_free"] is True
    relayer = json.loads(
        (
            tmp_path / "hyperlane" / "agents" / "config" / "relayer.json"
        ).read_text()
    )
    assert relayer["allowLocalCheckpointSyncers"] is True
    assert relayer["gasPaymentEnforcement"] == [{"type": "none"}]
    assert "signer" not in relayer


def test_hyperlane_official_events_are_classified_and_gap_checked() -> None:
    receipt = {
        "transactionHash": "0x" + "11" * 32,
        "logs": [
            {
                "logIndex": "0x2",
                "address": ADDRESS,
                "topics": [EVENT_TOPICS["dispatch_id"], "0x" + "22" * 32],
                "data": "0x",
            }
        ],
    }
    classified = classify_hyperlane_receipt_logs(receipt)
    assert classified[0]["event"] == "dispatch_id"
    assert classified[0]["log_index"] == 2

    complete = HyperlaneMessageEvidence(
        message_id="0x" + "22" * 32,
        dispatch_transaction="0x" + "11" * 32,
        dispatch_log_index=2,
        inserted_log_index=3,
        checkpoint_sha256=DIGEST,
        validator_signature_sha256=DIGEST,
        relayer_decision_sha256=DIGEST,
        process_transaction="0x" + "33" * 32,
        process_log_index=1,
    )
    reconcile_hyperlane_message(complete)
    with pytest.raises(LocalTopologyError, match="incomplete"):
        reconcile_hyperlane_message(
            HyperlaneMessageEvidence(**{**complete.__dict__, "process_transaction": ""})
        )


def test_hyperlane_deployment_capture_verifies_transactions_code_and_domain(
    tmp_path: Path,
) -> None:
    render_hyperlane_deployment_inputs(
        profile_path=PROFILE, identities=_identities(), runtime_root=tmp_path
    )
    registry = tmp_path / "hyperlane" / "registry"
    for name in CHAIN_NAMES:
        path = registry / "chains" / name / "addresses.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "mailbox": ADDRESS,
                    "interchainGasPaymaster": ADDRESS,
                    "validatorAnnounce": ADDRESS,
                    "merkleTreeHook": ADDRESS,
                }
            )
        )

    domains = {
        "http://127.0.0.1:18545": 3133701,
        "http://127.0.0.1:28545": 3133702,
        "http://127.0.0.1:38545": 3133703,
    }

    def fake_rpc(url: str, method: str, params: list[object]) -> object:
        if method == "eth_blockNumber":
            return "0x1"
        if method == "eth_getBlockByNumber":
            return {
                "transactions": [
                    {
                        "from": ADDRESS,
                        "hash": "0x" + str(domains[url])[-2:].zfill(2) * 32,
                    }
                ]
            }
        if method == "eth_getTransactionReceipt":
            return {
                "blockNumber": "0x1",
                "status": "0x1",
                "contractAddress": ADDRESS,
                "logs": [],
            }
        if method == "eth_getCode":
            return "0x6000"
        if method == "eth_call":
            return hex(domains[url])
        raise AssertionError((url, method, params))

    evidence = capture_hyperlane_deployment_evidence(
        profile_path=PROFILE,
        runtime_root=tmp_path,
        owner_address=ADDRESS,
        start_blocks={name: 1 for name in CHAIN_NAMES},
        rpc_call=fake_rpc,
    )
    assert len(evidence["chains"]) == 3
    assert all(chain["transactions"][0]["status"] == 1 for chain in evidence["chains"])
