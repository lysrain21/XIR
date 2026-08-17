from __future__ import annotations

import json
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import (
    FORMAL_COMPONENTS,
    LayerZeroMessageEvidence,
    build_dvn_instruction,
    decode_packet,
    encode_commit_verification,
    encode_dvn_execute,
    encode_executor_submission,
    executor_lz_receive_options,
    reconcile_layerzero_message,
    verify_formal_component_set,
)


def _packet() -> bytes:
    sender = bytes.fromhex("00" * 12 + "11" * 20)
    receiver = bytes.fromhex("00" * 12 + "22" * 20)
    return (
        b"\x01"
        + (7).to_bytes(8, "big")
        + (49001).to_bytes(4, "big")
        + sender
        + (49002).to_bytes(4, "big")
        + receiver
        + bytes.fromhex("33" * 32)
        + b"matched-payload"
    )


def test_packet_codec_and_options_match_official_packed_layout() -> None:
    packet = decode_packet(_packet())
    assert packet.nonce == 7
    assert packet.source_eid == 49001
    assert packet.destination_eid == 49002
    assert packet.receiver_address == "0x" + "22" * 20
    assert packet.payload_hash == keccak(packet.guid + packet.message)
    options = executor_lz_receive_options(1_500_000)
    assert options[:6] == bytes.fromhex("000301001101")
    assert int.from_bytes(options[6:], "big") == 1_500_000


def test_dvn_instruction_uses_official_hash_and_eth_signed_message() -> None:
    account = Account.create("xir-layerzero-test")
    packet = decode_packet(_packet())
    instruction = build_dvn_instruction(
        vid=49002,
        receive_uln_address="0x" + "44" * 20,
        packet=packet,
        confirmations=1,
        expiration=2_000_000_000,
        signer_private_key=account.key.hex(),
    )
    expected = keccak(
        (49002).to_bytes(4, "big")
        + bytes.fromhex("44" * 20)
        + (2_000_000_000).to_bytes(32, "big")
        + instruction.call_data
    )
    assert instruction.instruction_hash == expected
    recovered = Account.recover_message(
        encode_defunct(primitive=expected), signature=instruction.signature
    )
    assert recovered == account.address
    assert encode_dvn_execute(instruction)[:4] == keccak(
        text="execute((uint32,address,bytes,uint256,bytes)[])"
    )[:4]
    assert encode_commit_verification(packet)[:4] == keccak(
        text="commitVerification(bytes,bytes32)"
    )[:4]
    assert encode_executor_submission(packet, 1_500_000)[:4] == keccak(
        text="execute302((address,(uint32,bytes32,uint64),bytes32,bytes,bytes,uint256))"
    )[:4]


def test_formal_component_gate_rejects_missing_or_mock() -> None:
    verify_formal_component_set(set(FORMAL_COMPONENTS))
    with pytest.raises(LocalTopologyError, match="lacks"):
        verify_formal_component_set(set(FORMAL_COMPONENTS) - {"DVN"})
    with pytest.raises(LocalTopologyError, match="mock"):
        verify_formal_component_set(set(FORMAL_COMPONENTS) | {"EndpointV2Mock"})


def test_gap_free_layerzero_reconciliation() -> None:
    complete = LayerZeroMessageEvidence(
        guid="0x" + "11" * 32,
        nonce=1,
        packet_sent_transaction="0xsent",
        encoded_packet_sha256="22" * 32,
        source_confirmation_block=10,
        dvn_instruction_hash="0x" + "33" * 32,
        dvn_signature_sha256="44" * 32,
        payload_verified_transaction="0xpayload",
        packet_verified_transaction="0xverified",
        executor_transaction="0xexecutor",
        packet_delivered_transaction="0xdelivered",
    )
    reconcile_layerzero_message(complete)
    with pytest.raises(LocalTopologyError, match="incomplete"):
        reconcile_layerzero_message(
            LayerZeroMessageEvidence(
                **{**complete.__dict__, "packet_delivered_transaction": ""}
            )
        )


def test_import_only_project_does_not_vendor_upstream_implementation() -> None:
    project = Path(__file__).parents[2] / "protocol-projects" / "layerzero-native"
    solidity = list((project / "src").rglob("*.sol")) + list(
        (project / "script").rglob("*.sol")
    )
    assert {path.name for path in solidity} == {
        "ProjectMarker.sol",
        "DeployLayerZeroNative.s.sol",
    }


def test_five_chain_deployer_passes_every_frozen_profile_eid_to_forge() -> None:
    repository = Path(__file__).parents[2]
    profile = json.loads(
        (repository / "configs/profiles/native-multihop-five-chain-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert [chain["layerzero_eid"] for chain in profile["chains"]] == [
        49001,
        49002,
        49003,
        49004,
        49005,
    ]
    deployer = (repository / "scripts/deploy_layerzero_native.sh").read_text(
        encoding="utf-8"
    )
    for role in "ABCDE":
        assert f'export LZ_EID_{role}=' in deployer
    assert "LayerZero deployment requires exactly five profile EIDs" in deployer
    assert "LayerZero profile EIDs must be unique" in deployer
    assert '[[ ${lz_labels[*]} == "A B C D E" ]]' in deployer
