"""Pinned official LayerZero V2 packet, deployment, and worker primitives."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, cast

from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.rpc import qbft_web3

PACKET_HEADER_BYTES = 81
PACKET_GUID_OFFSET = 81
PACKET_MESSAGE_OFFSET = 113
PACKET_VERSION = 1
FORMAL_COMPONENTS = frozenset(
    {
        "EndpointV2",
        "SendUln302",
        "ReceiveUln302",
        "DVN",
        "Executor",
        "PriceFeed",
        "DVNFeeLib",
        "ExecutorFeeLib",
        "Treasury",
        "ERC1967Proxy",
    }
)
FORBIDDEN_COMPONENTS = frozenset(
    {
        "TestIsm",
        "MockMailbox",
        "EndpointV2Mock",
        "SendUln302Mock",
        "ReceiveUln302Mock",
        "DVNMock",
        "ExecutorMock",
        "SimpleMessageLib",
    }
)
EVENT_TOPICS = {
    "packet_sent": "0x" + keccak(text="PacketSent(bytes,bytes,address)").hex(),
    "payload_verified": "0x"
    + keccak(text="PayloadVerified(address,bytes,uint256,bytes32)").hex(),
    "packet_verified": "0x"
    + keccak(text="PacketVerified((uint32,bytes32,uint64),address,bytes32)").hex(),
    "packet_delivered": "0x"
    + keccak(text="PacketDelivered((uint32,bytes32,uint64),address)").hex(),
}


@dataclass(frozen=True)
class LayerZeroPacket:
    encoded: bytes
    header: bytes
    version: int
    nonce: int
    source_eid: int
    sender: bytes
    destination_eid: int
    receiver: bytes
    guid: bytes
    message: bytes
    payload_hash: bytes

    @property
    def receiver_address(self) -> str:
        if any(self.receiver[:12]):
            raise LocalTopologyError("LayerZero receiver is not an EVM bytes32 address")
        return "0x" + self.receiver[12:].hex()


@dataclass(frozen=True)
class DVNInstruction:
    vid: int
    target: str
    call_data: bytes
    expiration: int
    instruction_hash: bytes
    signature: bytes


@dataclass(frozen=True)
class LayerZeroMessageEvidence:
    guid: str
    nonce: int
    packet_sent_transaction: str
    encoded_packet_sha256: str
    source_confirmation_block: int
    dvn_instruction_hash: str
    dvn_signature_sha256: str
    payload_verified_transaction: str
    packet_verified_transaction: str
    executor_transaction: str
    packet_delivered_transaction: str


def decode_packet(encoded: bytes) -> LayerZeroPacket:
    """Decode the official PacketV1Codec packed wire format."""

    if len(encoded) < PACKET_MESSAGE_OFFSET:
        raise LocalTopologyError("LayerZero packet is shorter than PacketV1Codec")
    if encoded[0] != PACKET_VERSION:
        raise LocalTopologyError("LayerZero packet version is not V1")
    receiver = encoded[49:81]
    packet = LayerZeroPacket(
        encoded=encoded,
        header=encoded[:PACKET_HEADER_BYTES],
        version=encoded[0],
        nonce=int.from_bytes(encoded[1:9], "big"),
        source_eid=int.from_bytes(encoded[9:13], "big"),
        sender=encoded[13:45],
        destination_eid=int.from_bytes(encoded[45:49], "big"),
        receiver=receiver,
        guid=encoded[PACKET_GUID_OFFSET:PACKET_MESSAGE_OFFSET],
        message=encoded[PACKET_MESSAGE_OFFSET:],
        payload_hash=keccak(encoded[PACKET_GUID_OFFSET:]),
    )
    packet.receiver_address
    return packet


def executor_lz_receive_options(gas_limit: int) -> bytes:
    """Build official Type-3 Executor LZ_RECEIVE options with zero native value."""

    if gas_limit <= 0 or gas_limit >= 2**128:
        raise LocalTopologyError("LayerZero executor gas limit is out of uint128 range")
    return (
        (3).to_bytes(2, "big")
        + (1).to_bytes(1, "big")
        + (17).to_bytes(2, "big")
        + (1).to_bytes(1, "big")
        + gas_limit.to_bytes(16, "big")
    )


def build_dvn_instruction(
    *,
    vid: int,
    receive_uln_address: str,
    packet: LayerZeroPacket,
    confirmations: int,
    expiration: int,
    signer_private_key: str,
) -> DVNInstruction:
    """Build and sign the exact official DVN.execute verification instruction."""

    if not 0 < vid < 2**32:
        raise LocalTopologyError("LayerZero DVN vid is out of range")
    if not 0 <= confirmations < 2**64:
        raise LocalTopologyError("LayerZero confirmations are out of range")
    if expiration <= 0:
        raise LocalTopologyError("LayerZero DVN expiration is invalid")
    try:
        target = bytes.fromhex(receive_uln_address.removeprefix("0x"))
    except ValueError as exc:
        raise LocalTopologyError("LayerZero receive ULN address is invalid") from exc
    if len(target) != 20 or not any(target):
        raise LocalTopologyError("LayerZero receive ULN address is invalid")
    selector = keccak(text="verify(bytes,bytes32,uint64)")[:4]
    call_data = selector + encode(
        ["bytes", "bytes32", "uint64"],
        [packet.header, packet.payload_hash, confirmations],
    )
    packed = (
        vid.to_bytes(4, "big")
        + target
        + expiration.to_bytes(32, "big")
        + call_data
    )
    instruction_hash = keccak(packed)
    signed = Account.sign_message(
        encode_defunct(primitive=instruction_hash),
        private_key=signer_private_key,
    )
    return DVNInstruction(
        vid=vid,
        target="0x" + target.hex(),
        call_data=call_data,
        expiration=expiration,
        instruction_hash=instruction_hash,
        signature=bytes(signed.signature),
    )


def encode_dvn_execute(instruction: DVNInstruction) -> bytes:
    selector = keccak(text="execute((uint32,address,bytes,uint256,bytes)[])")[:4]
    return selector + encode(
        ["(uint32,address,bytes,uint256,bytes)[]"],
        [
            [
                (
                    instruction.vid,
                    instruction.target,
                    instruction.call_data,
                    instruction.expiration,
                    instruction.signature,
                )
            ]
        ],
    )


def encode_commit_verification(packet: LayerZeroPacket) -> bytes:
    selector = keccak(text="commitVerification(bytes,bytes32)")[:4]
    return selector + encode(["bytes", "bytes32"], [packet.header, packet.payload_hash])


def encode_executor_submission(packet: LayerZeroPacket, gas_limit: int) -> bytes:
    selector = keccak(
        text="execute302((address,(uint32,bytes32,uint64),bytes32,bytes,bytes,uint256))"
    )[:4]
    return selector + encode(
        ["(address,(uint32,bytes32,uint64),bytes32,bytes,bytes,uint256)"],
        [
            (
                packet.receiver_address,
                (packet.source_eid, packet.sender, packet.nonce),
                packet.guid,
                packet.message,
                b"",
                gas_limit,
            )
        ],
    )


def classify_layerzero_receipt_logs(
    receipt: dict[str, Any],
) -> list[dict[str, Any]]:
    """Classify official V2 event logs while retaining raw topics/data."""

    reverse = {topic.lower(): name for name, topic in EVENT_TOPICS.items()}
    result: list[dict[str, Any]] = []
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise LocalTopologyError("LayerZero receipt logs must be a list")
    for log in logs:
        if not isinstance(log, dict):
            raise LocalTopologyError("LayerZero receipt log must be an object")
        topics = log.get("topics")
        if not isinstance(topics, list) or not topics:
            continue
        event = reverse.get(str(topics[0]).lower())
        if event is None:
            continue
        result.append(
            {
                "event": event,
                "transaction_hash": str(receipt.get("transactionHash", "")).lower(),
                "log_index": int(str(log["logIndex"]), 16),
                "address": str(log["address"]).lower(),
                "topics": [str(value).lower() for value in topics],
                "data": str(log.get("data", "0x")).lower(),
            }
        )
    return result


def verify_formal_component_set(component_names: set[str]) -> None:
    missing = FORMAL_COMPONENTS - component_names
    forbidden = FORBIDDEN_COMPONENTS & component_names
    if missing:
        raise LocalTopologyError(
            "LayerZero formal deployment lacks: " + ",".join(sorted(missing))
        )
    if forbidden:
        raise LocalTopologyError(
            "LayerZero formal deployment contains mock: "
            + ",".join(sorted(forbidden))
        )


def reconcile_layerzero_message(evidence: LayerZeroMessageEvidence) -> None:
    """Reject a packet unless its official V2 evidence chain has no gaps."""

    missing = [
        name
        for name, value in evidence.__dict__.items()
        if value == "" or value is None
    ]
    if missing:
        raise LocalTopologyError(
            "LayerZero message evidence is incomplete: " + ",".join(missing)
        )
    if evidence.nonce <= 0 or evidence.source_confirmation_block < 0:
        raise LocalTopologyError("LayerZero message coordinates are invalid")
    for name in ("encoded_packet_sha256", "dvn_signature_sha256"):
        if len(cast(str, getattr(evidence, name))) != 64:
            raise LocalTopologyError(f"LayerZero {name} is not SHA-256")
    if len(evidence.dvn_instruction_hash.removeprefix("0x")) != 64:
        raise LocalTopologyError("LayerZero DVN instruction hash is invalid")


def inspect_layerzero_effective_configuration(
    *,
    rpc_url: str,
    local_eid: int,
    remote_eids: list[int],
    subject_address: str,
    contracts: dict[str, str],
) -> dict[str, Any]:
    """Read effective official library/ULN/DVN/Executor state from one chain."""

    client = qbft_web3(rpc_url, timeout=30)
    subject = Web3.to_checksum_address(subject_address)
    endpoint = client.eth.contract(
        address=Web3.to_checksum_address(contracts["endpoint_v2"]),
        abi=[
            {
                "type": "function",
                "name": "eid",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"type": "uint32"}],
            },
            {
                "type": "function",
                "name": "getSendLibrary",
                "stateMutability": "view",
                "inputs": [{"type": "address"}, {"type": "uint32"}],
                "outputs": [{"type": "address"}],
            },
            {
                "type": "function",
                "name": "getReceiveLibrary",
                "stateMutability": "view",
                "inputs": [{"type": "address"}, {"type": "uint32"}],
                "outputs": [{"type": "address"}, {"type": "bool"}],
            },
        ],
    )
    uln_abi = [
        {
            "type": "function",
            "name": "getUlnConfig",
            "stateMutability": "view",
            "inputs": [{"type": "address"}, {"type": "uint32"}],
            "outputs": [
                {
                    "type": "tuple",
                    "components": [
                        {"name": "confirmations", "type": "uint64"},
                        {"name": "requiredDVNCount", "type": "uint8"},
                        {"name": "optionalDVNCount", "type": "uint8"},
                        {"name": "optionalDVNThreshold", "type": "uint8"},
                        {"name": "requiredDVNs", "type": "address[]"},
                        {"name": "optionalDVNs", "type": "address[]"},
                    ],
                }
            ],
        }
    ]
    send_uln = client.eth.contract(
        address=Web3.to_checksum_address(contracts["send_uln_302"]),
        abi=uln_abi
        + [
            {
                "type": "function",
                "name": "getExecutorConfig",
                "stateMutability": "view",
                "inputs": [{"type": "address"}, {"type": "uint32"}],
                "outputs": [
                    {
                        "type": "tuple",
                        "components": [
                            {"name": "maxMessageSize", "type": "uint32"},
                            {"name": "executor", "type": "address"},
                        ],
                    }
                ],
            }
        ],
    )
    receive_uln = client.eth.contract(
        address=Web3.to_checksum_address(contracts["receive_uln_302"]),
        abi=uln_abi,
    )
    dvn = client.eth.contract(
        address=Web3.to_checksum_address(contracts["dvn"]),
        abi=[
            {
                "type": "function",
                "name": "getSigners",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"type": "address[]"}],
            },
            {
                "type": "function",
                "name": "quorum",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"type": "uint64"}],
            },
        ],
    )
    expected_send = Web3.to_checksum_address(contracts["send_uln_302"])
    expected_receive = Web3.to_checksum_address(contracts["receive_uln_302"])
    expected_dvn = Web3.to_checksum_address(contracts["dvn"])
    expected_executor = Web3.to_checksum_address(contracts["executor"])
    remotes: list[dict[str, Any]] = []
    for remote_eid in remote_eids:
        send_library = endpoint.functions.getSendLibrary(subject, remote_eid).call()
        receive_library, receive_is_default = (
            endpoint.functions.getReceiveLibrary(subject, remote_eid).call()
        )
        send_config = send_uln.functions.getUlnConfig(subject, remote_eid).call()
        receive_config = receive_uln.functions.getUlnConfig(subject, remote_eid).call()
        executor_config = send_uln.functions.getExecutorConfig(
            subject, remote_eid
        ).call()
        checks = {
            "send_library": send_library == expected_send,
            "receive_library": receive_library == expected_receive,
            "receive_library_is_default": bool(receive_is_default),
            "send_confirmations": int(send_config[0]) == 1,
            "send_required_dvn_count": int(send_config[1]) == 1,
            "send_required_dvn": list(send_config[4]) == [expected_dvn],
            "receive_confirmations": int(receive_config[0]) == 1,
            "receive_required_dvn_count": int(receive_config[1]) == 1,
            "receive_required_dvn": list(receive_config[4]) == [expected_dvn],
            "executor": executor_config[1] == expected_executor,
        }
        if not all(checks.values()):
            failed = ",".join(name for name, passed in checks.items() if not passed)
            raise LocalTopologyError(
                f"LayerZero effective configuration failed for {remote_eid}: {failed}"
            )
        remotes.append({"remote_eid": remote_eid, "checks": checks})
    signers = list(dvn.functions.getSigners().call())
    quorum = int(dvn.functions.quorum().call())
    if not signers or quorum != 1:
        raise LocalTopologyError("LayerZero DVN signer/quorum configuration is invalid")
    if int(endpoint.functions.eid().call()) != local_eid:
        raise LocalTopologyError("LayerZero EndpointV2 EID mismatch")
    return {
        "local_eid": local_eid,
        "subject": subject.lower(),
        "dvn_signers": [str(value).lower() for value in signers],
        "dvn_quorum": quorum,
        "remotes": remotes,
    }


def capture_layerzero_deployment_evidence(
    *,
    profile_path: Path,
    runtime_root: Path,
    rpc_call: Callable[[str, str, list[Any]], Any],
) -> dict[str, Any]:
    """Capture bytecode and every Forge broadcast receipt for the three deployments."""

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    chains = cast(list[dict[str, Any]], profile["chains"])
    project_broadcast = (
        Path(__file__).parents[3]
        / "protocol-projects"
        / "layerzero-native"
        / "broadcast"
        / "DeployLayerZeroNative.s.sol"
    )
    output_chains: list[dict[str, Any]] = []
    observed_names: set[str] = {"ERC1967Proxy"}
    role_to_component = {
        "endpoint_v2": "EndpointV2",
        "send_uln_302": "SendUln302",
        "receive_uln_302": "ReceiveUln302",
        "dvn": "DVN",
        "executor": "Executor",
        "price_feed": "PriceFeed",
        "treasury": "Treasury",
        "dvn_fee_lib": "DVNFeeLib",
        "executor_fee_lib": "ExecutorFeeLib",
    }
    for chain in chains:
        chain_id = int(chain["chain_id"])
        deployment_path = runtime_root / "layerzero" / "deployments" / f"{chain_id}.json"
        deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
        contracts = cast(dict[str, str], deployment["contracts"])
        broadcast_path = project_broadcast / str(chain_id) / "run-latest.json"
        broadcast = json.loads(broadcast_path.read_text(encoding="utf-8"))
        receipts = cast(list[dict[str, Any]], broadcast.get("receipts", []))
        transactions = cast(list[dict[str, Any]], broadcast.get("transactions", []))
        if not receipts:
            raise LocalTopologyError(f"LayerZero receipts missing for chain {chain_id}")
        broadcast_names = {
            str(transaction["contractName"])
            for transaction in transactions
            if transaction.get("transactionType") == "CREATE"
            and transaction.get("contractName") is not None
        }
        forbidden_names = FORBIDDEN_COMPONENTS & broadcast_names
        if forbidden_names:
            raise LocalTopologyError(
                "LayerZero Forge broadcast contains mock: "
                + ",".join(sorted(forbidden_names))
            )
        components: list[dict[str, Any]] = []
        for role, address in contracts.items():
            code = rpc_call(cast(str, chain["rpc_url"]), "eth_getCode", [address, "latest"])
            if not isinstance(code, str) or code == "0x":
                raise LocalTopologyError(f"LayerZero component has no code: {role}")
            component = role_to_component.get(role)
            if component is not None:
                observed_names.add(component)
            components.append(
                {
                    "role": role,
                    "address": address.lower(),
                    "runtime_code_sha256": hashlib.sha256(
                        bytes.fromhex(code.removeprefix("0x"))
                    ).hexdigest(),
                }
            )
        output_chains.append(
            {
                "chain_id": chain_id,
                "layerzero_eid": chain["layerzero_eid"],
                "components": components,
                "receipts": receipts,
                "transactions": transactions,
                "receipt_count": len(receipts),
            }
        )
    verify_formal_component_set(observed_names)
    return {
        "schema_version": "xir-lab-layerzero-deployment-evidence-v1",
        "official_chain_components": True,
        "managed_layerzero_service": False,
        "worker_classification": "self-hosted-research-worker",
        "chains": output_chains,
    }
