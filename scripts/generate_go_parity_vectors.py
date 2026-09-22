"""Generate the Go runtime parity vectors from the Python reference runtime.

The Go runtime in ``go-runtime/`` re-implements the XIR wire encoding, the
transaction-level signatures, and the protocol codecs. This script derives
vectors from the shipping Python modules and writes them to one JSON document
that ``go-runtime/internal/xir/vectors_test.go`` and the protocol package tests
compare against byte for byte.

Usage:
    uv run python scripts/generate_go_parity_vectors.py --output go-runtime/testdata/vectors.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.native.layerzero import (
    build_dvn_instruction,
    decode_packet,
    encode_commit_verification,
    encode_dvn_execute,
    encode_executor_submission,
    executor_lz_receive_options,
)
from xir_lab.native.multihop_deployer import (
    REGISTRY_VERSION,
    adapter_key,
    multihop_gateway_typed_id,
    multihop_profile_hash,
)
from xir_lab.native.multihop_scalability import ROUTE_ORDER
from xir_lab.native.xir_trace import (
    XIRContext,
    XIRReceipt,
    XIRRecord,
    bundle_commitment,
    bundle_start,
    bundle_step,
    context_hash,
    message_id,
    next_prefix,
    receipt_hash,
    receipt_tuple,
    record_hash,
    record_tuple,
    root_id,
    root_prefix,
    transition_hash,
)

SCHEMA_VERSION = "xir-go-parity-vectors-v1"
FIXED_SEED = "xir-native-multihop-switching-pilot-v1-100-per-route"
PAYLOAD_SCHEDULE = {
    "minimum_bytes": 32,
    "size_bucket_count": 4,
    "size_step_bytes": 32,
}


def _fixture_key(label: str) -> str:
    """Return one deterministic disposable signing key for local tests only."""

    return "0x" + keccak(text=f"xir-go-parity-fixture-signer:{label}").hex()


FIXTURE_KEYS = {
    "root_signer": _fixture_key("root-signer"),
    "dvn_signer": _fixture_key("dvn-signer"),
    "validator": _fixture_key("validator"),
}
CHAIN_IDS = (3133701, 3133702, 3133703, 3133704, 3133705)
ATTEMPTS = (
    {
        "attempt_id": "xir-multihop-fixture-000001",
        "phase": "smoke",
        "route": "HL",
        "route_sequence": 0,
    },
    {
        "attempt_id": "xir-multihop-fixture-000002",
        "phase": "smoke",
        "route": "LH",
        "route_sequence": 3,
    },
    {
        "attempt_id": "xir-multihop-fixture-000003",
        "phase": "publication_smoke",
        "route": "HHH",
        "route_sequence": 5,
    },
)


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def _application_payload(attempt: dict[str, Any], schedule: dict[str, int]) -> tuple[bytes, bytes]:
    size = (
        schedule["minimum_bytes"]
        + (attempt["route_sequence"] % schedule["size_bucket_count"]) * schedule["size_step_bytes"]
    )
    material = (
        f"xir-multihop-v1:{FIXED_SEED}:{attempt['phase']}:{attempt['route_sequence']}".encode()
    )
    application = bytearray()
    counter = 0
    while len(application) < size:
        application.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
        counter += 1
    application_bytes = bytes(application[:size])
    encoded = encode(
        ["(bytes32,bytes,uint64,bytes)"],
        [
            (
                keccak(text=attempt["attempt_id"]),
                attempt["route"].encode("ascii"),
                attempt["route_sequence"],
                application_bytes,
            )
        ],
    )
    return application_bytes, encoded


def _record(seed: int) -> XIRRecord:
    gateway = multihop_gateway_typed_id(CHAIN_IDS[0])
    source_app = (1, bytes.fromhex(f"{seed:040x}"))
    destination_app = (1, bytes.fromhex(f"{seed + 1:040x}"))
    return XIRRecord(
        source_gateway=(gateway[0], gateway[1]),
        source_app=source_app,
        destination_app=destination_app,
        nonce=seed,
        payload_hash=keccak(text=f"xir-go-parity-payload-{seed}"),
    )


def _context(seed: int) -> XIRContext:
    return XIRContext(1, keccak(text=f"xir-go-parity-policy-{seed}"))


def _receipt(
    seed: int,
    hop_index: int,
    record: XIRRecord,
    context: XIRContext,
    route: str = "HL",
) -> XIRReceipt:
    """Build a receipt whose transition hash is the on-chain derivation."""

    source = multihop_gateway_typed_id(CHAIN_IDS[hop_index - 1])
    destination = multihop_gateway_typed_id(CHAIN_IDS[hop_index])
    return XIRReceipt(
        source_gateway=(source[0], source[1]),
        destination_gateway=(destination[0], destination[1]),
        profile_hash=multihop_profile_hash(route, hop_index),
        evidence_hash=keccak(text=f"xir-go-parity-evidence-{seed}-{hop_index}"),
        transition_hash=transition_hash(
            record,
            context,
            (source[0], source[1]),
            (destination[0], destination[1]),
        ),
        prior_prefix=keccak(text=f"xir-go-parity-prefix-{seed}-{hop_index}"),
    )


def _envelope_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for seed in (7, 19):
        record = _record(seed)
        context = _context(seed)
        rid = root_id(record, context, REGISTRY_VERSION)
        receipts = [_receipt(seed, hop_index, record, context) for hop_index in range(1, 3)]
        trace_receipts = []
        prior = root_prefix(rid)
        for receipt in receipts:
            trace_receipts.append(
                XIRReceipt(
                    source_gateway=receipt.source_gateway,
                    destination_gateway=receipt.destination_gateway,
                    profile_hash=receipt.profile_hash,
                    evidence_hash=receipt.evidence_hash,
                    transition_hash=receipt.transition_hash,
                    prior_prefix=prior,
                )
            )
            prior = next_prefix(trace_receipts[-1])
        signature = bytes(
            Account.sign_message(
                encode_defunct(primitive=rid), private_key=FIXTURE_KEYS["root_signer"]
            ).signature
        )
        envelope = (
            record_tuple(record),
            (context.required_security, context.policy_hash),
            (REGISTRY_VERSION, signature),
            [receipt_tuple(receipt) for receipt in trace_receipts],
        )
        encoded = encode(
            [
                (
                    "(((uint8,bytes),(uint8,bytes),(uint8,bytes),uint64,bytes32),"
                    "(uint8,bytes32),(uint32,bytes),"
                    "((uint8,bytes),(uint8,bytes),bytes32,bytes32,bytes32,bytes32)[])"
                )
            ],
            [envelope],
        )
        vectors.append(
            {
                "seed": seed,
                "record": {
                    "source_gateway": _hex(record.source_gateway[1]),
                    "source_app": _hex(record.source_app[1]),
                    "destination_app": _hex(record.destination_app[1]),
                    "nonce": record.nonce,
                    "payload_hash": _hex(record.payload_hash),
                },
                "context": {
                    "required_security": context.required_security,
                    "policy_hash": _hex(context.policy_hash),
                },
                "rid": _hex(rid),
                "mid": _hex(message_id(rid, record.destination_app)),
                "root_prefix": _hex(root_prefix(rid)),
                "transition_hashes": [
                    _hex(
                        transition_hash(
                            record,
                            context,
                            receipt.source_gateway,
                            receipt.destination_gateway,
                        )
                    )
                    for receipt in trace_receipts
                ],
                "receipts": [
                    {
                        "source_gateway": _hex(receipt.source_gateway[1]),
                        "destination_gateway": _hex(receipt.destination_gateway[1]),
                        "profile_hash": _hex(receipt.profile_hash),
                        "evidence_hash": _hex(receipt.evidence_hash),
                        "transition_hash": _hex(receipt.transition_hash),
                        "prior_prefix": _hex(receipt.prior_prefix),
                        "receipt_hash": _hex(receipt_hash(receipt)),
                        "next_prefix": _hex(next_prefix(receipt)),
                        "bundle_commitment_prefix": _hex(bundle_commitment([receipt])),
                    }
                    for receipt in trace_receipts
                ],
                "bundle_commitment": _hex(bundle_commitment(trace_receipts)),
                "root_signature": _hex(signature),
                "envelope_encoding": _hex(encoded),
                "record_hash": _hex(record_hash(record)),
                "context_hash": _hex(context_hash(context)),
            }
        )
    return vectors


def _packet_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for nonce, source_eid, destination_eid in ((1, 40161, 40231), (9, 40231, 40161)):
        message = encode(
            ["uint8", "bytes"], [3, encode(["bytes32"], [keccak(text="xir-go-parity")])]
        )
        sender = bytes.fromhex("00" * 12 + "aa" * 20)
        receiver = bytes.fromhex("00" * 12 + "bb" * 20)
        guid = keccak(text=f"xir-go-parity-guid-{nonce}")
        header = (
            (1).to_bytes(1, "big")
            + nonce.to_bytes(8, "big")
            + source_eid.to_bytes(4, "big")
            + sender
            + destination_eid.to_bytes(4, "big")
            + receiver
        )
        encoded = header + guid + message
        packet = decode_packet(encoded)
        instruction = build_dvn_instruction(
            vid=destination_eid,
            receive_uln_address="0x" + "cc" * 20,
            packet=packet,
            confirmations=1,
            expiration=1_900_000_000,
            signer_private_key=FIXTURE_KEYS["dvn_signer"],
        )
        vectors.append(
            {
                "nonce": nonce,
                "encoded_packet": _hex(encoded),
                "source_eid": source_eid,
                "destination_eid": destination_eid,
                "sender": _hex(sender),
                "receiver": _hex(receiver),
                "guid": _hex(guid),
                "message": _hex(message),
                "payload_hash": _hex(packet.payload_hash),
                "dvn_instruction": {
                    "vid": instruction.vid,
                    "target": instruction.target,
                    "call_data": _hex(instruction.call_data),
                    "expiration": instruction.expiration,
                    "instruction_hash": _hex(instruction.instruction_hash),
                    "signature": _hex(instruction.signature),
                },
                "dvn_execute_calldata": _hex(encode_dvn_execute(instruction)),
                "commit_verification_calldata": _hex(encode_commit_verification(packet)),
                "executor_calldata": _hex(encode_executor_submission(packet, 1_500_000)),
                "executor_options": _hex(executor_lz_receive_options(1_500_000)),
            }
        )
    return vectors


def _hyperlane_evidence_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for hop_index, domain in ((1, 31337), (2, 31338)):
        profiles = [keccak(text=f"xir-go-parity-profile-{index}") for index in range(hop_index - 1)]
        evidence_hashes = [
            keccak(text=f"xir-go-parity-evidence-{index}") for index in range(hop_index - 1)
        ]
        transitions = [
            keccak(text=f"xir-go-parity-transition-{index}") for index in range(hop_index - 1)
        ]
        current_profile = keccak(text=f"xir-go-parity-current-profile-{hop_index}")
        current_transition = keccak(text=f"xir-go-parity-current-transition-{hop_index}")
        inner = encode(
            ["(bytes32,bytes32,bytes32[],bytes32[],bytes32[])"],
            [
                (
                    current_profile,
                    current_transition,
                    profiles,
                    evidence_hashes,
                    transitions,
                )
            ],
        )
        body = encode(["uint8", "bytes"], [3, inner])
        sender = bytes.fromhex("00" * 12 + "dd" * 20)
        evidence = keccak(encode(["uint32", "bytes32", "bytes"], [domain, sender, body]))
        vectors.append(
            {
                "hop_index": hop_index,
                "domain": domain,
                "sender": _hex(sender),
                "current_profile": _hex(current_profile),
                "current_transition": _hex(current_transition),
                "prior_profiles": [_hex(value) for value in profiles],
                "prior_evidence": [_hex(value) for value in evidence_hashes],
                "prior_transitions": [_hex(value) for value in transitions],
                "body": _hex(body),
                "evidence_hash": _hex(evidence),
            }
        )
    return vectors


def build_document() -> dict[str, Any]:
    payload_vectors = []
    for attempt in ATTEMPTS:
        application, encoded = _application_payload(attempt, PAYLOAD_SCHEDULE)
        payload_vectors.append(
            {
                **attempt,
                "attempt_key": _hex(keccak(text=attempt["attempt_id"])),
                "application_sha256": hashlib.sha256(application).hexdigest(),
                "application_bytes": _hex(application),
                "payload_encoding": _hex(encoded),
            }
        )
    bundle_steps = []
    bundle_record = _record(3)
    bundle_context = _context(3)
    for index in range(3):
        receipt = _receipt(3, 1, bundle_record, bundle_context)
        prefix = bundle_start(index)
        bundle_steps.append(
            {
                "index": index,
                "receipt_count": index,
                "bundle_start": _hex(prefix),
                "step": _hex(bundle_step(prefix, index, receipt)),
                "profile_hash": _hex(receipt.profile_hash),
                "evidence_hash": _hex(receipt.evidence_hash),
                "transition_hash": _hex(receipt.transition_hash),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": {
            "script": "scripts/generate_go_parity_vectors.py",
            "python_source": "src/xir_lab/native",
            "fixed_seed": FIXED_SEED,
        },
        "constants": {
            "registry_version": REGISTRY_VERSION,
            "payload_schedule": PAYLOAD_SCHEDULE,
            "fixed_seed": FIXED_SEED,
            "fixture_keys": FIXTURE_KEYS,
            "chain_ids": list(CHAIN_IDS),
            "routes": list(ROUTE_ORDER),
        },
        "profile_hashes": [
            {
                "route": route,
                "hop_index": hop_index,
                "hash": _hex(multihop_profile_hash(route, hop_index)),
            }
            for route in ROUTE_ORDER
            for hop_index in range(1, len(route) + 1)
        ],
        "gateway_typed_ids": [
            {"chain_id": chain_id, "kind": 1, "value": _hex(multihop_gateway_typed_id(chain_id)[1])}
            for chain_id in CHAIN_IDS
        ],
        "adapter_keys": [
            {
                "route": route,
                "hop_index": hop_index,
                "direction": direction,
                "key": adapter_key(route, hop_index, direction),
            }
            for route in ROUTE_ORDER
            for hop_index in range(1, len(route) + 1)
            for direction in ("in", "out")
        ],
        "typed_ids": [
            {
                "kind": 1,
                "value": _hex(bytes.fromhex(f"{seed:040x}")),
                "hash": _hex(keccak(bytes([1, 20]) + bytes.fromhex(f"{seed:040x}"))),
            }
            for seed in (1, 42)
        ]
        + [
            {
                "kind": 2,
                "value": _hex(bytes.fromhex(f"{seed:064x}")),
                "hash": _hex(keccak(bytes([2, 32]) + bytes.fromhex(f"{seed:064x}"))),
            }
            for seed in (5,)
        ],
        "envelopes": _envelope_vectors(),
        "bundle_steps": bundle_steps,
        "payloads": payload_vectors,
        "layerzero_packets": _packet_vectors(),
        "hyperlane_evidence": _hyperlane_evidence_vectors(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    document = build_document()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {arguments.output} ({arguments.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
