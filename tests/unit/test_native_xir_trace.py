from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.native.xir_trace import (
    XIRContext,
    XIRReceipt,
    XIRRecord,
    encode_typed_id,
    next_prefix,
    receipt_hash,
    record_hash,
    root_id,
    root_prefix,
    transition_hash,
)


def test_xir_packed_hash_chain_uses_versioned_tags() -> None:
    source = (1, bytes.fromhex("11" * 20))
    intermediate = (1, bytes.fromhex("22" * 20))
    destination = (1, bytes.fromhex("33" * 20))
    record = XIRRecord(
        source,
        (1, bytes.fromhex("44" * 20)),
        (1, bytes.fromhex("55" * 20)),
        7,
        keccak(b"payload"),
    )
    context = XIRContext(1, keccak(b"policy"))
    assert record_hash(record) == keccak(
        b"XIR_RECORD_V1"
        + encode_typed_id(source)
        + encode_typed_id(record.source_app)
        + encode_typed_id(record.destination_app)
        + (7).to_bytes(8, "big")
        + record.payload_hash
    )
    rid = root_id(record, context, 1)
    receipt = XIRReceipt(
        source,
        intermediate,
        keccak(b"profile"),
        keccak(b"evidence"),
        transition_hash(record, context, source, intermediate),
        root_prefix(rid),
    )
    assert next_prefix(receipt) == keccak(
        b"XIR_PREFIX_V1" + receipt.prior_prefix + receipt_hash(receipt)
    )
    assert transition_hash(record, context, intermediate, destination) != (
        receipt.transition_hash
    )
