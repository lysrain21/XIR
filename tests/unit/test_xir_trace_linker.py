from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from xir_lab.collect.xir import (
    DecodedDestinationEffect,
    DecodedXirSource,
    DecodedXirVerification,
    XirLinkError,
    XirTraceLinker,
)
from xir_lab.evidence.store import EvidenceStore

RID = "0x" + "11" * 32
MID = "0x" + "22" * 32
PAYLOAD = "33" * 32
LEG0 = "0x" + "44" * 32
LEG1 = "0x" + "55" * 32


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("11" * 32,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hh', 'run-1', 'HH', 'running')
            """
        )
        for attempt_index, arm in enumerate(("xir", "baseline")):
            connection.execute(
                """
                INSERT INTO pairs(pair_id, condition_id, slot_index)
                VALUES (?, 'condition-hh', ?)
                """,
                (f"pair-{attempt_index}", attempt_index),
            )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, condition_id, pair_id, arm, attempt_kind,
                    state, created_at
                ) VALUES (?, 'condition-hh', ?, ?, 'primary', 'in_flight',
                          '2026-07-26T00:00:00Z')
                """,
                (
                    f"attempt-{attempt_index}",
                    f"pair-{attempt_index}",
                    arm,
                ),
            )
            for ordinal, chain_id in enumerate((11_155_420, 421_614, 84_532)):
                suffix = f"{attempt_index}-{ordinal}"
                connection.execute(
                    """
                    INSERT INTO stages(
                        stage_id, attempt_id, ordinal, stage_name,
                        chain_id, state
                    ) VALUES (?, ?, ?, ?, ?, 'completed')
                    """,
                    (
                        f"stage-{suffix}",
                        f"attempt-{attempt_index}",
                        ordinal,
                        f"stage-{ordinal}",
                        chain_id,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO intents(
                        intent_id, stage_id, signer_operation_id, chain_id,
                        nonce, state, payload_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'included', ?,
                              '2026-07-26T00:00:00Z')
                    """,
                    (
                        f"intent-{suffix}",
                        f"stage-{suffix}",
                        f"signop-{suffix}",
                        chain_id,
                        ordinal,
                        PAYLOAD,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO transactions(
                        transaction_id, intent_id, chain_id, nonce,
                        transaction_hash, state
                    ) VALUES (?, ?, ?, ?, ?, 'included')
                    """,
                    (
                        f"transaction-{suffix}",
                        f"intent-{suffix}",
                        chain_id,
                        ordinal,
                        f"0x{attempt_index + 1:02x}{ordinal + 1:02x}" + "00" * 30,
                    ),
                )
            for leg_index, identifier in enumerate((LEG0, LEG1)):
                connection.execute(
                    """
                    INSERT INTO carrier_messages(
                        carrier_message_id, attempt_id, leg_index, protocol,
                        protocol_identifier, source_selector,
                        destination_selector, protocol_nonce, payload_sha256,
                        source_transaction_id, destination_transaction_id
                    ) VALUES (?, ?, ?, 'hyperlane', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"carrier-{attempt_index}-{leg_index}",
                        f"attempt-{attempt_index}",
                        leg_index,
                        (
                            identifier
                            if attempt_index == 0
                            else f"0x{attempt_index + 6:02x}{leg_index + 1:02x}"
                            + "00" * 30
                        ),
                        1000 + leg_index,
                        2000 + leg_index,
                        leg_index,
                        PAYLOAD,
                        f"transaction-{attempt_index}-{leg_index}",
                        f"transaction-{attempt_index}-{leg_index + 1}",
                    ),
                )
    return store


def _records() -> tuple[
    DecodedXirSource,
    DecodedXirVerification,
    DecodedXirVerification,
    DecodedDestinationEffect,
]:
    source = DecodedXirSource(
        "transaction-0-0",
        RID,
        MID,
        PAYLOAD,
        "66" * 32,
        "77" * 32,
        "88" * 32,
    )
    intermediate = DecodedXirVerification(
        "transaction-0-1",
        "intermediate",
        RID,
        MID,
        "consumed-key-1",
        True,
        LEG0,
    )
    destination = DecodedXirVerification(
        "transaction-0-2",
        "destination",
        RID,
        MID,
        "consumed-key-1",
        True,
        LEG1,
    )
    effect = DecodedDestinationEffect(
        "transaction-0-2",
        "effect-v1",
        PAYLOAD,
        "99" * 32,
        "aa" * 32,
        True,
    )
    return source, intermediate, destination, effect


def test_links_complete_xir_trace_and_destination_effect_idempotently(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    linker = XirTraceLinker(store=store)
    source, intermediate, destination, effect = _records()
    first = linker.link(
        source=source,
        intermediate=intermediate,
        destination=destination,
        effect=effect,
    )
    second = linker.link(
        source=source,
        intermediate=intermediate,
        destination=destination,
        effect=effect,
    )
    assert first == second
    assert first.attempt_id == "attempt-0"
    with store.connect(read_only=True) as connection:
        row = connection.execute(
            """
            SELECT rid, mid, consumed_key, intermediate_verified,
                   destination_verified, destination_effect_id,
                   effect_succeeded
            FROM xir_attempt_records
            """
        ).fetchone()
    assert tuple(row) == (
        RID,
        MID,
        "consumed-key-1",
        1,
        1,
        "effect-v1",
        1,
    )


def test_rid_mid_consumed_and_receipt_path_must_remain_continuous(
    tmp_path: Path,
) -> None:
    linker = XirTraceLinker(store=_store(tmp_path))
    source, intermediate, destination, effect = _records()
    with pytest.raises(XirLinkError, match="RID or MID"):
        linker.link(
            source=source,
            intermediate=replace(intermediate, mid="0x" + "ff" * 32),
            destination=destination,
            effect=effect,
        )
    with pytest.raises(XirLinkError, match="consumed/replay"):
        linker.link(
            source=source,
            intermediate=intermediate,
            destination=replace(destination, consumed_key="different"),
            effect=effect,
        )
    with pytest.raises(XirLinkError, match="receipt path"):
        linker.link(
            source=source,
            intermediate=replace(
                intermediate,
                carrier_protocol_identifier="0x" + "ee" * 32,
            ),
            destination=destination,
            effect=effect,
        )


def test_verification_effect_and_baseline_boundaries_fail_closed(
    tmp_path: Path,
) -> None:
    linker = XirTraceLinker(store=_store(tmp_path))
    source, intermediate, destination, effect = _records()
    with pytest.raises(XirLinkError, match="verification"):
        linker.link(
            source=source,
            intermediate=replace(intermediate, verified=False),
            destination=destination,
            effect=effect,
        )
    with pytest.raises(XirLinkError, match="effect did not succeed"):
        linker.link(
            source=source,
            intermediate=intermediate,
            destination=destination,
            effect=replace(effect, succeeded=False),
        )
    baseline_source = replace(source, transaction_id="transaction-1-0")
    baseline_intermediate = replace(
        intermediate,
        transaction_id="transaction-1-1",
        carrier_protocol_identifier="0x0701" + "00" * 30,
    )
    baseline_destination = replace(
        destination,
        transaction_id="transaction-1-2",
        carrier_protocol_identifier="0x0702" + "00" * 30,
    )
    baseline_effect = replace(effect, transaction_id="transaction-1-2")
    with pytest.raises(XirLinkError, match="baseline attempt"):
        linker.link(
            source=baseline_source,
            intermediate=baseline_intermediate,
            destination=baseline_destination,
            effect=baseline_effect,
        )
