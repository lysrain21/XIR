from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from xir_lab.collect.protocol import (
    CarrierMessageLinker,
    CarrierRouteIdentity,
    DecodedCarrierEvent,
    ProtocolLinkError,
)
from xir_lab.evidence.store import EvidenceStore

PAYLOAD = "aa" * 32


def _routes() -> tuple[CarrierRouteIdentity, ...]:
    return (
        CarrierRouteIdentity("hyperlane", 0, 1000, 2000),
        CarrierRouteIdentity("hyperlane", 1, 2000, 3000),
        CarrierRouteIdentity("layerzero-v2", 0, 40161, 40231),
        CarrierRouteIdentity("layerzero-v2", 1, 40231, 40245),
    )


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
            VALUES ('condition-hl', 'run-1', 'HL', 'running')
            """
        )
        for attempt_index in range(2):
            connection.execute(
                """
                INSERT INTO pairs(pair_id, condition_id, slot_index)
                VALUES (?, 'condition-hl', ?)
                """,
                (f"pair-{attempt_index}", attempt_index),
            )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, condition_id, pair_id, arm, attempt_kind,
                    state, created_at
                ) VALUES (?, 'condition-hl', ?, 'baseline', 'primary',
                          'in_flight', '2026-07-26T00:00:00Z')
                """,
                (f"attempt-{attempt_index}", f"pair-{attempt_index}"),
            )
            for ordinal, chain_id in enumerate((11_155_420, 421_614, 84_532)):
                suffix = f"{attempt_index}-{ordinal}"
                connection.execute(
                    """
                    INSERT INTO stages(
                        stage_id, attempt_id, ordinal, stage_name,
                        chain_id, state
                    ) VALUES (?, ?, ?, ?, ?, 'in_flight')
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
                    ) VALUES (?, ?, ?, ?, ?, 'submitted', ?,
                              '2026-07-26T00:00:00Z')
                    """,
                    (
                        f"intent-{suffix}",
                        f"stage-{suffix}",
                        f"signop-{suffix}",
                        chain_id,
                        ordinal,
                        "22" * 32,
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
    return store


def _event(
    *,
    kind: str,
    transaction_id: str,
    protocol: str,
    identifier: str,
    leg: int,
    source_selector: int,
    destination_selector: int,
    nonce: int | None,
) -> DecodedCarrierEvent:
    return DecodedCarrierEvent(
        event_kind=kind,  # type: ignore[arg-type]
        transaction_id=transaction_id,
        protocol=protocol,  # type: ignore[arg-type]
        protocol_identifier=identifier,
        leg_index=leg,
        source_selector=source_selector,
        destination_selector=destination_selector,
        protocol_nonce=nonce,
        payload_sha256=PAYLOAD,
    )


def test_links_hyperlane_and_layerzero_across_both_fixed_legs(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    linker = CarrierMessageLinker(store=store, routes=_routes())
    message_id = "0x" + "11" * 32
    leg0 = linker.link(
        dispatch=_event(
            kind="dispatch",
            transaction_id="transaction-0-0",
            protocol="hyperlane",
            identifier=message_id,
            leg=0,
            source_selector=1000,
            destination_selector=2000,
            nonce=1,
        ),
        delivery=_event(
            kind="delivery",
            transaction_id="transaction-0-1",
            protocol="hyperlane",
            identifier=message_id,
            leg=0,
            source_selector=1000,
            destination_selector=2000,
            nonce=1,
        ),
    )
    guid = "0x" + "22" * 32
    leg1_dispatch = _event(
        kind="dispatch",
        transaction_id="transaction-0-1",
        protocol="layerzero-v2",
        identifier=guid,
        leg=1,
        source_selector=40231,
        destination_selector=40245,
        nonce=9,
    )
    leg1_delivery = replace(
        leg1_dispatch,
        event_kind="delivery",
        transaction_id="transaction-0-2",
    )
    leg1 = linker.link(dispatch=leg1_dispatch, delivery=leg1_delivery)
    assert (leg0.leg_index, leg0.protocol) == (0, "hyperlane")
    assert (leg1.leg_index, leg1.protocol) == (1, "layerzero-v2")
    with store.connect(read_only=True) as connection:
        rows = connection.execute(
            """
            SELECT leg_index, protocol, protocol_identifier, protocol_nonce,
                   source_transaction_id, destination_transaction_id
            FROM carrier_messages ORDER BY leg_index
            """
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        (
            0,
            "hyperlane",
            message_id,
            1,
            "transaction-0-0",
            "transaction-0-1",
        ),
        (
            1,
            "layerzero-v2",
            guid,
            9,
            "transaction-0-1",
            "transaction-0-2",
        ),
    ]


def test_link_is_idempotent_but_attempt_leg_cannot_be_reused(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    linker = CarrierMessageLinker(store=store, routes=_routes())
    dispatch = _event(
        kind="dispatch",
        transaction_id="transaction-0-0",
        protocol="hyperlane",
        identifier="0x" + "11" * 32,
        leg=0,
        source_selector=1000,
        destination_selector=2000,
        nonce=None,
    )
    delivery = replace(
        dispatch,
        event_kind="delivery",
        transaction_id="transaction-0-1",
    )
    assert linker.link(dispatch=dispatch, delivery=delivery) == linker.link(
        dispatch=dispatch,
        delivery=delivery,
    )
    changed = replace(dispatch, protocol_identifier="0x" + "33" * 32)
    with pytest.raises(ProtocolLinkError, match="already linked"):
        linker.link(
            dispatch=changed,
            delivery=replace(
                changed,
                event_kind="delivery",
                transaction_id="transaction-0-1",
            ),
        )


def test_wrong_selector_cross_attempt_and_missing_lz_nonce_fail_closed(
    tmp_path: Path,
) -> None:
    linker = CarrierMessageLinker(store=_store(tmp_path), routes=_routes())
    dispatch = _event(
        kind="dispatch",
        transaction_id="transaction-0-0",
        protocol="hyperlane",
        identifier="0x" + "11" * 32,
        leg=0,
        source_selector=999,
        destination_selector=2000,
        nonce=None,
    )
    with pytest.raises(ProtocolLinkError, match="domain or EID"):
        linker.link(
            dispatch=dispatch,
            delivery=replace(
                dispatch,
                event_kind="delivery",
                transaction_id="transaction-0-1",
            ),
        )

    dispatch = replace(dispatch, source_selector=1000)
    with pytest.raises(ProtocolLinkError, match="different attempts"):
        linker.link(
            dispatch=dispatch,
            delivery=replace(
                dispatch,
                event_kind="delivery",
                transaction_id="transaction-1-1",
            ),
        )

    lz = _event(
        kind="dispatch",
        transaction_id="transaction-0-1",
        protocol="layerzero-v2",
        identifier="0x" + "22" * 32,
        leg=1,
        source_selector=40231,
        destination_selector=40245,
        nonce=None,
    )
    with pytest.raises(ProtocolLinkError, match="requires its protocol nonce"):
        linker.link(
            dispatch=lz,
            delivery=replace(
                lz,
                event_kind="delivery",
                transaction_id="transaction-0-2",
            ),
        )
