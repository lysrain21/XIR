"""Carrier identifier decoding/linkage across fixed-route transactions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal, cast

from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import EvidenceStore

Protocol = Literal["hyperlane", "layerzero-v2"]
EventKind = Literal["dispatch", "delivery"]

LEG_CHAINS = (
    (11_155_420, 421_614),
    (421_614, 84_532),
)


class ProtocolLinkError(RuntimeError):
    """Raised when carrier identifiers cannot form one exact causal leg."""


@dataclass(frozen=True)
class CarrierRouteIdentity:
    protocol: Protocol
    leg_index: int
    source_selector: int
    destination_selector: int


@dataclass(frozen=True)
class DecodedCarrierEvent:
    event_kind: EventKind
    transaction_id: str
    protocol: Protocol
    protocol_identifier: str
    leg_index: int
    source_selector: int
    destination_selector: int
    protocol_nonce: int | None
    payload_sha256: str


@dataclass(frozen=True)
class LinkedCarrierMessage:
    carrier_message_id: str
    attempt_id: str
    protocol: Protocol
    protocol_identifier: str
    leg_index: int
    source_transaction_id: str
    destination_transaction_id: str


class CarrierMessageLinker:
    def __init__(
        self,
        *,
        store: EvidenceStore,
        routes: tuple[CarrierRouteIdentity, ...],
    ) -> None:
        coordinates = {
            (route.protocol, route.leg_index): route for route in routes
        }
        expected = {
            (protocol, leg)
            for protocol in ("hyperlane", "layerzero-v2")
            for leg in (0, 1)
        }
        if len(routes) != 4 or set(coordinates) != expected:
            raise ProtocolLinkError(
                "route identities must cover both carriers on both fixed legs"
            )
        if any(
            route.source_selector <= 0 or route.destination_selector <= 0
            for route in routes
        ):
            raise ProtocolLinkError("carrier domain and EID selectors must be positive")
        self.store = store
        self.routes = coordinates

    def link(
        self,
        *,
        dispatch: DecodedCarrierEvent,
        delivery: DecodedCarrierEvent,
    ) -> LinkedCarrierMessage:
        if dispatch.event_kind != "dispatch" or delivery.event_kind != "delivery":
            raise ProtocolLinkError("carrier link requires dispatch then delivery")
        comparable = (
            dispatch.protocol,
            dispatch.protocol_identifier.lower(),
            dispatch.leg_index,
            dispatch.source_selector,
            dispatch.destination_selector,
            dispatch.protocol_nonce,
            dispatch.payload_sha256,
        )
        observed = (
            delivery.protocol,
            delivery.protocol_identifier.lower(),
            delivery.leg_index,
            delivery.source_selector,
            delivery.destination_selector,
            delivery.protocol_nonce,
            delivery.payload_sha256,
        )
        if comparable != observed:
            raise ProtocolLinkError(
                "dispatch and delivery identifiers, selectors, nonce, or payload differ"
            )
        _validate_identifier(dispatch.protocol_identifier)
        _validate_digest(dispatch.payload_sha256)
        if dispatch.protocol == "layerzero-v2" and dispatch.protocol_nonce is None:
            raise ProtocolLinkError("LayerZero link requires its protocol nonce")
        if dispatch.protocol_nonce is not None and dispatch.protocol_nonce < 0:
            raise ProtocolLinkError("protocol nonce cannot be negative")
        route = self.routes[(dispatch.protocol, dispatch.leg_index)]
        if (
            route.source_selector,
            route.destination_selector,
        ) != (
            dispatch.source_selector,
            dispatch.destination_selector,
        ):
            raise ProtocolLinkError("carrier domain or EID differs from route identity")
        expected_source_chain, expected_destination_chain = LEG_CHAINS[
            dispatch.leg_index
        ]
        source = self._transaction(dispatch.transaction_id)
        destination = self._transaction(delivery.transaction_id)
        if source["attempt_id"] != destination["attempt_id"]:
            raise ProtocolLinkError("carrier transactions belong to different attempts")
        if (
            int(source["chain_id"]),
            int(destination["chain_id"]),
        ) != (expected_source_chain, expected_destination_chain):
            raise ProtocolLinkError("carrier transactions changed fixed leg chain order")
        attempt_id = str(source["attempt_id"])
        message_id = stable_id(
            "message",
            attempt_id,
            dispatch.leg_index,
            dispatch.protocol,
            dispatch.protocol_identifier.lower(),
        )
        with self.store.write() as connection:
            existing = connection.execute(
                """
                SELECT * FROM carrier_messages
                WHERE carrier_message_id = ?
                """,
                (message_id,),
            ).fetchone()
            if existing is None:
                try:
                    connection.execute(
                        """
                        INSERT INTO carrier_messages(
                            carrier_message_id, attempt_id, leg_index, protocol,
                            protocol_identifier, source_selector,
                            destination_selector, protocol_nonce, payload_sha256,
                            source_transaction_id, destination_transaction_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            message_id,
                            attempt_id,
                            dispatch.leg_index,
                            dispatch.protocol,
                            dispatch.protocol_identifier.lower(),
                            dispatch.source_selector,
                            dispatch.destination_selector,
                            dispatch.protocol_nonce,
                            dispatch.payload_sha256,
                            dispatch.transaction_id,
                            delivery.transaction_id,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ProtocolLinkError(
                        "carrier identifier or attempt leg is already linked"
                    ) from exc
            else:
                expected = (
                    attempt_id,
                    dispatch.leg_index,
                    dispatch.protocol,
                    dispatch.protocol_identifier.lower(),
                    dispatch.transaction_id,
                    delivery.transaction_id,
                )
                current = (
                    existing["attempt_id"],
                    int(existing["leg_index"]),
                    existing["protocol"],
                    existing["protocol_identifier"],
                    existing["source_transaction_id"],
                    existing["destination_transaction_id"],
                )
                if current != expected:
                    raise ProtocolLinkError("carrier message ID maps to changed linkage")
        return LinkedCarrierMessage(
            carrier_message_id=message_id,
            attempt_id=attempt_id,
            protocol=dispatch.protocol,
            protocol_identifier=dispatch.protocol_identifier.lower(),
            leg_index=dispatch.leg_index,
            source_transaction_id=dispatch.transaction_id,
            destination_transaction_id=delivery.transaction_id,
        )

    def _transaction(self, transaction_id: str) -> sqlite3.Row:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT transaction_record.chain_id, stage.attempt_id
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
        if row is None:
            raise ProtocolLinkError(f"unknown carrier transaction: {transaction_id}")
        return cast(sqlite3.Row, row)


def _validate_identifier(value: str) -> None:
    if (
        len(value) != 66
        or not value.startswith("0x")
        or any(character not in "0123456789abcdefABCDEF" for character in value[2:])
    ):
        raise ProtocolLinkError("carrier message ID or GUID must be bytes32 hex")


def _validate_digest(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ProtocolLinkError("carrier payload digest must be lowercase SHA-256")
