"""XIR causal trace linkage from source record through destination effect."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal, cast

from xir_lab.evidence.store import EvidenceStore


class XirLinkError(RuntimeError):
    """Raised when XIR identifiers, verification, or effect continuity fails."""


@dataclass(frozen=True)
class DecodedXirSource:
    transaction_id: str
    rid: str
    mid: str
    payload_sha256: str
    profile_sha256: str
    evidence_sha256: str
    transition_sha256: str


@dataclass(frozen=True)
class DecodedXirVerification:
    transaction_id: str
    location: Literal["intermediate", "destination"]
    rid: str
    mid: str
    consumed_key: str
    verified: bool
    carrier_protocol_identifier: str


@dataclass(frozen=True)
class DecodedDestinationEffect:
    transaction_id: str
    destination_effect_id: str
    payload_sha256: str
    before_state_sha256: str
    after_state_sha256: str
    succeeded: bool


@dataclass(frozen=True)
class LinkedXirTrace:
    attempt_id: str
    rid: str
    mid: str
    destination_effect_id: str


class XirTraceLinker:
    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def link(
        self,
        *,
        source: DecodedXirSource,
        intermediate: DecodedXirVerification,
        destination: DecodedXirVerification,
        effect: DecodedDestinationEffect,
    ) -> LinkedXirTrace:
        if (
            intermediate.location != "intermediate"
            or destination.location != "destination"
        ):
            raise XirLinkError("XIR verification locations are reordered")
        continuity = (
            source.rid.lower(),
            source.mid.lower(),
        )
        if continuity != (
            intermediate.rid.lower(),
            intermediate.mid.lower(),
        ) or continuity != (
            destination.rid.lower(),
            destination.mid.lower(),
        ):
            raise XirLinkError("RID or MID continuity failed")
        _bytes32(source.rid, "RID")
        _bytes32(source.mid, "MID")
        for digest in (
            source.payload_sha256,
            source.profile_sha256,
            source.evidence_sha256,
            source.transition_sha256,
            effect.payload_sha256,
            effect.before_state_sha256,
            effect.after_state_sha256,
        ):
            _digest(digest)
        if source.payload_sha256 != effect.payload_sha256:
            raise XirLinkError("destination effect payload differs from source payload")
        if intermediate.consumed_key != destination.consumed_key:
            raise XirLinkError("XIR consumed/replay key changed across the route")
        if not intermediate.verified or not destination.verified:
            raise XirLinkError("XIR verification or consumed-state check failed")
        if not effect.succeeded:
            raise XirLinkError("destination application effect did not succeed")
        source_tx = self._transaction(source.transaction_id)
        intermediate_tx = self._transaction(intermediate.transaction_id)
        destination_tx = self._transaction(destination.transaction_id)
        attempts = {
            str(source_tx["attempt_id"]),
            str(intermediate_tx["attempt_id"]),
            str(destination_tx["attempt_id"]),
        }
        if len(attempts) != 1:
            raise XirLinkError("XIR transactions belong to different attempts")
        attempt_id = attempts.pop()
        if source_tx["arm"] != "xir":
            raise XirLinkError("baseline attempt cannot contain XIR trace records")
        if (
            int(source_tx["chain_id"]),
            int(intermediate_tx["chain_id"]),
            int(destination_tx["chain_id"]),
        ) != (11_155_420, 421_614, 84_532):
            raise XirLinkError("XIR transactions changed fixed route order")
        if effect.transaction_id != destination.transaction_id:
            raise XirLinkError("destination verification and effect are not atomic")
        messages = self._messages(attempt_id)
        if set(messages) != {0, 1}:
            raise XirLinkError("XIR receipt path requires both carrier legs")
        leg0 = messages[0]
        leg1 = messages[1]
        if (
            intermediate.carrier_protocol_identifier.lower()
            != str(leg0["protocol_identifier"]).lower()
            or destination.carrier_protocol_identifier.lower()
            != str(leg1["protocol_identifier"]).lower()
        ):
            raise XirLinkError("XIR receipt path differs from linked carrier messages")
        if (
            leg0["payload_sha256"] != source.payload_sha256
            or leg1["payload_sha256"] != source.payload_sha256
        ):
            raise XirLinkError("carrier payload does not match XIR source payload")
        with self.store.write() as connection:
            existing = connection.execute(
                "SELECT * FROM xir_attempt_records WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            values = (
                source.rid.lower(),
                source.mid.lower(),
                source.payload_sha256,
                source.profile_sha256,
                source.evidence_sha256,
                source.transition_sha256,
                intermediate.consumed_key,
                leg0["carrier_message_id"],
                leg1["carrier_message_id"],
                source.transaction_id,
                intermediate.transaction_id,
                destination.transaction_id,
                effect.destination_effect_id,
                effect.before_state_sha256,
                effect.after_state_sha256,
            )
            if existing is None:
                try:
                    connection.execute(
                        """
                        INSERT INTO xir_attempt_records(
                            attempt_id, rid, mid, payload_sha256, profile_sha256,
                            evidence_sha256, transition_sha256, consumed_key,
                            leg0_carrier_message_id, leg1_carrier_message_id,
                            source_transaction_id, intermediate_transaction_id,
                            destination_transaction_id, intermediate_verified,
                            destination_verified, destination_effect_id,
                            effect_before_sha256, effect_after_sha256,
                            effect_succeeded
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1,
                                  ?, ?, ?, 1)
                        """,
                        (attempt_id, *values),
                    )
                except sqlite3.IntegrityError as exc:
                    raise XirLinkError("RID or MID is already linked") from exc
            else:
                current = (
                    existing["rid"],
                    existing["mid"],
                    existing["payload_sha256"],
                    existing["profile_sha256"],
                    existing["evidence_sha256"],
                    existing["transition_sha256"],
                    existing["consumed_key"],
                    existing["leg0_carrier_message_id"],
                    existing["leg1_carrier_message_id"],
                    existing["source_transaction_id"],
                    existing["intermediate_transaction_id"],
                    existing["destination_transaction_id"],
                    existing["destination_effect_id"],
                    existing["effect_before_sha256"],
                    existing["effect_after_sha256"],
                )
                if current != values:
                    raise XirLinkError("attempt already maps to a changed XIR trace")
            connection.execute(
                """
                INSERT OR IGNORE INTO destination_effects(
                    attempt_id, transaction_id, destination_effect_id,
                    predicate_sha256, succeeded
                ) VALUES (?, ?, ?, ?, 1)
                """,
                (
                    attempt_id,
                    effect.transaction_id,
                    effect.destination_effect_id,
                    effect.after_state_sha256,
                ),
            )
        return LinkedXirTrace(
            attempt_id=attempt_id,
            rid=source.rid.lower(),
            mid=source.mid.lower(),
            destination_effect_id=effect.destination_effect_id,
        )

    def _transaction(self, transaction_id: str) -> sqlite3.Row:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT transaction_record.chain_id, stage.attempt_id, attempt.arm
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
        if row is None:
            raise XirLinkError(f"unknown XIR transaction: {transaction_id}")
        return cast(sqlite3.Row, row)

    def _messages(self, attempt_id: str) -> dict[int, sqlite3.Row]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT * FROM carrier_messages
                WHERE attempt_id = ? ORDER BY leg_index
                """,
                (attempt_id,),
            ).fetchall()
        return {int(row["leg_index"]): row for row in rows}


class DestinationEffectRecorder:
    """Record the common destination predicate for either experiment arm."""

    def __init__(self, *, store: EvidenceStore) -> None:
        self.store = store

    def record(
        self,
        *,
        attempt_id: str,
        transaction_id: str,
        destination_effect_id: str,
        predicate_sha256: str,
        succeeded: bool,
    ) -> None:
        _digest(predicate_sha256)
        with self.store.write() as connection:
            row = connection.execute(
                """
                SELECT stage.attempt_id, stage.ordinal,
                       (
                           SELECT max(peer.ordinal) FROM stages AS peer
                           WHERE peer.attempt_id = stage.attempt_id
                       ) AS final_ordinal
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
            if (
                row is None
                or row["attempt_id"] != attempt_id
                or row["ordinal"] != row["final_ordinal"]
            ):
                raise XirLinkError(
                    "destination effect is not linked to the attempt final stage"
                )
            existing = connection.execute(
                """
                SELECT transaction_id, destination_effect_id,
                       predicate_sha256, succeeded
                FROM destination_effects WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            values = (
                transaction_id,
                destination_effect_id,
                predicate_sha256,
                int(succeeded),
            )
            if existing is not None:
                if tuple(existing) != values:
                    raise XirLinkError("destination effect is immutable")
                return
            connection.execute(
                """
                INSERT INTO destination_effects(
                    attempt_id, transaction_id, destination_effect_id,
                    predicate_sha256, succeeded
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (attempt_id, *values),
            )

def _bytes32(value: str, label: str) -> None:
    if (
        len(value) != 66
        or not value.startswith("0x")
        or any(character not in "0123456789abcdefABCDEF" for character in value[2:])
    ):
        raise XirLinkError(f"{label} must be bytes32 hex")


def _digest(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise XirLinkError("XIR hash fields must be lowercase SHA-256")
