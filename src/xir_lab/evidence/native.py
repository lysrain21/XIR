"""Typed append-only evidence operations for native protocol-stack runs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import rfc8785

from xir_lab.evidence.store import EvidenceStore, StoreError

NativeProtocol = Literal[
    "hyperlane", "layerzero-v2", "xir", "application", "operations"
]
ActionState = Literal[
    "intended",
    "signed",
    "broadcast_unknown",
    "submitted",
    "included",
    "finalized",
    "succeeded",
    "failed",
    "skipped",
]
TERMINAL_ACTION_STATES = frozenset({"succeeded", "failed", "skipped"})


def _now() -> str:
    return datetime.now(UTC).isoformat()


def native_evidence_id(kind: str, *components: str | int) -> str:
    canonical = rfc8785.dumps({"kind": kind, "components": list(components)})
    return f"native_{kind}_{hashlib.sha256(canonical).hexdigest()[:24]}"


@dataclass(frozen=True)
class NativeActionIntent:
    action_id: str
    run_id: str
    attempt_id: str | None
    protocol: NativeProtocol
    action_kind: str
    chain_id: int | None
    actor_public_id: str
    nonce: int | None
    target: str | None
    calldata_sha256: str | None
    calldata_bytes: int | None
    protocol_identifier: str | None
    retry_of_action_id: str | None = None
    retry_index: int = 0


@dataclass(frozen=True)
class NativeActionObservation:
    observation_id: str
    action_id: str
    state: ActionState
    transaction_id: str | None
    raw_sha256: str | None
    error_class: str | None
    details: dict[str, Any]


@dataclass(frozen=True)
class NativeProtocolMessage:
    native_message_id: str
    attempt_id: str
    leg_index: int
    protocol: Literal["hyperlane", "layerzero-v2"]
    protocol_identifier: str
    protocol_nonce: int | None
    source_chain_id: int
    destination_chain_id: int
    source_transaction_id: str
    encoded_message_sha256: str
    payload_sha256: str
    dispatch_time: str


@dataclass(frozen=True)
class NativeProcessSample:
    sample_id: str
    run_id: str
    phase: Literal["smoke", "rehearsal", "scale", "recovery"]
    process_kind: str
    process_id: str
    pid: int | None
    cpu_percent: float | None
    rss_bytes: int | None
    read_bytes: int | None
    write_bytes: int | None
    network_rx_bytes: int | None
    network_tx_bytes: int | None
    queue_depth: int | None
    healthy: bool | None
    gap_error: str | None


class NativeEvidenceStore:
    """Fail-closed native evidence writer layered on the shared ledger."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def record_action_intent(self, intent: NativeActionIntent) -> None:
        if not intent.action_kind or not intent.actor_public_id:
            raise StoreError("native action intent lacks kind or public actor")
        if intent.calldata_sha256 is not None and len(intent.calldata_sha256) != 64:
            raise StoreError("native action calldata digest must be SHA-256")
        with self.store.write() as connection:
            if intent.retry_of_action_id is not None:
                prior = connection.execute(
                    """
                    SELECT attempt_id, protocol, action_kind, chain_id, actor_public_id,
                           target, calldata_sha256, protocol_identifier, retry_index
                    FROM native_action_intents WHERE action_id = ?
                    """,
                    (intent.retry_of_action_id,),
                ).fetchone()
                if prior is None:
                    raise StoreError(
                        f"unknown native retry predecessor: {intent.retry_of_action_id}"
                    )
                coordinates = (
                    intent.attempt_id,
                    intent.protocol,
                    intent.action_kind,
                    intent.chain_id,
                    intent.actor_public_id,
                    intent.target,
                    intent.calldata_sha256,
                    intent.protocol_identifier,
                )
                if coordinates != tuple(prior)[:8]:
                    raise StoreError("native retry changed semantic coordinates")
                if intent.retry_index != int(prior["retry_index"]) + 1:
                    raise StoreError("native retry index is not consecutive")
            elif intent.retry_index != 0:
                raise StoreError("native root action must have retry index zero")
            connection.execute(
                """
                INSERT INTO native_action_intents(
                    action_id, run_id, attempt_id, protocol, action_kind, chain_id,
                    actor_public_id, nonce, target, calldata_sha256, calldata_bytes,
                    protocol_identifier, retry_of_action_id, retry_index, intended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent.action_id,
                    intent.run_id,
                    intent.attempt_id,
                    intent.protocol,
                    intent.action_kind,
                    intent.chain_id,
                    intent.actor_public_id,
                    intent.nonce,
                    intent.target,
                    intent.calldata_sha256,
                    intent.calldata_bytes,
                    intent.protocol_identifier,
                    intent.retry_of_action_id,
                    intent.retry_index,
                    _now(),
                ),
            )
            observation_id = native_evidence_id(
                "action_observation", intent.action_id, 0, "intended"
            )
            connection.execute(
                """
                INSERT INTO native_action_observations(
                    observation_id, action_id, observation_index, state,
                    details_json, observed_at
                ) VALUES (?, ?, 0, 'intended', ?, ?)
                """,
                (observation_id, intent.action_id, "{}", _now()),
            )

    def append_action_observation(
        self, observation: NativeActionObservation
    ) -> None:
        with self.store.write() as connection:
            current = connection.execute(
                """
                SELECT observation_index, state
                FROM native_action_observations
                WHERE action_id = ?
                ORDER BY observation_index DESC LIMIT 1
                """,
                (observation.action_id,),
            ).fetchone()
            if current is None:
                raise StoreError(
                    f"native side effect lacks prior intent: {observation.action_id}"
                )
            if str(current["state"]) in TERMINAL_ACTION_STATES:
                raise StoreError(
                    f"terminal native action cannot transition: {observation.action_id}"
                )
            if observation.state == "intended":
                raise StoreError("native intended observation is created with the intent")
            connection.execute(
                """
                INSERT INTO native_action_observations(
                    observation_id, action_id, observation_index, state,
                    transaction_id, raw_sha256, error_class, details_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.observation_id,
                    observation.action_id,
                    int(current["observation_index"]) + 1,
                    observation.state,
                    observation.transaction_id,
                    observation.raw_sha256,
                    observation.error_class,
                    rfc8785.dumps(observation.details).decode("utf-8"),
                    _now(),
                ),
            )

    def record_protocol_message(self, message: NativeProtocolMessage) -> None:
        if message.leg_index not in (0, 1):
            raise StoreError("native protocol message leg must be zero or one")
        with self.store.write() as connection:
            intent = connection.execute(
                """
                SELECT 1
                FROM native_action_intents AS action
                JOIN native_action_observations AS observation
                  ON observation.action_id = action.action_id
                WHERE action.attempt_id = ?
                  AND action.protocol = ?
                  AND action.protocol_identifier = ?
                  AND observation.state = 'intended'
                LIMIT 1
                """,
                (
                    message.attempt_id,
                    message.protocol,
                    message.protocol_identifier,
                ),
            ).fetchone()
            if intent is None:
                raise StoreError("protocol message lacks a persisted action intent")
            connection.execute(
                """
                INSERT INTO native_protocol_messages(
                    native_message_id, attempt_id, leg_index, protocol,
                    protocol_identifier, protocol_nonce, source_chain_id,
                    destination_chain_id, source_transaction_id,
                    encoded_message_sha256, payload_sha256, dispatch_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.native_message_id,
                    message.attempt_id,
                    message.leg_index,
                    message.protocol,
                    message.protocol_identifier,
                    message.protocol_nonce,
                    message.source_chain_id,
                    message.destination_chain_id,
                    message.source_transaction_id,
                    message.encoded_message_sha256,
                    message.payload_sha256,
                    message.dispatch_time,
                ),
            )

    def record_process_sample(self, sample: NativeProcessSample) -> None:
        measurements = (
            sample.pid,
            sample.cpu_percent,
            sample.rss_bytes,
            sample.read_bytes,
            sample.write_bytes,
            sample.network_rx_bytes,
            sample.network_tx_bytes,
            sample.queue_depth,
            sample.healthy,
        )
        if sample.gap_error is None and all(value is None for value in measurements):
            raise StoreError("empty native process sample requires a gap error")
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT INTO native_process_samples(
                    sample_id, run_id, phase, process_kind, process_id, pid,
                    cpu_percent, rss_bytes, read_bytes, write_bytes,
                    network_rx_bytes, network_tx_bytes, queue_depth, healthy,
                    gap_error, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.sample_id,
                    sample.run_id,
                    sample.phase,
                    sample.process_kind,
                    sample.process_id,
                    sample.pid,
                    sample.cpu_percent,
                    sample.rss_bytes,
                    sample.read_bytes,
                    sample.write_bytes,
                    sample.network_rx_bytes,
                    sample.network_tx_bytes,
                    sample.queue_depth,
                    (
                        None
                        if sample.healthy is None
                        else int(sample.healthy)
                    ),
                    sample.gap_error,
                    _now(),
                ),
            )
