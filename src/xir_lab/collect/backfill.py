"""Versioned, bounded, and fully auditable public-chain backfill."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import EvidenceStore

BackfillStrategy = Literal[
    "known_transaction_hash",
    "exact_identifier",
    "bounded_filter",
]


class BackfillError(RuntimeError):
    """Raised when collection would exceed its approved, linked search scope."""


@dataclass(frozen=True)
class CollectorCheckpoint:
    checkpoint_id: str
    collector_key: str
    version: int
    chain_id: int
    contract_addresses: tuple[str, ...]
    topics: tuple[str, ...]
    exact_filter: dict[str, str]
    approved_from_block: int
    approved_to_block: int
    last_finalized_block_number: int
    last_finalized_block_hash: str
    overlap_blocks: int
    parser_version: str
    provider_id: str
    state: str
    backlog_reason: str | None


@dataclass(frozen=True)
class ChainEvent:
    block_number: int
    block_hash: str
    transaction_hash: str
    log_index: int
    contract_address: str
    topic0: str | None
    exact_identifier_kind: str | None = None
    exact_identifier: str | None = None


@dataclass(frozen=True)
class EventPage:
    events: tuple[ChainEvent, ...]
    next_page_token: str | None
    complete: bool
    raw_bytes: bytes
    provider_id: str


@dataclass(frozen=True)
class ExactIdentifier:
    kind: Literal["rid", "mid", "carrier"]
    value: str


@dataclass(frozen=True)
class ScanResult:
    checkpoint_id: str
    checkpoint_version: int
    provider_calls: int
    unique_events: int
    duplicate_events: int
    advanced: bool
    backlog_reason: str | None


class ReadOnlyBackfillProvider(Protocol):
    def logs_by_transaction_hash(self, transaction_hash: str) -> EventPage:
        """Read logs for one already-known transaction hash."""

    def logs_by_identifier(self, identifier: ExactIdentifier) -> EventPage:
        """Read logs linked by one exact RID, MID, or carrier identifier."""

    def logs_by_filter(
        self,
        *,
        chain_id: int,
        addresses: tuple[str, ...],
        topics: tuple[str, ...],
        from_block: int,
        to_block: int,
        page_token: str | None,
    ) -> EventPage:
        """Read one page within an explicit address/topic and block bound."""


class BoundedBackfillCollector:
    """Run priority-ordered read-only backfill and version its checkpoint."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        provider: ReadOnlyBackfillProvider,
        max_pages: int = 100,
    ) -> None:
        if max_pages < 1:
            raise BackfillError("max_pages must be positive")
        self.store = store
        self.provider = provider
        self.max_pages = max_pages

    def create_checkpoint(
        self,
        *,
        collector_key: str,
        chain_id: int,
        contract_addresses: tuple[str, ...],
        topics: tuple[str, ...],
        exact_filter: dict[str, str],
        approved_from_block: int,
        approved_to_block: int,
        last_finalized_block_number: int,
        last_finalized_block_hash: str,
        overlap_blocks: int,
        parser_version: str,
        provider_id: str,
    ) -> CollectorCheckpoint:
        if not collector_key or chain_id <= 0:
            raise BackfillError("collector key and chain ID are required")
        if not contract_addresses or not topics:
            raise BackfillError("bounded collector requires addresses and topics")
        if approved_from_block < 0 or approved_to_block < approved_from_block:
            raise BackfillError("approved block bounds are invalid")
        if not approved_from_block <= last_finalized_block_number <= approved_to_block:
            raise BackfillError("finalized checkpoint is outside approved bounds")
        if overlap_blocks < 1 or not parser_version or not provider_id:
            raise BackfillError("overlap, parser version, and provider are required")
        addresses = tuple(sorted({value.lower() for value in contract_addresses}))
        normalized_topics = tuple(value.lower() for value in topics)
        with self.store.write() as connection:
            prior = connection.execute(
                """
                SELECT max(version) FROM collector_checkpoints
                WHERE collector_key = ?
                """,
                (collector_key,),
            ).fetchone()[0]
            version = 1 if prior is None else int(prior) + 1
            checkpoint_id = stable_id(
                "observation", "collector-checkpoint", collector_key, version
            )
            connection.execute(
                """
                INSERT INTO collector_checkpoints(
                    checkpoint_id, collector_key, version, chain_id,
                    contract_addresses_json, topics_json, exact_filter_json,
                    approved_from_block, approved_to_block,
                    last_finalized_block_number, last_finalized_block_hash,
                    overlap_blocks, parser_version, provider_id, state,
                    backlog_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready',
                          NULL, ?)
                """,
                (
                    checkpoint_id,
                    collector_key,
                    version,
                    chain_id,
                    _canonical(addresses),
                    _canonical(normalized_topics),
                    _canonical(exact_filter),
                    approved_from_block,
                    approved_to_block,
                    last_finalized_block_number,
                    last_finalized_block_hash.lower(),
                    overlap_blocks,
                    parser_version,
                    provider_id,
                    _now(),
                ),
            )
        return self.checkpoint(checkpoint_id)

    def checkpoint(self, checkpoint_id: str) -> CollectorCheckpoint:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM collector_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
        if row is None:
            raise BackfillError(f"unknown collector checkpoint: {checkpoint_id}")
        return _checkpoint(row)

    def scan(
        self,
        *,
        checkpoint_id: str,
        known_transaction_hashes: tuple[str, ...] = (),
        exact_identifiers: tuple[ExactIdentifier, ...] = (),
        target_finalized_block_number: int,
        target_finalized_block_hash: str,
    ) -> ScanResult:
        checkpoint = self.checkpoint(checkpoint_id)
        with self.store.connect(read_only=True) as connection:
            latest_version = int(
                connection.execute(
                    """
                    SELECT max(version) FROM collector_checkpoints
                    WHERE collector_key = ?
                    """,
                    (checkpoint.collector_key,),
                ).fetchone()[0]
            )
        if checkpoint.version != latest_version:
            raise BackfillError("only the latest checkpoint version may be resumed")
        if checkpoint.state != "ready":
            raise BackfillError("backlogged checkpoint must be reconciled before restart")
        if not (
            checkpoint.last_finalized_block_number
            <= target_finalized_block_number
            <= checkpoint.approved_to_block
        ):
            raise BackfillError("target finalized block exceeds checkpoint bounds")
        provider_calls = 0
        unique_events = 0
        duplicate_events = 0
        backlog_reason: str | None = None

        for transaction_hash in known_transaction_hashes:
            page = self.provider.logs_by_transaction_hash(transaction_hash)
            inserted, duplicates = self._record_page(
                checkpoint=checkpoint,
                strategy="known_transaction_hash",
                query_value=transaction_hash.lower(),
                from_block=None,
                to_block=None,
                page_token=None,
                page=page,
            )
            provider_calls += 1
            unique_events += inserted
            duplicate_events += duplicates
            if not page.complete or page.next_page_token is not None:
                backlog_reason = "known_hash_query_incomplete"
                break

        if backlog_reason is None:
            for identifier in exact_identifiers:
                page = self.provider.logs_by_identifier(identifier)
                inserted, duplicates = self._record_page(
                    checkpoint=checkpoint,
                    strategy="exact_identifier",
                    query_value=f"{identifier.kind}:{identifier.value.lower()}",
                    from_block=None,
                    to_block=None,
                    page_token=None,
                    page=page,
                )
                provider_calls += 1
                unique_events += inserted
                duplicate_events += duplicates
                if not page.complete or page.next_page_token is not None:
                    backlog_reason = "exact_identifier_query_incomplete"
                    break

        if backlog_reason is None:
            from_block = max(
                checkpoint.approved_from_block,
                checkpoint.last_finalized_block_number
                - checkpoint.overlap_blocks
                + 1,
            )
            page_token: str | None = None
            seen_tokens: set[str] = set()
            for _ in range(self.max_pages):
                page = self.provider.logs_by_filter(
                    chain_id=checkpoint.chain_id,
                    addresses=checkpoint.contract_addresses,
                    topics=checkpoint.topics,
                    from_block=from_block,
                    to_block=target_finalized_block_number,
                    page_token=page_token,
                )
                inserted, duplicates = self._record_page(
                    checkpoint=checkpoint,
                    strategy="bounded_filter",
                    query_value=None,
                    from_block=from_block,
                    to_block=target_finalized_block_number,
                    page_token=page_token,
                    page=page,
                )
                provider_calls += 1
                unique_events += inserted
                duplicate_events += duplicates
                if not page.complete:
                    backlog_reason = "bounded_filter_query_incomplete"
                    break
                if page.next_page_token is None:
                    break
                if page.next_page_token in seen_tokens:
                    backlog_reason = "pagination_token_repeated"
                    break
                seen_tokens.add(page.next_page_token)
                page_token = page.next_page_token
            else:
                backlog_reason = "pagination_limit_exceeded"

        if backlog_reason is not None:
            with self.store.write() as connection:
                connection.execute(
                    """
                    UPDATE collector_checkpoints
                    SET state = 'backlogged', backlog_reason = ?
                    WHERE checkpoint_id = ?
                    """,
                    (backlog_reason, checkpoint_id),
                )
            return ScanResult(
                checkpoint_id=checkpoint_id,
                checkpoint_version=checkpoint.version,
                provider_calls=provider_calls,
                unique_events=unique_events,
                duplicate_events=duplicate_events,
                advanced=False,
                backlog_reason=backlog_reason,
            )

        advanced = self.create_checkpoint(
            collector_key=checkpoint.collector_key,
            chain_id=checkpoint.chain_id,
            contract_addresses=checkpoint.contract_addresses,
            topics=checkpoint.topics,
            exact_filter=checkpoint.exact_filter,
            approved_from_block=checkpoint.approved_from_block,
            approved_to_block=checkpoint.approved_to_block,
            last_finalized_block_number=target_finalized_block_number,
            last_finalized_block_hash=target_finalized_block_hash,
            overlap_blocks=checkpoint.overlap_blocks,
            parser_version=checkpoint.parser_version,
            provider_id=checkpoint.provider_id,
        )
        return ScanResult(
            checkpoint_id=advanced.checkpoint_id,
            checkpoint_version=advanced.version,
            provider_calls=provider_calls,
            unique_events=unique_events,
            duplicate_events=duplicate_events,
            advanced=True,
            backlog_reason=None,
        )

    def record_auxiliary_carrier_status(
        self,
        *,
        attempt_id: str,
        protocol: Literal["hyperlane", "layerzero-v2"],
        protocol_identifier: str,
        reported_status: str,
        provider_id: str,
        raw_bytes: bytes,
    ) -> str:
        raw_sha256 = self.store.put_raw(
            raw_bytes,
            media_type="application/json",
            metadata={
                "source": "auxiliary_carrier_status_api",
                "provider_id": provider_id,
                "protocol": protocol,
            },
        )
        observation_id = stable_id(
            "observation",
            "auxiliary-carrier-status",
            attempt_id,
            protocol,
            protocol_identifier.lower(),
            raw_sha256,
        )
        with self.store.write() as connection:
            linked = connection.execute(
                """
                SELECT 1 FROM carrier_messages
                WHERE attempt_id = ? AND protocol = ?
                  AND lower(protocol_identifier) = ?
                """,
                (attempt_id, protocol, protocol_identifier.lower()),
            ).fetchone()
            if linked is None:
                raise BackfillError("auxiliary status is not linked to a carrier message")
            connection.execute(
                """
                INSERT OR IGNORE INTO auxiliary_carrier_observations(
                    auxiliary_observation_id, attempt_id, protocol,
                    protocol_identifier, reported_status, provider_id,
                    raw_sha256, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    attempt_id,
                    protocol,
                    protocol_identifier.lower(),
                    reported_status,
                    provider_id,
                    raw_sha256,
                    _now(),
                ),
            )
        return observation_id

    def _record_page(
        self,
        *,
        checkpoint: CollectorCheckpoint,
        strategy: BackfillStrategy,
        query_value: str | None,
        from_block: int | None,
        to_block: int | None,
        page_token: str | None,
        page: EventPage,
    ) -> tuple[int, int]:
        if page.provider_id != checkpoint.provider_id:
            raise BackfillError("provider identity changed from checkpoint")
        for event in page.events:
            self._validate_event(checkpoint, event, from_block, to_block)
            if (
                strategy == "known_transaction_hash"
                and event.transaction_hash.lower() != query_value
            ):
                raise BackfillError("known-hash result is not linked to the query")
            if strategy == "exact_identifier":
                assert query_value is not None
                kind, value = query_value.split(":", maxsplit=1)
                if (
                    event.exact_identifier_kind != kind
                    or event.exact_identifier is None
                    or event.exact_identifier.lower() != value
                ):
                    raise BackfillError(
                        "exact-identifier result is not linked to the query"
                    )
        raw_sha256 = self.store.put_raw(
            page.raw_bytes,
            media_type="application/json",
            metadata={
                "source": "public_read_rpc",
                "provider_id": page.provider_id,
                "kind": "collector_log_page",
                "strategy": strategy,
            },
        )
        inserted = 0
        with self.store.write() as connection:
            cursor = connection.execute(
                """
                INSERT INTO collector_calls(
                    checkpoint_id, strategy, query_value, from_block, to_block,
                    page_token, result_count, complete, raw_sha256, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint.checkpoint_id,
                    strategy,
                    query_value,
                    from_block,
                    to_block,
                    page_token,
                    len(page.events),
                    int(page.complete),
                    raw_sha256,
                    _now(),
                ),
            )
            if cursor.lastrowid is None:
                raise BackfillError("collector call did not receive an audit sequence")
            call_sequence = cursor.lastrowid
            for event in page.events:
                event_id = stable_id(
                    "observation",
                    "collector-event",
                    checkpoint.chain_id,
                    event.block_hash.lower(),
                    event.transaction_hash.lower(),
                    event.log_index,
                )
                result = connection.execute(
                    """
                    INSERT OR IGNORE INTO collector_chain_events(
                        collector_event_id, chain_id, block_number, block_hash,
                        transaction_hash, log_index, contract_address, topic0,
                        exact_identifier_kind, exact_identifier, raw_sha256,
                        first_call_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        checkpoint.chain_id,
                        event.block_number,
                        event.block_hash.lower(),
                        event.transaction_hash.lower(),
                        event.log_index,
                        event.contract_address.lower(),
                        None if event.topic0 is None else event.topic0.lower(),
                        event.exact_identifier_kind,
                        event.exact_identifier,
                        raw_sha256,
                        call_sequence,
                    ),
                )
                inserted += result.rowcount
        return inserted, len(page.events) - inserted

    @staticmethod
    def _validate_event(
        checkpoint: CollectorCheckpoint,
        event: ChainEvent,
        from_block: int | None,
        to_block: int | None,
    ) -> None:
        if event.block_number < checkpoint.approved_from_block:
            raise BackfillError("event is below approved block bounds")
        if event.block_number > checkpoint.approved_to_block:
            raise BackfillError("event is above approved block bounds")
        if from_block is not None and event.block_number < from_block:
            raise BackfillError("filter result is below requested overlap range")
        if to_block is not None and event.block_number > to_block:
            raise BackfillError("filter result is above requested block range")
        if event.contract_address.lower() not in checkpoint.contract_addresses:
            raise BackfillError("event address is outside checkpoint filter")
        if event.topic0 is not None and event.topic0.lower() not in checkpoint.topics:
            raise BackfillError("event topic is outside checkpoint filter")
        if event.log_index < 0:
            raise BackfillError("event log index is negative")


def _checkpoint(row: sqlite3.Row) -> CollectorCheckpoint:
    return CollectorCheckpoint(
        checkpoint_id=str(row["checkpoint_id"]),
        collector_key=str(row["collector_key"]),
        version=int(row["version"]),
        chain_id=int(row["chain_id"]),
        contract_addresses=tuple(json.loads(row["contract_addresses_json"])),
        topics=tuple(json.loads(row["topics_json"])),
        exact_filter=cast(dict[str, str], json.loads(row["exact_filter_json"])),
        approved_from_block=int(row["approved_from_block"]),
        approved_to_block=int(row["approved_to_block"]),
        last_finalized_block_number=int(row["last_finalized_block_number"]),
        last_finalized_block_hash=str(row["last_finalized_block_hash"]),
        overlap_blocks=int(row["overlap_blocks"]),
        parser_version=str(row["parser_version"]),
        provider_id=str(row["provider_id"]),
        state=str(row["state"]),
        backlog_reason=(
            None if row["backlog_reason"] is None else str(row["backlog_reason"])
        ),
    )


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    return datetime.now(UTC).isoformat()
