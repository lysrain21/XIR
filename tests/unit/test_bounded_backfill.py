from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from xir_lab.collect.backfill import (
    BackfillError,
    BoundedBackfillCollector,
    ChainEvent,
    EventPage,
    ExactIdentifier,
)
from xir_lab.evidence.store import EvidenceStore

CHAIN = 11_155_420
ADDRESS = "0x" + "11" * 20
TOPIC = "0x" + "22" * 32
BLOCK_HASH = "0x" + "33" * 32
TX_HASH = "0x" + "44" * 32
CARRIER_ID = "0x" + "55" * 32


class FixtureBackfillProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.event = ChainEvent(
            99,
            BLOCK_HASH,
            TX_HASH,
            0,
            ADDRESS,
            TOPIC,
            "rid",
            "0x" + "66" * 32,
        )
        self.filter_pages = (
            EventPage((self.event,), "page-2", True, b'{"page":1}', "rpc-a"),
            EventPage((self.event,), None, True, b'{"page":2}', "rpc-a"),
        )

    def logs_by_transaction_hash(self, transaction_hash: str) -> EventPage:
        self.calls.append(("known_transaction_hash", transaction_hash))
        return EventPage((self.event,), None, True, b'{"known":1}', "rpc-a")

    def logs_by_identifier(self, identifier: ExactIdentifier) -> EventPage:
        self.calls.append(("exact_identifier", identifier.kind, identifier.value))
        return EventPage((self.event,), None, True, b'{"exact":1}', "rpc-a")

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
        self.calls.append(
            (
                "bounded_filter",
                chain_id,
                addresses,
                topics,
                from_block,
                to_block,
                page_token,
            )
        )
        return self.filter_pages[0 if page_token is None else 1]


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    return store


def _checkpoint(
    collector: BoundedBackfillCollector,
    *,
    last_finalized_block_number: int = 100,
) -> str:
    return collector.create_checkpoint(
        collector_key="op-xir-events",
        chain_id=CHAIN,
        contract_addresses=(ADDRESS,),
        topics=(TOPIC,),
        exact_filter={"event": "XirVerified"},
        approved_from_block=90,
        approved_to_block=110,
        last_finalized_block_number=last_finalized_block_number,
        last_finalized_block_hash="0x" + "77" * 32,
        overlap_blocks=3,
        parser_version="xir-events-v1",
        provider_id="rpc-a",
    ).checkpoint_id


def test_priority_order_overlap_pagination_and_duplicates_are_auditable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureBackfillProvider()
    collector = BoundedBackfillCollector(store=store, provider=provider)
    checkpoint_id = _checkpoint(collector)
    result = collector.scan(
        checkpoint_id=checkpoint_id,
        known_transaction_hashes=(TX_HASH,),
        exact_identifiers=(ExactIdentifier("rid", "0x" + "66" * 32),),
        target_finalized_block_number=105,
        target_finalized_block_hash="0x" + "88" * 32,
    )
    assert result.advanced is True
    assert result.checkpoint_version == 2
    assert result.provider_calls == 4
    assert result.unique_events == 1
    assert result.duplicate_events == 3
    assert [call[0] for call in provider.calls] == [
        "known_transaction_hash",
        "exact_identifier",
        "bounded_filter",
        "bounded_filter",
    ]
    assert provider.calls[2][4:6] == (98, 105)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM collector_chain_events"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM collector_calls"
        ).fetchone()[0] == 4
        versions = connection.execute(
            """
            SELECT version, last_finalized_block_number
            FROM collector_checkpoints ORDER BY version
            """
        ).fetchall()
    assert [tuple(row) for row in versions] == [(1, 100), (2, 105)]


def test_incomplete_page_exposes_backlog_without_advancing_checkpoint(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureBackfillProvider()
    provider.filter_pages = (
        replace(
            provider.filter_pages[0],
            next_page_token=None,
            complete=False,
        ),
    )
    collector = BoundedBackfillCollector(store=store, provider=provider)
    checkpoint_id = _checkpoint(collector)
    result = collector.scan(
        checkpoint_id=checkpoint_id,
        target_finalized_block_number=105,
        target_finalized_block_hash="0x" + "88" * 32,
    )
    assert result.advanced is False
    assert result.backlog_reason == "bounded_filter_query_incomplete"
    checkpoint = collector.checkpoint(checkpoint_id)
    assert checkpoint.version == 1
    assert checkpoint.last_finalized_block_number == 100
    assert checkpoint.state == "backlogged"
    with pytest.raises(BackfillError, match="reconciled"):
        collector.scan(
            checkpoint_id=checkpoint_id,
            target_finalized_block_number=105,
            target_finalized_block_hash="0x" + "88" * 32,
        )


def test_unbounded_or_provider_changed_search_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    provider = FixtureBackfillProvider()
    collector = BoundedBackfillCollector(store=store, provider=provider)
    with pytest.raises(BackfillError, match="addresses and topics"):
        collector.create_checkpoint(
            collector_key="unbounded",
            chain_id=CHAIN,
            contract_addresses=(),
            topics=(TOPIC,),
            exact_filter={},
            approved_from_block=90,
            approved_to_block=110,
            last_finalized_block_number=100,
            last_finalized_block_hash=BLOCK_HASH,
            overlap_blocks=3,
            parser_version="v1",
            provider_id="rpc-a",
        )
    checkpoint_id = _checkpoint(collector)
    provider.filter_pages = (
        replace(provider.filter_pages[0], provider_id="different-rpc"),
    )
    with pytest.raises(BackfillError, match="provider identity"):
        collector.scan(
            checkpoint_id=checkpoint_id,
            target_finalized_block_number=105,
            target_finalized_block_hash="0x" + "88" * 32,
        )


def test_auxiliary_carrier_delivery_does_not_finalize_attempt(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
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
            VALUES ('condition-1', 'run-1', 'HH', 'running')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-1', 'condition-1', 0)
            """
        )
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, pair_id, arm, attempt_kind,
                state, created_at
            ) VALUES (
                'attempt-1', 'condition-1', 'pair-1', 'baseline',
                'primary', 'in_flight', '2026-07-26T00:00:00Z'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO carrier_messages(
                carrier_message_id, attempt_id, protocol, protocol_identifier
            ) VALUES ('carrier-1', 'attempt-1', 'hyperlane', ?)
            """,
            (CARRIER_ID,),
        )
    collector = BoundedBackfillCollector(
        store=store,
        provider=FixtureBackfillProvider(),
    )
    collector.record_auxiliary_carrier_status(
        attempt_id="attempt-1",
        protocol="hyperlane",
        protocol_identifier=CARRIER_ID,
        reported_status="delivered",
        provider_id="carrier-explorer",
        raw_bytes=b'{"status":"delivered"}',
    )
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM attempts WHERE attempt_id = 'attempt-1'"
        ).fetchone()[0] == "in_flight"
        row = connection.execute(
            """
            SELECT reported_status, provider_id
            FROM auxiliary_carrier_observations
            """
        ).fetchone()
    assert tuple(row) == ("delivered", "carrier-explorer")
