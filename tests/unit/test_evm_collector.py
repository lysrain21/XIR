from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from xir_lab.collect.evm import (
    EvmCollector,
    EvmCollectorError,
    PublicBalance,
    PublicBlockHeader,
    PublicLog,
    PublicReceipt,
    PublicTransaction,
    RawEnvelope,
)
from xir_lab.evidence.store import EvidenceStore
from xir_lab.faults import CrashPoint, InjectedCrash, OneShotCrashInjector

CHAIN = 11_155_420
TX_HASH = "0x" + "11" * 32
BLOCK_HASH = "0x" + "22" * 32
SENDER = "0x" + "33" * 20
RECIPIENT = "0x" + "44" * 20


class FixtureReadProvider:
    def __init__(self) -> None:
        self.calls = {"transaction": 0, "receipt": 0, "block": 0, "balance": 0}
        self.broadcast_calls = 0
        self.transaction_value = PublicTransaction(
            TX_HASH,
            CHAIN,
            7,
            SENDER,
            RECIPIENT,
            "0x1234",
            50,
        )
        self.receipt_value = PublicReceipt(
            TX_HASH,
            100,
            BLOCK_HASH,
            1,
            21_000,
            2,
            (
                PublicLog(0, "0x" + "aa" * 32),
                PublicLog(1, "0x" + "bb" * 32),
            ),
            None,
            "provider_does_not_expose_rollup_fee",
            10,
            "experiment",
        )
        self.block_value = PublicBlockHeader(
            100,
            BLOCK_HASH,
            "0x" + "55" * 32,
            1_700_000_000,
        )

    def transaction(self, transaction_hash: str) -> RawEnvelope[PublicTransaction]:
        assert transaction_hash == TX_HASH
        self.calls["transaction"] += 1
        return RawEnvelope(
            self.transaction_value,
            b'{"jsonrpc":"2.0","result":{"hash":"fixture"}}',
            "fixture-read-rpc",
        )

    def receipt(self, transaction_hash: str) -> RawEnvelope[PublicReceipt]:
        assert transaction_hash == TX_HASH
        self.calls["receipt"] += 1
        return RawEnvelope(
            self.receipt_value,
            b'{"jsonrpc":"2.0","result":{"receipt":"fixture"}}',
            "fixture-read-rpc",
        )

    def block_header(
        self, block_number: int
    ) -> RawEnvelope[PublicBlockHeader]:
        assert block_number == 100
        self.calls["block"] += 1
        return RawEnvelope(
            self.block_value,
            b'{"jsonrpc":"2.0","result":{"block":"fixture"}}',
            "fixture-read-rpc",
        )

    def balance(self, address: str, block_number: int) -> RawEnvelope[PublicBalance]:
        self.calls["balance"] += 1
        value = PublicBalance(address, block_number, 1_000 - block_number)
        return RawEnvelope(
            value,
            f'{{"address":"{address}","block":{block_number}}}'.encode(),
            "fixture-read-rpc",
        )

    def broadcast(self, payload: bytes) -> None:  # pragma: no cover - must stay unused
        del payload
        self.broadcast_calls += 1


def _store(
    tmp_path: Path,
    *,
    stage_name: str = "source_dispatch",
) -> EvidenceStore:
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
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-0', 'condition-hh', 0)
            """
        )
        connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, condition_id, pair_id, arm, attempt_kind,
                state, created_at
            ) VALUES (
                'attempt-0', 'condition-hh', 'pair-0', 'baseline',
                'primary', 'in_flight', '2026-07-26T00:00:00Z'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO stages(stage_id, attempt_id, ordinal, stage_name, state)
            VALUES ('stage-0', 'attempt-0', 0, ?, 'in_flight')
            """,
            (stage_name,),
        )
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES (
                'intent-0', 'stage-0', 'signop-0', ?, 7,
                'submitted', ?, '2026-07-26T00:00:00Z'
            )
            """,
            (CHAIN, "22" * 32),
        )
        connection.execute(
            """
            INSERT INTO transactions(
                transaction_id, intent_id, chain_id, nonce,
                transaction_hash, state
            ) VALUES (
                'transaction-0', 'intent-0', ?, 7, ?, 'submitted'
            )
            """,
            (CHAIN, TX_HASH),
        )
    return store


def test_collects_raw_and_normalized_public_resources_with_zero_writes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureReadProvider()
    collector = EvmCollector(store=store, provider=provider)
    result = collector.collect_transaction(
        transaction_id="transaction-0",
        balance_accounts=(SENDER, RECIPIENT),
    )
    assert result.execution_fee_wei == 42_000
    assert result.input_bytes == 2
    assert result.balance_snapshots == 4
    assert provider.broadcast_calls == 0
    with store.connect(read_only=True) as connection:
        resource = connection.execute(
            """
            SELECT transaction_value_wei, gas_used, effective_gas_price_wei,
                   execution_fee_wei, l1_data_fee_wei,
                   l1_data_fee_unavailable_reason, carrier_payment_wei,
                   funding_attribution
            FROM transaction_resources
            """
        ).fetchone()
        assert tuple(resource) == (
            "50",
            21_000,
            "2",
            "42000",
            None,
            "provider_does_not_expose_rollup_fee",
            "10",
            "experiment",
        )
        assert connection.execute("SELECT count(*) FROM raw_blobs").fetchone()[0] == 7
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM account_snapshots"
        ).fetchone()[0] == 4
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id = 'transaction-0'"
        ).fetchone()[0] == "included"


def test_collection_is_idempotent_and_does_not_repeat_provider_reads(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureReadProvider()
    collector = EvmCollector(store=store, provider=provider)
    first = collector.collect_transaction(transaction_id="transaction-0")
    calls = dict(provider.calls)
    second = collector.collect_transaction(transaction_id="transaction-0")
    assert first == second
    assert provider.calls == calls


def test_observed_l1_data_fee_is_preserved_separately(tmp_path: Path) -> None:
    store = _store(tmp_path)
    provider = FixtureReadProvider()
    provider.receipt_value = replace(
        provider.receipt_value,
        l1_data_fee_wei=123,
        l1_data_fee_unavailable_reason=None,
        funding_attribution="external",
    )
    EvmCollector(store=store, provider=provider).collect_transaction(
        transaction_id="transaction-0"
    )
    with store.connect(read_only=True) as connection:
        row = connection.execute(
            """
            SELECT l1_data_fee_wei, l1_data_fee_unavailable_reason,
                   funding_attribution
            FROM transaction_resources
            """
        ).fetchone()
    assert tuple(row) == ("123", None, "external")


def test_hash_block_and_l1_fee_inconsistency_fail_before_normalization(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureReadProvider()
    provider.receipt_value = replace(
        provider.receipt_value,
        block_hash="0x" + "ff" * 32,
    )
    with pytest.raises(EvmCollectorError, match="block header mismatch"):
        EvmCollector(store=store, provider=provider).collect_transaction(
            transaction_id="transaction-0"
        )
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM transaction_resources"
        ).fetchone()[0] == 0

    store = _store(tmp_path / "l1")
    provider = FixtureReadProvider()
    provider.receipt_value = replace(
        provider.receipt_value,
        l1_data_fee_wei=None,
        l1_data_fee_unavailable_reason=None,
    )
    with pytest.raises(EvmCollectorError, match="exactly one"):
        EvmCollector(store=store, provider=provider).collect_transaction(
            transaction_id="transaction-0"
        )


@pytest.mark.parametrize("unavailable", ["transaction", "receipt", "block"])
def test_null_receipt_and_archive_unavailability_remain_pending(
    tmp_path: Path,
    unavailable: str,
) -> None:
    store = _store(tmp_path)

    class UnavailableProvider(FixtureReadProvider):
        def transaction(
            self,
            transaction_hash: str,
        ) -> RawEnvelope[PublicTransaction] | None:
            if unavailable == "transaction":
                return None
            return super().transaction(transaction_hash)

        def receipt(
            self,
            transaction_hash: str,
        ) -> RawEnvelope[PublicReceipt] | None:
            if unavailable == "receipt":
                return None
            return super().receipt(transaction_hash)

        def block_header(
            self,
            block_number: int,
        ) -> RawEnvelope[PublicBlockHeader] | None:
            if unavailable == "block":
                return None
            return super().block_header(block_number)

    with pytest.raises(EvmCollectorError, match="unavailable|not yet available"):
        EvmCollector(
            store=store,
            provider=UnavailableProvider(),
        ).collect_transaction(transaction_id="transaction-0")
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM transaction_receipts"
        ).fetchone()[0] == 0
        assert connection.execute(
            """
            SELECT state FROM transactions
            WHERE transaction_id = 'transaction-0'
            """
        ).fetchone()[0] == "submitted"


def test_provider_timeout_is_observer_failure_not_execution_evidence(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    class TimeoutProvider(FixtureReadProvider):
        def receipt(
            self,
            transaction_hash: str,
        ) -> RawEnvelope[PublicReceipt] | None:
            del transaction_hash
            raise TimeoutError("fixture archive timeout")

    with pytest.raises(EvmCollectorError, match="read failed"):
        EvmCollector(
            store=store,
            provider=TimeoutProvider(),
        ).collect_transaction(transaction_id="transaction-0")
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM transaction_resources"
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    ("point", "expected_raw_count"),
    [
        ("after_receipt_before_raw_commit", 0),
        ("after_raw_commit_before_normalized_commit", 3),
    ],
)
@pytest.mark.parametrize(
    "stage_name",
    [
        "hyperlane_dispatch",
        "layerzero_send",
        "intermediate_forward",
        "destination_apply",
    ],
)
def test_evidence_crash_boundaries_resume_without_partial_normalization(
    tmp_path: Path,
    point: CrashPoint,
    expected_raw_count: int,
    stage_name: str,
) -> None:
    store = _store(tmp_path, stage_name=stage_name)
    provider = FixtureReadProvider()
    injector = OneShotCrashInjector(point)
    collector = EvmCollector(
        store=store,
        provider=provider,
        crash_injector=injector,
    )
    with pytest.raises(InjectedCrash, match=point):
        collector.collect_transaction(transaction_id="transaction-0")
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM raw_blobs"
        ).fetchone()[0] == expected_raw_count
        assert connection.execute(
            "SELECT count(*) FROM transaction_receipts"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM transaction_resources"
        ).fetchone()[0] == 0
    result = collector.collect_transaction(transaction_id="transaction-0")
    assert result.execution_fee_wei == 42_000
