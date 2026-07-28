from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xir_lab.collect.finality import (
    ChainFinalityPolicy,
    FinalityError,
    FinalityKind,
    FinalityManager,
)
from xir_lab.evidence.store import EvidenceStore

CHAIN = 11_155_420
BLOCK_HASH = "0x" + "11" * 32
NEW_BLOCK_HASH = "0x" + "22" * 32
TX_HASH = "0x" + "33" * 32


class FixtureFinalityProvider:
    def __init__(self) -> None:
        self.block_hashes = {(CHAIN, 100): BLOCK_HASH}
        self.heads: dict[tuple[int, FinalityKind], int | None] = {}

    def canonical_block_hash(self, chain_id: int, block_number: int) -> str | None:
        return self.block_hashes.get((chain_id, block_number))

    def policy_head(self, chain_id: int, kind: FinalityKind) -> int | None:
        return self.heads.get((chain_id, kind))


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    receipt_raw = store.put_raw(
        b'{"receipt":"fixture"}',
        media_type="application/json",
        metadata={"source": "fixture"},
    )
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'running', '2026-07-26T00:00:00Z')
            """,
            ("44" * 32,),
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
            INSERT INTO stages(stage_id, attempt_id, ordinal, stage_name, state)
            VALUES ('stage-1', 'attempt-1', 0, 'source', 'collecting')
            """
        )
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES (
                'intent-1', 'stage-1', 'signop-1', ?, 1, 'included', ?,
                '2026-07-26T00:00:00Z'
            )
            """,
            (CHAIN, "55" * 32),
        )
        connection.execute(
            """
            INSERT INTO transactions(
                transaction_id, intent_id, chain_id, nonce,
                transaction_hash, state
            ) VALUES ('transaction-1', 'intent-1', ?, 1, ?, 'included')
            """,
            (CHAIN, TX_HASH),
        )
        connection.execute(
            """
            INSERT INTO transaction_receipts(
                transaction_id, block_number, block_hash, receipt_status,
                gas_used, effective_gas_price_wei, raw_sha256
            ) VALUES ('transaction-1', 100, ?, 1, 21000, '2', ?)
            """,
            (BLOCK_HASH, receipt_raw),
        )
    return store


def test_confirmation_finality_is_distinct_and_freeze_audited(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureFinalityProvider()
    manager = FinalityManager(store=store, provider=provider)
    manager.register_policies(
        run_id="run-1",
        policies=(ChainFinalityPolicy(CHAIN, "confirmations", 3),),
    )
    included = manager.observe_included("transaction-1")
    assert included.state == "included"
    provider.heads[(CHAIN, "confirmations")] = 101
    with pytest.raises(FinalityError, match="not reached"):
        manager.finalize("transaction-1")
    with pytest.raises(FinalityError, match="unresolved"):
        manager.audit_for_freeze(run_id="run-1")
    provider.heads[(CHAIN, "confirmations")] = 102
    finalized = manager.finalize("transaction-1")
    assert finalized.state == "finalized"
    assert finalized.supersedes_observation_id == included.observation_id
    audit = manager.audit_for_freeze(run_id="run-1")
    assert audit.finalized_transactions == 1
    assert audit.labels == ("confirmations",)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id = 'transaction-1'"
        ).fetchone()[0] == "finalized"
        assert connection.execute(
            "SELECT state FROM stages WHERE stage_id = 'stage-1'"
        ).fetchone()[0] == "completed"


@pytest.mark.parametrize("kind", ["l2-safe", "l1-settlement"])
def test_l2_and_l1_policy_strengths_are_recorded_without_overclaiming(
    tmp_path: Path,
    kind: FinalityKind,
) -> None:
    store = _store(tmp_path)
    provider = FixtureFinalityProvider()
    provider.heads[(CHAIN, kind)] = 100
    manager = FinalityManager(store=store, provider=provider)
    manager.register_policies(
        run_id="run-1",
        policies=(ChainFinalityPolicy(CHAIN, kind, None),),
    )
    finalized = manager.finalize("transaction-1")
    assert finalized.policy_kind == kind
    assert manager.audit_for_freeze(run_id="run-1").labels == (kind,)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            """
            SELECT policy_kind FROM transaction_finality_observations
            WHERE observation_state = 'finalized'
            """
        ).fetchone()[0] == kind


def test_reorg_preserves_orphan_and_new_inclusion_supersedes_it(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    provider = FixtureFinalityProvider()
    provider.heads[(CHAIN, "l2-finalized")] = 100
    manager = FinalityManager(store=store, provider=provider)
    manager.register_policies(
        run_id="run-1",
        policies=(ChainFinalityPolicy(CHAIN, "l2-finalized", None),),
    )
    manager.finalize("transaction-1")
    provider.block_hashes[(CHAIN, 100)] = NEW_BLOCK_HASH
    assert manager.recheck_canonicality(run_id="run-1") == ("transaction-1",)
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id = 'transaction-1'"
        ).fetchone()[0] == "orphaned"
        assert connection.execute(
            "SELECT state FROM stages WHERE stage_id = 'stage-1'"
        ).fetchone()[0] == "collecting"
        states = connection.execute(
            """
            SELECT observation_state FROM transaction_finality_observations
            ORDER BY rowid
            """
        ).fetchall()
        assert [row[0] for row in states] == ["included", "finalized", "orphaned"]
        orphan_id = connection.execute(
            """
            SELECT finality_observation_id
            FROM transaction_finality_observations
            WHERE observation_state = 'orphaned'
            """
        ).fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            """
            UPDATE transaction_finality_observations
            SET observation_state = 'included'
            WHERE observation_state = 'orphaned'
            """
        )
    with store.write() as connection:
        connection.execute(
            """
            UPDATE transaction_receipts SET block_hash = ?
            WHERE transaction_id = 'transaction-1'
            """,
            (NEW_BLOCK_HASH,),
        )
    reincluded = manager.observe_included("transaction-1")
    assert reincluded.state == "included"
    assert reincluded.supersedes_observation_id == orphan_id


def test_policies_are_preregistered_and_immutable(tmp_path: Path) -> None:
    manager = FinalityManager(
        store=_store(tmp_path),
        provider=FixtureFinalityProvider(),
    )
    manager.register_policies(
        run_id="run-1",
        policies=(ChainFinalityPolicy(CHAIN, "confirmations", 3),),
    )
    with pytest.raises(FinalityError, match="immutable"):
        manager.register_policies(
            run_id="run-1",
            policies=(ChainFinalityPolicy(CHAIN, "l2-safe", None),),
        )
