from __future__ import annotations

import gzip
import hashlib
import sqlite3
import threading
from pathlib import Path

import pytest

from xir_lab.evidence.store import EvidenceStore, StoreError


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    return store


def _seed_plan(store: EvidenceStore) -> None:
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO runs(run_id, profile_id, plan_sha256, state, created_at)
            VALUES ('run-1', 'profile-1', ?, 'planned', '2026-07-25T00:00:00Z')
            """,
            ("11" * 32,),
        )
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('condition-hh', 'run-1', 'HH', 'planned')
            """
        )
        connection.execute(
            """
            INSERT INTO pairs(pair_id, condition_id, slot_index)
            VALUES ('pair-0', 'condition-hh', 0)
            """
        )


def _seed_intent(store: EvidenceStore) -> None:
    store.insert_attempt(
        attempt_id="attempt-primary",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="primary",
    )
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO stages(stage_id, attempt_id, ordinal, stage_name, state)
            VALUES ('stage-0', 'attempt-primary', 0, 'source_dispatch', 'planned')
            """
        )
        connection.execute(
            """
            INSERT INTO intents(
                intent_id, stage_id, signer_operation_id, chain_id, nonce,
                state, payload_sha256, created_at
            ) VALUES (
                'intent-0', 'stage-0', 'signer-op-0', 11155420, 7,
                'prepared', ?, '2026-07-25T00:00:00Z'
            )
            """,
            ("22" * 32,),
        )


def test_migration_creates_all_durable_tables_and_foreign_keys(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with store.connect(read_only=True) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "runs",
            "conditions",
            "pairs",
            "attempts",
            "stages",
            "intents",
            "transactions",
            "work_leases",
            "nonce_leases",
            "budgets",
            "events",
            "carrier_messages",
            "observations",
            "checkpoints",
            "account_snapshots",
            "raw_blobs",
            "invariant_violations",
            "freezes",
        } <= tables
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            """
            INSERT INTO conditions(condition_id, run_id, carrier_sequence, state)
            VALUES ('orphan', 'missing', 'HH', 'planned')
            """
        )


def test_retry_lineage_terminal_guard_and_journal_are_immutable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_plan(store)
    store.insert_attempt(
        attempt_id="attempt-primary",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="primary",
    )
    store.insert_attempt(
        attempt_id="attempt-retry",
        condition_id="condition-hh",
        pair_id="pair-0",
        arm="baseline",
        attempt_kind="retry",
        original_attempt_kind="primary",
        retry_of="attempt-primary",
    )
    with pytest.raises(StoreError, match="matching coordinates"):
        store.insert_attempt(
            attempt_id="attempt-bad-retry",
            condition_id="condition-hh",
            pair_id="pair-0",
            arm="xir",
            attempt_kind="retry",
            original_attempt_kind="primary",
            retry_of="attempt-primary",
        )
    store.update_attempt_state("attempt-primary", "delivered")
    with pytest.raises(StoreError, match="terminal attempt"):
        store.update_attempt_state("attempt-primary", "running")
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            "UPDATE transition_journal SET to_state = 'forged' WHERE sequence = 1"
        )


def test_transaction_replacement_preserves_intent_chain_and_nonce(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_plan(store)
    _seed_intent(store)
    store.insert_transaction(
        transaction_id="tx-0",
        intent_id="intent-0",
        chain_id=11155420,
        nonce=7,
        transaction_hash="0x" + "11" * 32,
    )
    store.insert_transaction(
        transaction_id="tx-1",
        intent_id="intent-0",
        chain_id=11155420,
        nonce=7,
        transaction_hash="0x" + "22" * 32,
        replaces_transaction_id="tx-0",
    )
    with pytest.raises(StoreError, match="changed intent, chain, or nonce"):
        store.insert_transaction(
            transaction_id="tx-bad",
            intent_id="intent-0",
            chain_id=11155420,
            nonce=8,
            transaction_hash="0x" + "33" * 32,
            replaces_transaction_id="tx-0",
        )


def test_raw_blob_exact_bytes_corrections_and_repair(tmp_path: Path) -> None:
    store = _store(tmp_path)
    digest = store.put_raw(
        b'{"status":"included"}',
        media_type="application/json",
        metadata={"provider": "fixture"},
    )
    assert digest == hashlib.sha256(b'{"status":"included"}').hexdigest()
    assert store.read_raw(digest) == b'{"status":"included"}'
    store.append_observation(
        observation_id="obs-1",
        subject_kind="transaction",
        subject_id="tx-fixture",
        raw_sha256=digest,
        status="included",
    )
    store.append_observation(
        observation_id="obs-2",
        subject_kind="transaction",
        subject_id="tx-fixture",
        raw_sha256=digest,
        status="finalized",
        supersedes="obs-1",
    )
    with store.connect(read_only=True) as connection:
        current = connection.execute(
            "SELECT observation_id FROM current_observations"
        ).fetchall()
        assert [row[0] for row in current] == ["obs-2"]
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            "UPDATE observations SET status = 'forged' WHERE observation_id = 'obs-1'"
        )

    registered_path = (
        store.raw_root / "sha256" / digest[:2] / f"{digest}.gz"
    )
    registered_path.unlink()
    orphan_digest = "ff" * 32
    orphan = store.raw_root / "sha256" / "ff" / f"{orphan_digest}.gz"
    orphan.parent.mkdir(parents=True)
    with gzip.open(orphan, "wb") as handle:
        handle.write(b"orphan")
    repair = store.repair_raw()
    assert repair["missing"] == [digest]
    assert repair["orphans"] == [f"sha256/ff/{orphan_digest}.gz"]


def test_secret_markers_are_rejected_before_raw_persistence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(StoreError, match="secret marker"):
        store.put_raw(
            b'{"private_key":"do-not-store"}',
            media_type="application/json",
            metadata={},
        )
    with pytest.raises(StoreError, match="secret marker"):
        store.put_raw(
            b"safe",
            media_type="application/octet-stream",
            metadata={"note": "contains mnemonic"},
        )


def test_serialized_writers_backup_restore_and_freeze(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_plan(store)
    errors: list[BaseException] = []

    def writer(worker: int) -> None:
        try:
            for index in range(10):
                with store.write() as connection:
                    store.append_transition(
                        connection,
                        entity_kind="worker",
                        entity_id=f"{worker}-{index}",
                        from_state=None,
                        to_state="done",
                        payload={},
                    )
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(worker,)) for worker in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    with store.connect(read_only=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM transition_journal"
        ).fetchone()[0] == 40

    backup = tmp_path / "backups" / "evidence.sqlite"
    backup_digest = store.backup(backup)
    assert backup_digest == hashlib.sha256(backup.read_bytes()).hexdigest()
    restored = tmp_path / "restored" / "evidence.sqlite"
    store.restore_backup(backup, restored)

    freeze_manifest = store.create_freeze(
        freeze_id="freeze-1",
        run_id="run-1",
        version=1,
        scope={"attempt_ids": []},
        destination=tmp_path / "freezes" / "freeze-1",
    )
    assert freeze_manifest.is_file()
    assert not any(
        "private-spool" in path.parts
        for path in freeze_manifest.parent.rglob("*")
    )
    with pytest.raises(sqlite3.IntegrityError), store.write() as connection:
        connection.execute(
            """
            INSERT INTO freezes(
                freeze_id, run_id, version, scope_json, database_sha256,
                raw_manifest_sha256, journal_sha256, created_at
            ) VALUES ('freeze-duplicate-version', 'run-1', 1, '{}', ?, ?, ?, 'now')
            """,
            ("00" * 32, "00" * 32, "00" * 32),
        )


def test_freeze_blocks_unresolved_invariant_and_private_spool_destination(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_plan(store)
    with store.write() as connection:
        connection.execute(
            """
            INSERT INTO invariant_violations(
                violation_id, run_id, invariant_code, details_json, resolved_at
            ) VALUES ('violation-1', 'run-1', 'fixture', '{}', NULL)
            """
        )
    with pytest.raises(StoreError, match="unresolved invariant"):
        store.create_freeze(
            freeze_id="freeze-blocked",
            run_id="run-1",
            version=1,
            scope={},
            destination=tmp_path / "freeze-blocked",
        )
    with pytest.raises(StoreError, match="private spool"):
        store.create_freeze(
            freeze_id="freeze-private",
            run_id="run-1",
            version=1,
            scope={},
            destination=tmp_path / "private-spool" / "freeze-private",
        )


def test_disk_full_raw_write_leaves_no_blob_or_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)

    def disk_full(source: str, destination: Path) -> None:
        del source, destination
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("xir_lab.evidence.store.os.replace", disk_full)
    secret_value = "sensitive-fixture-value"
    with pytest.raises(OSError, match="No space") as caught:
        store.put_raw(
            b'{"status":"safe"}',
            media_type="application/json",
            metadata={"request_id": secret_value},
        )
    with store.connect(read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM raw_blobs").fetchone()[0] == 0
    assert not tuple(store.raw_root.rglob("*.tmp"))
    assert secret_value not in str(caught.value)


def test_truncated_raw_and_corrupted_backup_fail_validation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_plan(store)
    digest = store.put_raw(
        b'{"status":"safe"}',
        media_type="application/json",
        metadata={"source": "fixture"},
    )
    with store.connect(read_only=True) as connection:
        relative = connection.execute(
            "SELECT relative_path FROM raw_blobs WHERE raw_sha256 = ?",
            (digest,),
        ).fetchone()[0]
    (store.raw_root / relative).write_bytes(b"truncated-gzip")
    assert store.repair_raw()["corrupt"] == [digest]
    with pytest.raises(StoreError, match="unreadable|mismatch"):
        store.read_raw(digest)

    backup = tmp_path / "backup.sqlite"
    store.backup(backup)
    backup.write_bytes(backup.read_bytes()[:256])
    with pytest.raises(StoreError, match="integrity"):
        store.restore_backup(backup, tmp_path / "restored.sqlite")
    assert not (tmp_path / "restored.sqlite").exists()
