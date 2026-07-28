"""SQLite evidence ledger, exact-byte raw store, repair, backup, and freeze support."""

from __future__ import annotations

import gzip
import hashlib
import os
import secrets
import shutil
import sqlite3
import tempfile
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785

SCHEMA_VERSION = 1
TERMINAL_ATTEMPT_STATES = frozenset(
    {
        "not_submitted",
        "delivered",
        "submission_failed",
        "carrier_failed",
        "xir_rejected",
        "destination_failed",
        "timed_out",
        "observer_failed",
        "incomplete_evidence",
    }
)
SECRET_MARKERS = (
    b"private_key",
    b"private key",
    b"mnemonic",
    b"seed phrase",
    b"xir_deployer_private_key",
    b"xir_administrator_private_key",
)


class StoreError(RuntimeError):
    """Raised when durable evidence invariants would be violated."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return rfc8785.dumps(value).decode("utf-8")


def _scan_secret_bytes(value: bytes, label: str) -> None:
    lowered = value.lower()
    for marker in SECRET_MARKERS:
        if marker in lowered:
            raise StoreError(f"secret marker found in publishable material: {label}")


class EvidenceStore:
    """One-process serialized SQLite writer with explicit durable transactions."""

    def __init__(self, database_path: Path, raw_root: Path) -> None:
        self.database_path = database_path
        self.raw_root = raw_root
        self._writer_lock = threading.RLock()

    def connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            uri = f"file:{self.database_path.resolve()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True)
        else:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if not read_only:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        return connection

    def initialize(self) -> None:
        migration = (
            Path(__file__).resolve().parent
            / "migrations"
            / "001_initial.sql"
        ).read_text(encoding="utf-8")
        with self._writer_lock, self.connect() as connection:
            present = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone()
            if present is None:
                connection.executescript(migration)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, _now()),
                )
            version = connection.execute(
                "SELECT max(version) AS version FROM schema_migrations"
            ).fetchone()["version"]
            if version != SCHEMA_VERSION:
                raise StoreError(f"unsupported database schema version: {version}")
        self.raw_root.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        with self._writer_lock:
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    def integrity_check(self, path: Path | None = None) -> None:
        target = path or self.database_path
        uri = f"file:{target.resolve()}?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                foreign_keys = connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall()
                if integrity != "ok" or foreign_keys:
                    raise StoreError(
                        f"database integrity failure: integrity={integrity}, "
                        f"foreign_key_rows={len(foreign_keys)}"
                    )
                version = connection.execute(
                    "SELECT max(version) FROM schema_migrations"
                ).fetchone()[0]
                if version != SCHEMA_VERSION:
                    raise StoreError(f"unsupported backup schema version: {version}")
        except sqlite3.DatabaseError as exc:
            raise StoreError("database integrity check failed") from exc

    def backup(self, destination: Path) -> str:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{secrets.token_hex(8)}.tmp"
        )
        with self._writer_lock, self.connect(read_only=True) as source:
            with sqlite3.connect(temporary) as target:
                source.backup(target)
                target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        self.integrity_check(destination)
        return _sha256_file(destination)

    def append_transition(
        self,
        connection: sqlite3.Connection,
        *,
        entity_kind: str,
        entity_id: str,
        from_state: str | None,
        to_state: str,
        payload: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO transition_journal(
                entity_kind, entity_id, from_state, to_state, payload_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entity_kind,
                entity_id,
                from_state,
                to_state,
                _canonical_json(dict(payload)),
                _now(),
            ),
        )

    def update_attempt_state(self, attempt_id: str, to_state: str) -> None:
        with self.write() as connection:
            row = connection.execute(
                "SELECT state FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown attempt: {attempt_id}")
            current = str(row["state"])
            if current in TERMINAL_ATTEMPT_STATES:
                raise StoreError(f"terminal attempt cannot transition: {attempt_id}")
            connection.execute(
                "UPDATE attempts SET state = ? WHERE attempt_id = ?",
                (to_state, attempt_id),
            )
            self.append_transition(
                connection,
                entity_kind="attempt",
                entity_id=attempt_id,
                from_state=current,
                to_state=to_state,
                payload={},
            )

    def insert_attempt(
        self,
        *,
        attempt_id: str,
        condition_id: str,
        pair_id: str | None,
        arm: str,
        attempt_kind: str,
        original_attempt_kind: str | None = None,
        retry_of: str | None = None,
    ) -> None:
        with self.write() as connection:
            if attempt_kind == "retry":
                prior = connection.execute(
                    """
                    SELECT condition_id, pair_id, arm, attempt_kind, original_attempt_kind
                    FROM attempts WHERE attempt_id = ?
                    """,
                    (retry_of,),
                ).fetchone()
                if prior is None:
                    raise StoreError(f"unknown retry predecessor: {retry_of}")
                expected_original = (
                    prior["original_attempt_kind"]
                    if prior["attempt_kind"] == "retry"
                    else prior["attempt_kind"]
                )
                if (
                    prior["condition_id"],
                    prior["pair_id"],
                    prior["arm"],
                    expected_original,
                ) != (condition_id, pair_id, arm, original_attempt_kind):
                    raise StoreError("retry changed matching coordinates or original kind")
            elif retry_of is not None or original_attempt_kind is not None:
                raise StoreError("non-retry attempt cannot carry retry lineage")
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, condition_id, pair_id, arm, attempt_kind,
                    original_attempt_kind, retry_of, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'planned', ?)
                """,
                (
                    attempt_id,
                    condition_id,
                    pair_id,
                    arm,
                    attempt_kind,
                    original_attempt_kind,
                    retry_of,
                    _now(),
                ),
            )
            self.append_transition(
                connection,
                entity_kind="attempt",
                entity_id=attempt_id,
                from_state=None,
                to_state="planned",
                payload={"attempt_kind": attempt_kind},
            )

    def insert_transaction(
        self,
        *,
        transaction_id: str,
        intent_id: str,
        chain_id: int,
        nonce: int,
        transaction_hash: str | None,
        replaces_transaction_id: str | None = None,
    ) -> None:
        with self.write() as connection:
            if replaces_transaction_id is not None:
                prior = connection.execute(
                    """
                    SELECT intent_id, chain_id, nonce FROM transactions
                    WHERE transaction_id = ?
                    """,
                    (replaces_transaction_id,),
                ).fetchone()
                if prior is None:
                    raise StoreError(
                        f"unknown replacement predecessor: {replaces_transaction_id}"
                    )
                if (prior["intent_id"], prior["chain_id"], prior["nonce"]) != (
                    intent_id,
                    chain_id,
                    nonce,
                ):
                    raise StoreError("replacement changed intent, chain, or nonce")
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce, transaction_hash,
                    replaces_transaction_id, state
                ) VALUES (?, ?, ?, ?, ?, ?, 'prepared')
                """,
                (
                    transaction_id,
                    intent_id,
                    chain_id,
                    nonce,
                    transaction_hash,
                    replaces_transaction_id,
                ),
            )

    def put_raw(
        self,
        data: bytes,
        *,
        media_type: str,
        metadata: Mapping[str, Any],
    ) -> str:
        _scan_secret_bytes(data, "raw blob")
        metadata_json = _canonical_json(dict(metadata))
        _scan_secret_bytes(metadata_json.encode(), "raw metadata")
        digest = hashlib.sha256(data).hexdigest()
        relative = Path("sha256") / digest[:2] / f"{digest}.gz"
        destination = self.raw_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{digest}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as raw_handle:
                    with gzip.GzipFile(
                        fileobj=raw_handle, mode="wb", mtime=0, filename=""
                    ) as compressed:
                        compressed.write(data)
                    raw_handle.flush()
                    os.fsync(raw_handle.fileno())
                os.replace(temporary_name, destination)
                directory_fd = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
        with self.write() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO raw_blobs(
                    raw_sha256, relative_path, exact_size, stored_size,
                    compression, media_type, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, 'gzip', ?, ?, ?)
                """,
                (
                    digest,
                    relative.as_posix(),
                    len(data),
                    destination.stat().st_size,
                    media_type,
                    metadata_json,
                    _now(),
                ),
            )
        return digest

    def read_raw(self, digest: str) -> bytes:
        with self.connect(read_only=True) as connection:
            row = connection.execute(
                "SELECT relative_path FROM raw_blobs WHERE raw_sha256 = ?", (digest,)
            ).fetchone()
        if row is None:
            raise StoreError(f"unknown raw blob: {digest}")
        path = self.raw_root / str(row["relative_path"])
        try:
            with gzip.open(path, "rb") as handle:
                data = handle.read()
        except (OSError, EOFError) as exc:
            raise StoreError(f"raw blob is unreadable: {digest}") from exc
        if hashlib.sha256(data).hexdigest() != digest:
            raise StoreError(f"raw blob exact-byte digest mismatch: {digest}")
        return data

    def append_observation(
        self,
        *,
        observation_id: str,
        subject_kind: str,
        subject_id: str,
        raw_sha256: str,
        status: str,
        supersedes: str | None = None,
    ) -> None:
        with self.write() as connection:
            if supersedes is not None:
                prior = connection.execute(
                    """
                    SELECT subject_kind, subject_id FROM observations
                    WHERE observation_id = ?
                    """,
                    (supersedes,),
                ).fetchone()
                if prior is None:
                    raise StoreError(f"unknown superseded observation: {supersedes}")
                if (prior["subject_kind"], prior["subject_id"]) != (
                    subject_kind,
                    subject_id,
                ):
                    raise StoreError("observation correction changed subject")
            connection.execute(
                """
                INSERT INTO observations(
                    observation_id, subject_kind, subject_id, observed_at,
                    raw_sha256, supersedes_observation_id, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    subject_kind,
                    subject_id,
                    _now(),
                    raw_sha256,
                    supersedes,
                    status,
                ),
            )

    def repair_raw(self) -> dict[str, list[str]]:
        with self.connect(read_only=True) as connection:
            rows = connection.execute(
                "SELECT raw_sha256, relative_path FROM raw_blobs"
            ).fetchall()
        registered = {str(row["relative_path"]): str(row["raw_sha256"]) for row in rows}
        missing: list[str] = []
        corrupt: list[str] = []
        for relative, digest in registered.items():
            path = self.raw_root / relative
            if not path.is_file():
                missing.append(digest)
                continue
            try:
                self.read_raw(digest)
            except StoreError:
                corrupt.append(digest)
        present = {
            path.relative_to(self.raw_root).as_posix()
            for path in self.raw_root.glob("sha256/*/*.gz")
        }
        orphans = sorted(present - set(registered))
        return {
            "missing": sorted(missing),
            "corrupt": sorted(corrupt),
            "orphans": orphans,
        }

    def create_freeze(
        self,
        *,
        freeze_id: str,
        run_id: str,
        version: int,
        scope: Mapping[str, Any],
        destination: Path,
    ) -> Path:
        if "private-spool" in destination.parts:
            raise StoreError("freeze destination cannot be inside private spool")
        destination.mkdir(parents=True, exist_ok=False)
        with self.connect(read_only=True) as connection:
            unresolved = connection.execute(
                """
                SELECT count(*) FROM invariant_violations
                WHERE run_id = ? AND resolved_at IS NULL
                """,
                (run_id,),
            ).fetchone()[0]
            if unresolved:
                raise StoreError("cannot freeze with unresolved invariant violations")
            raw_rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT raw_sha256, relative_path, exact_size, stored_size,
                           compression, media_type
                    FROM raw_blobs ORDER BY raw_sha256
                    """
                )
            ]
            journal_rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM transition_journal ORDER BY sequence"
                )
            ]
        for row in raw_rows:
            _scan_secret_bytes(_canonical_json(row).encode(), "raw manifest")
            if "private-spool" in Path(str(row["relative_path"])).parts:
                raise StoreError("private spool path cannot enter a freeze")
        scope_json = _canonical_json(dict(scope))
        _scan_secret_bytes(scope_json.encode(), "freeze scope")
        snapshot = destination / "evidence.sqlite"
        database_sha256 = self.backup(snapshot)
        raw_manifest = _canonical_json(
            {"schema_version": "xir-lab-raw-manifest-v1", "entries": raw_rows}
        )
        journal_manifest = _canonical_json(
            {
                "schema_version": "xir-lab-journal-manifest-v1",
                "entries": journal_rows,
            }
        )
        raw_manifest_sha256 = hashlib.sha256(raw_manifest.encode()).hexdigest()
        journal_sha256 = hashlib.sha256(journal_manifest.encode()).hexdigest()
        (destination / "raw-manifest.json").write_text(raw_manifest, encoding="utf-8")
        (destination / "journal-manifest.json").write_text(
            journal_manifest, encoding="utf-8"
        )
        with self.write() as connection:
            connection.execute(
                """
                INSERT INTO freezes(
                    freeze_id, run_id, version, scope_json, database_sha256,
                    raw_manifest_sha256, journal_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    freeze_id,
                    run_id,
                    version,
                    scope_json,
                    database_sha256,
                    raw_manifest_sha256,
                    journal_sha256,
                    _now(),
                ),
            )
        freeze_manifest = _canonical_json(
            {
                "schema_version": "xir-lab-freeze-manifest-v1",
                "freeze_id": freeze_id,
                "run_id": run_id,
                "version": version,
                "scope": dict(scope),
                "database_sha256": database_sha256,
                "raw_manifest_sha256": raw_manifest_sha256,
                "journal_sha256": journal_sha256,
            }
        )
        (destination / "freeze-manifest.json").write_text(
            freeze_manifest, encoding="utf-8"
        )
        return destination / "freeze-manifest.json"

    def restore_backup(self, backup: Path, destination: Path) -> None:
        self.integrity_check(backup)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(backup, destination)
        self.integrity_check(destination)
