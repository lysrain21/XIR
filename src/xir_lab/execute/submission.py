"""Write-ahead signing and broadcast state machine with fail-closed revalidation."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.signer import (
    SignerCoordinator,
    SignerRequest,
    SpoolReference,
    signer_operation_id,
)
from xir_lab.faults import CrashInjector, NoCrashInjector


class SubmissionError(RuntimeError):
    """Raised when durable submission state or a live gate is unsafe."""


@dataclass(frozen=True)
class IntentPreparation:
    transaction_id: str
    stage_id: str
    lineage_id: str
    reservation_id: str
    reservation_stage_key: str
    approval_id: str
    approval_payload_sha256: str
    signer_identity_sha256: str
    network_identity_sha256: str
    quote_sha256: str
    quote_valid_until: datetime
    payload_sha256: str
    requested_wei: int
    request: SignerRequest
    is_source_stage: bool
    replaces_transaction_id: str | None = None


@dataclass(frozen=True)
class GateEvidence:
    approval_id: str
    approval_payload_sha256: str
    signer_id: str
    signer_identity_sha256: str
    network_identity_sha256: str
    quote_sha256: str
    observed_nonce: int
    checked_at: datetime


@dataclass(frozen=True)
class BroadcastResult:
    accepted: bool
    provider_reference: str | None = None


@dataclass(frozen=True)
class RecoveryReport:
    quarantined_orphans: tuple[str, ...]
    corrupt_references: tuple[str, ...]
    recoverable_pending: tuple[str, ...]


class Broadcaster(Protocol):
    def broadcast(
        self, signed_bytes: bytes, expected_transaction_hash: str
    ) -> BroadcastResult:
        """Submit exact bytes and report only a positive RPC acknowledgement."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise SubmissionError("gate and quote times must be timezone-aware")
    return value.astimezone(UTC)


def _time(value: datetime | None = None) -> str:
    current = datetime.now(UTC) if value is None else _utc(value)
    return current.isoformat()


def _digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SubmissionError(f"{label} must be a lowercase SHA-256 value")


class SubmissionCoordinator:
    """Persist intent before signing and signed-byte metadata before broadcast."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        signer: SignerCoordinator,
        broadcaster: Broadcaster,
        crash_injector: CrashInjector | None = None,
    ) -> None:
        self.store = store
        self.signer = signer
        self.broadcaster = broadcaster
        self.crash_injector = crash_injector or NoCrashInjector()

    def prepare_intent(
        self, preparation: IntentPreparation, *, now: datetime | None = None
    ) -> str:
        request = preparation.request
        if request.intent_id == "" or preparation.transaction_id == "":
            raise SubmissionError("intent and transaction identifiers must be non-empty")
        if request.chain_id < 0 or request.nonce < 0 or preparation.requested_wei < 0:
            raise SubmissionError("chain, nonce, and requested amount cannot be negative")
        for value, label in (
            (preparation.approval_payload_sha256, "approval payload digest"),
            (preparation.signer_identity_sha256, "signer identity digest"),
            (preparation.network_identity_sha256, "network identity digest"),
            (preparation.quote_sha256, "quote digest"),
            (preparation.payload_sha256, "payload digest"),
        ):
            _digest(value, label)
        valid_until = _utc(preparation.quote_valid_until)
        operation_id = signer_operation_id(request)
        created_at = _time(now)
        with self.store.write() as connection:
            if connection.execute(
                "SELECT 1 FROM intents WHERE intent_id = ?", (request.intent_id,)
            ).fetchone() is not None:
                existing = connection.execute(
                    "SELECT signer_operation_id FROM intents WHERE intent_id = ?",
                    (request.intent_id,),
                ).fetchone()
                if existing is not None and existing["signer_operation_id"] == operation_id:
                    return operation_id
                raise SubmissionError("intent ID is already bound to different bytes")
            coordinates = connection.execute(
                """
                SELECT stage.attempt_id, sub.chain_id, sub.reserved_wei,
                       sub.allocated_wei, nonce.signer_id, nonce.nonce,
                       nonce.locked, nonce.state, nonce.intent_id,
                       budget.source_in_flight
                FROM stages AS stage
                JOIN transaction_subreservations AS sub
                  ON sub.attempt_id = stage.attempt_id
                 AND sub.reservation_id = ?
                 AND sub.stage_key = ?
                JOIN nonce_leases AS nonce
                  ON nonce.lineage_id = ?
                 AND nonce.reservation_id = sub.reservation_id
                 AND nonce.stage_key = sub.stage_key
                JOIN budgets AS budget
                  ON budget.reservation_id = sub.reservation_id
                 AND budget.chain_id = sub.chain_id
                WHERE stage.stage_id = ?
                """,
                (
                    preparation.reservation_id,
                    preparation.reservation_stage_key,
                    preparation.lineage_id,
                    preparation.stage_id,
                ),
            ).fetchone()
            if coordinates is None:
                raise SubmissionError("stage, nonce, and budget coordinates do not match")
            if (
                int(coordinates["chain_id"]) != request.chain_id
                or int(coordinates["nonce"]) != request.nonce
                or coordinates["signer_id"] != request.signer_id
            ):
                raise SubmissionError("request changed approved chain, nonce, or signer")
            if (
                not coordinates["source_in_flight"]
                or not coordinates["locked"]
                or coordinates["state"] in {"finalized", "released"}
            ):
                raise SubmissionError("nonce lineage or complete-route reservation is inactive")
            if coordinates["intent_id"] not in {None, request.intent_id}:
                if preparation.replaces_transaction_id is None:
                    raise SubmissionError(
                        "nonce lineage is already bound to another intent"
                    )
                prior = connection.execute(
                    """
                    SELECT transaction_record.chain_id,
                           transaction_record.nonce, stage.attempt_id
                    FROM transactions AS transaction_record
                    JOIN intents AS intent
                      ON intent.intent_id = transaction_record.intent_id
                    JOIN stages AS stage ON stage.stage_id = intent.stage_id
                    WHERE transaction_record.transaction_id = ?
                    """,
                    (preparation.replaces_transaction_id,),
                ).fetchone()
                if prior is None or (
                    int(prior["chain_id"]),
                    int(prior["nonce"]),
                    prior["attempt_id"],
                ) != (
                    request.chain_id,
                    request.nonce,
                    coordinates["attempt_id"],
                ):
                    raise SubmissionError(
                        "replacement changed nonce lineage or attempt"
                    )
            if preparation.requested_wei > int(coordinates["allocated_wei"]):
                raise SubmissionError("intent exceeds its transaction sub-reservation")
            approval = connection.execute(
                """
                SELECT payload_sha256 FROM approval_consumptions
                WHERE approval_id = ?
                """,
                (preparation.approval_id,),
            ).fetchone()
            if (
                approval is None
                or approval["payload_sha256"] != preparation.approval_payload_sha256
            ):
                raise SubmissionError("approval is not consumed for this operation")
            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, stage_id, signer_operation_id, chain_id, nonce,
                    state, payload_sha256, approval_id, approval_payload_sha256,
                    signer_id, signer_identity_sha256, network_identity_sha256,
                    quote_sha256, quote_valid_until, reservation_id,
                    reservation_stage_key, requested_wei, created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    request.intent_id,
                    preparation.stage_id,
                    operation_id,
                    request.chain_id,
                    request.nonce,
                    preparation.payload_sha256,
                    preparation.approval_id,
                    preparation.approval_payload_sha256,
                    request.signer_id,
                    preparation.signer_identity_sha256,
                    preparation.network_identity_sha256,
                    preparation.quote_sha256,
                    valid_until.isoformat(),
                    preparation.reservation_id,
                    preparation.reservation_stage_key,
                    preparation.requested_wei,
                    created_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO transactions(
                    transaction_id, intent_id, chain_id, nonce,
                    replaces_transaction_id, state
                ) VALUES (?, ?, ?, ?, ?, 'prepared')
                """,
                (
                    preparation.transaction_id,
                    request.intent_id,
                    request.chain_id,
                    request.nonce,
                    preparation.replaces_transaction_id,
                ),
            )
            connection.execute(
                """
                UPDATE nonce_leases SET intent_id = ?
                WHERE lineage_id = ? AND (intent_id IS NULL OR intent_id = ?)
                """,
                (request.intent_id, preparation.lineage_id, request.intent_id),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=preparation.transaction_id,
                from_state=None,
                to_state="prepared",
                payload={
                    "intent_id": request.intent_id,
                    "is_source_stage": preparation.is_source_stage,
                },
            )
            self.crash_injector.hit("before_prepared_intent_commit")
        self.crash_injector.hit("after_prepared_intent_commit")
        return operation_id

    def sign_prepared(
        self,
        *,
        transaction_id: str,
        request: SignerRequest,
        gates: GateEvidence,
    ) -> SpoolReference:
        row = self._transaction(transaction_id)
        if row["state"] not in {"prepared", "signer_return"}:
            if row["state"] == "signed_hash_persisted":
                return self._reference(row)
            raise SubmissionError("transaction is not eligible for signing")
        if row["intent_id"] != request.intent_id:
            raise SubmissionError("signer request changed the prepared intent")
        if row["signer_operation_id"] != signer_operation_id(request):
            raise SubmissionError("signer request changed after intent preparation")
        self.revalidate(transaction_id=transaction_id, gates=gates, phase="sign")

        signed = self.signer.obtain_signed(request)
        self.crash_injector.hit("after_signer_return")
        returned_at = _time(gates.checked_at)
        with self.store.write() as connection:
            current = self._transaction_from(connection, transaction_id)
            if current["state"] not in {"prepared", "signer_return"}:
                raise SubmissionError("transaction changed while signer was running")
            connection.execute(
                """
                UPDATE transactions SET state = 'signer_return', signer_returned_at = ?
                WHERE transaction_id = ?
                """,
                (returned_at, transaction_id),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state=str(current["state"]),
                to_state="signer_return",
                payload={"operation_id": signed.operation_id},
            )

        reference = self.signer.persist_signed(signed)
        persisted_at = _time()
        with self.store.write() as connection:
            current = self._transaction_from(connection, transaction_id)
            if current["state"] not in {"signer_return", "signed_hash_persisted"}:
                raise SubmissionError("transaction changed before spool reference persistence")
            if current["state"] == "signed_hash_persisted":
                existing = self._reference(current)
                if existing != reference:
                    raise SubmissionError("persisted signer operation metadata changed")
                return existing
            connection.execute(
                """
                UPDATE transactions
                SET state = 'signed_hash_persisted', transaction_hash = ?,
                    signed_sha256 = ?, signed_length = ?, spool_relative_path = ?,
                    signed_hash_persisted_at = ?
                WHERE transaction_id = ?
                """,
                (
                    signed.transaction_hash,
                    reference.signed_sha256,
                    reference.signed_length,
                    reference.relative_path,
                    persisted_at,
                    transaction_id,
                ),
            )
            connection.execute(
                """
                UPDATE intents SET state = 'signed_hash_persisted'
                WHERE intent_id = ?
                """,
                (request.intent_id,),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state="signer_return",
                to_state="signed_hash_persisted",
                payload={
                    "signed_sha256": reference.signed_sha256,
                    "signed_length": reference.signed_length,
                },
            )
        self.crash_injector.hit("after_hash_reference_persistence")
        return reference

    def broadcast(
        self,
        *,
        transaction_id: str,
        gates: GateEvidence,
        allow_repeat: bool = False,
    ) -> BroadcastResult:
        row = self._transaction(transaction_id)
        allowed = {"signed_hash_persisted", "broadcast_unknown"}
        if allow_repeat:
            allowed.add("submitted")
        if row["state"] not in allowed:
            raise SubmissionError("transaction is not eligible for this broadcast")
        self.revalidate(transaction_id=transaction_id, gates=gates, phase="broadcast")
        reference = self._reference(row)
        signed_bytes = self.signer.spool.load(reference)
        expected_hash = str(row["transaction_hash"])
        started_at = _time(gates.checked_at)
        with self.store.write() as connection:
            current = self._transaction_from(connection, transaction_id)
            if current["state"] not in allowed:
                raise SubmissionError("transaction changed before broadcast")
            connection.execute(
                """
                UPDATE transactions
                SET state = 'broadcast_unknown', broadcast_started_at = ?
                WHERE transaction_id = ?
                """,
                (started_at, transaction_id),
            )
            connection.execute(
                "UPDATE intents SET state = 'broadcast_unknown' WHERE intent_id = ?",
                (row["intent_id"],),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state=str(current["state"]),
                to_state="broadcast_unknown",
                payload={"repeat": current["state"] != "signed_hash_persisted"},
            )

        result = self.broadcaster.broadcast(signed_bytes, expected_hash)
        self.crash_injector.hit("after_broadcast_before_acknowledgement")
        if not result.accepted:
            return result
        with self.store.write() as connection:
            current = self._transaction_from(connection, transaction_id)
            if current["state"] != "broadcast_unknown":
                raise SubmissionError("transaction changed before RPC acknowledgement")
            connection.execute(
                """
                UPDATE transactions SET state = 'submitted', submitted_at = ?
                WHERE transaction_id = ?
                """,
                (_time(), transaction_id),
            )
            connection.execute(
                "UPDATE intents SET state = 'submitted' WHERE intent_id = ?",
                (row["intent_id"],),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state="broadcast_unknown",
                to_state="submitted",
                payload={"provider_reference": result.provider_reference},
            )
        self.crash_injector.hit("after_acknowledgement_before_receipt")
        return result

    def record_included(
        self, *, transaction_id: str, observed_at: datetime | None = None
    ) -> None:
        self._advance_observation(
            transaction_id=transaction_id,
            expected={"broadcast_unknown", "submitted"},
            to_state="included",
            timestamp_column="included_at",
            observed_at=observed_at,
        )

    def record_finalized(
        self, *, transaction_id: str, observed_at: datetime | None = None
    ) -> None:
        self._advance_observation(
            transaction_id=transaction_id,
            expected={"included"},
            to_state="finalized",
            timestamp_column="finalized_at",
            observed_at=observed_at,
        )

    def revalidate(
        self,
        *,
        transaction_id: str,
        gates: GateEvidence,
        phase: str,
    ) -> None:
        if phase not in {"sign", "broadcast"}:
            raise SubmissionError("gate phase must be sign or broadcast")
        checked_at = _utc(gates.checked_at)
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT intent.*, stage.stage_name, attempt.state AS attempt_state,
                       run.state AS run_state, nonce.lineage_id, nonce.signer_id AS nonce_signer,
                       nonce.nonce AS leased_nonce, nonce.locked, nonce.state AS nonce_state,
                       sub.allocated_wei, sub.state AS reservation_state,
                       budget.source_in_flight,
                       approval.payload_sha256 AS consumed_approval_sha256,
                       approval.valid_from AS approval_valid_from,
                       approval.valid_until AS approval_valid_until,
                       EXISTS(
                           SELECT 1 FROM approval_revocations AS revocation
                           WHERE revocation.approval_id = approval.approval_id
                       ) AS approval_revoked
                FROM transactions AS transaction_record
                JOIN intents AS intent ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                    ON condition.condition_id = attempt.condition_id
                JOIN runs AS run ON run.run_id = condition.run_id
                JOIN transaction_subreservations AS sub
                  ON sub.attempt_id = attempt.attempt_id
                 AND sub.reservation_id = intent.reservation_id
                 AND sub.stage_key = intent.reservation_stage_key
                JOIN nonce_leases AS nonce ON nonce.lineage_id = sub.lineage_id
                JOIN budgets AS budget
                  ON budget.reservation_id = sub.reservation_id
                 AND budget.chain_id = sub.chain_id
                JOIN approval_consumptions AS approval
                  ON approval.approval_id = intent.approval_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
        if row is None:
            raise SubmissionError("submission gates cannot resolve durable coordinates")
        expected = (
            row["approval_id"],
            row["approval_payload_sha256"],
            row["signer_id"],
            row["signer_identity_sha256"],
            row["network_identity_sha256"],
            row["quote_sha256"],
            int(row["nonce"]),
        )
        observed = (
            gates.approval_id,
            gates.approval_payload_sha256,
            gates.signer_id,
            gates.signer_identity_sha256,
            gates.network_identity_sha256,
            gates.quote_sha256,
            gates.observed_nonce,
        )
        if expected != observed:
            raise SubmissionError("approval, identity, quote, or nonce gate changed")
        if row["consumed_approval_sha256"] != gates.approval_payload_sha256:
            raise SubmissionError("consumed approval no longer matches the intent")
        if row["approval_revoked"]:
            raise SubmissionError("approval is revoked")
        if not (
            datetime.fromisoformat(str(row["approval_valid_from"]))
            <= checked_at
            < datetime.fromisoformat(str(row["approval_valid_until"]))
        ):
            raise SubmissionError("approval is expired or not yet valid")
        if row["run_state"] in {"halted", "revoked"}:
            raise SubmissionError(f"persistent stop state blocks {phase}")
        is_source = str(row["stage_name"]).startswith("source")
        if row["run_state"] == "drain" and is_source:
            raise SubmissionError("drain blocks a new source signature or broadcast")
        if row["attempt_state"] != "in_flight" or not row["source_in_flight"]:
            raise SubmissionError("attempt no longer owns an in-flight route reservation")
        if (
            not row["locked"]
            or row["nonce_state"] in {"finalized", "released"}
            or int(row["leased_nonce"]) != gates.observed_nonce
            or row["nonce_signer"] != gates.signer_id
        ):
            raise SubmissionError("nonce lease is no longer valid")
        if (
            row["reservation_state"] in {"finalized", "released"}
            or int(row["requested_wei"]) > int(row["allocated_wei"])
        ):
            raise SubmissionError("transaction reservation is no longer valid")
        if checked_at >= datetime.fromisoformat(str(row["quote_valid_until"])):
            raise SubmissionError("quote is stale")

    def recover_spool(self) -> RecoveryReport:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT transaction_id, transaction_record.state,
                       signer_operation_id, spool_relative_path,
                       signed_sha256, signed_length
                FROM transactions
                AS transaction_record JOIN intents USING(intent_id)
                WHERE spool_relative_path IS NOT NULL
                   OR transaction_record.state = 'signer_return'
                """
            ).fetchall()
        recoverable: list[str] = []
        referenced_values: list[str] = []
        for row in rows:
            if row["spool_relative_path"] is not None:
                referenced_values.append(str(row["spool_relative_path"]))
                continue
            relative = self.signer.spool.relative_path(
                str(row["signer_operation_id"])
            )
            if (self.signer.spool.root / relative).is_file():
                referenced_values.append(relative)
                recoverable.append(str(row["transaction_id"]))
        referenced = tuple(referenced_values)
        quarantined = self.signer.spool.quarantine_orphans(referenced)
        corrupt: list[str] = []
        for row in rows:
            if row["spool_relative_path"] is None:
                continue
            reference = SpoolReference(
                operation_id=str(row["signer_operation_id"]),
                relative_path=str(row["spool_relative_path"]),
                signed_sha256=str(row["signed_sha256"]),
                signed_length=int(row["signed_length"]),
            )
            try:
                self.signer.spool.load(reference)
            except (OSError, RuntimeError):
                corrupt.append(str(row["transaction_id"]))
        return RecoveryReport(
            quarantined,
            tuple(sorted(corrupt)),
            tuple(sorted(recoverable)),
        )

    def _transaction(self, transaction_id: str) -> sqlite3.Row:
        with self.store.connect(read_only=True) as connection:
            return self._transaction_from(connection, transaction_id)

    @staticmethod
    def _transaction_from(
        connection: sqlite3.Connection, transaction_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT transaction_record.*, intent.signer_operation_id
            FROM transactions AS transaction_record
            JOIN intents AS intent ON intent.intent_id = transaction_record.intent_id
            WHERE transaction_record.transaction_id = ?
            """,
            (transaction_id,),
        ).fetchone()
        if row is None:
            raise SubmissionError(f"unknown transaction: {transaction_id}")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _reference(row: sqlite3.Row) -> SpoolReference:
        values = (
            row["signer_operation_id"],
            row["spool_relative_path"],
            row["signed_sha256"],
            row["signed_length"],
        )
        if any(value is None for value in values):
            raise SubmissionError("signed spool metadata is incomplete")
        return SpoolReference(
            operation_id=str(row["signer_operation_id"]),
            relative_path=str(row["spool_relative_path"]),
            signed_sha256=str(row["signed_sha256"]),
            signed_length=int(row["signed_length"]),
        )

    def _advance_observation(
        self,
        *,
        transaction_id: str,
        expected: set[str],
        to_state: str,
        timestamp_column: str,
        observed_at: datetime | None,
    ) -> None:
        if timestamp_column not in {"included_at", "finalized_at"}:
            raise SubmissionError("unsupported observation timestamp")
        with self.store.write() as connection:
            row = self._transaction_from(connection, transaction_id)
            if row["state"] == to_state:
                return
            if row["state"] not in expected:
                raise SubmissionError(
                    f"cannot advance transaction from {row['state']} to {to_state}"
                )
            connection.execute(
                f"""
                UPDATE transactions SET state = ?, {timestamp_column} = ?
                WHERE transaction_id = ?
                """,
                (to_state, _time(observed_at), transaction_id),
            )
            connection.execute(
                "UPDATE intents SET state = ? WHERE intent_id = ?",
                (to_state, row["intent_id"]),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state=str(row["state"]),
                to_state=to_state,
                payload={},
            )
