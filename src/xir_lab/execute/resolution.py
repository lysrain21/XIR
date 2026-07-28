"""Ambiguous submission resolution and bounded same-nonce replacements."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.execute.controls import ControlDecision, RunControlManager
from xir_lab.execute.submission import (
    IntentPreparation,
    SubmissionCoordinator,
    SubmissionError,
)


class ResolutionError(RuntimeError):
    """Raised when ambiguous submission or replacement safety cannot be proved."""


@dataclass(frozen=True)
class TransactionProbe:
    transaction_hash: str
    nonce: int
    included: bool
    canonical: bool


@dataclass(frozen=True)
class ResolutionResult:
    transaction_id: str
    status: str
    reason_code: str
    safe_to_repeat_exact_bytes: bool


class TransactionLookup(Protocol):
    def transaction_by_hash(
        self, chain_id: int, transaction_hash: str
    ) -> TransactionProbe | None:
        """Read exact precomputed hash from a public provider."""

    def account_nonce(self, chain_id: int, signer_address: str) -> int | None:
        """Read latest public account nonce without submission."""


def _time(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ResolutionError("resolution timestamps must be timezone-aware")
    return current.astimezone(UTC).isoformat()


class AmbiguousSubmissionResolver:
    def __init__(
        self,
        *,
        store: EvidenceStore,
        controls: RunControlManager,
        lookup: TransactionLookup,
    ) -> None:
        self.store = store
        self.controls = controls
        self.lookup = lookup

    def resolve(
        self,
        *,
        transaction_id: str,
        signer_address: str,
        checked_at: datetime | None = None,
    ) -> ResolutionResult:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT transaction_record.*, stage.attempt_id, condition.run_id
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
        if row is None:
            raise ResolutionError(f"unknown transaction: {transaction_id}")
        if row["state"] not in {"broadcast_unknown", "submitted"}:
            raise ResolutionError("only ambiguous or pending submissions can be resolved")
        expected_hash = row["transaction_hash"]
        if expected_hash is None:
            raise ResolutionError("transaction lacks a precomputed hash")
        try:
            probe = self.lookup.transaction_by_hash(
                int(row["chain_id"]), str(expected_hash)
            )
        except Exception:
            return ResolutionResult(
                transaction_id,
                "unknown",
                "hash_lookup_error",
                False,
            )
        if probe is not None:
            if (
                probe.transaction_hash.lower() != str(expected_hash).lower()
                or probe.nonce != int(row["nonce"])
            ):
                self._halt_conflict(
                    row,
                    transaction_id=transaction_id,
                    reason_code="hash_or_nonce_conflict",
                    checked_at=checked_at,
                )
                return ResolutionResult(
                    transaction_id,
                    "conflict",
                    "hash_or_nonce_conflict",
                    False,
                )
            target_state = "included" if probe.included and probe.canonical else "submitted"
            self._advance(
                transaction_id=transaction_id,
                intent_id=str(row["intent_id"]),
                from_state=str(row["state"]),
                to_state=target_state,
                checked_at=checked_at,
            )
            return ResolutionResult(
                transaction_id,
                target_state,
                "precomputed_hash_found",
                False,
            )
        try:
            observed_nonce = self.lookup.account_nonce(
                int(row["chain_id"]), signer_address
            )
        except Exception:
            observed_nonce = None
        if observed_nonce is None:
            return ResolutionResult(
                transaction_id,
                "unknown",
                "nonce_lookup_unavailable",
                False,
            )
        if observed_nonce > int(row["nonce"]):
            self._halt_conflict(
                row,
                transaction_id=transaction_id,
                reason_code="nonce_consumed_without_known_hash",
                checked_at=checked_at,
            )
            return ResolutionResult(
                transaction_id,
                "conflict",
                "nonce_consumed_without_known_hash",
                False,
            )
        return ResolutionResult(
            transaction_id,
            "not_found",
            "exact_hash_absent_nonce_not_consumed",
            True,
        )

    def _advance(
        self,
        *,
        transaction_id: str,
        intent_id: str,
        from_state: str,
        to_state: str,
        checked_at: datetime | None,
    ) -> None:
        if from_state == to_state:
            return
        with self.store.write() as connection:
            current = connection.execute(
                "SELECT state FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if current is None or current["state"] != from_state:
                raise ResolutionError("transaction changed during resolution")
            timestamp_column = "included_at" if to_state == "included" else "submitted_at"
            connection.execute(
                f"""
                UPDATE transactions SET state = ?, {timestamp_column} = ?
                WHERE transaction_id = ?
                """,
                (to_state, _time(checked_at), transaction_id),
            )
            connection.execute(
                "UPDATE intents SET state = ? WHERE intent_id = ?",
                (to_state, intent_id),
            )
            self.store.append_transition(
                connection,
                entity_kind="transaction",
                entity_id=transaction_id,
                from_state=from_state,
                to_state=to_state,
                payload={"resolution": "precomputed_hash"},
            )

    def _halt_conflict(
        self,
        row: sqlite3.Row,
        *,
        transaction_id: str,
        reason_code: str,
        checked_at: datetime | None,
    ) -> None:
        occurred_at = _time(checked_at)
        material = {
            "run_id": str(row["run_id"]),
            "transaction_id": transaction_id,
            "reason_code": reason_code,
            "occurred_at": occurred_at,
        }
        digest = hashlib.sha256(rfc8785.dumps(material)).hexdigest()
        violation_id = "violation_" + digest[:24]
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO invariant_violations(
                    violation_id, run_id, invariant_code, details_json, resolved_at
                ) VALUES (?, ?, 'ambiguous_submission_conflict', ?, NULL)
                """,
                (
                    violation_id,
                    row["run_id"],
                    rfc8785.dumps(material).decode(),
                ),
            )
        state = self.controls.state(str(row["run_id"]))
        if state.mode in {"running", "drain"}:
            self.controls.halt(
                run_id=str(row["run_id"]),
                decision=ControlDecision(
                    decision_id=violation_id,
                    decision_sha256=digest,
                    reason_code=reason_code,
                ),
                now=datetime.fromisoformat(occurred_at),
            )


class ReplacementManager:
    """Prepare a new concrete intent within one bounded nonce lineage."""

    def __init__(
        self,
        *,
        store: EvidenceStore,
        submissions: SubmissionCoordinator,
        max_replacements_per_lineage: int,
    ) -> None:
        if max_replacements_per_lineage < 0:
            raise ResolutionError("maximum replacements cannot be negative")
        self.store = store
        self.submissions = submissions
        self.maximum = max_replacements_per_lineage

    def prepare_replacement(
        self,
        *,
        prior_transaction_id: str,
        preparation: IntentPreparation,
        now: datetime | None = None,
    ) -> str:
        with self.store.connect(read_only=True) as connection:
            prior = connection.execute(
                """
                SELECT transaction_record.state, transaction_record.chain_id,
                       transaction_record.nonce, intent.stage_id
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                WHERE transaction_record.transaction_id = ?
                """,
                (prior_transaction_id,),
            ).fetchone()
            if prior is None:
                raise ResolutionError("unknown replacement predecessor")
            count = int(
                connection.execute(
                    """
                    WITH RECURSIVE ancestors(transaction_id, predecessor) AS (
                        SELECT transaction_id, replaces_transaction_id
                        FROM transactions WHERE transaction_id = ?
                        UNION ALL
                        SELECT prior.transaction_id, prior.replaces_transaction_id
                        FROM transactions AS prior
                        JOIN ancestors
                          ON prior.transaction_id = ancestors.predecessor
                    )
                    SELECT count(*) - 1 FROM ancestors
                    """,
                    (prior_transaction_id,),
                ).fetchone()[0]
            )
        if count >= self.maximum:
            raise ResolutionError("same-nonce replacement limit exhausted")
        if prior["state"] not in {"broadcast_unknown", "submitted", "orphaned"}:
            raise ResolutionError("replacement predecessor is not pending or orphaned")
        request = preparation.request
        if (
            request.chain_id != int(prior["chain_id"])
            or request.nonce != int(prior["nonce"])
            or preparation.stage_id != prior["stage_id"]
        ):
            raise ResolutionError("replacement changed stage, chain, or nonce")
        bound = replace(
            preparation,
            replaces_transaction_id=prior_transaction_id,
        )
        try:
            return self.submissions.prepare_intent(bound, now=now)
        except SubmissionError as exc:
            raise ResolutionError("replacement intent failed durable safety gates") from exc
