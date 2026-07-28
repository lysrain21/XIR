"""Per-chain finality labeling, canonical rechecks, and freeze audits."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import EvidenceStore

FinalityKind = Literal[
    "confirmations",
    "l2-safe",
    "l2-finalized",
    "l1-settlement",
]


class FinalityError(RuntimeError):
    """Raised when canonicality or approved finality cannot be established."""


@dataclass(frozen=True)
class ChainFinalityPolicy:
    chain_id: int
    kind: FinalityKind
    confirmation_count: int | None


@dataclass(frozen=True)
class FinalityObservation:
    observation_id: str
    transaction_id: str
    state: Literal["included", "finalized", "orphaned"]
    block_number: int
    block_hash: str
    policy_kind: FinalityKind
    policy_head_block: int | None
    supersedes_observation_id: str | None


@dataclass(frozen=True)
class FinalityAudit:
    run_id: str
    finalized_transactions: int
    labels: tuple[FinalityKind, ...]
    orphaned_transactions: tuple[str, ...]


class ReadOnlyFinalityProvider(Protocol):
    def canonical_block_hash(self, chain_id: int, block_number: int) -> str | None:
        """Return the current canonical hash, or None if unavailable."""

    def policy_head(self, chain_id: int, kind: FinalityKind) -> int | None:
        """Return the strongest observed L2 or L1-backed head for this policy."""


class FinalityManager:
    def __init__(
        self,
        *,
        store: EvidenceStore,
        provider: ReadOnlyFinalityProvider,
    ) -> None:
        self.store = store
        self.provider = provider

    def register_policies(
        self,
        *,
        run_id: str,
        policies: tuple[ChainFinalityPolicy, ...],
    ) -> None:
        if not policies or len({policy.chain_id for policy in policies}) != len(
            policies
        ):
            raise FinalityError("finality policies must have unique chain IDs")
        with self.store.write() as connection:
            if connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone() is None:
                raise FinalityError(f"unknown run: {run_id}")
            for policy in policies:
                _validate_policy(policy)
                existing = connection.execute(
                    """
                    SELECT policy_kind, confirmation_count
                    FROM finality_policies
                    WHERE run_id = ? AND chain_id = ?
                    """,
                    (run_id, policy.chain_id),
                ).fetchone()
                values = (policy.kind, policy.confirmation_count)
                if existing is not None:
                    if tuple(existing) != values:
                        raise FinalityError("registered finality policy is immutable")
                    continue
                connection.execute(
                    """
                    INSERT INTO finality_policies(
                        run_id, chain_id, policy_kind, confirmation_count,
                        registered_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        policy.chain_id,
                        policy.kind,
                        policy.confirmation_count,
                        _now(),
                    ),
                )

    def observe_included(self, transaction_id: str) -> FinalityObservation:
        transaction = self._transaction_receipt(transaction_id)
        policy = self._policy(
            str(transaction["run_id"]),
            int(transaction["chain_id"]),
        )
        canonical_hash = self.provider.canonical_block_hash(
            policy.chain_id,
            int(transaction["block_number"]),
        )
        if (
            canonical_hash is None
            or canonical_hash.lower() != str(transaction["block_hash"]).lower()
        ):
            raise FinalityError("included receipt is not on the canonical chain")
        latest = self._latest(transaction_id)
        if (
            latest is not None
            and latest.state in {"included", "finalized"}
            and latest.block_number == int(transaction["block_number"])
            and latest.block_hash == str(transaction["block_hash"]).lower()
        ):
            return latest
        observation = self._append(
            transaction_id=transaction_id,
            chain_id=policy.chain_id,
            block_number=int(transaction["block_number"]),
            block_hash=str(transaction["block_hash"]),
            state="included",
            canonical=True,
            policy_kind=policy.kind,
            policy_head_block=None,
            supersedes=None if latest is None else latest.observation_id,
        )
        self._set_transaction_state(transaction_id, "included", complete_stage=False)
        return observation

    def finalize(self, transaction_id: str) -> FinalityObservation:
        included = self.observe_included(transaction_id)
        if included.state == "finalized":
            return included
        policy = self._policy_for_transaction(transaction_id)
        policy_head = self.provider.policy_head(policy.chain_id, policy.kind)
        if policy_head is None:
            raise FinalityError("approved finality head is unavailable")
        if policy.kind == "confirmations":
            assert policy.confirmation_count is not None
            reached = (
                policy_head - included.block_number + 1
                >= policy.confirmation_count
            )
        else:
            reached = policy_head >= included.block_number
        if not reached:
            raise FinalityError("transaction has not reached approved finality")
        canonical_hash = self.provider.canonical_block_hash(
            policy.chain_id,
            included.block_number,
        )
        if canonical_hash is None or canonical_hash.lower() != included.block_hash:
            raise FinalityError("canonical hash changed before finalization")
        observation = self._append(
            transaction_id=transaction_id,
            chain_id=policy.chain_id,
            block_number=included.block_number,
            block_hash=included.block_hash,
            state="finalized",
            canonical=True,
            policy_kind=policy.kind,
            policy_head_block=policy_head,
            supersedes=included.observation_id,
        )
        self._set_transaction_state(transaction_id, "finalized", complete_stage=True)
        return observation

    def recheck_canonicality(self, *, run_id: str) -> tuple[str, ...]:
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT transaction_record.transaction_id
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ?
                ORDER BY transaction_record.transaction_id
                """,
                (run_id,),
            ).fetchall()
        orphaned: list[str] = []
        for row in rows:
            transaction_id = str(row["transaction_id"])
            latest = self._latest(transaction_id)
            if latest is None or latest.state == "orphaned":
                continue
            policy = self._policy_for_transaction(transaction_id)
            canonical_hash = self.provider.canonical_block_hash(
                policy.chain_id,
                latest.block_number,
            )
            if canonical_hash is None:
                raise FinalityError(
                    f"canonical block hash unavailable for {transaction_id}"
                )
            if canonical_hash.lower() == latest.block_hash:
                continue
            self._append(
                transaction_id=transaction_id,
                chain_id=policy.chain_id,
                block_number=latest.block_number,
                block_hash=latest.block_hash,
                state="orphaned",
                canonical=False,
                policy_kind=policy.kind,
                policy_head_block=None,
                supersedes=latest.observation_id,
            )
            self._set_transaction_state(
                transaction_id,
                "orphaned",
                complete_stage=False,
                collect_stage=True,
            )
            orphaned.append(transaction_id)
        return tuple(orphaned)

    def audit_for_freeze(self, *, run_id: str) -> FinalityAudit:
        orphaned = self.recheck_canonicality(run_id=run_id)
        with self.store.connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT transaction_record.transaction_id,
                       transaction_record.state
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                JOIN attempts AS attempt ON attempt.attempt_id = stage.attempt_id
                JOIN conditions AS condition
                  ON condition.condition_id = attempt.condition_id
                WHERE condition.run_id = ?
                ORDER BY transaction_record.transaction_id
                """,
                (run_id,),
            ).fetchall()
        incomplete: list[str] = []
        labels: set[FinalityKind] = set()
        for row in rows:
            transaction_id = str(row["transaction_id"])
            latest = self._latest(transaction_id)
            if (
                row["state"] != "finalized"
                or latest is None
                or latest.state != "finalized"
            ):
                incomplete.append(transaction_id)
            else:
                labels.add(latest.policy_kind)
        if orphaned or incomplete:
            unresolved = sorted(set(orphaned) | set(incomplete))
            raise FinalityError(
                "freeze finality audit has unresolved transactions: "
                + ",".join(unresolved)
            )
        return FinalityAudit(
            run_id=run_id,
            finalized_transactions=len(rows),
            labels=tuple(sorted(labels)),
            orphaned_transactions=(),
        )

    def _append(
        self,
        *,
        transaction_id: str,
        chain_id: int,
        block_number: int,
        block_hash: str,
        state: Literal["included", "finalized", "orphaned"],
        canonical: bool,
        policy_kind: FinalityKind,
        policy_head_block: int | None,
        supersedes: str | None,
    ) -> FinalityObservation:
        observation_id = stable_id(
            "observation",
            "transaction-finality",
            transaction_id,
            state,
            block_hash.lower(),
            "root" if supersedes is None else supersedes,
        )
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT INTO transaction_finality_observations(
                    finality_observation_id, transaction_id, chain_id,
                    block_number, block_hash, observation_state, canonical,
                    policy_kind, policy_head_block, supersedes_observation_id,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    transaction_id,
                    chain_id,
                    block_number,
                    block_hash.lower(),
                    state,
                    int(canonical),
                    policy_kind,
                    policy_head_block,
                    supersedes,
                    _now(),
                ),
            )
        return FinalityObservation(
            observation_id=observation_id,
            transaction_id=transaction_id,
            state=state,
            block_number=block_number,
            block_hash=block_hash.lower(),
            policy_kind=policy_kind,
            policy_head_block=policy_head_block,
            supersedes_observation_id=supersedes,
        )

    def _latest(self, transaction_id: str) -> FinalityObservation | None:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT current.*
                FROM transaction_finality_observations AS current
                WHERE current.transaction_id = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM transaction_finality_observations AS later
                    WHERE later.supersedes_observation_id =
                          current.finality_observation_id
                  )
                """,
                (transaction_id,),
            ).fetchone()
        return None if row is None else _observation(row)

    def _policy_for_transaction(self, transaction_id: str) -> ChainFinalityPolicy:
        transaction = self._transaction_receipt(transaction_id)
        return self._policy(
            str(transaction["run_id"]),
            int(transaction["chain_id"]),
        )

    def _policy(self, run_id: str, chain_id: int) -> ChainFinalityPolicy:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT chain_id, policy_kind, confirmation_count
                FROM finality_policies
                WHERE run_id = ? AND chain_id = ?
                """,
                (run_id, chain_id),
            ).fetchone()
        if row is None:
            raise FinalityError("transaction chain has no preregistered finality policy")
        return ChainFinalityPolicy(
            chain_id=int(row["chain_id"]),
            kind=cast(FinalityKind, row["policy_kind"]),
            confirmation_count=(
                None
                if row["confirmation_count"] is None
                else int(row["confirmation_count"])
            ),
        )

    def _transaction_receipt(self, transaction_id: str) -> sqlite3.Row:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT transaction_record.chain_id, receipt.block_number,
                       receipt.block_hash, condition.run_id
                FROM transactions AS transaction_record
                JOIN transaction_receipts AS receipt
                  ON receipt.transaction_id = transaction_record.transaction_id
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
            raise FinalityError("finality requires a collected transaction receipt")
        return cast(sqlite3.Row, row)

    def _set_transaction_state(
        self,
        transaction_id: str,
        state: str,
        *,
        complete_stage: bool,
        collect_stage: bool = False,
    ) -> None:
        with self.store.write() as connection:
            row = connection.execute(
                """
                SELECT transaction_record.state, stage.stage_id,
                       stage.state AS stage_state
                FROM transactions AS transaction_record
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE transaction_record.transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()
            if row is None:
                raise FinalityError(f"unknown transaction: {transaction_id}")
            connection.execute(
                """
                UPDATE transactions
                SET state = ?,
                    included_at = CASE
                        WHEN ? = 'included' THEN coalesce(included_at, ?)
                        ELSE included_at
                    END,
                    finalized_at = CASE
                        WHEN ? = 'finalized' THEN ?
                        WHEN ? = 'orphaned' THEN NULL
                        ELSE finalized_at
                    END
                WHERE transaction_id = ?
                """,
                (state, state, _now(), state, _now(), state, transaction_id),
            )
            stage_state = (
                "completed"
                if complete_stage
                else "collecting"
                if collect_stage
                else str(row["stage_state"])
            )
            if stage_state != row["stage_state"]:
                connection.execute(
                    "UPDATE stages SET state = ? WHERE stage_id = ?",
                    (stage_state, row["stage_id"]),
                )


def _validate_policy(policy: ChainFinalityPolicy) -> None:
    if policy.chain_id <= 0:
        raise FinalityError("finality policy chain ID must be positive")
    if policy.kind == "confirmations":
        if policy.confirmation_count is None or policy.confirmation_count < 1:
            raise FinalityError("confirmation policy requires a positive count")
    elif policy.confirmation_count is not None:
        raise FinalityError("tag or settlement finality must not set confirmations")


def _observation(row: sqlite3.Row) -> FinalityObservation:
    return FinalityObservation(
        observation_id=str(row["finality_observation_id"]),
        transaction_id=str(row["transaction_id"]),
        state=cast(
            Literal["included", "finalized", "orphaned"],
            row["observation_state"],
        ),
        block_number=int(row["block_number"]),
        block_hash=str(row["block_hash"]),
        policy_kind=cast(FinalityKind, row["policy_kind"]),
        policy_head_block=(
            None if row["policy_head_block"] is None else int(row["policy_head_block"])
        ),
        supersedes_observation_id=(
            None
            if row["supersedes_observation_id"] is None
            else str(row["supersedes_observation_id"])
        ),
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()
