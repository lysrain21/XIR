"""Schema-backed immutable record identities for the experiment ledger."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785

IdKind = Literal[
    "run",
    "condition",
    "arm",
    "pair",
    "repetition",
    "attempt",
    "stage",
    "message",
    "intent",
    "transaction",
    "observation",
    "freeze",
]
AttemptKind = Literal["pilot", "warmup", "primary", "retry"]
ArmName = Literal["baseline", "xir"]


class RecordError(ValueError):
    """Raised when evidence records are not reconstructable or internally consistent."""


def stable_id(kind: IdKind, *components: str | int) -> str:
    """Return a deterministic, namespace-separated identifier.

    Identifiers are derived from canonical JSON rather than display labels, so the
    same logical coordinates reproduce the same ID on offline rebuild.
    """

    canonical = rfc8785.dumps({"kind": kind, "components": list(components)})
    return f"{kind}_{hashlib.sha256(canonical).hexdigest()[:24]}"


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    profile_id: str
    plan_sha256: str


@dataclass(frozen=True)
class ConditionRecord:
    condition_id: str
    run_id: str
    carrier_sequence: str


@dataclass(frozen=True)
class ArmRecord:
    arm_id: str
    condition_id: str
    arm: ArmName


@dataclass(frozen=True)
class PairSlotRecord:
    pair_slot_id: str
    condition_id: str
    slot_index: int


@dataclass(frozen=True)
class RepetitionRecord:
    repetition_id: str
    pair_slot_id: str
    repetition_index: int


@dataclass(frozen=True)
class AttemptRecord:
    attempt_id: str
    condition_id: str
    arm_id: str
    pair_slot_id: str | None
    repetition_id: str | None
    attempt_kind: AttemptKind
    prior_attempt_id: str | None
    original_attempt_kind: AttemptKind | None
    state: str


@dataclass(frozen=True)
class StageRecord:
    stage_id: str
    attempt_id: str
    stage_name: str
    ordinal: int


@dataclass(frozen=True)
class MessageRecord:
    message_id: str
    stage_id: str
    protocol: str
    protocol_message_id: str | None


@dataclass(frozen=True)
class TransactionIntentRecord:
    intent_id: str
    stage_id: str
    chain_id: int
    operation_id: str


@dataclass(frozen=True)
class TransactionRecord:
    transaction_id: str
    intent_id: str
    chain_id: int
    nonce: int
    transaction_hash: str | None
    replaces_transaction_id: str | None


@dataclass(frozen=True)
class ObservationRecord:
    observation_id: str
    subject_kind: str
    subject_id: str
    observed_at: str
    raw_sha256: str
    supersedes_observation_id: str | None


@dataclass(frozen=True)
class FreezeScopeRecord:
    freeze_scope_id: str
    run_id: str
    attempt_ids: tuple[str, ...]
    prior_freeze_sha256: str | None
    scope_sha256: str


@dataclass(frozen=True)
class EvidenceRecordBundle:
    runs: tuple[RunRecord, ...]
    conditions: tuple[ConditionRecord, ...]
    arms: tuple[ArmRecord, ...]
    pair_slots: tuple[PairSlotRecord, ...]
    repetitions: tuple[RepetitionRecord, ...]
    attempts: tuple[AttemptRecord, ...]
    stages: tuple[StageRecord, ...]
    messages: tuple[MessageRecord, ...]
    transaction_intents: tuple[TransactionIntentRecord, ...]
    transactions: tuple[TransactionRecord, ...]
    observations: tuple[ObservationRecord, ...]
    freeze_scopes: tuple[FreezeScopeRecord, ...]


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / "evidence-record-bundle-v1.schema.json"


def _read_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecordError(f"cannot read evidence bundle: {path}") from exc
    if not isinstance(value, dict):
        raise RecordError("evidence bundle root must be an object")
    return value


def _validate_schema(document: dict[str, Any]) -> None:
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise RecordError(f"schema validation failed at {location}: {first.message}")


def _records(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], document[key])


def _unique(records: list[Any], attribute: str, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for record in records:
        identifier = cast(str, getattr(record, attribute))
        if identifier in result:
            raise RecordError(f"duplicate {label}: {identifier}")
        result[identifier] = record
    return result


def _assert_reference(identifier: str, index: dict[str, Any], label: str) -> None:
    if identifier not in index:
        raise RecordError(f"unknown {label}: {identifier}")


def _assert_acyclic(
    nodes: dict[str, Any],
    predecessor_attribute: str,
    label: str,
) -> None:
    for start in nodes:
        seen: set[str] = set()
        current: str | None = start
        while current is not None:
            if current in seen:
                raise RecordError(f"cyclic {label} lineage at {current}")
            seen.add(current)
            record = nodes.get(current)
            if record is None:
                raise RecordError(f"unknown {label} predecessor: {current}")
            current = cast(str | None, getattr(record, predecessor_attribute))


def _semantic_validation(bundle: EvidenceRecordBundle) -> None:
    runs = _unique(list(bundle.runs), "run_id", "run")
    conditions = _unique(list(bundle.conditions), "condition_id", "condition")
    arms = _unique(list(bundle.arms), "arm_id", "arm")
    pairs = _unique(list(bundle.pair_slots), "pair_slot_id", "pair slot")
    repetitions = _unique(list(bundle.repetitions), "repetition_id", "repetition")
    attempts = _unique(list(bundle.attempts), "attempt_id", "attempt")
    stages = _unique(list(bundle.stages), "stage_id", "stage")
    messages = _unique(list(bundle.messages), "message_id", "message")
    intents = _unique(list(bundle.transaction_intents), "intent_id", "intent")
    transactions = _unique(list(bundle.transactions), "transaction_id", "transaction")
    observations = _unique(list(bundle.observations), "observation_id", "observation")
    freezes = _unique(list(bundle.freeze_scopes), "freeze_scope_id", "freeze scope")

    for condition in bundle.conditions:
        _assert_reference(condition.run_id, runs, "run")
    for arm in bundle.arms:
        _assert_reference(arm.condition_id, conditions, "condition")
    for pair in bundle.pair_slots:
        _assert_reference(pair.condition_id, conditions, "condition")
    for repetition in bundle.repetitions:
        _assert_reference(repetition.pair_slot_id, pairs, "pair slot")

    arm_cells: set[tuple[str, str]] = set()
    pair_cells: set[tuple[str, int]] = set()
    repetition_cells: set[tuple[str, int]] = set()
    for arm in bundle.arms:
        arm_cell = (arm.condition_id, arm.arm)
        if arm_cell in arm_cells:
            raise RecordError(f"duplicate condition/arm cell: {arm_cell}")
        arm_cells.add(arm_cell)
    for pair in bundle.pair_slots:
        pair_cell = (pair.condition_id, pair.slot_index)
        if pair_cell in pair_cells:
            raise RecordError(f"duplicate condition/pair-slot cell: {pair_cell}")
        pair_cells.add(pair_cell)
    for repetition in bundle.repetitions:
        repetition_cell = (repetition.pair_slot_id, repetition.repetition_index)
        if repetition_cell in repetition_cells:
            raise RecordError(f"duplicate pair/repetition cell: {repetition_cell}")
        repetition_cells.add(repetition_cell)

    for attempt in bundle.attempts:
        _assert_reference(attempt.condition_id, conditions, "condition")
        _assert_reference(attempt.arm_id, arms, "arm")
        arm = cast(ArmRecord, arms[attempt.arm_id])
        if arm.condition_id != attempt.condition_id:
            raise RecordError(f"attempt arm belongs to another condition: {attempt.attempt_id}")
        if attempt.attempt_kind == "retry":
            if attempt.prior_attempt_id is None or attempt.original_attempt_kind is None:
                raise RecordError(f"retry lacks immutable lineage fields: {attempt.attempt_id}")
        elif attempt.prior_attempt_id is not None or attempt.original_attempt_kind is not None:
            raise RecordError(f"non-retry carries retry lineage: {attempt.attempt_id}")
        if attempt.pair_slot_id is not None:
            _assert_reference(attempt.pair_slot_id, pairs, "pair slot")
            pair = cast(PairSlotRecord, pairs[attempt.pair_slot_id])
            if pair.condition_id != attempt.condition_id:
                raise RecordError(f"attempt pair belongs to another condition: {attempt.attempt_id}")
        if attempt.repetition_id is not None:
            _assert_reference(attempt.repetition_id, repetitions, "repetition")
            repetition = cast(RepetitionRecord, repetitions[attempt.repetition_id])
            if repetition.pair_slot_id != attempt.pair_slot_id:
                raise RecordError(f"attempt repetition belongs to another pair: {attempt.attempt_id}")

    _assert_acyclic(attempts, "prior_attempt_id", "retry")
    for attempt in bundle.attempts:
        if attempt.prior_attempt_id is None:
            continue
        prior = cast(AttemptRecord, attempts[attempt.prior_attempt_id])
        expected_original = (
            prior.original_attempt_kind if prior.attempt_kind == "retry" else prior.attempt_kind
        )
        if (
            attempt.condition_id,
            attempt.arm_id,
            attempt.pair_slot_id,
            attempt.repetition_id,
        ) != (
            prior.condition_id,
            prior.arm_id,
            prior.pair_slot_id,
            prior.repetition_id,
        ):
            raise RecordError(f"retry changed matching coordinates: {attempt.attempt_id}")
        if attempt.original_attempt_kind != expected_original:
            raise RecordError(f"retry changed original attempt kind: {attempt.attempt_id}")

    for stage in bundle.stages:
        _assert_reference(stage.attempt_id, attempts, "attempt")
    for message in bundle.messages:
        _assert_reference(message.stage_id, stages, "stage")
    for intent in bundle.transaction_intents:
        _assert_reference(intent.stage_id, stages, "stage")
    for transaction in bundle.transactions:
        _assert_reference(transaction.intent_id, intents, "intent")
        intent = cast(TransactionIntentRecord, intents[transaction.intent_id])
        if intent.chain_id != transaction.chain_id:
            raise RecordError(f"transaction chain differs from intent: {transaction.transaction_id}")
    _assert_acyclic(transactions, "replaces_transaction_id", "transaction replacement")
    for transaction in bundle.transactions:
        if transaction.replaces_transaction_id is None:
            continue
        prior_transaction = cast(
            TransactionRecord, transactions[transaction.replaces_transaction_id]
        )
        if (transaction.intent_id, transaction.chain_id, transaction.nonce) != (
            prior_transaction.intent_id,
            prior_transaction.chain_id,
            prior_transaction.nonce,
        ):
            raise RecordError(
                f"replacement changed intent, chain, or nonce: {transaction.transaction_id}"
            )

    subject_indexes = {
        "attempt": attempts,
        "stage": stages,
        "message": messages,
        "transaction": transactions,
    }
    for observation in bundle.observations:
        _assert_reference(
            observation.subject_id,
            subject_indexes[observation.subject_kind],
            observation.subject_kind,
        )
    _assert_acyclic(observations, "supersedes_observation_id", "observation correction")

    for freeze in bundle.freeze_scopes:
        _assert_reference(freeze.run_id, runs, "run")
        for attempt_id in freeze.attempt_ids:
            _assert_reference(attempt_id, attempts, "attempt")
            attempt = cast(AttemptRecord, attempts[attempt_id])
            condition = cast(ConditionRecord, conditions[attempt.condition_id])
            if condition.run_id != freeze.run_id:
                raise RecordError(f"freeze includes attempt from another run: {attempt_id}")

    del freezes


def load_evidence_record_bundle(path: Path) -> EvidenceRecordBundle:
    """Load a complete record bundle, then enforce cross-record semantics."""

    document = _read_document(path)
    _validate_schema(document)
    bundle = EvidenceRecordBundle(
        runs=tuple(RunRecord(**item) for item in _records(document, "runs")),
        conditions=tuple(
            ConditionRecord(**item) for item in _records(document, "conditions")
        ),
        arms=tuple(ArmRecord(**item) for item in _records(document, "arms")),
        pair_slots=tuple(
            PairSlotRecord(**item) for item in _records(document, "pair_slots")
        ),
        repetitions=tuple(
            RepetitionRecord(**item) for item in _records(document, "repetitions")
        ),
        attempts=tuple(AttemptRecord(**item) for item in _records(document, "attempts")),
        stages=tuple(StageRecord(**item) for item in _records(document, "stages")),
        messages=tuple(MessageRecord(**item) for item in _records(document, "messages")),
        transaction_intents=tuple(
            TransactionIntentRecord(**item)
            for item in _records(document, "transaction_intents")
        ),
        transactions=tuple(
            TransactionRecord(**item) for item in _records(document, "transactions")
        ),
        observations=tuple(
            ObservationRecord(**item) for item in _records(document, "observations")
        ),
        freeze_scopes=tuple(
            FreezeScopeRecord(
                **{
                    **item,
                    "attempt_ids": tuple(cast(list[str], item["attempt_ids"])),
                }
            )
            for item in _records(document, "freeze_scopes")
        ),
    )
    _semantic_validation(bundle)
    return bundle
