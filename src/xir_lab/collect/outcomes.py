"""Immutable deadline/eventual outcomes and explicitly separated clocks."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from xir_lab.evidence.records import stable_id
from xir_lab.evidence.store import EvidenceStore

FailureSource = Literal[
    "observer",
    "evidence",
    "submission",
    "carrier",
    "xir",
    "destination",
]
FailureOutcome = Literal[
    "observer_failed",
    "incomplete_evidence",
    "submission_failed",
    "carrier_failed",
    "xir_rejected",
    "destination_failed",
]
EventualOutcome = Literal[
    "delivered_after_timeout",
    "carrier_failed_after_timeout",
    "xir_rejected_after_timeout",
    "destination_failed_after_timeout",
    "incomplete_evidence",
]


class OutcomeClockError(RuntimeError):
    """Raised when outcome or clock evidence would change historical meaning."""


@dataclass(frozen=True)
class OutcomeObservation:
    observation_id: str
    attempt_id: str
    kind: Literal["deadline", "eventual", "failure"]
    outcome: str
    observed_utc: str
    observed_monotonic_ns: int


@dataclass(frozen=True)
class ClockObservation:
    observation_id: str
    attempt_id: str
    phase: str
    observer_session_id: str
    wall_utc: str
    monotonic_ns: int
    wall_clock_discontinuity: bool
    discontinuity_reason: str | None


@dataclass(frozen=True)
class ChainClockObservation:
    observation_id: str
    attempt_id: str
    role: Literal["source", "intermediate", "destination"]
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int


@dataclass(frozen=True)
class ClockMeasurement:
    measurement_id: str
    kind: Literal["observer_elapsed", "cross_chain_block_interval"]
    elapsed_ms: int | None
    unavailable_reason: str | None
    clock_statement: str


class OutcomeClockRecorder:
    def __init__(
        self,
        *,
        store: EvidenceStore,
        wall_discontinuity_threshold_ms: int = 1_000,
    ) -> None:
        if wall_discontinuity_threshold_ms < 0:
            raise OutcomeClockError("wall discontinuity threshold cannot be negative")
        self.store = store
        self.wall_discontinuity_threshold_ms = wall_discontinuity_threshold_ms

    def register_window(
        self,
        *,
        attempt_id: str,
        approval_id: str,
        approval_payload_sha256: str,
        observer_session_id: str,
        started_utc: str,
        started_monotonic_ns: int,
        deadline_utc: str,
    ) -> None:
        start = _utc(started_utc)
        deadline = _utc(deadline_utc)
        if deadline <= start:
            raise OutcomeClockError("observation deadline must follow its start")
        if started_monotonic_ns < 0 or not observer_session_id:
            raise OutcomeClockError("observer session and monotonic start are required")
        values = (
            approval_id,
            approval_payload_sha256,
            observer_session_id,
            _format(start),
            started_monotonic_ns,
            _format(deadline),
        )
        with self.store.write() as connection:
            approval = connection.execute(
                """
                SELECT payload_sha256 FROM approval_consumptions
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            if (
                approval is None
                or approval["payload_sha256"] != approval_payload_sha256
            ):
                raise OutcomeClockError(
                    "observation window is not bound to the consumed approval"
                )
            existing = connection.execute(
                """
                SELECT approval_id, approval_payload_sha256,
                       observer_session_id, started_utc,
                       started_monotonic_ns, deadline_utc
                FROM attempt_observation_windows WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != values:
                    raise OutcomeClockError("observation window is immutable")
                return
            connection.execute(
                """
                INSERT INTO attempt_observation_windows(
                    attempt_id, approval_id, approval_payload_sha256,
                    observer_session_id, started_utc, started_monotonic_ns,
                    deadline_utc, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (attempt_id, *values, _now()),
            )

    def record_phase(
        self,
        *,
        attempt_id: str,
        phase: str,
        observer_session_id: str,
        wall_utc: str,
        monotonic_ns: int,
    ) -> ClockObservation:
        wall = _utc(wall_utc)
        if not phase or not observer_session_id or monotonic_ns < 0:
            raise OutcomeClockError("phase clock fields are invalid")
        with self.store.connect(read_only=True) as connection:
            prior = connection.execute(
                """
                SELECT wall_utc, monotonic_ns
                FROM observer_clock_observations
                WHERE attempt_id = ? AND observer_session_id = ?
                ORDER BY monotonic_ns DESC LIMIT 1
                """,
                (attempt_id, observer_session_id),
            ).fetchone()
        discontinuity = False
        reason: str | None = None
        if prior is not None:
            monotonic_delta_ms = (monotonic_ns - int(prior["monotonic_ns"])) // 1_000_000
            if monotonic_delta_ms < 0:
                raise OutcomeClockError("monotonic phase clock moved backwards")
            wall_delta_ms = int(
                (wall - _utc(str(prior["wall_utc"]))).total_seconds() * 1_000
            )
            if abs(wall_delta_ms - monotonic_delta_ms) > (
                self.wall_discontinuity_threshold_ms
            ):
                discontinuity = True
                reason = "wall_and_monotonic_elapsed_diverged"
        observation_id = stable_id(
            "observation",
            "observer-clock",
            attempt_id,
            observer_session_id,
            phase,
            monotonic_ns,
        )
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT INTO observer_clock_observations(
                    clock_observation_id, attempt_id, phase,
                    observer_session_id, wall_utc, monotonic_ns,
                    wall_clock_discontinuity, discontinuity_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    attempt_id,
                    phase,
                    observer_session_id,
                    _format(wall),
                    monotonic_ns,
                    int(discontinuity),
                    reason,
                ),
            )
        return ClockObservation(
            observation_id,
            attempt_id,
            phase,
            observer_session_id,
            _format(wall),
            monotonic_ns,
            discontinuity,
            reason,
        )

    def observer_duration(
        self,
        *,
        start_observation_id: str,
        end_observation_id: str,
    ) -> ClockMeasurement:
        start = self._observer_clock(start_observation_id)
        end = self._observer_clock(end_observation_id)
        if start.attempt_id != end.attempt_id:
            raise OutcomeClockError("observer duration changed attempt")
        elapsed_ms: int | None
        unavailable: str | None
        if start.observer_session_id != end.observer_session_id:
            elapsed_ms = None
            unavailable = "monotonic_sessions_differ"
        elif end.monotonic_ns < start.monotonic_ns:
            elapsed_ms = None
            unavailable = "monotonic_order_invalid"
        else:
            elapsed_ms = (end.monotonic_ns - start.monotonic_ns) // 1_000_000
            unavailable = (
                "wall_clock_discontinuity_recorded"
                if start.wall_clock_discontinuity
                or end.wall_clock_discontinuity
                else None
            )
        return self._measurement(
            attempt_id=start.attempt_id,
            kind="observer_elapsed",
            start_observation_id=start_observation_id,
            end_observation_id=end_observation_id,
            elapsed_ms=elapsed_ms,
            unavailable_reason=unavailable,
            statement="elapsed time uses one process monotonic clock session",
        )

    def record_chain_clock(
        self,
        *,
        attempt_id: str,
        role: Literal["source", "intermediate", "destination"],
        chain_id: int,
        block_number: int,
        block_hash: str,
        block_timestamp: int,
    ) -> ChainClockObservation:
        if chain_id <= 0 or block_number < 0 or block_timestamp < 0:
            raise OutcomeClockError("chain clock fields are invalid")
        observation_id = stable_id(
            "observation",
            "chain-clock",
            attempt_id,
            role,
            chain_id,
            block_hash.lower(),
        )
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO chain_clock_observations(
                    chain_clock_observation_id, attempt_id, role, chain_id,
                    block_number, block_hash, block_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    attempt_id,
                    role,
                    chain_id,
                    block_number,
                    block_hash.lower(),
                    block_timestamp,
                ),
            )
        return ChainClockObservation(
            observation_id,
            attempt_id,
            role,
            chain_id,
            block_number,
            block_hash.lower(),
            block_timestamp,
        )

    def cross_chain_interval(
        self,
        *,
        source_observation_id: str,
        terminal_observation_id: str,
        maximum_plausible_seconds: int,
    ) -> ClockMeasurement:
        source = self._chain_clock(source_observation_id)
        terminal = self._chain_clock(terminal_observation_id)
        if source.attempt_id != terminal.attempt_id:
            raise OutcomeClockError("cross-chain interval changed attempt")
        if source.role != "source" or terminal.role != "destination":
            raise OutcomeClockError("cross-chain interval endpoints are not source/destination")
        seconds = terminal.block_timestamp - source.block_timestamp
        if seconds < 0:
            elapsed_ms = None
            reason = "independent_chain_clocks_out_of_order"
        elif seconds > maximum_plausible_seconds:
            elapsed_ms = None
            reason = "independent_chain_clocks_implausible"
        else:
            elapsed_ms = seconds * 1_000
            reason = None
        return self._measurement(
            attempt_id=source.attempt_id,
            kind="cross_chain_block_interval",
            start_observation_id=source_observation_id,
            end_observation_id=terminal_observation_id,
            elapsed_ms=elapsed_ms,
            unavailable_reason=reason,
            statement=(
                "independent chain block timestamps are not a precise common clock"
            ),
        )

    def mark_deadline_timeout(
        self,
        *,
        attempt_id: str,
        observed_utc: str,
        observer_session_id: str,
        observed_monotonic_ns: int,
    ) -> OutcomeObservation:
        window = self._window(attempt_id)
        observed = _utc(observed_utc)
        deadline = _utc(str(window["deadline_utc"]))
        if observed < deadline:
            raise OutcomeClockError("observation deadline has not been reached")
        with self.store.connect(read_only=True) as connection:
            attempt = connection.execute(
                "SELECT state FROM attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        if attempt is None:
            raise OutcomeClockError(f"unknown attempt: {attempt_id}")
        if attempt["state"] in {
            "delivered",
            "carrier_failed",
            "xir_rejected",
            "destination_failed",
        }:
            raise OutcomeClockError("terminal chain outcome already exists at deadline")
        horizon_ms = int(
            (deadline - _utc(str(window["started_utc"]))).total_seconds() * 1_000
        )
        observation = self._append_outcome(
            attempt_id=attempt_id,
            kind="deadline",
            outcome="timed_out",
            failure_source=None,
            failure_code=None,
            observation_horizon_ms=horizon_ms,
            observed_utc=observed,
            observer_session_id=observer_session_id,
            observed_monotonic_ns=observed_monotonic_ns,
            proof_finality_observation_id=None,
        )
        with self.store.write() as connection:
            connection.execute(
                "UPDATE attempts SET state = 'timed_out' WHERE attempt_id = ?",
                (attempt_id,),
            )
        return observation

    def record_eventual_outcome(
        self,
        *,
        attempt_id: str,
        outcome: EventualOutcome,
        observed_utc: str,
        observer_session_id: str,
        observed_monotonic_ns: int,
        proof_finality_observation_id: str | None = None,
    ) -> OutcomeObservation:
        deadline = self._outcome(attempt_id, "deadline")
        if deadline is None or deadline.outcome != "timed_out":
            raise OutcomeClockError("eventual outcome requires historical timeout")
        if outcome == "delivered_after_timeout":
            if proof_finality_observation_id is None:
                raise OutcomeClockError("eventual delivery requires finalized chain proof")
            self._validate_destination_finality(
                attempt_id,
                proof_finality_observation_id,
            )
        elif proof_finality_observation_id is not None:
            raise OutcomeClockError("failure eventual outcome cannot use delivery proof")
        return self._append_outcome(
            attempt_id=attempt_id,
            kind="eventual",
            outcome=outcome,
            failure_source=None,
            failure_code=None,
            observation_horizon_ms=None,
            observed_utc=_utc(observed_utc),
            observer_session_id=observer_session_id,
            observed_monotonic_ns=observed_monotonic_ns,
            proof_finality_observation_id=proof_finality_observation_id,
        )

    def record_failure(
        self,
        *,
        attempt_id: str,
        outcome: FailureOutcome,
        source: FailureSource,
        failure_code: str,
        observed_utc: str,
        observer_session_id: str,
        observed_monotonic_ns: int,
    ) -> OutcomeObservation:
        self._window(attempt_id)
        expected_sources: dict[FailureOutcome, set[FailureSource]] = {
            "observer_failed": {"observer"},
            "incomplete_evidence": {"observer", "evidence"},
            "submission_failed": {"submission"},
            "carrier_failed": {"carrier"},
            "xir_rejected": {"xir"},
            "destination_failed": {"destination"},
        }
        if source not in expected_sources[outcome]:
            raise OutcomeClockError("failure source does not match outcome class")
        observation = self._append_outcome(
            attempt_id=attempt_id,
            kind="failure",
            outcome=outcome,
            failure_source=source,
            failure_code=failure_code,
            observation_horizon_ms=None,
            observed_utc=_utc(observed_utc),
            observer_session_id=observer_session_id,
            observed_monotonic_ns=observed_monotonic_ns,
            proof_finality_observation_id=None,
        )
        if self._outcome(attempt_id, "deadline") is None:
            with self.store.write() as connection:
                connection.execute(
                    "UPDATE attempts SET state = ? WHERE attempt_id = ?",
                    (outcome, attempt_id),
                )
        return observation

    def _append_outcome(
        self,
        *,
        attempt_id: str,
        kind: Literal["deadline", "eventual", "failure"],
        outcome: str,
        failure_source: FailureSource | None,
        failure_code: str | None,
        observation_horizon_ms: int | None,
        observed_utc: datetime,
        observer_session_id: str,
        observed_monotonic_ns: int,
        proof_finality_observation_id: str | None,
    ) -> OutcomeObservation:
        if observed_monotonic_ns < 0 or not observer_session_id:
            raise OutcomeClockError("outcome observer clock is invalid")
        observation_id = stable_id(
            "observation",
            "attempt-outcome",
            attempt_id,
            kind,
            outcome,
        )
        try:
            with self.store.write() as connection:
                connection.execute(
                    """
                    INSERT INTO attempt_outcome_observations(
                        outcome_observation_id, attempt_id, outcome_kind,
                        outcome, failure_source, failure_code,
                        observation_horizon_ms, observed_utc,
                        observer_session_id, observed_monotonic_ns,
                        proof_finality_observation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observation_id,
                        attempt_id,
                        kind,
                        outcome,
                        failure_source,
                        failure_code,
                        observation_horizon_ms,
                        _format(observed_utc),
                        observer_session_id,
                        observed_monotonic_ns,
                        proof_finality_observation_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise OutcomeClockError(f"{kind} outcome is already recorded") from exc
        return OutcomeObservation(
            observation_id,
            attempt_id,
            kind,
            outcome,
            _format(observed_utc),
            observed_monotonic_ns,
        )

    def _measurement(
        self,
        *,
        attempt_id: str,
        kind: Literal["observer_elapsed", "cross_chain_block_interval"],
        start_observation_id: str,
        end_observation_id: str,
        elapsed_ms: int | None,
        unavailable_reason: str | None,
        statement: str,
    ) -> ClockMeasurement:
        measurement_id = stable_id(
            "observation",
            "clock-measurement",
            kind,
            start_observation_id,
            end_observation_id,
        )
        with self.store.write() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO clock_measurements(
                    measurement_id, attempt_id, measurement_kind,
                    start_observation_id, end_observation_id, elapsed_ms,
                    unavailable_reason, clock_statement, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    measurement_id,
                    attempt_id,
                    kind,
                    start_observation_id,
                    end_observation_id,
                    elapsed_ms,
                    unavailable_reason,
                    statement,
                    _now(),
                ),
            )
        return ClockMeasurement(
            measurement_id,
            kind,
            elapsed_ms,
            unavailable_reason,
            statement,
        )

    def _window(self, attempt_id: str) -> sqlite3.Row:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM attempt_observation_windows WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise OutcomeClockError("attempt has no approval-bound observation window")
        return cast(sqlite3.Row, row)

    def _outcome(
        self,
        attempt_id: str,
        kind: Literal["deadline", "eventual", "failure"],
    ) -> OutcomeObservation | None:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM attempt_outcome_observations
                WHERE attempt_id = ? AND outcome_kind = ?
                """,
                (attempt_id, kind),
            ).fetchone()
        if row is None:
            return None
        return OutcomeObservation(
            str(row["outcome_observation_id"]),
            str(row["attempt_id"]),
            kind,
            str(row["outcome"]),
            str(row["observed_utc"]),
            int(row["observed_monotonic_ns"]),
        )

    def _observer_clock(self, observation_id: str) -> ClockObservation:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM observer_clock_observations
                WHERE clock_observation_id = ?
                """,
                (observation_id,),
            ).fetchone()
        if row is None:
            raise OutcomeClockError(f"unknown observer clock: {observation_id}")
        return ClockObservation(
            str(row["clock_observation_id"]),
            str(row["attempt_id"]),
            str(row["phase"]),
            str(row["observer_session_id"]),
            str(row["wall_utc"]),
            int(row["monotonic_ns"]),
            bool(row["wall_clock_discontinuity"]),
            (
                None
                if row["discontinuity_reason"] is None
                else str(row["discontinuity_reason"])
            ),
        )

    def _chain_clock(self, observation_id: str) -> ChainClockObservation:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM chain_clock_observations
                WHERE chain_clock_observation_id = ?
                """,
                (observation_id,),
            ).fetchone()
        if row is None:
            raise OutcomeClockError(f"unknown chain clock: {observation_id}")
        return ChainClockObservation(
            str(row["chain_clock_observation_id"]),
            str(row["attempt_id"]),
            cast(Literal["source", "intermediate", "destination"], row["role"]),
            int(row["chain_id"]),
            int(row["block_number"]),
            str(row["block_hash"]),
            int(row["block_timestamp"]),
        )

    def _validate_destination_finality(
        self,
        attempt_id: str,
        observation_id: str,
    ) -> None:
        with self.store.connect(read_only=True) as connection:
            row = connection.execute(
                """
                SELECT finality.observation_state, finality.canonical,
                       stage.attempt_id, stage.ordinal,
                       (
                           SELECT max(peer.ordinal)
                           FROM stages AS peer
                           WHERE peer.attempt_id = stage.attempt_id
                       ) AS final_ordinal
                FROM transaction_finality_observations AS finality
                JOIN transactions AS transaction_record
                  ON transaction_record.transaction_id = finality.transaction_id
                JOIN intents AS intent
                  ON intent.intent_id = transaction_record.intent_id
                JOIN stages AS stage ON stage.stage_id = intent.stage_id
                WHERE finality.finality_observation_id = ?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM transaction_finality_observations AS later
                      WHERE later.supersedes_observation_id =
                            finality.finality_observation_id
                  )
                """,
                (observation_id,),
            ).fetchone()
        if (
            row is None
            or row["attempt_id"] != attempt_id
            or row["observation_state"] != "finalized"
            or row["canonical"] != 1
            or row["ordinal"] != row["final_ordinal"]
        ):
            raise OutcomeClockError(
                "eventual delivery proof is not canonical finalized destination evidence"
            )


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OutcomeClockError(f"invalid UTC timestamp: {value}") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise OutcomeClockError("timestamp must use UTC")
    return parsed


def _format(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _now() -> str:
    return datetime.now(UTC).isoformat()
