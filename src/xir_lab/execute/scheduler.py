"""Deterministic profile expansion and bounded in-flight dispatch."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal, cast

import rfc8785

from xir_lab.config.profiles import ExecutionProfile
from xir_lab.evidence.records import stable_id

Arm = Literal["baseline", "xir"]
ScheduleAttemptKind = Literal["pilot", "warmup", "primary", "retry"]


class ScheduleError(RuntimeError):
    """Raised when a runtime schedule would diverge from its frozen plan."""


@dataclass(frozen=True)
class ScheduledAttempt:
    attempt_id: str
    condition: str
    arm: Arm
    attempt_kind: ScheduleAttemptKind
    pair_id: str | None
    pair_slot_index: int | None
    retry_of: str | None
    retry_index: int | None
    sequence_index: int
    batch_index: int


@dataclass(frozen=True)
class ExecutionPlan:
    plan_id: str
    run_id: str
    profile_id: str
    fixed_seed: str
    profile_kind: str
    executable: bool
    max_retries_per_lineage: int | None
    max_batch_attempts: int | None
    max_in_flight_attempts: int | None
    attempts: tuple[ScheduledAttempt, ...]
    plan_sha256: str

    @property
    def planned_pair_slots(self) -> int:
        return len({item.pair_id for item in self.attempts if item.pair_id is not None})

    @property
    def planned_non_retry_attempts(self) -> int:
        return sum(item.attempt_kind != "retry" for item in self.attempts)


def _seeded_key(seed: str, domain: str, *coordinates: str | int) -> str:
    canonical = rfc8785.dumps(
        {
            "domain": domain,
            "seed": seed,
            "coordinates": list(coordinates),
        }
    )
    return hashlib.sha256(canonical).hexdigest()


def _plan_digest(
    *,
    plan_id: str,
    run_id: str,
    profile: ExecutionProfile,
    attempts: tuple[ScheduledAttempt, ...],
) -> str:
    document: dict[str, Any] = {
        "schema_version": "xir-lab-execution-plan-v1",
        "plan_id": plan_id,
        "run_id": run_id,
        "profile_id": profile.profile_id,
        "profile_kind": profile.profile_kind,
        "fixed_seed": profile.fixed_seed,
        "live_limits": {
            "max_retries_per_lineage": profile.live_limits.max_retries_per_lineage,
            "max_batch_attempts": profile.live_limits.max_batch_attempts,
            "max_in_flight_attempts": profile.live_limits.max_in_flight_attempts,
        },
        "attempts": [
            {
                "attempt_id": item.attempt_id,
                "condition": item.condition,
                "arm": item.arm,
                "attempt_kind": item.attempt_kind,
                "pair_id": item.pair_id,
                "pair_slot_index": item.pair_slot_index,
                "retry_of": item.retry_of,
                "retry_index": item.retry_index,
                "sequence_index": item.sequence_index,
                "batch_index": item.batch_index,
            }
            for item in attempts
        ],
    }
    return hashlib.sha256(rfc8785.dumps(document)).hexdigest()


def expand_plan(profile: ExecutionProfile, *, run_id: str) -> ExecutionPlan:
    """Expand exact profile counts with hash-seeded pair and within-pair order."""
    if run_id == "":
        raise ScheduleError("run ID must be non-empty")
    seed = profile.fixed_seed
    warmup_coordinates = [
        (condition, arm)
        for condition in profile.conditions
        for arm in ("baseline", "xir")
        for _ in range(profile.counts.warmups_per_condition_arm)
    ]
    warmup_coordinates.sort(
        key=lambda item: _seeded_key(seed, "warmup-order", item[0], item[1])
    )

    pair_coordinates = [
        (condition, slot)
        for condition in profile.conditions
        for slot in range(profile.counts.pair_slots_per_condition)
    ]
    pair_coordinates.sort(
        key=lambda item: _seeded_key(seed, "pair-order", item[0], item[1])
    )

    raw: list[
        tuple[
            str,
            Arm,
            ScheduleAttemptKind,
            str | None,
            int | None,
        ]
    ] = []
    for condition, arm_name in warmup_coordinates:
        arm = cast_arm(arm_name)
        raw.append((condition, arm, "warmup", None, None))
    designated_kind = profile.counts.designated_attempt_kind
    if designated_kind not in {"pilot", "primary"}:
        raise ScheduleError("profile designated attempt kind is unsupported")
    scheduled_kind = cast(ScheduleAttemptKind, designated_kind)
    for condition, slot in pair_coordinates:
        pair_id = stable_id("pair", run_id, condition, slot)
        arms: tuple[Arm, Arm]
        if _seeded_key(seed, "within-pair-order", condition, slot)[-1] in "02468ace":
            arms = ("baseline", "xir")
        else:
            arms = ("xir", "baseline")
        for arm in arms:
            raw.append(
                (
                    condition,
                    arm,
                    scheduled_kind,
                    pair_id,
                    slot,
                )
            )

    batch_size = profile.live_limits.max_batch_attempts
    attempts: list[ScheduledAttempt] = []
    warmup_cell_index: dict[tuple[str, Arm], int] = {}
    for sequence_index, (
        scheduled_condition,
        scheduled_arm,
        kind,
        scheduled_pair_id,
        scheduled_slot,
    ) in enumerate(raw):
        if kind == "warmup":
            cell = (scheduled_condition, scheduled_arm)
            repetition = warmup_cell_index.get(cell, 0)
            warmup_cell_index[cell] = repetition + 1
            attempt_id = stable_id(
                "attempt",
                run_id,
                scheduled_condition,
                scheduled_arm,
                "warmup",
                repetition,
            )
        else:
            if scheduled_slot is None:
                raise ScheduleError("designated attempt lost its pair slot")
            attempt_id = stable_id(
                "attempt",
                run_id,
                scheduled_condition,
                scheduled_arm,
                designated_kind,
                scheduled_slot,
            )
        batch_index = 0 if batch_size is None else sequence_index // batch_size
        attempts.append(
            ScheduledAttempt(
                attempt_id=attempt_id,
                condition=scheduled_condition,
                arm=scheduled_arm,
                attempt_kind=kind,
                pair_id=scheduled_pair_id,
                pair_slot_index=scheduled_slot,
                retry_of=None,
                retry_index=None,
                sequence_index=sequence_index,
                batch_index=batch_index,
            )
        )
    frozen = tuple(attempts)
    if len(frozen) != profile.counts.planned_total_non_retry_attempts:
        raise ScheduleError("expanded attempt count differs from profile identity")
    pair_count = len({item.pair_id for item in frozen if item.pair_id is not None})
    if pair_count != profile.counts.planned_pair_slots:
        raise ScheduleError("expanded pair-slot count differs from profile identity")
    per_cell = {
        (condition, arm): sum(
            item.condition == condition
            and item.arm == arm
            and item.attempt_kind == designated_kind
            for item in frozen
        )
        for condition in profile.conditions
        for arm in ("baseline", "xir")
    }
    if set(per_cell.values()) != {profile.counts.pair_slots_per_condition}:
        raise ScheduleError("condition/arm designated counts are not balanced")
    plan_id = stable_id("run", run_id, profile.profile_id, profile.fixed_seed)
    return ExecutionPlan(
        plan_id=plan_id,
        run_id=run_id,
        profile_id=profile.profile_id,
        fixed_seed=profile.fixed_seed,
        profile_kind=profile.profile_kind,
        executable=profile.executable,
        max_retries_per_lineage=profile.live_limits.max_retries_per_lineage,
        max_batch_attempts=batch_size,
        max_in_flight_attempts=profile.live_limits.max_in_flight_attempts,
        attempts=frozen,
        plan_sha256=_plan_digest(
            plan_id=plan_id,
            run_id=run_id,
            profile=profile,
            attempts=frozen,
        ),
    )


def cast_arm(value: str) -> Arm:
    if value not in {"baseline", "xir"}:
        raise ScheduleError(f"unsupported arm: {value}")
    return cast(Arm, value)


class BoundedScheduler:
    """Dispatch a frozen live plan without crossing batch or in-flight bounds."""

    def __init__(self, plan: ExecutionPlan) -> None:
        if not plan.executable:
            raise ScheduleError("template plans cannot be dispatched")
        if plan.max_batch_attempts is None or plan.max_in_flight_attempts is None:
            raise ScheduleError("live plan is missing batch or in-flight limits")
        self.plan = plan
        self._next_index = 0
        self._active: dict[str, ScheduledAttempt] = {}
        self._completed: set[str] = set()
        self._retries: dict[str, ScheduledAttempt] = {}

    @property
    def active_attempt_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._active))

    @property
    def complete(self) -> bool:
        return (
            self._next_index == len(self.plan.attempts)
            and not self._active
            and set(self._retries) <= self._completed
        )

    def claim_next(self) -> ScheduledAttempt | None:
        if len(self._active) >= cast_int(self.plan.max_in_flight_attempts):
            return None
        if self._next_index >= len(self.plan.attempts):
            pending_retries = [
                retry
                for retry in self._retries.values()
                if retry.attempt_id not in self._completed
                and retry.attempt_id not in self._active
            ]
            if not pending_retries:
                return None
            item = min(pending_retries, key=lambda retry: retry.sequence_index)
        else:
            item = self.plan.attempts[self._next_index]
            current_batch = item.batch_index
            if any(active.batch_index != current_batch for active in self._active.values()):
                return None
            if item.pair_id is not None and any(
                active.pair_id == item.pair_id for active in self._active.values()
            ):
                return None
            self._next_index += 1
        self._active[item.attempt_id] = item
        return item

    def complete_attempt(self, attempt_id: str) -> None:
        if attempt_id not in self._active:
            raise ScheduleError("only an active planned attempt can complete")
        del self._active[attempt_id]
        self._completed.add(attempt_id)

    def register_retry(
        self, *, prior_attempt_id: str, retry_index: int
    ) -> ScheduledAttempt:
        maximum = self._max_retries()
        if retry_index < 1 or retry_index > maximum:
            raise ScheduleError("retry index exceeds the frozen profile limit")
        planned = {item.attempt_id: item for item in self.plan.attempts}
        prior = planned.get(prior_attempt_id) or self._retries.get(prior_attempt_id)
        if prior is None:
            raise ScheduleError("retry predecessor is outside the frozen plan")
        root_id = self._root_attempt_id(prior)
        root = planned[root_id]
        existing_for_root = [
            item
            for item in self._retries.values()
            if self._root_attempt_id(item) == root.attempt_id
        ]
        if any(item.retry_index == retry_index for item in existing_for_root):
            raise ScheduleError("retry index is already registered")
        attempt_id = stable_id(
            "attempt",
            self.plan.run_id,
            root.attempt_id,
            "retry",
            retry_index,
        )
        retry = ScheduledAttempt(
            attempt_id=attempt_id,
            condition=root.condition,
            arm=root.arm,
            attempt_kind="retry",
            pair_id=root.pair_id,
            pair_slot_index=root.pair_slot_index,
            retry_of=prior.attempt_id,
            retry_index=retry_index,
            sequence_index=len(self.plan.attempts) + len(self._retries),
            batch_index=max(
                (item.batch_index for item in self.plan.attempts),
                default=0,
            )
            + 1,
            # Retry batches are separate from designated batches and remain bounded.
        )
        retry_batch_offset = len(self._retries) // cast_int(
            self.plan.max_batch_attempts
        )
        retry = replace_batch(retry, retry.batch_index + retry_batch_offset)
        self._retries[attempt_id] = retry
        return retry

    def assert_registered(self, attempt_id: str) -> None:
        if (
            attempt_id not in {item.attempt_id for item in self.plan.attempts}
            and attempt_id not in self._retries
        ):
            raise ScheduleError("unplanned replacement attempt or pair slot")

    def _max_retries(self) -> int:
        return cast_int(self.plan.max_retries_per_lineage)

    def _root_attempt_id(self, item: ScheduledAttempt) -> str:
        current = item
        while current.retry_of is not None:
            predecessor = self._retries.get(current.retry_of)
            if predecessor is None:
                return current.retry_of
            current = predecessor
        return current.attempt_id


def cast_int(value: int | None) -> int:
    if value is None:
        raise ScheduleError("required live limit is missing")
    return value


def replace_batch(item: ScheduledAttempt, batch_index: int) -> ScheduledAttempt:
    return ScheduledAttempt(
        attempt_id=item.attempt_id,
        condition=item.condition,
        arm=item.arm,
        attempt_kind=item.attempt_kind,
        pair_id=item.pair_id,
        pair_slot_index=item.pair_slot_index,
        retry_of=item.retry_of,
        retry_index=item.retry_index,
        sequence_index=item.sequence_index,
        batch_index=batch_index,
    )
