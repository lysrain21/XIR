from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from xir_lab.config.profiles import Derivation, ExecutionProfile, LiveLimits, load_execution_profile
from xir_lab.execute.scheduler import BoundedScheduler, ScheduleError, expand_plan

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "configs" / "profiles" / "pilot-template-v1.json"
PRIMARY = ROOT / "configs" / "profiles" / "primary-template-v1.json"
SCALE = ROOT / "configs" / "profiles" / "scale-template-v1.json"


def _live(profile: ExecutionProfile) -> ExecutionProfile:
    derived = profile.derived_from
    if profile.profile_kind == "primary":
        derived = Derivation("pilot", "pilot-run", "ab" * 32, True)
    elif profile.profile_kind == "scale":
        derived = Derivation("primary", "primary-run", "cd" * 32, True)
    return replace(
        profile,
        profile_mode="live",
        live_limits=LiveLimits(
            max_retries_per_lineage=1,
            max_batch_attempts=4,
            max_duration_seconds=3_600,
            max_in_flight_attempts=2,
            chain_budget_wei={"11155420": 1, "421614": 1, "84532": 1},
            stop_policy={"fixture": True},
            allow_partial_conditions=False,
        ),
        derived_from=derived,
    )


@pytest.mark.parametrize(
    ("path", "pairs", "attempts", "warmups"),
    (
        (PILOT, 20, 40, 0),
        (PRIMARY, 120, 248, 8),
        (SCALE, 5_000, 10_000, 0),
    ),
)
def test_exact_profile_expansion_counts_and_stable_ids(
    path: Path, pairs: int, attempts: int, warmups: int
) -> None:
    profile = load_execution_profile(path)
    first = expand_plan(profile, run_id="run-fixture")
    second = expand_plan(profile, run_id="run-fixture")
    assert first == second
    assert first.planned_pair_slots == pairs
    assert first.planned_non_retry_attempts == attempts
    assert sum(item.attempt_kind == "warmup" for item in first.attempts) == warmups
    assert len({item.attempt_id for item in first.attempts}) == attempts
    assert first.plan_sha256 == second.plan_sha256

    pair_members: dict[str, set[str]] = {}
    for item in first.attempts:
        if item.pair_id is not None:
            pair_members.setdefault(item.pair_id, set()).add(item.arm)
    assert set(map(frozenset, pair_members.values())) == {frozenset({"baseline", "xir"})}


def test_primary_warmups_precede_designated_attempts_and_seed_interleaves_pairs() -> None:
    profile = load_execution_profile(PRIMARY)
    plan = expand_plan(profile, run_id="run-primary")
    assert all(item.attempt_kind == "warmup" for item in plan.attempts[:8])
    assert all(item.attempt_kind == "primary" for item in plan.attempts[8:])
    first_20 = plan.attempts[8:28]
    assert {item.condition for item in first_20} != {"HH"}
    assert {item.arm for item in first_20} == {"baseline", "xir"}

    changed = replace(profile, fixed_seed="00" * 32)
    changed_plan = expand_plan(changed, run_id="run-primary")
    assert [item.attempt_id for item in changed_plan.attempts] != [
        item.attempt_id for item in plan.attempts
    ]
    assert changed_plan.plan_sha256 != plan.plan_sha256


def test_bounded_scheduler_preserves_order_batches_inflight_and_pair_isolation() -> None:
    plan = expand_plan(_live(load_execution_profile(PILOT)), run_id="run-live")
    scheduler = BoundedScheduler(plan)
    claimed: list[str] = []
    while not scheduler.complete:
        wave = []
        while True:
            item = scheduler.claim_next()
            if item is None:
                break
            wave.append(item)
            claimed.append(item.attempt_id)
            assert len(scheduler.active_attempt_ids) <= 2
        assert wave or scheduler.active_attempt_ids
        assert len({item.batch_index for item in wave}) <= 1
        assert len({item.pair_id for item in wave}) == len(wave)
        for attempt_id in tuple(scheduler.active_attempt_ids):
            scheduler.complete_attempt(attempt_id)
    assert claimed == [item.attempt_id for item in plan.attempts]


def test_template_plan_cannot_dispatch_and_unplanned_attempt_is_rejected() -> None:
    plan = expand_plan(load_execution_profile(PILOT), run_id="run-template")
    with pytest.raises(ScheduleError, match="Template|template"):
        BoundedScheduler(plan)

    live = BoundedScheduler(
        expand_plan(_live(load_execution_profile(PILOT)), run_id="run-live")
    )
    with pytest.raises(ScheduleError, match="unplanned replacement"):
        live.assert_registered("attempt-invented")


def test_retry_keeps_original_pair_and_does_not_create_replacement_slot() -> None:
    plan = expand_plan(_live(load_execution_profile(PILOT)), run_id="run-live")
    scheduler = BoundedScheduler(plan)
    prior = plan.attempts[0]
    retry = scheduler.register_retry(prior_attempt_id=prior.attempt_id, retry_index=1)
    assert retry.attempt_kind == "retry"
    assert retry.retry_of == prior.attempt_id
    assert retry.pair_id == prior.pair_id
    assert retry.pair_slot_index == prior.pair_slot_index
    assert plan.planned_pair_slots == 20
    scheduler.assert_registered(retry.attempt_id)
    with pytest.raises(ScheduleError, match="already registered"):
        scheduler.register_retry(prior_attempt_id=prior.attempt_id, retry_index=1)
    with pytest.raises(ScheduleError, match="exceeds"):
        scheduler.register_retry(prior_attempt_id=prior.attempt_id, retry_index=2)
