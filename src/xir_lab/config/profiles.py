"""Execution profile loader with template/live safety gates."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema

ProfileMode = Literal["template", "live"]
ProfileKind = Literal["pilot", "primary", "scale"]


class ProfileError(ValueError):
    """Raised when execution counts or live limits are unsafe or ambiguous."""


@dataclass(frozen=True)
class ProfileCounts:
    pair_slots_per_condition: int
    planned_pair_slots: int
    designated_attempt_kind: str
    planned_designated_attempts: int
    warmups_per_condition_arm: int
    planned_warmup_attempts: int
    planned_total_non_retry_attempts: int
    retry_attempts_in_designated_count: bool


@dataclass(frozen=True)
class LiveLimits:
    max_retries_per_lineage: int | None
    max_batch_attempts: int | None
    max_duration_seconds: int | None
    max_in_flight_attempts: int | None
    chain_budget_wei: dict[str, int | None]
    stop_policy: dict[str, Any] | None
    allow_partial_conditions: bool | None


@dataclass(frozen=True)
class Derivation:
    kind: str
    run_id: str | None
    freeze_sha256: str | None
    reconciled: bool | None


@dataclass(frozen=True)
class ExecutionProfile:
    profile_id: str
    profile_version: int
    profile_mode: ProfileMode
    profile_kind: ProfileKind
    approval_operation_type: ProfileKind
    fixed_seed: str
    conditions: tuple[str, ...]
    counts: ProfileCounts
    live_limits: LiveLimits
    derived_from: Derivation

    @property
    def executable(self) -> bool:
        return self.profile_mode == "live"


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / "execution-profile-v1.schema.json"


def _validate_schema(document: dict[str, Any]) -> None:
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ProfileError(f"schema validation failed at {location}: {first.message}")


def _validate_counts(profile: ExecutionProfile) -> None:
    counts = profile.counts
    expected: dict[ProfileKind, tuple[int, int, str, int, int, int, int]] = {
        "pilot": (5, 20, "pilot", 40, 0, 0, 40),
        "primary": (30, 120, "primary", 240, 1, 8, 248),
        "scale": (1250, 5000, "primary", 10000, 0, 0, 10000),
    }
    observed = (
        counts.pair_slots_per_condition,
        counts.planned_pair_slots,
        counts.designated_attempt_kind,
        counts.planned_designated_attempts,
        counts.warmups_per_condition_arm,
        counts.planned_warmup_attempts,
        counts.planned_total_non_retry_attempts,
        counts.retry_attempts_in_designated_count,
    )
    expected_with_retry_rule = expected[profile.profile_kind] + (False,)
    if observed != expected_with_retry_rule:
        raise ProfileError(
            f"count identity does not match {profile.profile_kind} profile: {observed}"
        )
    if profile.approval_operation_type != profile.profile_kind:
        raise ProfileError("profile requires its own operation-typed approval")


def _validate_mode(profile: ExecutionProfile) -> None:
    limits = profile.live_limits
    scalar_limits = (
        limits.max_retries_per_lineage,
        limits.max_batch_attempts,
        limits.max_duration_seconds,
        limits.max_in_flight_attempts,
    )
    budgets = tuple(limits.chain_budget_wei.values())
    if profile.profile_mode == "template":
        if any(value is not None for value in scalar_limits + budgets):
            raise ProfileError("template profile must retain null live-limit placeholders")
        if limits.stop_policy is not None or limits.allow_partial_conditions is not None:
            raise ProfileError("template profile must not be executable")
        if profile.profile_kind == "pilot":
            expected_derivation = ("none", None, None, None)
        elif profile.profile_kind == "primary":
            expected_derivation = ("pilot", None, None, None)
        else:
            expected_derivation = ("primary", None, None, None)
    else:
        if any(value is None for value in scalar_limits + budgets):
            raise ProfileError("live profile has unresolved limit placeholders")
        if limits.stop_policy is None or limits.allow_partial_conditions is None:
            raise ProfileError("live profile needs concrete stop and partial-condition policy")
        if profile.profile_kind == "pilot":
            expected_derivation = ("none", None, None, None)
        else:
            expected_kind = "pilot" if profile.profile_kind == "primary" else "primary"
            if (
                profile.derived_from.kind != expected_kind
                or profile.derived_from.run_id is None
                or profile.derived_from.freeze_sha256 is None
                or profile.derived_from.reconciled is not True
            ):
                raise ProfileError(
                    f"live {profile.profile_kind} profile requires a reconciled "
                    f"{expected_kind} freeze"
                )
            return

    observed_derivation = (
        profile.derived_from.kind,
        profile.derived_from.run_id,
        profile.derived_from.freeze_sha256,
        profile.derived_from.reconciled,
    )
    if observed_derivation != expected_derivation:
        raise ProfileError(
            f"invalid {profile.profile_mode} {profile.profile_kind} derivation"
        )


def load_execution_profile(path: Path) -> ExecutionProfile:
    """Load a profile and reject templates or counts that imply a different run."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot read execution profile: {path}") from exc
    if not isinstance(document, dict):
        raise ProfileError("execution profile root must be an object")
    _validate_schema(document)
    limits = cast(dict[str, Any], document["live_limits"])
    derivation = cast(dict[str, Any], document["derived_from"])
    profile = ExecutionProfile(
        profile_id=cast(str, document["profile_id"]),
        profile_version=cast(int, document["profile_version"]),
        profile_mode=cast(ProfileMode, document["profile_mode"]),
        profile_kind=cast(ProfileKind, document["profile_kind"]),
        approval_operation_type=cast(ProfileKind, document["approval_operation_type"]),
        fixed_seed=cast(str, document["fixed_seed"]),
        conditions=tuple(cast(list[str], document["conditions"])),
        counts=ProfileCounts(**cast(dict[str, Any], document["counts"])),
        live_limits=LiveLimits(
            max_retries_per_lineage=cast(int | None, limits["max_retries_per_lineage"]),
            max_batch_attempts=cast(int | None, limits["max_batch_attempts"]),
            max_duration_seconds=cast(int | None, limits["max_duration_seconds"]),
            max_in_flight_attempts=cast(
                int | None, limits["max_in_flight_attempts"]
            ),
            chain_budget_wei=cast(dict[str, int | None], limits["chain_budget_wei"]),
            stop_policy=cast(dict[str, Any] | None, limits["stop_policy"]),
            allow_partial_conditions=cast(
                bool | None, limits["allow_partial_conditions"]
            ),
        ),
        derived_from=Derivation(
            kind=cast(str, derivation["kind"]),
            run_id=cast(str | None, derivation["run_id"]),
            freeze_sha256=cast(str | None, derivation["freeze_sha256"]),
            reconciled=cast(bool | None, derivation["reconciled"]),
        ),
    )
    _validate_counts(profile)
    _validate_mode(profile)
    return profile
