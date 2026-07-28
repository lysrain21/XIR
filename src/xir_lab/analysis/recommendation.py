"""Non-authorizing pilot recommendation derived only from frozen evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

import rfc8785

Recommendation = Literal["go", "revise", "stop"]


class RecommendationError(ValueError):
    """Raised when recommendation inputs are incomplete or ambiguous."""


@dataclass(frozen=True)
class PilotRecommendationInputs:
    run_id: str
    freeze_sha256: str
    reconciliation_valid: bool
    invariants_valid: bool
    pending_backfill: int
    first_rebuild_sha256: str
    second_rebuild_sha256: str
    eligible_pairs_by_condition: dict[str, int]
    minimum_eligible_pairs_per_condition: int
    hard_stop_triggered: bool
    unresolved_limitations: tuple[str, ...]


def build_pilot_recommendation(
    inputs: PilotRecommendationInputs,
) -> tuple[dict[str, Any], str]:
    for digest, label in (
        (inputs.freeze_sha256, "freeze"),
        (inputs.first_rebuild_sha256, "first rebuild"),
        (inputs.second_rebuild_sha256, "second rebuild"),
    ):
        if len(digest) != 64:
            raise RecommendationError(f"{label} digest is invalid")
    if (
        not inputs.run_id
        or inputs.pending_backfill < 0
        or inputs.minimum_eligible_pairs_per_condition < 1
        or set(inputs.eligible_pairs_by_condition) != {"HH", "HL", "LH", "LL"}
        or any(value < 0 or value > 5 for value in inputs.eligible_pairs_by_condition.values())
    ):
        raise RecommendationError("pilot recommendation scope is invalid")
    reasons: list[str] = []
    if not inputs.reconciliation_valid:
        reasons.append("reconciliation_invalid")
    if not inputs.invariants_valid:
        reasons.append("invariants_invalid")
    if inputs.pending_backfill:
        reasons.append("pending_backfill")
    if inputs.first_rebuild_sha256 != inputs.second_rebuild_sha256:
        reasons.append("offline_rebuild_mismatch")
    if inputs.hard_stop_triggered:
        reasons.append("hard_stop_triggered")
    if reasons:
        recommendation: Recommendation = "stop"
    else:
        low_coverage = any(
            value < inputs.minimum_eligible_pairs_per_condition
            for value in inputs.eligible_pairs_by_condition.values()
        )
        if low_coverage:
            reasons.append("eligible_pair_coverage_below_threshold")
        if inputs.unresolved_limitations:
            reasons.append("unresolved_limitations")
        recommendation = "revise" if reasons else "go"
    document: dict[str, Any] = {
        "schema_version": "xir-lab-pilot-recommendation-v1",
        "run_id": inputs.run_id,
        "freeze_sha256": inputs.freeze_sha256,
        "recommendation": recommendation,
        "reason_codes": reasons or ["pilot_evidence_gates_passed"],
        "eligible_pairs_by_condition": inputs.eligible_pairs_by_condition,
        "minimum_eligible_pairs_per_condition": (
            inputs.minimum_eligible_pairs_per_condition
        ),
        "unresolved_limitations": list(inputs.unresolved_limitations),
        "authority": {
            "authorizes_primary": False,
            "authorizes_scale": False,
            "authorizes_any_public_write": False,
            "new_openspec_change_required": True,
            "fresh_approval_required": True,
        },
    }
    raw = rfc8785.dumps(document)
    return document, hashlib.sha256(raw).hexdigest()
