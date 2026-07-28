from __future__ import annotations

from dataclasses import replace

from xir_lab.analysis.recommendation import (
    PilotRecommendationInputs,
    build_pilot_recommendation,
)


def _inputs() -> PilotRecommendationInputs:
    return PilotRecommendationInputs(
        run_id="pilot-1",
        freeze_sha256="11" * 32,
        reconciliation_valid=True,
        invariants_valid=True,
        pending_backfill=0,
        first_rebuild_sha256="22" * 32,
        second_rebuild_sha256="22" * 32,
        eligible_pairs_by_condition={"HH": 5, "HL": 5, "LH": 5, "LL": 5},
        minimum_eligible_pairs_per_condition=3,
        hard_stop_triggered=False,
        unresolved_limitations=(),
    )


def test_go_is_machine_readable_but_cannot_authorize_followup_work() -> None:
    document, digest = build_pilot_recommendation(_inputs())
    assert document["recommendation"] == "go"
    assert set(document["authority"].values()) == {False, True}
    assert document["authority"]["authorizes_primary"] is False
    assert document["authority"]["authorizes_scale"] is False
    assert document["authority"]["new_openspec_change_required"] is True
    assert len(digest) == 64


def test_coverage_or_limitations_revise_and_evidence_failure_stops() -> None:
    revise, _ = build_pilot_recommendation(
        replace(
            _inputs(),
            eligible_pairs_by_condition={"HH": 5, "HL": 2, "LH": 5, "LL": 5},
        )
    )
    assert revise["recommendation"] == "revise"

    stop, _ = build_pilot_recommendation(
        replace(_inputs(), second_rebuild_sha256="33" * 32)
    )
    assert stop["recommendation"] == "stop"
    assert "offline_rebuild_mismatch" in stop["reason_codes"]
