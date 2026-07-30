from xir_lab.native.analysis import _expected_cumulative_per_route


def test_phase_cumulative_denominators_are_explicit() -> None:
    profile = {
        "progression": {
            "smoke_attempts_per_route": 10,
            "rehearsal_attempts_per_route": 250,
            "scale_attempts_per_route": 10_000,
        }
    }
    assert _expected_cumulative_per_route(profile, "smoke") == 10
    assert _expected_cumulative_per_route(profile, "rehearsal") == 260
    assert _expected_cumulative_per_route(profile, "scale") == 10_260
