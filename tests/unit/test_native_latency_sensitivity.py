from __future__ import annotations

from xir_lab.native.latency_sensitivity import block_median_interval


def test_block_median_interval_is_deterministic() -> None:
    values = [float(index) for index in range(1, 65)]
    first = block_median_interval(
        values,
        block_length=8,
        repetitions=100,
        confidence_level=0.95,
        seed=17,
    )
    second = block_median_interval(
        values,
        block_length=8,
        repetitions=100,
        confidence_level=0.95,
        seed=17,
    )
    assert first == second
    assert first["attempts"] == 64
    assert first["estimate"] == 32.5
