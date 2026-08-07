import hashlib
import json
import random
from pathlib import Path

from xir_lab.native.latency_v2 import (
    AttemptLatency,
    accepted_analysis_semantic_valid,
    bootstrap_latency,
    boundary_is_first_documented,
    clean_prefix,
    derive_seed,
    figure_source_rows,
    moving_block_resample,
    nearest_rank,
    semantic_digest,
    validate_json,
)


def _attempt(route: str, sequence: int, finished_at: float) -> AttemptLatency:
    return AttemptLatency(
        attempt_id=f"{route}-{sequence}",
        route=route,
        route_sequence=sequence,
        started_at=finished_at - 1,
        finished_at=finished_at,
    )


def test_nearest_rank_matches_frozen_native_analysis_definition() -> None:
    values = [float(number) for number in range(1, 101)]

    assert nearest_rank(values, 0.50) == 50
    assert nearest_rank(values, 0.95) == 95
    assert nearest_rank(values, 0.99) == 99


def test_moving_block_resample_is_deterministic_and_contiguous() -> None:
    values = [float(number) for number in range(12)]

    sample_a = moving_block_resample(
        values,
        block_length=4,
        generator=random.Random(17),
    )
    sample_b = moving_block_resample(
        values,
        block_length=4,
        generator=random.Random(17),
    )

    assert sample_a == sample_b
    for offset in range(0, len(values), 4):
        block = sample_a[offset : offset + 4]
        assert all(right - left == 1 for left, right in zip(block, block[1:]))


def test_bootstrap_digest_and_intervals_are_reproducible() -> None:
    values = [float(number % 11) + number / 100 for number in range(128)]
    seed = derive_seed(2026080701, "full", "HH")

    first = bootstrap_latency(
        values,
        block_length=16,
        repetitions=40,
        confidence_level=0.95,
        seed=seed,
    )
    second = bootstrap_latency(
        values,
        block_length=16,
        repetitions=40,
        confidence_level=0.95,
        seed=seed,
    )

    assert first == second
    intervals, rows, digest = first
    assert len(rows) == 40
    assert len(digest) == 64
    assert set(intervals) == {"mean", "median", "p95", "p99"}


def test_clean_prefix_requires_every_matched_route_to_finish() -> None:
    attempts = [
        _attempt(route, sequence, 10 + sequence)
        for sequence in range(4)
        for route in ("HH", "LL", "HL", "LH")
    ]
    attempts.append(_attempt("HH", 4, 13.5))
    attempts.extend(_attempt(route, 4, 15.5) for route in ("LL", "HL", "LH"))

    selected, maximum_sequence = clean_prefix(attempts, boundary_epoch=15)

    assert maximum_sequence == 3
    assert len(selected) == 16
    assert {item.route_sequence for item in selected} == {0, 1, 2, 3}


def test_boundary_is_derived_from_earliest_documented_directory(
    tmp_path: Path,
) -> None:
    first = tmp_path / "20260731T034948Z-first"
    second = tmp_path / "20260731T041313Z-second"
    first.mkdir()
    second.mkdir()
    (first / "event.json").write_text("{}\n", encoding="utf-8")
    (second / "event.json").write_text("{}\n", encoding="utf-8")

    assert boundary_is_first_documented(
        first / "event.json",
        "2026-07-31T03:49:48Z",
    )
    assert not boundary_is_first_documented(
        second / "event.json",
        "2026-07-31T04:13:13Z",
    )


def test_accepted_analysis_semantic_digest_excludes_its_own_field() -> None:
    document = {"schema_version": "fixture", "value": [1, 2, 3]}
    document["semantic_sha256"] = semantic_digest(document)

    assert accepted_analysis_semantic_valid(document)
    document["value"] = [1, 2, 4]
    assert not accepted_analysis_semantic_valid(document)


def test_frozen_latency_config_passes_its_schema() -> None:
    repository = Path(__file__).resolve().parents[2]
    config_path = repository / "configs/native/native-latency-v2.json"
    schema_path = repository / "schemas/native-latency-v2-config.schema.json"
    before = hashlib.sha256(config_path.read_bytes()).hexdigest()
    config = json.loads(config_path.read_text(encoding="utf-8"))

    validate_json(config, schema_path)

    assert hashlib.sha256(config_path.read_bytes()).hexdigest() == before


def test_figure_source_has_one_row_per_sample_route_metric() -> None:
    interval = {"estimate": 1.0, "lower": 0.9, "upper": 1.1}
    samples = []
    for sample_id, role, included, excluded in (
        ("full", "primary", 10_000, 0),
        ("clean-prefix", "sensitivity", 3_654, 6_346),
    ):
        samples.append(
            {
                "sample_id": sample_id,
                "role": role,
                "per_route": [
                    {
                        "route": route,
                        "included_attempts": included,
                        "excluded_attempts": excluded,
                        "median": interval,
                        "p95": interval,
                        "p99": interval,
                    }
                    for route in ("HH", "LL", "HL", "LH")
                ],
            }
        )
    rows = figure_source_rows({"primary_sample": samples[0], "sensitivity_sample": samples[1]})

    assert len(rows) == 24
    assert {(row["sample_id"], row["route"], row["metric"]) for row in rows} == {
        (sample_id, route, metric)
        for sample_id in ("full", "clean-prefix")
        for route in ("HH", "LL", "HL", "LH")
        for metric in ("median", "p95", "p99")
    }
