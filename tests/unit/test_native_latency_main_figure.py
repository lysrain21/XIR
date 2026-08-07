from __future__ import annotations

from pathlib import Path

from xir_lab.native.latency_main_figure import (
    ROUTE_ORDER,
    build_two_rebuild_publication,
    load_frozen_rows,
)


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def test_main_figure_selects_only_frozen_full_sample_medians() -> None:
    repository = _repository()
    rows, provenance, method = load_frozen_rows(
        repository_root=repository,
        latency_publication=repository / "experiment-results/native-latency-v2/publication",
        sensitivity_publication=repository
        / "experiment-results/native-latency-v2-block-sensitivity/publication",
    )
    assert tuple(row["route"] for row in rows) == ROUTE_ORDER
    assert [row["estimate_seconds"] for row in rows] == [
        7.102612376213074,
        5.158843994140625,
        10.954938292503357,
        10.918485760688782,
    ]
    assert sum(row["included_attempts"] for row in rows) == 40_000
    assert all(row["excluded_attempts"] == 0 for row in rows)
    assert method["statistics_recomputed"] is False
    assert method["block_length_sensitivity"] == [32, 64, 128]
    assert provenance["figure_1_sha256"] == (
        "2fa2864efe9f44357cf9e529fee7ee49415bee15410c9d54cd6ac0cd909a64a2"
    )


def test_main_figure_two_rebuilds_are_byte_identical(tmp_path: Path) -> None:
    repository = _repository()
    result = build_two_rebuild_publication(
        repository_root=repository,
        latency_publication=repository / "experiment-results/native-latency-v2/publication",
        sensitivity_publication=repository
        / "experiment-results/native-latency-v2-block-sensitivity/publication",
        output_root=tmp_path / "figure",
    )
    publication = Path(result["publication"])
    assert result["valid"] is True
    assert (publication / "latency-summary.pdf").is_file()
    assert (publication / "latency-summary.svg").is_file()
    assert (publication / "latency-summary-source.csv").is_file()
    assert (publication / "latency-summary-source.json").is_file()
    assert (publication / "visual-audit.json").is_file()
    assert (publication / "manifest.json").is_file()
