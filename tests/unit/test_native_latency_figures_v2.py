from __future__ import annotations

import json
from pathlib import Path

from xir_lab.native.latency_figures_v2 import (
    APPENDIX_NAMESPACE,
    MAIN_NAMESPACE,
    build_two_rebuild_publication,
    load_exact_table_rows,
)


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def _inputs() -> dict[str, Path]:
    repository = _repository()
    return {
        "repository_root": repository,
        "latency_publication": repository / "experiment-results/native-latency-v2/publication",
        "sensitivity_publication": repository
        / "experiment-results/native-latency-v2-block-sensitivity/publication",
    }


def test_exact_rows_preserve_both_frozen_samples() -> None:
    main, exact, provenance, method = load_exact_table_rows(**_inputs())
    assert len(main) == 4
    assert len(exact) == 24
    assert {row["metric"] for row in exact} == {"median", "p95", "p99"}
    assert {row["sample_id"] for row in exact} == {"full", "clean-prefix"}
    assert (
        sum(
            row["included_attempts"]
            for row in exact
            if row["sample_id"] == "full" and row["metric"] == "median"
        )
        == 40_000
    )
    assert (
        sum(
            row["included_attempts"]
            for row in exact
            if row["sample_id"] == "clean-prefix" and row["metric"] == "median"
        )
        == 14_616
    )
    assert method["statistics_recomputed"] is False
    assert provenance["preserved_assets"]["frozen_figure_1"].startswith("2fa2864e")


def test_native_width_main_publication_is_deterministic(tmp_path: Path) -> None:
    result = build_two_rebuild_publication(**_inputs(), output_root=tmp_path / "main", kind="main")
    publication = Path(result["publication"])
    audit = json.loads((publication / "visual-audit.json").read_text(encoding="utf-8"))
    assert result["namespace"] == MAIN_NAMESPACE
    assert audit["native_width_mm"] == 131.6
    assert audit["minimum_key_font_points"] >= 7.0
    assert audit["pdf"]["all_fonts_embedded"] is True
    assert (publication / "latency-summary-v2.pdf").is_file()


def test_native_width_appendix_publication_is_deterministic(tmp_path: Path) -> None:
    result = build_two_rebuild_publication(
        **_inputs(), output_root=tmp_path / "appendix", kind="appendix"
    )
    publication = Path(result["publication"])
    source = json.loads(
        (publication / "latency-comparison-v1-source.json").read_text(encoding="utf-8")
    )
    validation = json.loads((publication / "validation.json").read_text(encoding="utf-8"))
    assert result["namespace"] == APPENDIX_NAMESPACE
    assert len(source["rows"]) == 24
    assert "visualizes" not in source["caption_suggestion"].lower()
    assert source["visual_encoding"]["color"] == {
        "same_carrier": "#2563A6",
        "carrier_switch": "#C7792D",
    }
    assert source["visual_encoding"]["marker_fill"] == {
        "full": "filled",
        "clean-prefix": "open",
    }
    assert validation["checks"]["color_encodes_regime_only"] is True
    assert validation["checks"]["fill_encodes_sample_only"] is True
    assert (publication / "latency-comparison-v1.pdf").is_file()
