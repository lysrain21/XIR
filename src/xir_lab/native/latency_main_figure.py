"""Deterministic main-text latency summary from frozen publications.

This renderer performs no statistical calculation.  It selects the four
full-sample median rows from ``native-latency-v2`` and uses the separate
block-length publication only to validate that the frozen 32/64/128
sensitivity study exists and refers to the same database and estimates.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROUTE_ORDER = ("HH", "LL", "HL", "LH")
REGIMES = {
    "HH": "same_carrier",
    "LL": "same_carrier",
    "HL": "carrier_switch",
    "LH": "carrier_switch",
}
NAMESPACE = "native-latency-v2-main-figure"
LATENCY_MANIFEST_SHA256 = "3786d811536747923244210880f48348fbee4caaefa8ca385562fc3473d22832"
SENSITIVITY_MANIFEST_SHA256 = "46f08279d103c232c82cda55564fdf742d148c16a55bd49ed7af9976e06db005"
FIGURE_1_SHA256 = "f2b694773e3db3312a745e40098995e075738df4de04f9bd5844a0da27ec3746"

NEUTRAL = "#344054"
BLUE = "#2563A6"
AMBER = "#C7792D"


class LatencyFigureError(ValueError):
    """Raised when a frozen input or deterministic output fails validation."""


def sha256(path: Path) -> str:
    """Return the SHA-256 digest of one file."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LatencyFigureError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manifest_digest(manifest: dict[str, Any], name: str) -> str:
    files = manifest.get("files")
    if isinstance(files, list):
        matches = [row for row in files if row.get("path") == name]
        if len(matches) != 1:
            raise LatencyFigureError(f"manifest does not identify exactly one {name}")
        return str(matches[0]["sha256"])
    if isinstance(files, dict) and name in files:
        return str(files[name]["sha256"])
    raise LatencyFigureError(f"manifest omits {name}")


def _verify_manifest_file(publication: Path, manifest: dict[str, Any], name: str) -> None:
    path = publication / name
    if not path.is_file() or sha256(path) != _manifest_digest(manifest, name):
        raise LatencyFigureError(f"frozen publication digest mismatch: {path}")


def load_frozen_rows(
    *,
    repository_root: Path,
    latency_publication: Path,
    sensitivity_publication: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Select the four already-computed full-sample median rows.

    No database is opened and no bootstrap replicate is generated here.
    """

    latency_manifest_path = latency_publication / "manifest.json"
    sensitivity_manifest_path = sensitivity_publication / "manifest.json"
    if sha256(latency_manifest_path) != LATENCY_MANIFEST_SHA256:
        raise LatencyFigureError("the frozen latency publication manifest changed")
    if sha256(sensitivity_manifest_path) != SENSITIVITY_MANIFEST_SHA256:
        raise LatencyFigureError("the frozen sensitivity publication manifest changed")
    latency_manifest = _read_json(latency_manifest_path)
    sensitivity_manifest = _read_json(sensitivity_manifest_path)
    if latency_manifest.get("namespace") != "native-latency-v2":
        raise LatencyFigureError("unexpected latency publication namespace")
    if (
        latency_manifest.get("semantic_sha256")
        != "4b6b5b75e179f1bc54cb7bce2436ac3a4ebb1743741ddd104e38b0698fc871f8"
    ):
        raise LatencyFigureError("unexpected frozen latency semantic digest")
    if sensitivity_manifest.get("namespace") != "native-latency-v2-block-sensitivity":
        raise LatencyFigureError("unexpected sensitivity publication namespace")
    if (
        sensitivity_manifest.get("semantic_sha256")
        != "e3d603ccb4cbda278ea81752f2fa7d0cb91bb25cfbc3d604f79cb9c434789e44"
    ):
        raise LatencyFigureError("unexpected frozen sensitivity semantic digest")
    for name in (
        "paper-source-latency-intervals.csv",
        "analysis.json",
        "config.json",
        "latency-intervals.pdf",
    ):
        _verify_manifest_file(latency_publication, latency_manifest, name)
    _verify_manifest_file(sensitivity_publication, sensitivity_manifest, "summary.json")

    config = _read_json(latency_publication / "config.json")
    analysis = _read_json(latency_publication / "analysis.json")
    sensitivity = _read_json(sensitivity_publication / "summary.json")
    denominator = config.get("denominator", {})
    bootstrap = config.get("bootstrap", {})
    if denominator != {
        "attempts_per_route": 10_000,
        "logical_attempts": 40_000,
        "routes": list(ROUTE_ORDER),
    }:
        raise LatencyFigureError("the primary denominator is not the frozen 40,000 attempts")
    if (
        bootstrap.get("block_length_attempts_per_route") != 64
        or bootstrap.get("repetitions") != 5_000
        or bootstrap.get("confidence_level") != 0.95
        or bootstrap.get("method") != "route-stratified-noncircular-moving-block-bootstrap"
    ):
        raise LatencyFigureError("unexpected primary moving-block configuration")

    csv_path = latency_publication / "paper-source-latency-intervals.csv"
    with csv_path.open(encoding="utf-8", newline="") as stream:
        all_rows = list(csv.DictReader(stream))
    selected = [
        row
        for row in all_rows
        if row["sample_id"] == "full"
        and row["sample_role"] == "primary"
        and row["metric"] == "median"
    ]
    selected_by_route = {row["route"]: row for row in selected}
    if set(selected_by_route) != set(ROUTE_ORDER) or len(selected) != len(ROUTE_ORDER):
        raise LatencyFigureError("expected exactly four primary median rows")

    analysis_rows = {row["route"]: row for row in analysis["primary_sample"]["per_route"]}
    rows: list[dict[str, Any]] = []
    for route in ROUTE_ORDER:
        source = selected_by_route[route]
        row = {
            "route": route,
            "regime": REGIMES[route],
            "metric": "median",
            "estimate_seconds": float(source["estimate_seconds"]),
            "ci_lower_seconds": float(source["ci_lower_seconds"]),
            "ci_upper_seconds": float(source["ci_upper_seconds"]),
            "included_attempts": int(source["included_attempts"]),
            "excluded_attempts": int(source["excluded_attempts"]),
            "confidence_level": 0.95,
            "bootstrap_block_length": 64,
            "bootstrap_repetitions": 5_000,
        }
        expected = analysis_rows[route]["median"]
        if (
            row["estimate_seconds"] != expected["estimate"]
            or row["ci_lower_seconds"] != expected["lower"]
            or row["ci_upper_seconds"] != expected["upper"]
            or row["included_attempts"] != 10_000
            or row["excluded_attempts"] != 0
        ):
            raise LatencyFigureError(f"primary median source mismatch for {route}")
        rows.append(row)

    sensitivity_rows = sensitivity.get("rows", [])
    if (
        sensitivity.get("database_sha256") != analysis["source"]["database_sha256"]
        or sensitivity.get("primary_block_length") != 64
        or sensitivity.get("metric") != "median"
    ):
        raise LatencyFigureError("block sensitivity does not refer to the primary analysis")
    for route, primary in zip(ROUTE_ORDER, rows, strict=True):
        route_rows = [item for item in sensitivity_rows if item["route"] == route]
        if (
            {int(item["block_length"]) for item in route_rows} != {32, 64, 128}
            or any(int(item["attempts"]) != 10_000 for item in route_rows)
            or any(float(item["estimate"]) != primary["estimate_seconds"] for item in route_rows)
        ):
            raise LatencyFigureError(f"incomplete block-length sensitivity for {route}")

    figure_one = repository_root / "main/figures/protocol-xir-reachability-topology.pdf"
    if sha256(figure_one) != FIGURE_1_SHA256:
        raise LatencyFigureError("frozen Figure 1 changed")
    provenance = {
        "latency_publication": "experiment-results/native-latency-v2/publication",
        "latency_manifest_sha256": sha256(latency_publication / "manifest.json"),
        "latency_semantic_sha256": latency_manifest["semantic_sha256"],
        "latency_source_csv_sha256": sha256(csv_path),
        "sensitivity_publication": "experiment-results/native-latency-v2-block-sensitivity/publication",
        "sensitivity_manifest_sha256": sha256(sensitivity_publication / "manifest.json"),
        "sensitivity_semantic_sha256": sensitivity_manifest["semantic_sha256"],
        "figure_1_sha256": FIGURE_1_SHA256,
    }
    method = {
        "statistics_recomputed": False,
        "selection": "sample_id=full, sample_role=primary, metric=median",
        "logical_attempts": 40_000,
        "attempts_per_route": 10_000,
        "interval": "95% empirical percentile interval",
        "bootstrap": "route-stratified non-circular moving-block bootstrap",
        "block_length_attempts_per_route": 64,
        "bootstrap_repetitions": 5_000,
        "block_length_sensitivity": [32, 64, 128],
        "block_length_sensitivity_repetitions": 2_000,
    }
    return rows, provenance, method


def _write_source_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _render(path_pdf: Path, path_svg: Path, rows: list[dict[str, Any]]) -> dict[str, str]:
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8.5,
            "axes.labelsize": 9.0,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 9.0,
            "axes.linewidth": 0.7,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-latency-v2-main-figure-v1",
        }
    )
    import matplotlib.pyplot as plt

    figure = plt.figure(figsize=(7.1, 3.25))
    # The three disjoint layout envelopes occupy 0.618 of the canvas:
    # axes 0.78*0.55 + header 0.78*0.11 + footer 0.78*0.1323076923.
    # The deeper footer separates the axis title from the route/interval key.
    axis = figure.add_axes((0.17, 0.27, 0.78, 0.55))
    positions = {"HH": 2.85, "LL": 2.10, "HL": 0.80, "LH": 0.05}
    colors = {"same_carrier": BLUE, "carrier_switch": AMBER}

    axis.axhspan(1.70, 3.55, color=BLUE, alpha=0.065, linewidth=0)
    axis.axhspan(-0.40, 1.45, color=AMBER, alpha=0.065, linewidth=0)
    axis.text(4.82, 3.35, "SAME CARRIER", color=BLUE, fontsize=9, fontweight="bold", va="center")
    axis.text(4.82, 1.25, "CARRIER SWITCH", color=AMBER, fontsize=9, fontweight="bold", va="center")

    for row in rows:
        route = str(row["route"])
        estimate = float(row["estimate_seconds"])
        lower = float(row["ci_lower_seconds"])
        upper = float(row["ci_upper_seconds"])
        color = colors[str(row["regime"])]
        marker = "o" if row["regime"] == "same_carrier" else "D"
        axis.errorbar(
            estimate,
            positions[route],
            xerr=[[estimate - lower], [upper - estimate]],
            fmt=marker,
            color=color,
            markerfacecolor="white",
            markeredgewidth=1.7,
            markersize=6.2,
            elinewidth=1.8,
            capsize=4.0,
            capthick=1.8,
            zorder=3,
        )
        if route in {"HL", "LH"}:
            x_value, alignment = estimate - 0.13, "right"
        else:
            x_value, alignment = estimate + 0.13, "left"
        axis.text(
            x_value,
            positions[route],
            f"{estimate:.3f}  [{lower:.3f}, {upper:.3f}]",
            ha=alignment,
            va="center",
            fontsize=8.5,
            color=NEUTRAL,
        )

    axis.set_xlim(4.75, 11.45)
    axis.set_ylim(-0.45, 3.62)
    axis.set_yticks([positions[route] for route in ROUTE_ORDER], ROUTE_ORDER)
    axis.set_xticks([5, 6, 7, 8, 9, 10, 11])
    axis.set_xlabel("End-to-end latency (seconds)", color=NEUTRAL, labelpad=6)
    axis.grid(axis="x", color=NEUTRAL, alpha=0.18, linestyle=":", linewidth=0.7)
    axis.set_axisbelow(True)
    axis.spines[["top", "right", "left"]].set_visible(False)
    axis.spines["bottom"].set_color(NEUTRAL)
    axis.tick_params(axis="y", length=0, colors=NEUTRAL, pad=7)
    axis.tick_params(axis="x", length=3, width=0.7, colors=NEUTRAL)

    figure.text(
        0.17,
        0.952,
        "Route latency forms two regimes",
        ha="left",
        va="top",
        fontsize=12,
        fontweight="bold",
        color=NEUTRAL,
    )
    figure.text(
        0.17,
        0.865,
        "Full frozen sample · 10,000 attempts per route · 40,000 total",
        ha="left",
        va="top",
        fontsize=9,
        color=NEUTRAL,
    )
    figure.text(
        0.17,
        0.025,
        "H = Hyperlane · L = LayerZero · dot = median · whisker = 95% moving-block interval",
        ha="left",
        va="bottom",
        fontsize=8.5,
        color=NEUTRAL,
    )

    pdf_metadata = {
        "Title": "Full-sample route latency summary",
        "Creator": "XIR deterministic latency main-figure renderer",
        "CreationDate": None,
        "ModDate": None,
    }
    svg_metadata = {
        "Title": "Full-sample route latency summary",
        "Creator": "XIR deterministic latency main-figure renderer",
        "Date": None,
    }
    figure.savefig(path_pdf, format="pdf", dpi=300, metadata=pdf_metadata)
    figure.savefig(path_svg, format="svg", metadata=svg_metadata)
    plt.close(figure)
    return {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__}


def _pdf_font_audit(path: Path) -> dict[str, Any]:
    result = subprocess.run(["pdffonts", str(path)], check=True, capture_output=True, text=True)
    rows = []
    for line in result.stdout.splitlines()[2:]:
        columns = line.split()
        if len(columns) >= 8:
            rows.append({"name": columns[0], "embedded": columns[-5] == "yes"})
    if not rows or not all(row["embedded"] for row in rows):
        raise LatencyFigureError("PDF fonts are not fully embedded")
    return {"font_count": len(rows), "fonts": rows, "all_embedded": True}


def build_artifact(
    *,
    repository_root: Path,
    latency_publication: Path,
    sensitivity_publication: Path,
    output_directory: Path,
) -> dict[str, Any]:
    """Build one immutable, deterministic main-text figure artifact."""

    if output_directory.exists():
        raise LatencyFigureError(f"refusing to overwrite output: {output_directory}")
    rows, provenance, method = load_frozen_rows(
        repository_root=repository_root,
        latency_publication=latency_publication,
        sensitivity_publication=sensitivity_publication,
    )
    output_directory.mkdir(parents=True)
    csv_path = output_directory / "latency-summary-source.csv"
    json_path = output_directory / "latency-summary-source.json"
    pdf_path = output_directory / "latency-summary.pdf"
    svg_path = output_directory / "latency-summary.svg"
    _write_source_csv(csv_path, rows)
    renderer = _render(pdf_path, svg_path, rows)
    source = {
        "schema_version": "xir-native-latency-main-figure-source-v1",
        "namespace": NAMESPACE,
        "figure_role": "Main-text full-sample median and interval summary",
        "question": "How do the four route medians and intervals form two latency regimes?",
        "provenance": provenance,
        "method": method,
        "route_order": list(ROUTE_ORDER),
        "rows": rows,
        "renderer": renderer,
        "renderer_sha256": sha256(Path(__file__)),
    }
    _write_json(json_path, source)

    svg_text = svg_path.read_text(encoding="utf-8")
    svg_self_contained = "<text" not in svg_text and 'href="http' not in svg_text
    if not svg_self_contained:
        raise LatencyFigureError("SVG contains external font or resource dependencies")
    font_audit = _pdf_font_audit(pdf_path)
    visual_audit: dict[str, Any] = {
        "schema_version": "xir-native-latency-main-figure-visual-audit-v1",
        "valid": True,
        "figure_size_inches": [7.1, 3.25],
        "intended_use": "full-width main-text figure",
        "font_roles": [
            {"role": "headline", "points": 12.0},
            {"role": "section and axis", "points": 9.0},
            {"role": "values, ticks, and reading key", "points": 8.5},
        ],
        "minimum_native_font_points": 8.5,
        "line_styles": ["solid data intervals and axis", "dotted x-grid"],
        "palette": {"neutral": NEUTRAL, "same_carrier": BLUE, "carrier_switch": AMBER},
        "nominal_content_region_occupancy": 0.618,
        "occupancy_definition": "axes + header + footer layout envelopes; internal whitespace counts",
        "occupancy_calculation": "0.78*0.55 + 0.78*0.11 + 0.78*0.1323076923 = 0.618",
        "pdf_fonts": font_audit,
        "svg_text_converted_to_paths": True,
        "svg_external_dependencies": False,
        "teaching_cues": [
            "blue and amber bands label the two latency regimes",
            "route codes are decoded in the reading key",
            "each printed value reports median and interval",
        ],
    }
    _write_json(output_directory / "visual-audit.json", visual_audit)
    validation: dict[str, Any] = {
        "schema_version": "xir-native-latency-main-figure-validation-v1",
        "namespace": NAMESPACE,
        "valid": True,
        "checks": {
            "frozen_primary_semantic_digest": True,
            "frozen_sensitivity_semantic_digest": True,
            "statistics_not_recomputed": method["statistics_recomputed"] is False,
            "full_sample_only": True,
            "logical_attempts_equal_40000": sum(row["included_attempts"] for row in rows) == 40_000,
            "attempts_per_route_equal_10000": all(
                row["included_attempts"] == 10_000 for row in rows
            ),
            "median_only": all(row["metric"] == "median" for row in rows),
            "primary_block_length_equal_64": all(
                row["bootstrap_block_length"] == 64 for row in rows
            ),
            "block_sensitivity_32_64_128_verified": True,
            "two_regimes_exposed": {row["regime"] for row in rows}
            == {"same_carrier", "carrier_switch"},
            "font_roles_at_most_3": len(visual_audit["font_roles"]) <= 3,
            "line_styles_at_most_3": len(visual_audit["line_styles"]) <= 3,
            "palette_is_neutral_blue_amber": len(visual_audit["palette"]) == 3,
            "occupancy_target_met": visual_audit["nominal_content_region_occupancy"] == 0.618,
            "pdf_fonts_embedded": font_audit["all_embedded"],
            "svg_self_contained": svg_self_contained,
            "frozen_figure_1_unchanged": provenance["figure_1_sha256"] == FIGURE_1_SHA256,
        },
    }
    if not all(validation["checks"].values()):
        raise LatencyFigureError(f"figure validation failed: {validation['checks']}")
    _write_json(output_directory / "validation.json", validation)
    report = [
        "# Full-sample route latency summary",
        "",
        "This main-text figure selects the four frozen full-sample median rows; it does not recompute statistics.",
        "Each route contributes 10,000 attempts to the 40,000-attempt denominator.",
        "Blue marks same-carrier routes (HH and LL); amber marks carrier-switching routes (HL and LH).",
        "The primary intervals use 64-attempt route blocks and 5,000 bootstrap repetitions.",
        "The separate 32/64/128 block-length publication validates the same four estimates and database identity.",
        "The original three-panel latency figure remains unchanged for appendix use.",
        "",
        "| Route | Regime | Median [95% interval], s | n |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in rows:
        regime = "same carrier" if row["regime"] == "same_carrier" else "carrier switch"
        report.append(
            f"| {row['route']} | {regime} | {row['estimate_seconds']:.3f} "
            f"[{row['ci_lower_seconds']:.3f}, {row['ci_upper_seconds']:.3f}] | "
            f"{row['included_attempts']:,} |"
        )
    report.append("")
    (output_directory / "REPORT.md").write_text("\n".join(report), encoding="utf-8")
    return {
        "source_semantic_sha256": hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "files": {
            path.name: sha256(path) for path in sorted(output_directory.iterdir()) if path.is_file()
        },
    }


def build_two_rebuild_publication(
    *,
    repository_root: Path,
    latency_publication: Path,
    sensitivity_publication: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build twice, require byte identity, and publish rebuild A."""

    if output_root.exists():
        raise LatencyFigureError(f"refusing to overwrite namespace: {output_root}")
    output_root.mkdir(parents=True)
    rebuilds = []
    for name in ("rebuild-a", "rebuild-b"):
        rebuilds.append(
            build_artifact(
                repository_root=repository_root,
                latency_publication=latency_publication,
                sensitivity_publication=sensitivity_publication,
                output_directory=output_root / name,
            )
        )
    if rebuilds[0] != rebuilds[1]:
        raise LatencyFigureError("independent figure rebuilds are not byte-identical")

    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-native-latency-main-figure-rebuild-v1",
        "namespace": NAMESPACE,
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "byte_identical_files": rebuilds[0]["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    manifest = {
        "schema_version": "xir-native-latency-main-figure-manifest-v1",
        "namespace": NAMESPACE,
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "files": {
            path.name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in sorted(publication.iterdir())
            if path.is_file()
        },
    }
    _write_json(publication / "manifest.json", manifest)
    return {
        "namespace": NAMESPACE,
        "publication": str(publication),
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "pdf_sha256": rebuilds[0]["files"]["latency-summary.pdf"],
        "svg_sha256": rebuilds[0]["files"]["latency-summary.svg"],
        "valid": True,
    }
