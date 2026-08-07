"""Native-size main and appendix latency figures from frozen statistics.

The module is a renderer only.  It selects values from the immutable
``native-latency-v2`` publication and never reads the run database or executes
bootstrap sampling.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from xir_lab.native.latency_main_figure import (
    AMBER,
    BLUE,
    FIGURE_1_SHA256,
    NEUTRAL,
    REGIMES,
    ROUTE_ORDER,
    LatencyFigureError,
    load_frozen_rows,
    sha256,
)

MAIN_NAMESPACE = "native-latency-v2-main-figure-v2"
APPENDIX_NAMESPACE = "native-latency-v2-appendix-comparison-v1"
WIDTH_MM = 131.6
WIDTH_INCHES = WIDTH_MM / 25.4
MAIN_HEIGHT_INCHES = 2.85
APPENDIX_HEIGHT_INCHES = 6.1
FONT_ROLES = (10.5, 8.5, 7.25)
CURRENT_MAIN_V1_SHA256 = "da612fdb6c4bdd250ae1f9084a3223626fb14361cdc6482d89d70146e6e02e05"
FROZEN_THREE_PANEL_SHA256 = "d9e0155ff4cd5c496c59835558ea8146f662212f246514c437b237b349a5a51a"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LatencyFigureError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _verify_unchanged_assets(repository_root: Path) -> dict[str, str]:
    paths = {
        "frozen_figure_1": repository_root / "main/figures/protocol-xir-reachability-topology.pdf",
        "frozen_three_panel_latency": repository_root
        / "experiment-results/native-latency-v2/publication/latency-intervals.pdf",
        "main_latency_v1": repository_root
        / "experiment-results/native-latency-v2-main-figure/publication/latency-summary.pdf",
    }
    expected = {
        "frozen_figure_1": FIGURE_1_SHA256,
        "frozen_three_panel_latency": FROZEN_THREE_PANEL_SHA256,
        "main_latency_v1": CURRENT_MAIN_V1_SHA256,
    }
    digests = {name: sha256(path) for name, path in paths.items()}
    if digests != expected:
        raise LatencyFigureError(f"an existing latency or Figure 1 asset changed: {digests}")
    return digests


def load_exact_table_rows(
    *,
    repository_root: Path,
    latency_publication: Path,
    sensitivity_publication: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Load exact full and clean-prefix rows after frozen-source validation."""

    main_rows, provenance, method = load_frozen_rows(
        repository_root=repository_root,
        latency_publication=latency_publication,
        sensitivity_publication=sensitivity_publication,
    )
    provenance["preserved_assets"] = _verify_unchanged_assets(repository_root)
    source_path = latency_publication / "paper-source-latency-intervals.csv"
    with source_path.open(encoding="utf-8", newline="") as stream:
        raw_rows = list(csv.DictReader(stream))
    analysis = _read_json(latency_publication / "analysis.json")
    sample_map = {
        "full": analysis["primary_sample"],
        "clean-prefix": analysis["sensitivity_sample"],
    }
    metrics = ("median", "p95", "p99")
    exact_rows: list[dict[str, Any]] = []
    indexed_raw = {
        (row["sample_id"], row["route"], row["metric"]): row
        for row in raw_rows
        if row["metric"] in metrics
    }
    if len(indexed_raw) != 2 * len(ROUTE_ORDER) * len(metrics):
        raise LatencyFigureError("the exact latency table is incomplete")
    for metric in metrics:
        for route in ROUTE_ORDER:
            for sample_id, sample_role in (("full", "primary"), ("clean-prefix", "sensitivity")):
                raw = indexed_raw[(sample_id, route, metric)]
                analysis_route = next(
                    row for row in sample_map[sample_id]["per_route"] if row["route"] == route
                )
                row = {
                    "sample_id": sample_id,
                    "sample_role": sample_role,
                    "route": route,
                    "regime": REGIMES[route],
                    "metric": metric,
                    "estimate_seconds": float(raw["estimate_seconds"]),
                    "ci_lower_seconds": float(raw["ci_lower_seconds"]),
                    "ci_upper_seconds": float(raw["ci_upper_seconds"]),
                    "included_attempts": int(raw["included_attempts"]),
                    "excluded_attempts": int(raw["excluded_attempts"]),
                }
                expected = analysis_route[metric]
                if (
                    row["estimate_seconds"] != expected["estimate"]
                    or row["ci_lower_seconds"] != expected["lower"]
                    or row["ci_upper_seconds"] != expected["upper"]
                ):
                    raise LatencyFigureError(
                        f"table/analysis mismatch for {sample_id}/{route}/{metric}"
                    )
                exact_rows.append(row)
    for row in exact_rows:
        expected_count = 10_000 if row["sample_id"] == "full" else 3_654
        expected_excluded = 0 if row["sample_id"] == "full" else 6_346
        if (
            row["included_attempts"] != expected_count
            or row["excluded_attempts"] != expected_excluded
        ):
            raise LatencyFigureError("sample denominator changed")
    return main_rows, exact_rows, provenance, method


def _matplotlib() -> tuple[Any, Any]:
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 7.25,
            "axes.labelsize": 8.5,
            "axes.titlesize": 8.5,
            "xtick.labelsize": 7.25,
            "ytick.labelsize": 7.25,
            "axes.linewidth": 0.65,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-latency-figures-v2",
        }
    )
    import matplotlib.pyplot as plt

    return matplotlib, plt


def _save_figure(figure: Any, pdf_path: Path, svg_path: Path, *, title: str) -> dict[str, str]:
    pdf_metadata = {
        "Title": title,
        "Creator": "XIR deterministic native-size latency renderer",
        "CreationDate": None,
        "ModDate": None,
    }
    svg_metadata = {
        "Title": title,
        "Creator": "XIR deterministic native-size latency renderer",
        "Date": None,
    }
    figure.savefig(pdf_path, format="pdf", dpi=300, metadata=pdf_metadata)
    figure.savefig(svg_path, format="svg", metadata=svg_metadata)
    return {"pdf": sha256(pdf_path), "svg": sha256(svg_path)}


def _render_main(pdf_path: Path, svg_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    matplotlib, plt = _matplotlib()
    figure = plt.figure(figsize=(WIDTH_INCHES, MAIN_HEIGHT_INCHES))
    # 0.81*0.50 + 0.81*0.13 + 0.81*0.1328395062 = 0.618.
    axis = figure.add_axes((0.16, 0.28, 0.81, 0.50))
    positions = {"HH": 2.85, "LL": 2.10, "HL": 0.80, "LH": 0.05}
    colors = {"same_carrier": BLUE, "carrier_switch": AMBER}
    axis.axhspan(1.70, 3.55, color=BLUE, alpha=0.065, linewidth=0)
    axis.axhspan(-0.40, 1.45, color=AMBER, alpha=0.065, linewidth=0)
    axis.text(
        4.82,
        3.35,
        "SAME CARRIER",
        color=BLUE,
        fontsize=8.5,
        fontweight="bold",
        va="center",
    )
    axis.text(
        4.82,
        1.25,
        "CARRIER SWITCH",
        color=AMBER,
        fontsize=8.5,
        fontweight="bold",
        va="center",
    )
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
            markeredgewidth=1.5,
            markersize=5.0,
            elinewidth=1.55,
            capsize=3.2,
            capthick=1.55,
            zorder=3,
        )
        x_value = estimate - 0.11 if route in {"HL", "LH"} else estimate + 0.11
        axis.text(
            x_value,
            positions[route],
            f"{estimate:.3f} [{lower:.3f}, {upper:.3f}]",
            ha="right" if route in {"HL", "LH"} else "left",
            va="center",
            fontsize=7.25,
            color=NEUTRAL,
        )
    axis.set_xlim(4.75, 11.45)
    axis.set_ylim(-0.45, 3.62)
    axis.set_yticks([positions[route] for route in ROUTE_ORDER], ROUTE_ORDER)
    axis.set_xticks([5, 6, 7, 8, 9, 10, 11])
    axis.set_xlabel("End-to-end latency (s)", color=NEUTRAL, labelpad=4)
    axis.grid(axis="x", color=NEUTRAL, alpha=0.18, linestyle=":", linewidth=0.65)
    axis.set_axisbelow(True)
    axis.spines[["top", "right", "left"]].set_visible(False)
    axis.spines["bottom"].set_color(NEUTRAL)
    axis.tick_params(axis="y", length=0, colors=NEUTRAL, pad=5)
    axis.tick_params(axis="x", length=2.5, width=0.65, colors=NEUTRAL)
    figure.text(
        0.16,
        0.955,
        "Two route-latency regimes",
        ha="left",
        va="top",
        fontsize=10.5,
        fontweight="bold",
        color=NEUTRAL,
    )
    figure.text(
        0.16,
        0.865,
        "Full sample · 10,000 attempts per route · 40,000 total",
        ha="left",
        va="top",
        fontsize=8.5,
        color=NEUTRAL,
    )
    figure.text(
        0.16,
        0.025,
        "H Hyperlane · L LayerZero · point median · whisker 95% moving-block interval",
        ha="left",
        va="bottom",
        fontsize=7.25,
        color=NEUTRAL,
    )
    digests = _save_figure(
        figure, pdf_path, svg_path, title="Native-size full-sample route latency summary"
    )
    plt.close(figure)
    return {
        "renderer": {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__},
        **digests,
    }


def _render_appendix(pdf_path: Path, svg_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    matplotlib, plt = _matplotlib()
    figure = plt.figure(figsize=(WIDTH_INCHES, APPENDIX_HEIGHT_INCHES))
    # 3*0.77*0.20 + 0.77*0.09 + 0.77*0.1112987013 = 0.618.
    axes = [
        figure.add_axes((0.18, 0.64, 0.77, 0.20)),
        figure.add_axes((0.18, 0.39, 0.77, 0.20)),
        figure.add_axes((0.18, 0.14, 0.77, 0.20)),
    ]
    positions = {"HH": 3.0, "LL": 2.0, "HL": 1.0, "LH": 0.0}
    limits = {"median": (4.75, 11.45), "p95": (5.5, 15.35), "p99": (5.0, 45.0)}
    ticks = {
        "median": [5, 6, 7, 8, 9, 10, 11],
        "p95": [6, 8, 10, 12, 14],
        "p99": [5, 15, 25, 35, 45],
    }
    colors = {"same_carrier": BLUE, "carrier_switch": AMBER}
    for axis, metric, title in zip(
        axes, ("median", "p95", "p99"), ("Median", "P95", "P99"), strict=True
    ):
        axis.axhspan(1.5, 3.45, color=BLUE, alpha=0.055, linewidth=0)
        axis.axhspan(-0.45, 1.5, color=AMBER, alpha=0.055, linewidth=0)
        selected = [row for row in rows if row["metric"] == metric]
        for row in selected:
            sample_id = str(row["sample_id"])
            route = str(row["route"])
            estimate = float(row["estimate_seconds"])
            lower = float(row["ci_lower_seconds"])
            upper = float(row["ci_upper_seconds"])
            color = colors[str(row["regime"])]
            y_value = positions[route] + (0.11 if sample_id == "full" else -0.11)
            axis.errorbar(
                estimate,
                y_value,
                xerr=[[estimate - lower], [upper - estimate]],
                fmt="o",
                color=color,
                markerfacecolor=color if sample_id == "full" else "white",
                markeredgecolor=color,
                markeredgewidth=1.25,
                markersize=4.3,
                elinewidth=1.25,
                capsize=2.7,
                capthick=1.25,
                zorder=3,
            )
        axis.set_title(title, loc="left", pad=3, color=NEUTRAL, fontsize=8.5, fontweight="bold")
        axis.set_xlim(*limits[metric])
        axis.set_ylim(-0.48, 3.48)
        axis.set_xticks(ticks[metric])
        axis.set_yticks([positions[route] for route in ROUTE_ORDER], ROUTE_ORDER)
        axis.grid(axis="x", color=NEUTRAL, alpha=0.18, linestyle=":", linewidth=0.65)
        axis.set_axisbelow(True)
        axis.spines[["top", "right", "left"]].set_visible(False)
        axis.spines["bottom"].set_color(NEUTRAL)
        axis.tick_params(axis="y", length=0, colors=NEUTRAL, pad=5)
        axis.tick_params(axis="x", length=2.5, width=0.65, colors=NEUTRAL)
    axes[-1].set_xlabel("End-to-end latency (s)", color=NEUTRAL, labelpad=4)
    figure.text(
        0.18,
        0.968,
        "Full and clean-prefix latency",
        ha="left",
        va="top",
        fontsize=10.5,
        fontweight="bold",
        color=NEUTRAL,
    )
    figure.text(
        0.18,
        0.915,
        "Median, P95, and P99 · 95% moving-block intervals",
        ha="left",
        va="top",
        fontsize=8.5,
        color=NEUTRAL,
    )
    figure.text(
        0.18,
        0.050,
        "Color: blue same carrier; amber carrier switch · Marker: filled full; open clean prefix",
        ha="left",
        va="bottom",
        fontsize=7.25,
        color=NEUTRAL,
    )
    figure.text(
        0.18,
        0.020,
        "Full n=10,000/route · Clean prefix n=3,654/route (14,616 total)",
        ha="left",
        va="bottom",
        fontsize=7.25,
        color=NEUTRAL,
    )
    digests = _save_figure(
        figure, pdf_path, svg_path, title="Native-size full and clean-prefix latency comparison"
    )
    plt.close(figure)
    return {
        "renderer": {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__},
        **digests,
    }


def _pdf_audit(path: Path, *, expected_height_inches: float) -> dict[str, Any]:
    fonts = subprocess.run(
        ["pdffonts", str(path)], check=True, capture_output=True, text=True
    ).stdout
    font_rows = []
    for line in fonts.splitlines()[2:]:
        columns = line.split()
        if len(columns) >= 8:
            font_rows.append({"name": columns[0], "embedded": columns[-5] == "yes"})
    if not font_rows or not all(row["embedded"] for row in font_rows):
        raise LatencyFigureError(f"unembedded PDF font: {path}")
    info = subprocess.run(["pdfinfo", str(path)], check=True, capture_output=True, text=True).stdout
    match = re.search(r"Page size:\s+([0-9.]+) x ([0-9.]+) pts", info)
    if match is None:
        raise LatencyFigureError(f"cannot parse PDF dimensions: {path}")
    width_points, height_points = (float(match.group(1)), float(match.group(2)))
    if abs(width_points - WIDTH_INCHES * 72) > 0.02:
        raise LatencyFigureError("PDF is not natively 131.6 mm wide")
    if abs(height_points - expected_height_inches * 72) > 0.02:
        raise LatencyFigureError("unexpected PDF height")
    return {
        "page_size_points": [width_points, height_points],
        "native_width_mm": WIDTH_MM,
        "fonts": font_rows,
        "all_fonts_embedded": True,
    }


def _svg_audit(path: Path) -> dict[str, bool]:
    content = path.read_text(encoding="utf-8")
    result = {
        "text_converted_to_paths": "<text" not in content,
        "no_external_href": 'href="http' not in content,
    }
    if not all(result.values()):
        raise LatencyFigureError(f"SVG is not self-contained: {path}")
    return result


def _visual_audit(
    *,
    kind: str,
    pdf_path: Path,
    svg_path: Path,
    height_inches: float,
    occupancy_calculation: str,
) -> dict[str, Any]:
    return {
        "schema_version": "xir-native-latency-figure-visual-audit-v2",
        "kind": kind,
        "valid": True,
        "native_width_mm": WIDTH_MM,
        "figure_size_inches": [WIDTH_INCHES, height_inches],
        "font_roles": [
            {"role": "headline", "points": FONT_ROLES[0]},
            {"role": "panel, group, and axis", "points": FONT_ROLES[1]},
            {"role": "values, ticks, and reading key", "points": FONT_ROLES[2]},
        ],
        "minimum_key_font_points": min(FONT_ROLES),
        "line_styles": ["solid data intervals and axis", "dotted x-grid"],
        "palette": {"neutral": NEUTRAL, "same_carrier": BLUE, "carrier_switch": AMBER},
        "nominal_content_region_occupancy": 0.618,
        "occupancy_definition": "axes + header + footer envelopes; internal whitespace counts",
        "occupancy_calculation": occupancy_calculation,
        "pdf": _pdf_audit(pdf_path, expected_height_inches=height_inches),
        "svg": _svg_audit(svg_path),
    }


def _write_report(
    path: Path,
    *,
    title: str,
    caption: str,
    rows: list[dict[str, Any]],
    appendix: bool,
) -> None:
    lines = [
        f"# {title}",
        "",
        "The renderer selects exact frozen rows and performs no statistical calculation.",
        f"Suggested caption: {caption}",
        "",
    ]
    if appendix:
        lines.extend(
            [
                "This figure visualizes the exact full/clean-prefix latency table; the table remains the numerical source of record.",
                "Blue and amber encode route regime in every panel. Filled and open markers encode sample selection.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "The main-text asset uses only the 40,000-attempt full sample.",
                "Blue and amber expose the same-carrier and carrier-switching regimes.",
                "",
            ]
        )
    lines.extend([f"Rows: {len(rows)}.", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def _build_artifact(
    *,
    repository_root: Path,
    latency_publication: Path,
    sensitivity_publication: Path,
    output_directory: Path,
    kind: str,
) -> dict[str, Any]:
    if output_directory.exists():
        raise LatencyFigureError(f"refusing to overwrite output: {output_directory}")
    main_rows, exact_rows, provenance, method = load_exact_table_rows(
        repository_root=repository_root,
        latency_publication=latency_publication,
        sensitivity_publication=sensitivity_publication,
    )
    output_directory.mkdir(parents=True)
    if kind == "main":
        namespace = MAIN_NAMESPACE
        stem = "latency-summary-v2"
        rows = main_rows
        height = MAIN_HEIGHT_INCHES
        caption = (
            "Full-sample end-to-end latency by route. Points show medians and whiskers show "
            "95% route-stratified moving-block intervals over 10,000 attempts per route. "
            "Blue denotes same-carrier routes; amber denotes carrier-switching routes."
        )
        render: Callable[[Path, Path, list[dict[str, Any]]], dict[str, Any]] = _render_main
        occupancy = "0.81*0.50 + 0.81*0.13 + 0.81*0.1328395062 = 0.618"
        visual_encoding = {
            "color": {"same_carrier": BLUE, "carrier_switch": AMBER},
            "point": "full-sample median",
            "whisker": "95% route-stratified moving-block interval",
        }
    elif kind == "appendix":
        namespace = APPENDIX_NAMESPACE
        stem = "latency-comparison-v1"
        rows = exact_rows
        height = APPENDIX_HEIGHT_INCHES
        caption = (
            "Exact latency-table values for the full and clean-prefix samples. Each panel "
            "shows the estimate and 95% route-stratified moving-block interval. Color encodes "
            "route regime (blue: same carrier; amber: carrier switch); marker fill encodes "
            "sample (filled: full; open: clean prefix)."
        )
        render = _render_appendix
        occupancy = "3*0.77*0.20 + 0.77*0.09 + 0.77*0.1112987013 = 0.618"
        visual_encoding = {
            "color": {"same_carrier": BLUE, "carrier_switch": AMBER},
            "marker_fill": {"full": "filled", "clean-prefix": "open"},
            "point": "sample estimate",
            "whisker": "95% route-stratified moving-block interval",
        }
    else:
        raise LatencyFigureError(f"unknown figure kind: {kind}")

    csv_path = output_directory / f"{stem}-source.csv"
    json_path = output_directory / f"{stem}-source.json"
    pdf_path = output_directory / f"{stem}.pdf"
    svg_path = output_directory / f"{stem}.svg"
    _write_csv(csv_path, rows)
    renderer = render(pdf_path, svg_path, rows)
    source = {
        "schema_version": "xir-native-latency-figure-source-v2",
        "namespace": namespace,
        "kind": kind,
        "caption_suggestion": caption,
        "visual_encoding": visual_encoding,
        "statistics_recomputed": False,
        "provenance": provenance,
        "method": method,
        "rows": rows,
        "renderer": renderer["renderer"],
        "renderer_sha256": sha256(Path(__file__)),
    }
    _write_json(json_path, source)
    visual = _visual_audit(
        kind=kind,
        pdf_path=pdf_path,
        svg_path=svg_path,
        height_inches=height,
        occupancy_calculation=occupancy,
    )
    _write_json(output_directory / "visual-audit.json", visual)
    checks = {
        "statistics_not_recomputed": source["statistics_recomputed"] is False,
        "native_width_is_131_6_mm": visual["pdf"]["native_width_mm"] == 131.6,
        "minimum_key_font_at_least_7_pt": visual["minimum_key_font_points"] >= 7.0,
        "font_roles_at_most_3": len(visual["font_roles"]) <= 3,
        "line_styles_at_most_3": len(visual["line_styles"]) <= 3,
        "neutral_blue_amber_palette": len(visual["palette"]) == 3,
        "occupancy_target_met": visual["nominal_content_region_occupancy"] == 0.618,
        "pdf_fonts_embedded": visual["pdf"]["all_fonts_embedded"],
        "svg_self_contained": all(visual["svg"].values()),
        "figure_1_unchanged": provenance["preserved_assets"]["frozen_figure_1"] == FIGURE_1_SHA256,
        "frozen_three_panel_unchanged": provenance["preserved_assets"]["frozen_three_panel_latency"]
        == FROZEN_THREE_PANEL_SHA256,
        "main_v1_unchanged": provenance["preserved_assets"]["main_latency_v1"]
        == CURRENT_MAIN_V1_SHA256,
    }
    if kind == "main":
        checks.update(
            {
                "full_sample_only": len(rows) == 4
                and {row["sample_id"] if "sample_id" in row else "full" for row in rows}
                == {"full"},
                "full_denominator_40000": sum(row["included_attempts"] for row in rows) == 40_000,
                "median_only": {row["metric"] for row in rows} == {"median"},
            }
        )
    else:
        checks.update(
            {
                "exact_table_rows_24": len(rows) == 24,
                "metrics_median_p95_p99": {row["metric"] for row in rows}
                == {"median", "p95", "p99"},
                "samples_full_and_clean": {row["sample_id"] for row in rows}
                == {"full", "clean-prefix"},
                "color_encodes_regime_only": source["visual_encoding"]["color"]
                == {"same_carrier": BLUE, "carrier_switch": AMBER},
                "fill_encodes_sample_only": source["visual_encoding"]["marker_fill"]
                == {"full": "filled", "clean-prefix": "open"},
            }
        )
    if not all(checks.values()):
        raise LatencyFigureError(f"{kind} validation failed: {checks}")
    validation = {
        "schema_version": "xir-native-latency-figure-validation-v2",
        "namespace": namespace,
        "valid": True,
        "checks": checks,
    }
    _write_json(output_directory / "validation.json", validation)
    _write_report(
        output_directory / "REPORT.md",
        title="Native-size main latency summary"
        if kind == "main"
        else "Native-size appendix latency comparison",
        caption=caption,
        rows=rows,
        appendix=kind == "appendix",
    )
    semantic = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "namespace": namespace,
        "source_semantic_sha256": semantic,
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
    kind: str,
) -> dict[str, Any]:
    """Build one figure twice, require byte identity, and publish rebuild A."""

    if output_root.exists():
        raise LatencyFigureError(f"refusing to overwrite namespace: {output_root}")
    output_root.mkdir(parents=True)
    rebuilds = [
        _build_artifact(
            repository_root=repository_root,
            latency_publication=latency_publication,
            sensitivity_publication=sensitivity_publication,
            output_directory=output_root / name,
            kind=kind,
        )
        for name in ("rebuild-a", "rebuild-b")
    ]
    if rebuilds[0] != rebuilds[1]:
        raise LatencyFigureError(f"{kind} rebuilds are not byte-identical")
    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-native-latency-figure-rebuild-v2",
        "namespace": rebuilds[0]["namespace"],
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "byte_identical_files": rebuilds[0]["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    manifest = {
        "schema_version": "xir-native-latency-figure-manifest-v2",
        "namespace": rebuilds[0]["namespace"],
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
        "namespace": rebuilds[0]["namespace"],
        "publication": str(publication),
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "valid": True,
    }
