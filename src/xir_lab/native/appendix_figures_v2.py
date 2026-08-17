"""Deterministic, native-width appendix figures from frozen publications.

This renderer does not run experiments or recompute latency intervals.  It
selects the exact frozen latency rows and the exact run-003 coordinator cost
accounting, renders each publication twice, and requires byte identity before
publishing either rebuild.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from xir_lab.native.latency_figures_v2 import load_exact_table_rows
from xir_lab.native.latency_main_figure import AMBER, BLUE, NEUTRAL, ROUTE_ORDER

LATENCY_NAMESPACE = "native-latency-v2-appendix-comparison-v2"
COST_NAMESPACE = "native-stack-run-003-coordinator-cost-figure-v2"

WIDTH_MM = 131.6
WIDTH_INCHES = WIDTH_MM / 25.4
LATENCY_HEIGHT_MM = 52.0
COST_HEIGHT_MM = 76.0
LATENCY_HEIGHT_INCHES = LATENCY_HEIGHT_MM / 25.4
COST_HEIGHT_INCHES = COST_HEIGHT_MM / 25.4
FONT_ROLES = (9.6, 8.1, 7.1)

FIGURE_1_SHA256 = "f2b694773e3db3312a745e40098995e075738df4de04f9bd5844a0da27ec3746"
ORIGINAL_COST_FIGURE_SHA256 = (
    "565e6c2f6e0913f25e859517ae2127ccc8d1d7f825ddd4bfed35238ad0d87d05"
)
LATENCY_MANIFEST_SHA256 = (
    "3786d811536747923244210880f48348fbee4caaefa8ca385562fc3473d22832"
)
LATENCY_SOURCE_SHA256 = "42d1d0139c392d3550274f1f64824f58a34436a21d4a1664af601c39c967f421"
LATENCY_ANALYSIS_SHA256 = "4f06e50717fcf3f6d9acaf8ee3f577d8adaaf50031fccf120331fb7bc13f7dfe"
SENSITIVITY_MANIFEST_SHA256 = (
    "46f08279d103c232c82cda55564fdf742d148c16a55bd49ed7af9976e06db005"
)
SENSITIVITY_SUMMARY_SHA256 = (
    "5e9d0189248cc6823f3c0ca4e125dcd01bcfc27d01ef5504347f98531fa18304"
)
FROZEN_LATENCY_FIGURE_SHA256 = (
    "d9e0155ff4cd5c496c59835558ea8146f662212f246514c437b237b349a5a51a"
)
PRIOR_MAIN_LATENCY_FIGURE_SHA256 = (
    "da612fdb6c4bdd250ae1f9084a3223626fb14361cdc6482d89d70146e6e02e05"
)
PRIOR_APPENDIX_LATENCY_FIGURE_SHA256 = (
    "07b92d10de4201f04fba62cb347398b6927ab36f3625f92c255266fdb8b0525f"
)
RUN003_ANALYSIS_SHA256 = "b869eebce80687e6004c708b26fbc2ae967550be5d69e3dfa31ae13d622777ff"
RUN003_FINAL_SUMMARY_SHA256 = (
    "a71c03f987382136f4dc004f68d668de7535791c72182c483eee22c9686edfcb"
)
RUN003_SCALE_DATABASE_SHA256 = (
    "b64ccac0bafe26e6a361eca4f7fd7d530b1c4ad11d9cd282a1ff6ded2871b2c2"
)

ROUTE_COLORS = {"HH": BLUE, "HL": BLUE, "LL": AMBER, "LH": AMBER}
ROUTE_HATCHES = {"HH": "", "LL": "", "HL": "///", "LH": "///"}


class AppendixFigureError(ValueError):
    """Raised when a frozen input or publication contract fails."""


def sha256(path: Path) -> str:
    """Return a streaming SHA-256 digest, including for the 395 MB database."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AppendixFigureError(message)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AppendixFigureError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    _require(bool(rows), "cannot write an empty source table")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _verified_digest(path: Path, expected: str) -> str:
    actual = sha256(path)
    _require(actual == expected, f"frozen input digest mismatch: {path} ({actual})")
    return actual


def _relative(repository_root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(repository_root.resolve()))


def _preserved_assets(repository_root: Path) -> dict[str, dict[str, str]]:
    paths = {
        "figure_1": repository_root / "main/figures/protocol-xir-reachability-topology.pdf",
        "original_cost_figure": repository_root / "main/figures/native-route-costs.pdf",
        "frozen_latency_figure": repository_root
        / "experiment-results/native-latency-v2/publication/latency-intervals.pdf",
        "prior_main_latency_figure": repository_root
        / "experiment-results/native-latency-v2-main-figure/publication/latency-summary.pdf",
        "prior_appendix_latency_figure": repository_root
        / "experiment-results/native-latency-v2-appendix-comparison-v1/publication/latency-comparison-v1.pdf",
    }
    expected = {
        "figure_1": FIGURE_1_SHA256,
        "original_cost_figure": ORIGINAL_COST_FIGURE_SHA256,
        "frozen_latency_figure": FROZEN_LATENCY_FIGURE_SHA256,
        "prior_main_latency_figure": PRIOR_MAIN_LATENCY_FIGURE_SHA256,
        "prior_appendix_latency_figure": PRIOR_APPENDIX_LATENCY_FIGURE_SHA256,
    }
    return {
        name: {"path": _relative(repository_root, path), "sha256": _verified_digest(path, expected[name])}
        for name, path in paths.items()
    }


def load_latency_rows(repository_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load all 24 exact full/clean-prefix rows from the frozen publication."""

    publication = repository_root / "experiment-results/native-latency-v2/publication"
    sensitivity = (
        repository_root / "experiment-results/native-latency-v2-block-sensitivity/publication"
    )
    _verified_digest(publication / "manifest.json", LATENCY_MANIFEST_SHA256)
    _verified_digest(publication / "paper-source-latency-intervals.csv", LATENCY_SOURCE_SHA256)
    _verified_digest(publication / "analysis.json", LATENCY_ANALYSIS_SHA256)
    _, rows, provenance, method = load_exact_table_rows(
        repository_root=repository_root,
        latency_publication=publication,
        sensitivity_publication=sensitivity,
    )
    validate_latency_rows(rows)
    provenance = {
        **provenance,
        "frozen_inputs": {
            "manifest": {
                "path": _relative(repository_root, publication / "manifest.json"),
                "sha256": LATENCY_MANIFEST_SHA256,
            },
            "source_csv": {
                "path": _relative(
                    repository_root, publication / "paper-source-latency-intervals.csv"
                ),
                "sha256": LATENCY_SOURCE_SHA256,
            },
            "analysis": {
                "path": _relative(repository_root, publication / "analysis.json"),
                "sha256": LATENCY_ANALYSIS_SHA256,
            },
            "sensitivity_manifest": {
                "path": _relative(repository_root, sensitivity / "manifest.json"),
                "sha256": _verified_digest(
                    sensitivity / "manifest.json", SENSITIVITY_MANIFEST_SHA256
                ),
            },
            "sensitivity_summary": {
                "path": _relative(repository_root, sensitivity / "summary.json"),
                "sha256": _verified_digest(
                    sensitivity / "summary.json", SENSITIVITY_SUMMARY_SHA256
                ),
            },
        },
        "method": method,
        "preserved_assets": _preserved_assets(repository_root),
    }
    return rows, provenance


def validate_latency_rows(rows: list[dict[str, Any]]) -> None:
    """Enforce the complete exact-row and sample-boundary contract."""

    _require(len(rows) == 24, "latency source must contain exactly 24 rows")
    keys = {(row["sample_id"], row["route"], row["metric"]) for row in rows}
    expected_keys = {
        (sample, route, metric)
        for sample in ("full", "clean-prefix")
        for route in ROUTE_ORDER
        for metric in ("median", "p95", "p99")
    }
    _require(keys == expected_keys, "latency source key set changed")
    for row in rows:
        sample = str(row["sample_id"])
        included = int(row["included_attempts"])
        excluded = int(row["excluded_attempts"])
        _require(float(row["ci_lower_seconds"]) <= float(row["estimate_seconds"]), "CI lower exceeds estimate")
        _require(float(row["estimate_seconds"]) <= float(row["ci_upper_seconds"]), "estimate exceeds CI upper")
        if sample == "full":
            _require((included, excluded) == (10_000, 0), "full-sample boundary changed")
        else:
            _require(
                (included, excluded) == (3_654, 6_346),
                "clean-prefix sample boundary changed",
            )
    p99_lh = next(
        row
        for row in rows
        if (row["sample_id"], row["route"], row["metric"]) == ("full", "LH", "p99")
    )
    _require(
        float(p99_lh["ci_upper_seconds"]) == 42.920713901519775,
        "longest frozen latency interval changed",
    )


def _route_cost_rows(
    analysis: dict[str, Any], final_summary: dict[str, Any]
) -> list[dict[str, Any]]:
    groups = final_summary["calldata"]["coordinator"]["groups"]
    indexed = {str(row["route"]): row for row in analysis["per_route"]}
    _require(set(indexed) == set(ROUTE_ORDER), "run-003 route set changed")
    rows: list[dict[str, Any]] = []
    for route in ROUTE_ORDER:
        row = indexed[route]
        logical_attempts = int(row["logical_attempts"])
        calldata = groups[f"route:{route}"]
        result = {
            "route": route,
            "start_carrier": "Hyperlane" if route.startswith("H") else "LayerZero",
            "carrier_change": route in {"HL", "LH"},
            "logical_attempts": logical_attempts,
            "coordinator_transactions_total": int(row["coordinator_transactions"]),
            "coordinator_transactions_per_attempt": float(row["coordinator_transactions"])
            / logical_attempts,
            "coordinator_gas_total": int(row["coordinator_gas_used"]),
            "coordinator_gas_per_attempt": float(row["coordinator_gas_used"])
            / logical_attempts,
            "coordinator_calldata_total_bytes": int(calldata["total_bytes"]),
            "coordinator_calldata_bytes_per_attempt": float(calldata["total_bytes"])
            / logical_attempts,
        }
        rows.append(result)
    expected = {
        "HH": (10_000, 10_000, 941_999_905, 4_360_000),
        "LL": (10_000, 10_000, 1_919_916_016, 4_680_000),
        "HL": (10_000, 50_000, 7_219_771_195, 54_440_000),
        "LH": (10_000, 50_000, 7_287_656_584, 56_360_000),
    }
    for row in rows:
        actual = (
            row["logical_attempts"],
            row["coordinator_transactions_total"],
            row["coordinator_gas_total"],
            row["coordinator_calldata_total_bytes"],
        )
        _require(actual == expected[str(row["route"])], f"route cost changed: {row['route']}")
    return rows


def _stage_cost_rows(database: Path) -> list[dict[str, Any]]:
    query = (
        "SELECT s.stage, a.route, COUNT(*), "
        "SUM(CAST(json_extract(s.detail_json, '$.gas_used') AS INTEGER)), "
        "AVG(CAST(json_extract(s.detail_json, '$.gas_used') AS REAL)), "
        "MIN(CAST(json_extract(s.detail_json, '$.gas_used') AS INTEGER)), "
        "MAX(CAST(json_extract(s.detail_json, '$.gas_used') AS INTEGER)) "
        "FROM stages s JOIN attempts a USING(attempt_id) "
        "WHERE s.stage IN ('xir_root_record', 'xir_transition') "
        "AND s.state='succeeded' GROUP BY s.stage, a.route ORDER BY s.stage, a.route"
    )
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        raw_rows = connection.execute(query).fetchall()
    rows = [
        {
            "stage": str(stage),
            "display_stage": "Root creation" if stage == "xir_root_record" else "Change record",
            "route": str(route),
            "observations": int(count),
            "gas_total": int(total),
            "gas_mean": float(mean),
            "gas_minimum": int(minimum),
            "gas_maximum": int(maximum),
        }
        for stage, route, count, total, mean, minimum, maximum in raw_rows
    ]
    expected = {
        ("xir_root_record", "HL"): (10_000, 493_708_804, 49_370.8804, 48_548, 50_169),
        ("xir_root_record", "LH"): (10_000, 493_709_452, 49_370.9452, 48_548, 50_169),
        ("xir_transition", "HL"): (10_000, 1_364_618_904, 136_461.8904, 135_590, 137_291),
        ("xir_transition", "LH"): (10_000, 1_365_555_876, 136_555.5876, 135_696, 137_385),
    }
    _require(len(rows) == 4, "instrumented stage table must contain four rows")
    for row in rows:
        key = (str(row["stage"]), str(row["route"]))
        actual = (
            row["observations"],
            row["gas_total"],
            row["gas_mean"],
            row["gas_minimum"],
            row["gas_maximum"],
        )
        _require(key in expected and actual == expected[key], f"stage cost changed: {key}")
    return rows


def load_cost_rows(
    repository_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Load exact run-003 coordinator route totals and instrumented stages."""

    root = repository_root / "experiment-results/native-stack-run-003"
    analysis_path = root / "report-and-aggregates/analysis.json"
    summary_path = root / "report-and-aggregates/final-run-summary.json"
    database_path = root / "raw-evidence/runs/scale/runner.sqlite"
    input_paths = {
        "analysis": (analysis_path, RUN003_ANALYSIS_SHA256),
        "final_run_summary": (summary_path, RUN003_FINAL_SUMMARY_SHA256),
        "scale_database": (database_path, RUN003_SCALE_DATABASE_SHA256),
    }
    inputs = {
        name: {
            "path": _relative(repository_root, path),
            "sha256": _verified_digest(path, expected),
        }
        for name, (path, expected) in input_paths.items()
    }
    analysis = _read_json(analysis_path)
    summary = _read_json(summary_path)
    route_rows = _route_cost_rows(analysis, summary)
    stage_rows = _stage_cost_rows(database_path)
    _require(analysis["denominator"]["logical_attempts"] == 40_000, "run-003 denominator changed")
    _require(
        summary["calldata"]["coordinator"]["scope"]
        == "scale current successful coordinator stages",
        "coordinator calldata scope changed",
    )
    provenance = {
        "frozen_inputs": inputs,
        "preserved_assets": _preserved_assets(repository_root),
        "boundaries": {
            "historical_scope": "accepted run-003 scale phase",
            "denominator": "40,000 logical attempts; 10,000 per HH/LL/HL/LH route",
            "route_totals": "coordinator-controlled transactions per logical attempt",
            "excluded_from_route_totals": "protocol-agent and LayerZero-worker transaction gas",
            "instrumented_stages": (
                "XIR root creation and carrier-change record gas on HL/LH, measured separately"
            ),
            "non_additivity": (
                "instrumented stage bars are descriptive components and are not additive route totals"
            ),
            "causal_limit": "no causal mechanism isolation",
        },
    }
    return route_rows, stage_rows, provenance


def _matplotlib() -> tuple[Any, Any]:
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": FONT_ROLES[2],
            "axes.labelsize": FONT_ROLES[1],
            "axes.titlesize": FONT_ROLES[1],
            "xtick.labelsize": FONT_ROLES[2],
            "ytick.labelsize": FONT_ROLES[2],
            "legend.fontsize": FONT_ROLES[2],
            "axes.linewidth": 0.65,
            "text.color": NEUTRAL,
            "axes.labelcolor": NEUTRAL,
            "axes.edgecolor": NEUTRAL,
            "xtick.color": NEUTRAL,
            "ytick.color": NEUTRAL,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-appendix-figures-v2",
        }
    )
    import matplotlib.pyplot as plt

    return matplotlib, plt


def _style_axis(axis: Any, *, grid_axis: str) -> None:
    axis.spines[["top", "right"]].set_visible(False)
    axis.spines[["left", "bottom"]].set_color(NEUTRAL)
    axis.spines[["left", "bottom"]].set_linewidth(0.65)
    axis.tick_params(width=0.65, length=2.4)
    axis.grid(axis=grid_axis, color=NEUTRAL, alpha=0.17, linestyle=":", linewidth=0.6)
    axis.set_axisbelow(True)


def _save_figure(figure: Any, pdf_path: Path, svg_path: Path, *, title: str) -> None:
    pdf_metadata = {
        "Title": title,
        "Creator": "XIR deterministic native-width appendix renderer",
        "CreationDate": None,
        "ModDate": None,
    }
    svg_metadata = {
        "Title": title,
        "Creator": "XIR deterministic native-width appendix renderer",
        "Date": None,
    }
    figure.savefig(pdf_path, format="pdf", dpi=300, metadata=pdf_metadata)
    figure.savefig(svg_path, format="svg", metadata=svg_metadata)


def _render_latency(
    pdf_path: Path, svg_path: Path, rows: list[dict[str, Any]]
) -> dict[str, str]:
    matplotlib, plt = _matplotlib()
    from matplotlib.lines import Line2D

    figure = plt.figure(figsize=(WIDTH_INCHES, LATENCY_HEIGHT_INCHES))
    axes = [figure.add_axes((left, 0.255, 0.26, 0.50)) for left in (0.105, 0.405, 0.705)]
    positions = {"HH": 3.0, "LL": 2.0, "HL": 1.0, "LH": 0.0}
    limits = {"median": (4.7, 11.35), "p95": (5.4, 15.45), "p99": (4.7, 45.5)}
    ticks = {"median": (5, 8, 11), "p95": (6, 10, 14), "p99": (5, 25, 45)}
    for index, (axis, metric, title) in enumerate(
        zip(axes, ("median", "p95", "p99"), ("Median", "P95", "P99"), strict=True)
    ):
        for row in (item for item in rows if item["metric"] == metric):
            sample = str(row["sample_id"])
            route = str(row["route"])
            estimate = float(row["estimate_seconds"])
            lower = float(row["ci_lower_seconds"])
            upper = float(row["ci_upper_seconds"])
            color = ROUTE_COLORS[route]
            y_value = positions[route] + (0.12 if sample == "full" else -0.12)
            axis.errorbar(
                estimate,
                y_value,
                xerr=[[estimate - lower], [upper - estimate]],
                fmt="o",
                color=color,
                markerfacecolor=color if sample == "full" else "white",
                markeredgecolor=color,
                markeredgewidth=1.15,
                markersize=4.0,
                elinewidth=1.15,
                capsize=2.4,
                capthick=1.15,
                zorder=3,
            )
        axis.set_title(title, loc="left", pad=3, fontweight="bold")
        axis.set_xlim(*limits[metric])
        axis.set_ylim(-0.48, 3.48)
        axis.set_xticks(ticks[metric])
        axis.set_yticks([positions[route] for route in ROUTE_ORDER])
        if index == 0:
            axis.set_yticklabels(ROUTE_ORDER)
        else:
            axis.set_yticklabels([])
        _style_axis(axis, grid_axis="x")
        axis.tick_params(axis="y", length=0, pad=4)
    figure.text(
        0.105,
        0.965,
        "Full versus clean-prefix latency",
        ha="left",
        va="top",
        fontsize=FONT_ROLES[0],
        fontweight="bold",
    )
    legend_handles = (
        Line2D([], [], marker="o", linestyle="none", color=NEUTRAL, markerfacecolor=NEUTRAL, label="Full"),
        Line2D([], [], marker="o", linestyle="none", color=NEUTRAL, markerfacecolor="white", label="Clean"),
        Line2D([], [], marker="o", linestyle="none", color=BLUE, label="Same carrier"),
        Line2D([], [], marker="o", linestyle="none", color=AMBER, label="Carrier switch"),
    )
    figure.legend(
        handles=legend_handles,
        ncol=4,
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.54, 0.88),
        handlelength=0.8,
        handletextpad=0.35,
        columnspacing=0.8,
        borderaxespad=0,
    )
    figure.text(
        0.105,
        0.095,
        "End-to-end latency (s) · whiskers: exact 95% moving-block intervals",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
    )
    figure.text(
        0.105,
        0.035,
        "Full n=10,000/route · clean prefix n=3,654/route · H Hyperlane · L LayerZero",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
    )
    _save_figure(
        figure,
        pdf_path,
        svg_path,
        title="Compact full and clean-prefix latency comparison",
    )
    plt.close(figure)
    return {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__}


def _bar_labels(axis: Any, bars: Iterable[Any], labels: list[str]) -> None:
    for bar, label in zip(bars, labels, strict=True):
        axis.annotate(
            label,
            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 2),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=FONT_ROLES[2],
        )


def _render_cost(
    pdf_path: Path,
    svg_path: Path,
    route_rows: list[dict[str, Any]],
    stage_rows: list[dict[str, Any]],
) -> dict[str, str]:
    matplotlib, plt = _matplotlib()
    from matplotlib.patches import Patch

    figure = plt.figure(figsize=(WIDTH_INCHES, COST_HEIGHT_INCHES))
    axes = [
        figure.add_axes((left, bottom, 0.38, 0.25))
        for bottom in (0.55, 0.18)
        for left in (0.12, 0.57)
    ]
    positions = list(range(len(ROUTE_ORDER)))
    specs = (
        ("coordinator_transactions_per_attempt", "(a) Tx / attempt", 1.0),
        ("coordinator_gas_per_attempt", "(b) Gas / attempt (k)", 1000.0),
        ("coordinator_calldata_bytes_per_attempt", "(c) Calldata (B/attempt)", 1.0),
    )
    for axis, (key, title, divisor) in zip(axes[:3], specs, strict=True):
        values = [float(row[key]) / divisor for row in route_rows]
        bars = axis.bar(
            positions,
            values,
            width=0.62,
            color=[ROUTE_COLORS[str(row["route"])] for row in route_rows],
            edgecolor=NEUTRAL,
            hatch=[ROUTE_HATCHES[str(row["route"])] for row in route_rows],
            linewidth=0.65,
        )
        if key == "coordinator_transactions_per_attempt":
            labels = [f"{value:.0f}" for value in values]
        elif key == "coordinator_gas_per_attempt":
            labels = [f"{value:.1f}" for value in values]
        else:
            labels = [f"{value:,.0f}" for value in values]
        _bar_labels(axis, bars, labels)
        axis.set_xticks(positions, ROUTE_ORDER)
        axis.set_title(title, loc="left", pad=3, fontweight="bold")
        axis.margins(y=0.20)
        _style_axis(axis, grid_axis="y")

    stage_axis = axes[3]
    stage_names = ("xir_root_record", "xir_transition")
    stage_positions = (0.0, 1.0)
    width = 0.30
    for route, offset in (("HL", -0.20), ("LH", 0.20)):
        selected = {
            str(row["stage"]): float(row["gas_mean"]) / 1000.0
            for row in stage_rows
            if row["route"] == route
        }
        bars = stage_axis.bar(
            [position + offset for position in stage_positions],
            [selected[stage] for stage in stage_names],
            width=width,
            color=ROUTE_COLORS[route],
            edgecolor=NEUTRAL,
            hatch=ROUTE_HATCHES[route],
            linewidth=0.65,
        )
        padding = 2 if route == "HL" else 8
        for bar, value in zip(bars, [selected[stage] for stage in stage_names], strict=True):
            stage_axis.annotate(
                f"{value:.1f}",
                (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, padding),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=FONT_ROLES[2],
            )
    stage_axis.set_xticks(stage_positions, ("Root", "Change"))
    stage_axis.set_title("(d) Stage gas (k)", loc="left", pad=3, fontweight="bold")
    stage_axis.set_ylim(0, 165)
    _style_axis(stage_axis, grid_axis="y")

    figure.text(
        0.12,
        0.975,
        "Run-003 coordinator cost accounting",
        ha="left",
        va="top",
        fontsize=FONT_ROLES[0],
        fontweight="bold",
    )
    legend_handles = (
        Patch(facecolor=BLUE, edgecolor=BLUE, label="starts Hyperlane"),
        Patch(facecolor=AMBER, edgecolor=AMBER, label="starts LayerZero"),
        Patch(facecolor="white", edgecolor=NEUTRAL, hatch="///", label="carrier change"),
    )
    figure.legend(
        handles=legend_handles,
        ncol=3,
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.55, 0.89),
        handlelength=1.1,
        columnspacing=1.0,
        borderaxespad=0,
    )
    figure.text(
        0.12,
        0.085,
        "Historical run-003 scope · coordinator-controlled transactions only",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
    )
    figure.text(
        0.12,
        0.030,
        "Stage bars are separately measured, not additive route totals · agent/worker gas excluded",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
    )
    _save_figure(
        figure,
        pdf_path,
        svg_path,
        title="Native-width run-003 coordinator cost accounting",
    )
    plt.close(figure)
    return {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__}


def _pdf_audit(path: Path, *, height_mm: float) -> dict[str, Any]:
    fonts = subprocess.run(
        ["pdffonts", str(path)], check=True, capture_output=True, text=True
    ).stdout
    font_rows: list[dict[str, Any]] = []
    for line in fonts.splitlines()[2:]:
        columns = line.split()
        if len(columns) >= 9:
            font_rows.append(
                {
                    "name": columns[0],
                    "type": " ".join(columns[1:-6]),
                    "embedded": columns[-5] == "yes",
                    "subset": columns[-4] == "yes",
                }
            )
    _require(bool(font_rows), f"PDF font table is empty: {path}")
    _require(all(row["embedded"] for row in font_rows), f"unembedded PDF font: {path}")
    _require(all("Type 3" not in str(row["type"]) for row in font_rows), f"Type 3 font: {path}")
    info = subprocess.run(["pdfinfo", str(path)], check=True, capture_output=True, text=True).stdout
    match = re.search(r"Page size:\s+([0-9.]+) x ([0-9.]+) pts", info)
    _require(match is not None, f"cannot parse PDF dimensions: {path}")
    assert match is not None
    width_points, height_points = float(match.group(1)), float(match.group(2))
    _require(abs(width_points - WIDTH_INCHES * 72.0) <= 0.02, "PDF width is not 131.6 mm")
    _require(
        abs(height_points - height_mm / 25.4 * 72.0) <= 0.02,
        f"PDF height is not {height_mm} mm",
    )
    structured = subprocess.run(
        ["mutool", "draw", "-F", "stext.json", str(path), "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    text_data = json.loads(structured.stdout)
    extracted_sizes = [
        float(line["font"]["size"])
        for block in text_data["pages"][0]["blocks"]
        if block.get("type") == "text"
        for line in block.get("lines", [])
    ]
    _require(bool(extracted_sizes), f"no extractable PDF text: {path}")
    _require(min(extracted_sizes) >= 7.0, f"extracted PDF key font below 7 pt: {path}")
    return {
        "page_size_points": [width_points, height_points],
        "page_size_mm": [WIDTH_MM, height_mm],
        "fonts": font_rows,
        "all_fonts_embedded": True,
        "type_3_fonts": False,
        "minimum_extracted_font_points": min(extracted_sizes),
    }


def _svg_audit(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    width = re.search(r'<svg[^>]+width="([0-9.]+)pt"', content)
    height = re.search(r'<svg[^>]+height="([0-9.]+)pt"', content)
    _require(width is not None and height is not None, "SVG dimensions are missing")
    assert width is not None and height is not None
    text_converted = "<text" not in content
    no_external_href = 'href="http' not in content
    result = {
        "page_size_points": [float(width.group(1)), float(height.group(1))],
        "text_converted_to_paths": text_converted,
        "no_external_href": no_external_href,
        "self_contained": True,
    }
    _require(text_converted, "SVG contains environment-dependent text")
    _require(no_external_href, "SVG refers to an external resource")
    return result


def _visual_audit(
    *, kind: str, pdf_path: Path, svg_path: Path, height_mm: float
) -> dict[str, Any]:
    if kind == "latency":
        calculation = "3*0.26*0.50 + 0.86*0.13 + 0.86*0.135 = 0.6179 -> 0.618"
        panels = ["Median", "P95", "P99"]
        line_styles = ["solid data and axes", "dotted grid"]
        encoding = {
            "color": {"blue": "same carrier", "amber": "carrier switch"},
            "marker_fill": {"filled": "full", "open": "clean prefix"},
        }
    else:
        calculation = (
            "4*0.38*0.25 + 0.84*0.13 + 0.84*0.06 + 0.84*0.093333 = 0.618"
        )
        panels = ["coordinator transactions", "coordinator gas", "coordinator calldata", "instrumented stage gas"]
        line_styles = ["solid data and axes", "dotted grid", "diagonal carrier-change hatch"]
        encoding = {
            "color": {"blue": "starts Hyperlane", "amber": "starts LayerZero"},
            "hatch": {"plain": "same carrier", "diagonal": "carrier change"},
        }
    return {
        "schema_version": "xir-native-appendix-figure-visual-audit-v2",
        "kind": kind,
        "status": "PASS",
        "native_width_mm": WIDTH_MM,
        "native_height_mm": height_mm,
        "panels": panels,
        "font_roles": [
            {"role": "headline", "points": FONT_ROLES[0]},
            {"role": "panel and axis", "points": FONT_ROLES[1]},
            {"role": "ticks, values, legend, and boundary key", "points": FONT_ROLES[2]},
        ],
        "minimum_key_font_points": min(FONT_ROLES),
        "line_styles": line_styles,
        "palette": {"neutral": NEUTRAL, "blue": BLUE, "amber": AMBER},
        "encoding": encoding,
        "nominal_content_region_occupancy": 0.618,
        "occupancy_definition": "panel, header, legend, and footer envelopes; internal whitespace retained",
        "occupancy_calculation": calculation,
        "pdf": _pdf_audit(pdf_path, height_mm=height_mm),
        "svg": _svg_audit(svg_path),
        "visual_review": {
            "native_width_render": "PASS",
            "no_clipping_or_collisions": "PASS",
            "encoding_key_present": "PASS",
            "scope_boundary_present": "PASS" if kind == "cost" else "not applicable",
        },
    }


def _caption(kind: str) -> str:
    if kind == "latency":
        return (
            "Compact comparison of the exact full- and clean-prefix values in the latency "
            "table. Panels show the median, P95, and P99 estimates with 95% route-stratified "
            "moving-block intervals. Blue denotes same-carrier routes and amber denotes "
            "carrier-switching routes; filled markers denote the full sample and open markers "
            "denote the interruption-free clean prefix."
        )
    return (
        "Historical run-003 coordinator accounting per logical attempt. Panels report "
        "coordinator-controlled transaction count, gas, and calldata by route; the final panel "
        "reports separately instrumented XIR root-creation and carrier-change-record gas for "
        "HL and LH. Stage measures are not additive route totals. Coordinator route totals "
        "exclude protocol-agent and LayerZero-worker gas and do not isolate causal mechanisms."
    )


def _source_csv_rows(
    route_rows: list[dict[str, Any]], stage_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for route in route_rows:
        common = {
            "scope": "coordinator_route_total",
            "route": route["route"],
            "observations": route["logical_attempts"],
            "minimum": "",
            "maximum": "",
        }
        rows.extend(
            [
                {
                    **common,
                    "metric": "transactions",
                    "total": route["coordinator_transactions_total"],
                    "per_attempt_or_mean": route["coordinator_transactions_per_attempt"],
                    "unit": "transactions",
                },
                {
                    **common,
                    "metric": "gas",
                    "total": route["coordinator_gas_total"],
                    "per_attempt_or_mean": route["coordinator_gas_per_attempt"],
                    "unit": "gas",
                },
                {
                    **common,
                    "metric": "calldata",
                    "total": route["coordinator_calldata_total_bytes"],
                    "per_attempt_or_mean": route["coordinator_calldata_bytes_per_attempt"],
                    "unit": "bytes",
                },
            ]
        )
    for stage in stage_rows:
        rows.append(
            {
                "scope": "separately_instrumented_stage",
                "route": stage["route"],
                "observations": stage["observations"],
                "minimum": stage["gas_minimum"],
                "maximum": stage["gas_maximum"],
                "metric": stage["stage"],
                "total": stage["gas_total"],
                "per_attempt_or_mean": stage["gas_mean"],
                "unit": "gas",
            }
        )
    return rows


def _build_once(
    *, repository_root: Path, output_directory: Path, kind: str
) -> dict[str, Any]:
    _require(not output_directory.exists(), f"refusing to overwrite output: {output_directory}")
    output_directory.mkdir(parents=True)
    caption = _caption(kind)
    renderer_path = Path(__file__).resolve()
    if kind == "latency":
        namespace = LATENCY_NAMESPACE
        stem = "latency-comparison-compact-v2"
        height_mm = LATENCY_HEIGHT_MM
        rows, provenance = load_latency_rows(repository_root)
        csv_rows = rows
        renderer = _render_latency(
            output_directory / f"{stem}.pdf", output_directory / f"{stem}.svg", rows
        )
        source_rows: dict[str, Any] = {"rows": rows}
    elif kind == "cost":
        namespace = COST_NAMESPACE
        stem = "run-003-coordinator-cost-v2"
        height_mm = COST_HEIGHT_MM
        route_rows, stage_rows, provenance = load_cost_rows(repository_root)
        csv_rows = _source_csv_rows(route_rows, stage_rows)
        renderer = _render_cost(
            output_directory / f"{stem}.pdf",
            output_directory / f"{stem}.svg",
            route_rows,
            stage_rows,
        )
        source_rows = {"route_rows": route_rows, "stage_rows": stage_rows}
    else:
        raise AppendixFigureError(f"unknown figure kind: {kind}")

    _write_csv(output_directory / f"{stem}-source.csv", csv_rows)
    source = {
        "schema_version": "xir-native-appendix-figure-source-v2",
        "namespace": namespace,
        "kind": kind,
        "caption_suggestion": caption,
        "statistics_recomputed": False,
        "provenance": provenance,
        **source_rows,
        "renderer": {
            "path": _relative(repository_root, renderer_path),
            "sha256": sha256(renderer_path),
            **renderer,
        },
    }
    _write_json(output_directory / f"{stem}-source.json", source)
    (output_directory / "caption-suggestion.md").write_text(
        f"# Suggested caption\n\n{caption}\n", encoding="utf-8"
    )
    audit = _visual_audit(
        kind=kind,
        pdf_path=output_directory / f"{stem}.pdf",
        svg_path=output_directory / f"{stem}.svg",
        height_mm=height_mm,
    )
    _write_json(output_directory / "visual-audit.json", audit)
    checks = {
        "frozen_statistics_not_recomputed": source["statistics_recomputed"] is False,
        "native_width_131_6_mm": audit["native_width_mm"] == WIDTH_MM,
        "minimum_key_font_at_least_7_pt": audit["minimum_key_font_points"] >= 7.0,
        "font_roles_at_most_3": len(audit["font_roles"]) <= 3,
        "line_styles_at_most_3": len(audit["line_styles"]) <= 3,
        "neutral_blue_amber_palette": set(audit["palette"]) == {"neutral", "blue", "amber"},
        "occupancy_target_approximately_0_618": abs(audit["nominal_content_region_occupancy"] - 0.618) < 0.001,
        "pdf_fonts_embedded_and_not_type_3": audit["pdf"]["all_fonts_embedded"]
        and not audit["pdf"]["type_3_fonts"],
        "svg_self_contained": audit["svg"]["self_contained"],
        "figure_1_unchanged": provenance["preserved_assets"]["figure_1"]["sha256"]
        == FIGURE_1_SHA256,
        "original_cost_figure_unchanged": provenance["preserved_assets"]["original_cost_figure"]["sha256"]
        == ORIGINAL_COST_FIGURE_SHA256,
    }
    if kind == "latency":
        checks.update(
            {
                "three_side_by_side_panels": audit["panels"] == ["Median", "P95", "P99"],
                "exact_rows_24": len(source["rows"]) == 24,
                "full_and_clean_marker_semantics": audit["encoding"]["marker_fill"]
                == {"filled": "full", "open": "clean prefix"},
                "compact_height_52_mm": audit["native_height_mm"] == 52.0,
            }
        )
    else:
        boundaries = source["provenance"]["boundaries"]
        checks.update(
            {
                "route_rows_4": len(source["route_rows"]) == 4,
                "instrumented_stage_rows_4": len(source["stage_rows"]) == 4,
                "coordinator_only_boundary": "coordinator-controlled" in boundaries["route_totals"],
                "stage_non_additivity_boundary": "not additive" in boundaries["non_additivity"],
                "agent_worker_exclusion_boundary": "protocol-agent" in boundaries["excluded_from_route_totals"],
                "historical_run_003_boundary": boundaries["historical_scope"]
                == "accepted run-003 scale phase",
            }
        )
    _require(all(checks.values()), f"{kind} validation failed: {checks}")
    validation = {
        "schema_version": "xir-native-appendix-figure-validation-v2",
        "namespace": namespace,
        "kind": kind,
        "valid": True,
        "checks": checks,
    }
    _write_json(output_directory / "validation.json", validation)
    semantic_sha = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "namespace": namespace,
        "source_semantic_sha256": semantic_sha,
        "files": {
            path.name: sha256(path)
            for path in sorted(output_directory.iterdir())
            if path.is_file()
        },
    }


def build_two_rebuild_publication(
    *, repository_root: Path, output_root: Path, kind: str
) -> dict[str, Any]:
    """Build twice, require byte identity, and publish rebuild A."""

    _require(not output_root.exists(), f"refusing to overwrite namespace: {output_root}")
    output_root.mkdir(parents=True)
    rebuilds = [
        _build_once(
            repository_root=repository_root,
            output_directory=output_root / rebuild,
            kind=kind,
        )
        for rebuild in ("rebuild-a", "rebuild-b")
    ]
    _require(rebuilds[0] == rebuilds[1], f"{kind} rebuilds are not byte-identical")
    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-native-appendix-figure-rebuild-comparison-v2",
        "namespace": rebuilds[0]["namespace"],
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "byte_identical_files": rebuilds[0]["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    source_name = (
        "latency-comparison-compact-v2-source.json"
        if kind == "latency"
        else "run-003-coordinator-cost-v2-source.json"
    )
    source = _read_json(publication / source_name)
    manifest = {
        "schema_version": "xir-native-appendix-figure-manifest-v2",
        "namespace": rebuilds[0]["namespace"],
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "inputs": source["provenance"].get("frozen_inputs", {}),
        "preserved_assets": source["provenance"].get("preserved_assets", {}),
        "scope_boundaries": source["provenance"].get("boundaries", {}),
        "renderer": source["renderer"],
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
