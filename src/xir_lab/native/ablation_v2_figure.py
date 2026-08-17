"""Deterministic main-text figure for the final native-ablation-v2 publication.

This module is deliberately a renderer, not an analyzer.  It accepts only the
administrator-bound ``native-ablation-v2`` scale publication, verifies the
source and two offline rebuild manifests, and selects already-computed cell
means and paired adjacent-layer intervals.  It never reads a run database,
recomputes an interval, or accepts ``native-ablation-v1`` revision evidence.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import jsonschema

INPUT_NAMESPACE = "native-ablation-v2"
INPUT_RESULT_ROLE = "final_mechanism_cost_estimate"
OUTPUT_NAMESPACE = "native-ablation-v2-main-figure-v1"

ROUTES = ("HL", "LH")
LAYERS = ("B0", "B1", "B2", "B3")
INCREMENTS = ("B0->B1", "B1->B2", "B2->B3")
METRICS = (
    ("complete_gas", "Complete-route gas\n(k gas)", "gas", 1_000.0, "k gas"),
    ("complete_calldata", "Complete-route calldata\n(kB)", "bytes", 1_000.0, "kB"),
    ("latency_seconds", "End-to-end latency\n(s)", "seconds", 1.0, "s"),
)

WIDTH_MM = 131.6
HEIGHT_MM = 62.0
WIDTH_INCHES = WIDTH_MM / 25.4
HEIGHT_INCHES = HEIGHT_MM / 25.4
FONT_ROLES = (10.2, 8.3, 7.1)
OCCUPANCY = 0.618
OCCUPANCY_TOLERANCE = 0.015

NAVY = "#16324F"
BLUE = "#2563A6"
AMBER = "#D98B2B"
PALETTE = {"neutral_and_baseline": NAVY, "HL": BLUE, "LH": AMBER}
FIGURE_1_SHA256 = "f2b694773e3db3312a745e40098995e075738df4de04f9bd5844a0da27ec3746"

REQUIRED_PUBLICATION_FILES = (
    "analysis.json",
    "validation.json",
    "cell-summary.csv",
    "paired-deltas.csv",
)


class AblationV2FigureError(ValueError):
    """Raised when a frozen input or deterministic figure contract fails."""


def sha256(path: Path) -> str:
    """Return a streaming SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AblationV2FigureError(message)


def _read_json(path: Path) -> dict[str, Any]:
    _require(path.is_file(), f"missing JSON input: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(value, dict), f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _schema_root(repository_root: Path) -> Path:
    candidates = (
        repository_root / "xir-testnet-lab" / "schemas",
        repository_root / "schemas",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise AblationV2FigureError("cannot locate xir-testnet-lab schemas")


def _validate_schema(document: dict[str, Any], schema_path: Path) -> None:
    schema = _read_json(schema_path)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise AblationV2FigureError(
            f"{schema_path.name} violation at {location}: {errors[0].message}"
        )


def _manifest_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise AblationV2FigureError("ablation input manifest files must be a list")
    indexed: dict[str, dict[str, Any]] = {}
    for value in files:
        _require(isinstance(value, dict), "manifest file entry must be an object")
        item = cast(dict[str, Any], value)
        name = str(item.get("path", ""))
        _require(bool(name) and name not in indexed, f"duplicate or empty manifest path: {name!r}")
        indexed[name] = item
    return indexed


def _verify_publication_manifest(
    *, publication: Path, schema_root: Path, label: str
) -> dict[str, Any]:
    """Verify one source or offline-rebuild publication without trusting its report."""

    manifest_path = publication / "manifest.json"
    sidecar_path = publication / "manifest.sha256"
    manifest = _read_json(manifest_path)
    _require(
        manifest.get("namespace") == INPUT_NAMESPACE,
        f"{label} manifest is not {INPUT_NAMESPACE}",
    )
    _validate_schema(manifest, schema_root / "native-ablation-v2-manifest.schema.json")
    _require(sidecar_path.is_file(), f"{label} has no manifest.sha256")
    sidecar_parts = sidecar_path.read_text(encoding="utf-8").split()
    _require(bool(sidecar_parts), f"{label} manifest sidecar is empty")
    manifest_sha = sha256(manifest_path)
    _require(sidecar_parts[0] == manifest_sha, f"{label} manifest sidecar digest mismatch")

    index = _manifest_index(manifest)
    missing = sorted(set(REQUIRED_PUBLICATION_FILES) - set(index))
    _require(not missing, f"{label} manifest omits required files: {missing}")
    for name, item in index.items():
        path = publication / name
        _require(path.is_file(), f"{label} manifest names missing file: {name}")
        _require(path.stat().st_size == int(item["bytes"]), f"{label} size mismatch: {name}")
        _require(sha256(path) == item["sha256"], f"{label} digest mismatch: {name}")

    publication_validation = _read_json(publication / "publication-validation.json")
    _require(publication_validation.get("valid") is True, f"{label} publication is not valid")
    _require(
        not publication_validation.get("manifest_mismatches", []),
        f"{label} publication reports manifest mismatches",
    )
    _require(
        not publication_validation.get("forbidden_publishable_content", []),
        f"{label} publication reports forbidden content",
    )
    return {
        "manifest_sha256": manifest_sha,
        "file_sha256": {name: str(item["sha256"]) for name, item in index.items()},
    }


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _validate_cell_csv(
    publication: Path, cell_rows: list[dict[str, Any]]
) -> None:
    csv_rows = _load_csv(publication / "cell-summary.csv")
    indexed = {(row["route"], row["layer"]): row for row in csv_rows}
    _require(len(indexed) == 8, "cell-summary.csv must contain eight unique cells")
    for cell in cell_rows:
        key = (str(cell["route"]), str(cell["layer"]))
        _require(key in indexed, f"cell-summary.csv omits {key}")
        csv_row = indexed[key]
        _require(int(csv_row["n"]) == int(cell["n"]), f"cell n mismatch for {key}")
        for metric, _, _, _, _ in METRICS:
            field = f"{metric}_mean"
            _require(
                math.isclose(float(csv_row[field]), float(cell[field]), rel_tol=0, abs_tol=1e-12),
                f"cell-summary.csv {field} mismatch for {key}",
            )


def _validate_delta_csv(
    publication: Path, delta_rows: list[dict[str, Any]]
) -> None:
    csv_rows = _load_csv(publication / "paired-deltas.csv")
    indexed = {
        (row["route"], row["increment"], row["metric"], row["statistic"]): row
        for row in csv_rows
    }
    for row in delta_rows:
        key = (
            str(row["route"]),
            str(row["increment"]),
            str(row["metric"]),
            str(row["statistic"]),
        )
        _require(key in indexed, f"paired-deltas.csv omits {key}")
        csv_row = indexed[key]
        for field in ("estimate", "ci_low", "ci_high", "confidence"):
            _require(
                math.isclose(
                    float(csv_row[field]), float(row[field]), rel_tol=0, abs_tol=1e-12
                ),
                f"paired-deltas.csv {field} mismatch for {key}",
            )
        _require(int(csv_row["n_pairs"]) == int(row["n_pairs"]), f"n_pairs mismatch for {key}")


def _select_rows(analysis: dict[str, Any], source_publication: Path) -> list[dict[str, Any]]:
    cell_summary = cast(list[dict[str, Any]], analysis["cell_summary"])
    paired_deltas = cast(list[dict[str, Any]], analysis["paired_deltas"])
    cells = {(str(row["route"]), str(row["layer"])): row for row in cell_summary}
    expected_cells = {(route, layer) for route in ROUTES for layer in LAYERS}
    _require(set(cells) == expected_cells and len(cell_summary) == 8, "expected 2 x 4 cells")
    _require(all(int(row["n"]) == 1_000 for row in cell_summary), "each cell must contain 1,000 attempts")

    selected_deltas = [
        row
        for row in paired_deltas
        if row.get("statistic") == "mean"
        and row.get("metric") in {metric[0] for metric in METRICS}
    ]
    deltas = {
        (str(row["route"]), str(row["metric"]), str(row["increment"])): row
        for row in selected_deltas
    }
    expected_deltas = {
        (route, metric, increment)
        for route in ROUTES
        for metric, _, _, _, _ in METRICS
        for increment in INCREMENTS
    }
    _require(
        set(deltas) == expected_deltas and len(selected_deltas) == 18,
        "expected 18 paired mean increment rows",
    )

    rows: list[dict[str, Any]] = []
    for route in ROUTES:
        for metric, _, unit, _, _ in METRICS:
            previous_total: float | None = None
            for layer_index, layer in enumerate(LAYERS):
                cell = cells[(route, layer)]
                total = float(cell[f"{metric}_mean"])
                _require(math.isfinite(total) and total > 0, f"invalid complete mean for {route}/{layer}/{metric}")
                if layer_index == 0:
                    row = {
                        "route": route,
                        "metric": metric,
                        "unit": unit,
                        "layer": layer,
                        "n_attempts": int(cell["n"]),
                        "complete_route_mean": total,
                        "increment": None,
                        "paired_increment_mean": None,
                        "paired_ci_low": None,
                        "paired_ci_high": None,
                        "n_pairs": None,
                        "confidence": None,
                        "bootstrap_block_length": None,
                        "bootstrap_repetitions": None,
                        "interval_scope": "none_for_B0_baseline",
                    }
                else:
                    increment = INCREMENTS[layer_index - 1]
                    delta = deltas[(route, metric, increment)]
                    estimate = float(delta["estimate"])
                    low = float(delta["ci_low"])
                    high = float(delta["ci_high"])
                    _require(
                        all(math.isfinite(value) for value in (estimate, low, high)),
                        f"non-finite paired interval for {route}/{metric}/{increment}",
                    )
                    _require(low <= estimate <= high, f"invalid paired interval for {route}/{metric}/{increment}")
                    _require(float(delta["confidence"]) == 0.95, "all intervals must be 95%")
                    _require(int(delta["n_pairs"]) == 1_000, "each paired increment must contain 1,000 pairs")
                    if previous_total is None:
                        raise AblationV2FigureError("paired increment has no previous level")
                    _require(
                        math.isclose(
                            total - previous_total,
                            estimate,
                            rel_tol=1e-12,
                            abs_tol=1e-6,
                        ),
                        f"paired estimate does not equal matched mean difference for {route}/{metric}/{increment}",
                    )
                    row = {
                        "route": route,
                        "metric": metric,
                        "unit": unit,
                        "layer": layer,
                        "n_attempts": int(cell["n"]),
                        "complete_route_mean": total,
                        "increment": increment,
                        "paired_increment_mean": estimate,
                        "paired_ci_low": low,
                        "paired_ci_high": high,
                        "n_pairs": int(delta["n_pairs"]),
                        "confidence": float(delta["confidence"]),
                        "bootstrap_block_length": int(delta["block_length"]),
                        "bootstrap_repetitions": int(delta["bootstrap_repetitions"]),
                        "interval_scope": "one_adjacent_paired_increment_only",
                    }
                rows.append(row)
                previous_total = total

    _validate_cell_csv(source_publication, cell_summary)
    _validate_delta_csv(source_publication, selected_deltas)
    _require(len(rows) == 24, "figure source must contain 24 route/metric/layer rows")
    return rows


def load_frozen_rows(
    *,
    repository_root: Path,
    source_publication: Path,
    rebuild_a_publication: Path,
    rebuild_b_publication: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate the final v2 triplet and select figure rows without recomputation."""

    schema_root = _schema_root(repository_root)
    analysis = _read_json(source_publication / "analysis.json")
    # This explicit gate intentionally runs before schema validation.  Passing a
    # valid native-ablation-v1 tree is a hard error, never a compatibility path.
    _require(
        analysis.get("namespace") == INPUT_NAMESPACE,
        f"refusing non-final ablation namespace: {analysis.get('namespace')!r}",
    )
    _require(
        analysis.get("result_role") == INPUT_RESULT_ROLE,
        f"refusing non-final result role: {analysis.get('result_role')!r}",
    )
    _require(analysis.get("phase") == "scale", "the main figure requires the scale phase")
    _validate_schema(analysis, schema_root / "native-ablation-v2-analysis.schema.json")
    validation = _read_json(source_publication / "validation.json")
    _validate_schema(validation, schema_root / "native-ablation-v2-validation.schema.json")
    _require(analysis.get("validation") == validation, "analysis/validation documents differ")
    _require(validation.get("valid") is True, "ablation-v2 experiment validation is false")
    _require(int(analysis["attempt_count"]) == 8_000, "expected exactly 8,000 attempts")
    _require(int(validation["expected_attempts"]) == 8_000, "expected_attempts changed")
    _require(int(validation["reconciled_attempts"]) == 8_000, "reconciled_attempts changed")
    _require(int(validation["application_effects"]) == 8_000, "application_effects changed")
    _require(not validation["reconciliation_errors"], "reconciliation_errors is not empty")
    expected_counts = {f"{route}_{layer}": 1_000 for route in ROUTES for layer in LAYERS}
    _require(validation["cell_counts"] == expected_counts, "cell denominator is not 8 x 1,000")
    for gate in (
        "scale_minimum_satisfied",
        "physical_lineage_complete",
        "retry_free_complete_lineage",
        "administrator_prior_binding_required",
        "administrator_prior_binding_valid",
        "final_revision_source_lock_required",
        "final_revision_source_lock_valid",
        "onchain_prior_binding_valid",
    ):
        _require(validation.get(gate) is True, f"required final-revision gate failed: {gate}")

    source_manifest = _verify_publication_manifest(
        publication=source_publication, schema_root=schema_root, label="source publication"
    )
    rebuild_a_manifest = _verify_publication_manifest(
        publication=rebuild_a_publication, schema_root=schema_root, label="rebuild A"
    )
    rebuild_b_manifest = _verify_publication_manifest(
        publication=rebuild_b_publication, schema_root=schema_root, label="rebuild B"
    )
    _require(
        rebuild_a_manifest["manifest_sha256"] == rebuild_b_manifest["manifest_sha256"],
        "offline rebuild manifests are not byte-identical",
    )
    for name in REQUIRED_PUBLICATION_FILES:
        digests = {
            source_manifest["file_sha256"][name],
            rebuild_a_manifest["file_sha256"][name],
            rebuild_b_manifest["file_sha256"][name],
        }
        _require(len(digests) == 1, f"source/rebuild bytes differ for {name}")

    figure_one = repository_root / "main" / "figures" / "protocol-xir-reachability-topology.pdf"
    _require(sha256(figure_one) == FIGURE_1_SHA256, "frozen Figure 1 changed")
    rows = _select_rows(analysis, source_publication)
    provenance = {
        "input_namespace": INPUT_NAMESPACE,
        "input_result_role": INPUT_RESULT_ROLE,
        "input_phase": "scale",
        "analysis_sha256": sha256(source_publication / "analysis.json"),
        "validation_sha256": sha256(source_publication / "validation.json"),
        "source_manifest_sha256": source_manifest["manifest_sha256"],
        "rebuild_a_manifest_sha256": rebuild_a_manifest["manifest_sha256"],
        "rebuild_b_manifest_sha256": rebuild_b_manifest["manifest_sha256"],
        "input_semantic_digest": analysis["semantic_digest"],
        "figure_1_sha256": FIGURE_1_SHA256,
        "statistics_recomputed": False,
    }
    return rows, provenance


def _write_source_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


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
            "axes.linewidth": 0.65,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-ablation-v2-main-figure-v1",
        }
    )
    import matplotlib.pyplot as plt

    return matplotlib, plt


def _format_total(metric: str, value: float) -> str:
    if metric == "complete_gas":
        return f"{value / 1_000:.0f}k"
    if metric == "complete_calldata":
        return f"{value / 1_000:.1f}k"
    return f"{value:.1f}"


def _render(pdf_path: Path, svg_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    matplotlib, plt = _matplotlib()
    import matplotlib.ticker as ticker
    import numpy as np

    figure = plt.figure(figsize=(WIDTH_INCHES, HEIGHT_INCHES))
    grid = figure.add_gridspec(
        2,
        3,
        left=0.11,
        right=0.97,
        bottom=0.21,
        top=0.62,
        wspace=0.36,
        hspace=0.48,
    )
    axes = [[figure.add_subplot(grid[row, column]) for column in range(3)] for row in range(2)]
    indexed = {(row["route"], row["metric"], row["layer"]): row for row in rows}

    for route_index, route in enumerate(ROUTES):
        color = PALETTE[route]
        for metric_index, (metric, title, _, scale, unit_label) in enumerate(METRICS):
            axis = axes[route_index][metric_index]
            levels = [
                float(indexed[(route, metric, layer)]["complete_route_mean"]) / scale
                for layer in LAYERS
            ]
            axis.bar(
                [0],
                [levels[0]],
                width=0.50,
                color=NAVY,
                edgecolor=NAVY,
                alpha=0.13,
                linewidth=0.85,
                zorder=2,
            )
            for layer_index in range(1, len(LAYERS)):
                row = indexed[(route, metric, LAYERS[layer_index])]
                previous = levels[layer_index - 1]
                estimate = float(row["paired_increment_mean"]) / scale
                low = float(row["paired_ci_low"]) / scale
                high = float(row["paired_ci_high"]) / scale
                bottom = min(previous, previous + estimate)
                axis.bar(
                    [layer_index - 0.07],
                    [abs(estimate)],
                    bottom=[bottom],
                    width=0.40,
                    color=color,
                    edgecolor=color,
                    alpha=0.18,
                    linewidth=0.85,
                    zorder=2,
                )
                endpoint = previous + estimate
                axis.errorbar(
                    [layer_index + 0.18],
                    [endpoint],
                    yerr=[[estimate - low], [high - estimate]],
                    fmt="none",
                    ecolor=color,
                    elinewidth=1.05,
                    capsize=2.2,
                    capthick=1.05,
                    zorder=4,
                )
            x = np.arange(len(LAYERS), dtype=float)
            axis.plot(
                x,
                levels,
                color=color,
                linewidth=1.05,
                marker="o",
                markersize=3.4,
                markerfacecolor="white",
                markeredgewidth=1.0,
                zorder=3,
            )
            maximum = max(levels)
            minimum = min(0.0, *(levels[index] for index in range(len(levels))))
            span = maximum - minimum
            axis.set_ylim(minimum - span * 0.04, maximum + span * 0.24)
            axis.set_xlim(-0.42, 3.42)
            axis.set_xticks(range(4), LAYERS)
            axis.yaxis.set_major_locator(ticker.MaxNLocator(nbins=3, min_n_ticks=2))
            axis.grid(axis="y", color=NAVY, alpha=0.16, linestyle=":", linewidth=0.6)
            axis.set_axisbelow(True)
            axis.spines[["top", "right"]].set_visible(False)
            axis.spines[["left", "bottom"]].set_color(NAVY)
            axis.tick_params(colors=NAVY, length=2.0, width=0.6, pad=1.5)
            if route_index == 0:
                axis.set_title(title, color=NAVY, pad=2.5, linespacing=0.95)
            axis.text(
                0,
                levels[0] + span * 0.055,
                _format_total(metric, float(indexed[(route, metric, "B0")]["complete_route_mean"])),
                color=NAVY,
                ha="center",
                va="bottom",
                fontsize=FONT_ROLES[2],
            )
            axis.text(
                3,
                levels[3] + span * 0.055,
                _format_total(metric, float(indexed[(route, metric, "B3")]["complete_route_mean"])),
                color=color,
                ha="center",
                va="bottom",
                fontsize=FONT_ROLES[2],
                fontweight="bold",
            )

    figure.text(
        0.11,
        0.965,
        "Cost added by nested XIR mechanisms",
        ha="left",
        va="top",
        fontsize=FONT_ROLES[0],
        fontweight="bold",
        color=NAVY,
    )
    figure.text(
        0.11,
        0.895,
        "8,000 matched attempts · 1,000 per route × layer · primary sample",
        ha="left",
        va="top",
        fontsize=FONT_ROLES[1],
        color=NAVY,
    )
    mechanism_labels = (
        "B0\nNative two-hop",
        "B1\n+ record / mid",
        "B2\n+ receipts / lineage",
        "B3\n+ registry / delivery",
    )
    mechanism_x = (0.19, 0.415, 0.64, 0.865)
    for x_position, label in zip(mechanism_x, mechanism_labels, strict=True):
        figure.text(
            x_position,
            0.805,
            label,
            ha="center",
            va="center",
            fontsize=FONT_ROLES[2],
            fontweight="bold" if label.startswith("B") else "normal",
            color=NAVY,
            linespacing=0.95,
        )
    figure.text(
        0.025,
        0.535,
        "HL\nH→L",
        ha="center",
        va="center",
        fontsize=FONT_ROLES[1],
        fontweight="bold",
        color=BLUE,
    )
    figure.text(
        0.025,
        0.295,
        "LH\nL→H",
        ha="center",
        va="center",
        fontsize=FONT_ROLES[1],
        fontweight="bold",
        color=AMBER,
    )
    figure.text(
        0.11,
        0.112,
        "Dot = complete mean · bar = adjacent increment · whisker = paired 95% interval",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
        color=NAVY,
    )
    figure.text(
        0.11,
        0.070,
        "Intervals belong to one step; do not add them across B0→B3.",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
        color=NAVY,
    )
    figure.text(
        0.11,
        0.028,
        "Complete route includes coordinator, carrier, and worker transactions.",
        ha="left",
        va="bottom",
        fontsize=FONT_ROLES[2],
        color=NAVY,
    )

    pdf_metadata = {
        "Title": "Native-ablation-v2 mechanism cost",
        "Creator": "XIR deterministic native-ablation-v2 figure renderer",
        "CreationDate": None,
        "ModDate": None,
    }
    svg_metadata = {
        "Title": "Native-ablation-v2 mechanism cost",
        "Creator": "XIR deterministic native-ablation-v2 figure renderer",
        "Date": None,
    }
    figure.savefig(pdf_path, format="pdf", dpi=300, metadata=pdf_metadata)
    figure.savefig(svg_path, format="svg", metadata=svg_metadata)
    plt.close(figure)
    return {"python": sys.version.split()[0], "matplotlib": matplotlib.__version__}


def _pdf_audit(path: Path) -> dict[str, Any]:
    font_output = subprocess.run(
        ["pdffonts", str(path)], check=True, capture_output=True, text=True
    ).stdout
    font_rows = []
    for line in font_output.splitlines()[2:]:
        columns = line.split()
        if len(columns) >= 8:
            font_rows.append(
                {
                    "name": columns[0],
                    "embedded": columns[-5] == "yes",
                    "truetype": "TrueType" in line,
                }
            )
    _require(bool(font_rows), "PDF contains no auditable font")
    _require(all(row["embedded"] for row in font_rows), "PDF fonts are not embedded")
    _require(all(row["truetype"] for row in font_rows), "PDF fonts are not TrueType/Type42")

    info = subprocess.run(
        ["pdfinfo", str(path)], check=True, capture_output=True, text=True
    ).stdout
    match = re.search(r"Page size:\s+([0-9.]+) x ([0-9.]+) pts", info)
    if match is None:
        raise AblationV2FigureError("cannot parse PDF page size")
    width_points, height_points = (float(match.group(1)), float(match.group(2)))
    _require(abs(width_points - WIDTH_INCHES * 72) <= 0.02, "PDF width is not 131.6 mm")
    _require(abs(height_points - HEIGHT_INCHES * 72) <= 0.02, "PDF height changed")
    _require(height_points <= 62.0 / 25.4 * 72 + 0.02, "PDF exceeds 62 mm height")
    return {
        "page_size_points": [width_points, height_points],
        "native_width_mm": WIDTH_MM,
        "native_height_mm": HEIGHT_MM,
        "fonts": font_rows,
        "all_fonts_embedded": True,
        "all_fonts_truetype_type42": True,
    }


def _svg_audit(path: Path) -> dict[str, bool]:
    content = path.read_text(encoding="utf-8")
    result = {
        "text_converted_to_paths": "<text" not in content,
        "no_external_href": 'href="http' not in content,
        "no_external_image": "<image" not in content,
    }
    _require(all(result.values()), "SVG is not self-contained")
    return result


def _visual_audit(pdf_path: Path, svg_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "xir-native-ablation-v2-figure-visual-audit-v1",
        "valid": True,
        "native_width_mm": WIDTH_MM,
        "native_height_mm": HEIGHT_MM,
        "font_roles": [
            {"role": "headline", "points": FONT_ROLES[0]},
            {"role": "panel and subtitle", "points": FONT_ROLES[1]},
            {"role": "values, ticks, mechanisms, and reading key", "points": FONT_ROLES[2]},
        ],
        "minimum_native_font_points": min(FONT_ROLES),
        "line_styles": ["solid data, axes, and paired intervals", "dotted y-grid"],
        "palette": PALETTE,
        "tints": "alpha-only tints of the three base colors",
        "nominal_content_region_occupancy": OCCUPANCY,
        "occupancy_tolerance": OCCUPANCY_TOLERANCE,
        "occupancy_definition": "grid + header + mechanism strip + footer envelopes; internal whitespace counts",
        "occupancy_calculation": "0.86*(0.41 + 0.11 + 0.09 + 0.1086046512) = 0.618",
        "pdf": _pdf_audit(pdf_path),
        "svg": _svg_audit(svg_path),
        "teaching_cues": [
            "B0 through B3 are decoded before the panels",
            "HL and LH occupy separate rows",
            "gas, calldata, and latency occupy separate columns",
            "the reading key distinguishes complete means from adjacent paired intervals",
            "the non-additivity warning appears inside the figure",
        ],
    }


def _write_report(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Native-ablation-v2 main-text mechanism-cost figure",
        "",
        "The renderer selects frozen primary means and paired intervals; it recomputes no statistic.",
        "The source contains 8,000 attempts: 1,000 for every HL/LH × B0--B3 cell.",
        "HL and LH remain separate in the figure, source table, and caption.",
        "Each whisker belongs to one adjacent paired increment. Adjacent confidence intervals are not summed or presented as a confidence interval for a cumulative total.",
        "",
        "Suggested caption: Complete-route cost in the 8,000-attempt matched native-ablation-v2 campaign. Each route-layer cell contains 1,000 attempts. Dots mark complete-route means; floating bars show paired adjacent increments, and whiskers show 95% moving-block intervals for that single increment. Adjacent intervals are not additive. Complete-route totals include coordinator, native-carrier, and worker transactions.",
        "",
        f"Machine-readable rows: {len(rows)}.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _build_artifact(
    *,
    rows: list[dict[str, Any]],
    provenance: dict[str, Any],
    output_directory: Path,
) -> dict[str, Any]:
    _require(not output_directory.exists(), f"refusing to overwrite output: {output_directory}")
    output_directory.mkdir(parents=True)
    stem = "mechanism-cost-v2"
    csv_path = output_directory / f"{stem}-source.csv"
    json_path = output_directory / f"{stem}-source.json"
    pdf_path = output_directory / f"{stem}.pdf"
    svg_path = output_directory / f"{stem}.svg"
    _write_source_csv(csv_path, rows)
    renderer = _render(pdf_path, svg_path, rows)
    source: dict[str, Any] = {
        "schema_version": "xir-native-ablation-v2-figure-source-v1",
        "namespace": OUTPUT_NAMESPACE,
        "input_namespace": INPUT_NAMESPACE,
        "input_result_role": INPUT_RESULT_ROLE,
        "figure_role": "main-text complete-route mechanism cost",
        "question": "What complete-route gas, calldata, and latency does each nested mechanism add?",
        "statistics_recomputed": False,
        "denominator": {
            "attempts": 8_000,
            "routes": list(ROUTES),
            "layers": list(LAYERS),
            "attempts_per_route_layer_cell": 1_000,
        },
        "interval_semantics": {
            "confidence": 0.95,
            "scope": "one adjacent matched increment",
            "anchoring": "drawn beside the upper-layer endpoint after adding the paired estimate to the prior-layer mean",
            "cross_layer_aggregation": "forbidden",
            "complete_route_interval_claimed": False,
        },
        "complete_route_includes": [
            "coordinator transactions",
            "Hyperlane processing transactions",
            "LayerZero worker transactions",
        ],
        "provenance": provenance,
        "rows": rows,
        "renderer": renderer,
        "renderer_sha256": sha256(Path(__file__)),
    }
    _write_json(json_path, source)
    visual = _visual_audit(pdf_path, svg_path)
    _write_json(output_directory / "visual-audit.json", visual)
    checks = {
        "input_namespace_is_native_ablation_v2": provenance["input_namespace"] == INPUT_NAMESPACE,
        "result_role_is_final_mechanism_cost_estimate": provenance["input_result_role"]
        == INPUT_RESULT_ROLE,
        "scale_phase_only": provenance["input_phase"] == "scale",
        "source_and_rebuild_manifests_verified": bool(provenance["source_manifest_sha256"])
        and provenance["rebuild_a_manifest_sha256"] == provenance["rebuild_b_manifest_sha256"],
        "statistics_not_recomputed": source["statistics_recomputed"] is False,
        "exact_8000_attempt_denominator": source["denominator"]["attempts"] == 8_000,
        "exact_8_x_1000_cells": len(rows) == 24
        and {(row["route"], row["layer"]) for row in rows}
        == {(route, layer) for route in ROUTES for layer in LAYERS}
        and all(row["n_attempts"] == 1_000 for row in rows),
        "three_complete_route_metrics": {row["metric"] for row in rows}
        == {metric[0] for metric in METRICS},
        "hl_lh_separate": {row["route"] for row in rows} == set(ROUTES),
        "all_18_paired_intervals_present": len(
            [row for row in rows if row["interval_scope"] == "one_adjacent_paired_increment_only"]
        )
        == 18,
        "paired_intervals_are_95_percent": all(
            row["confidence"] == 0.95 for row in rows if row["confidence"] is not None
        ),
        "paired_intervals_not_aggregated": source["interval_semantics"]["cross_layer_aggregation"]
        == "forbidden"
        and source["interval_semantics"]["complete_route_interval_claimed"] is False,
        "native_width_is_131_6_mm": visual["pdf"]["native_width_mm"] == 131.6,
        "native_height_at_most_62_mm": visual["pdf"]["native_height_mm"] <= 62.0,
        "minimum_font_at_least_7_1_pt": visual["minimum_native_font_points"] >= 7.1,
        "font_roles_at_most_3": len(visual["font_roles"]) <= 3,
        "line_styles_at_most_3": len(visual["line_styles"]) <= 3,
        "palette_is_navy_blue_amber": visual["palette"] == PALETTE,
        "occupancy_within_tolerance": abs(
            visual["nominal_content_region_occupancy"] - OCCUPANCY
        )
        <= OCCUPANCY_TOLERANCE,
        "pdf_fonts_embedded_truetype": visual["pdf"]["all_fonts_embedded"]
        and visual["pdf"]["all_fonts_truetype_type42"],
        "svg_self_contained": all(visual["svg"].values()),
        "frozen_figure_1_unchanged": provenance["figure_1_sha256"] == FIGURE_1_SHA256,
    }
    _require(all(checks.values()), f"ablation-v2 figure validation failed: {checks}")
    validation = {
        "schema_version": "xir-native-ablation-v2-figure-validation-v1",
        "namespace": OUTPUT_NAMESPACE,
        "valid": True,
        "checks": checks,
    }
    _write_json(output_directory / "validation.json", validation)
    _write_report(output_directory / "REPORT.md", rows)
    semantic = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "source_semantic_sha256": semantic,
        "files": {
            path.name: sha256(path)
            for path in sorted(output_directory.iterdir())
            if path.is_file()
        },
    }


def build_two_rebuild_publication(
    *,
    repository_root: Path,
    source_publication: Path,
    rebuild_a_publication: Path,
    rebuild_b_publication: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build twice, require byte identity, and publish rebuild A."""

    _require(not output_root.exists(), f"refusing to overwrite namespace: {output_root}")
    rows, provenance = load_frozen_rows(
        repository_root=repository_root,
        source_publication=source_publication,
        rebuild_a_publication=rebuild_a_publication,
        rebuild_b_publication=rebuild_b_publication,
    )
    output_root.mkdir(parents=True)
    rebuilds = [
        _build_artifact(
            rows=rows,
            provenance=provenance,
            output_directory=output_root / name,
        )
        for name in ("rebuild-a", "rebuild-b")
    ]
    _require(rebuilds[0] == rebuilds[1], "figure rebuilds are not byte-identical")

    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-native-ablation-v2-figure-rebuild-comparison-v1",
        "namespace": OUTPUT_NAMESPACE,
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "byte_identical_files": rebuilds[0]["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    manifest = {
        "schema_version": "xir-native-ablation-v2-figure-manifest-v1",
        "namespace": OUTPUT_NAMESPACE,
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
        "namespace": OUTPUT_NAMESPACE,
        "publication": str(publication),
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "pdf_sha256": rebuilds[0]["files"]["mechanism-cost-v2.pdf"],
        "svg_sha256": rebuilds[0]["files"]["mechanism-cost-v2.svg"],
        "valid": True,
    }
