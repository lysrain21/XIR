#!/usr/bin/env python3
"""Render the deterministic paper-ready native-faults-v1 overview."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import jsonschema
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch, Rectangle

NAVY = "#16324F"
TEAL = "#1B8A83"
AMBER = "#D98B2B"
PAPER = "#FFFFFF"
PALE = "#F4F7F8"
FIXED_DATE = datetime(2026, 8, 7, tzinfo=UTC)

SCENARIOS = (
    ("pre_intent", "C1", "Before durable intent", "coordinator"),
    ("post_intent_pre_sign", "C2", "Intent durable; before sign", "coordinator"),
    ("post_sign_pre_broadcast", "C3", "Signed; before broadcast", "coordinator"),
    (
        "post_broadcast_pre_acknowledgement",
        "C4",
        "Broadcast; before local ack",
        "coordinator",
    ),
    (
        "post_acknowledgement_pre_mining",
        "C5",
        "Acknowledged; before mining",
        "coordinator",
    ),
    (
        "post_mining_pre_persistence",
        "C6",
        "Mined; before receipt persist",
        "coordinator",
    ),
    (
        "post_persistence_pre_stage_commit",
        "C7",
        "Receipt durable; before commit",
        "coordinator",
    ),
    (
        "worker_action_post_submit",
        "W1",
        "Worker action submitted",
        "worker",
    ),
    (
        "transient_retry_after_broadcast",
        "R1",
        "Transient retry after broadcast",
        "retry",
    ),
    ("concurrent_retry", "R2", "Two recoveries, one signed tx", "retry"),
)

SIGNED_TX_REUSE = {
    "pre_intent": "not signed",
    "post_intent_pre_sign": "not signed",
    "post_sign_pre_broadcast": "same tx",
    "post_broadcast_pre_acknowledgement": "same tx",
    "post_acknowledgement_pre_mining": "same tx",
    "post_mining_pre_persistence": "mined tx",
    "post_persistence_pre_stage_commit": "mined tx",
    "worker_action_post_submit": "worker tx",
    "transient_retry_after_broadcast": "same tx",
    "concurrent_retry": "same raw",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_matplotlib() -> None:
    mpl.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 7.0,
            "axes.linewidth": 0.0,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-faults-v1",
            "savefig.facecolor": PAPER,
            "figure.facecolor": PAPER,
        }
    )


def load_summary(path: Path, schema_root: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(
        (schema_root / "native-faults-v1-summary.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(document)
    return cast(dict[str, Any], document)


def panel_frame(ax: Axes, label: str, title: str) -> None:
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.add_patch(
        FancyBboxPatch(
            (0.0, 0.0),
            1.0,
            1.0,
            boxstyle="round,pad=0.012,rounding_size=0.025",
            facecolor=PAPER,
            edgecolor=NAVY,
            linewidth=0.8,
        )
    )
    ax.text(0.035, 0.948, label, color=TEAL, fontsize=8.0, fontweight="bold", va="top")
    ax.text(
        0.12,
        0.948,
        title,
        color=NAVY,
        fontsize=8.0,
        fontweight="bold",
        va="top",
    )


def draw_marker(ax: Axes, x: float, y: float, code: str, color: str) -> None:
    ax.add_patch(Circle((x, y), 0.028, facecolor=PAPER, edgecolor=color, linewidth=1.2))
    ax.text(
        x,
        y,
        code,
        ha="center",
        va="center",
        color=color,
        fontsize=5.7,
        fontweight="bold",
    )


def draw_lifecycle(ax: Axes) -> None:
    panel_frame(ax, "(a)", "Fault injection follows the durable lifecycle")
    stages = ("Plan", "Intent", "Sign", "Broadcast", "Ack", "Mine", "Persist", "Commit")
    stage_x = [0.07 + index * 0.125 for index in range(len(stages))]
    y = 0.735
    for index, (x, stage) in enumerate(zip(stage_x, stages, strict=True)):
        ax.add_patch(
            FancyBboxPatch(
                (x - 0.042, y - 0.026),
                0.084,
                0.052,
                boxstyle="round,pad=0.006,rounding_size=0.014",
                facecolor=PALE,
                edgecolor=NAVY,
                linewidth=0.75,
            )
        )
        ax.text(x, y, stage, ha="center", va="center", color=NAVY, fontsize=5.7)
        if index < len(stages) - 1:
            ax.add_patch(
                FancyArrowPatch(
                    (x + 0.045, y),
                    (stage_x[index + 1] - 0.045, y),
                    arrowstyle="-|>",
                    mutation_scale=6,
                    linewidth=0.8,
                    color=NAVY,
                )
            )

    coordinator_x = [
        (stage_x[0] + stage_x[1]) / 2,
        (stage_x[1] + stage_x[2]) / 2,
        (stage_x[2] + stage_x[3]) / 2,
        (stage_x[3] + stage_x[4]) / 2,
        (stage_x[4] + stage_x[5]) / 2,
        (stage_x[5] + stage_x[6]) / 2,
        (stage_x[6] + stage_x[7]) / 2,
    ]
    for index, x in enumerate(coordinator_x, start=1):
        ax.plot([x, x], [0.68, y - 0.028], color=TEAL, linewidth=0.7)
        draw_marker(ax, x, 0.65, f"C{index}", TEAL)
    ax.text(
        0.035,
        0.59,
        "coordinator process exits",
        color=TEAL,
        fontsize=5.6,
        fontweight="bold",
        va="center",
    )

    ax.plot([0.08, 0.92], [0.50, 0.50], color=NAVY, linewidth=0.75)
    ax.text(0.035, 0.535, "worker", color=NAVY, fontsize=5.7, fontweight="bold")
    worker_steps = ((0.22, "sign"), (0.48, "submit"), (0.76, "finalize"))
    for x, label in worker_steps:
        ax.text(x, 0.50, label, ha="center", va="center", color=NAVY, fontsize=5.7)
    draw_marker(ax, 0.60, 0.50, "W1", AMBER)

    ax.text(0.035, 0.405, "retry", color=NAVY, fontsize=5.7, fontweight="bold")
    draw_marker(ax, 0.36, 0.405, "R2", AMBER)
    ax.text(0.405, 0.405, "same signed tx → two recoveries", color=NAVY, va="center")
    draw_marker(ax, 0.36, 0.335, "R1", AMBER)
    ax.text(0.405, 0.335, "broadcast side effect → transient retry", color=NAVY, va="center")

    legend_y = 0.235
    columns = (0.045, 0.38, 0.705)
    rows = (legend_y, legend_y - 0.075, legend_y - 0.15, legend_y - 0.225)
    for index, (_, code, label, category) in enumerate(SCENARIOS):
        column = index // 4
        row = index % 4
        x = columns[column]
        yy = rows[row]
        color = TEAL if category == "coordinator" else AMBER
        ax.text(x, yy, code, color=color, fontsize=5.7, fontweight="bold", va="center")
        ax.text(x + 0.048, yy, label, color=NAVY, fontsize=5.45, va="center")


def result_lookup(summary: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(group["route"]), str(group["scenario"])): group
        for group in cast(list[dict[str, Any]], summary["groups"])
    }


def draw_matrix(ax: Axes, summary: dict[str, Any]) -> None:
    panel_frame(ax, "(b)", "Every route recovers with one application effect")
    lookup = result_lookup(summary)
    routes = ("HL", "LH")
    left = 0.055
    label_width = 0.39
    reuse_width = 0.20
    cell_width = 0.135
    top = 0.855
    row_height = 0.068
    ax.text(left, top, "Boundary", color=NAVY, fontsize=6.0, fontweight="bold", va="center")
    ax.text(
        left + label_width + reuse_width / 2,
        top,
        "Recovery identity",
        color=NAVY,
        fontsize=5.7,
        fontweight="bold",
        ha="center",
        va="center",
    )
    for index, route in enumerate(routes):
        ax.text(
            left + label_width + reuse_width + cell_width * (index + 0.5),
            top,
            route,
            color=NAVY,
            fontsize=6.3,
            fontweight="bold",
            ha="center",
            va="center",
        )
    ax.plot([left, 0.945], [top - 0.035, top - 0.035], color=NAVY, linewidth=0.8)

    for row, (scenario, code, _, category) in enumerate(SCENARIOS):
        y = top - 0.072 - row * row_height
        color = TEAL if category == "coordinator" else AMBER
        ax.text(left, y, code, color=color, fontsize=5.8, fontweight="bold", va="center")
        short_name = scenario.replace("_", " ")
        if len(short_name) > 29:
            short_name = short_name[:27] + "…"
        ax.text(left + 0.065, y, short_name, color=NAVY, fontsize=5.3, va="center")
        reuse = SIGNED_TX_REUSE[scenario]
        ax.text(
            left + label_width + reuse_width / 2,
            y,
            reuse,
            color=TEAL if reuse in {"same tx", "same raw"} else NAVY,
            fontsize=5.25,
            fontweight="bold" if reuse == "same raw" else "normal",
            ha="center",
            va="center",
        )
        for column, route in enumerate(routes):
            group = lookup.get((route, scenario))
            total = 0 if group is None else int(group["repetitions"])
            validated = 0 if group is None else int(group["validated"])
            passed = total > 0 and validated == total
            x = left + label_width + reuse_width + column * cell_width
            ax.add_patch(
                Rectangle(
                    (x + 0.013, y - 0.022),
                    cell_width - 0.026,
                    0.044,
                    facecolor=TEAL if passed else AMBER,
                    edgecolor="none",
                    alpha=0.14,
                )
            )
            ax.text(
                x + cell_width / 2,
                y,
                f"{validated}/{total}",
                color=TEAL if passed else AMBER,
                fontsize=5.8,
                fontweight="bold",
                ha="center",
                va="center",
            )
    ax.text(
        0.055,
        0.085,
        "same tx = one nonce/hash lineage; same raw = identical raw bytes,\n"
        "hash, and nonce in both recoveries. Each validated cell has one effect.",
        color=NAVY,
        fontsize=5.6,
        va="bottom",
        linespacing=1.35,
    )


def render(summary: dict[str, Any], output_dir: Path, summary_path: Path) -> dict[str, Any]:
    configure_matplotlib()
    output_dir.mkdir(parents=True, exist_ok=True)
    figure = plt.figure(figsize=(11.6, 6.8), facecolor=PAPER)
    figure.text(
        0.06,
        0.955,
        "Controlled recovery preserves one logical and physical transaction identity",
        color=NAVY,
        fontsize=11.0,
        fontweight="bold",
        va="top",
    )
    figure.text(
        0.06,
        0.915,
        "Failures span coordinator, worker, and retry boundaries on both carrier orders.",
        color=NAVY,
        fontsize=6.8,
        va="top",
    )
    lifecycle = figure.add_axes((0.06, 0.10, 0.55, 0.78))
    matrix = figure.add_axes((0.67, 0.17, 0.28, 0.67))
    draw_lifecycle(lifecycle)
    draw_matrix(matrix, summary)

    pdf_path = output_dir / "recovery-overview.pdf"
    svg_path = output_dir / "recovery-overview.svg"
    csv_path = output_dir / "recovery-overview.csv"
    metadata = {
        "Title": "Native faults v1 recovery overview",
        "Author": "XIR research artifact",
        "Subject": "Controlled durable-boundary recovery",
        "Keywords": "XIR, recovery, fault injection",
        "Creator": "xir-testnet-lab",
        "Producer": "Matplotlib",
        "CreationDate": FIXED_DATE,
        "ModDate": FIXED_DATE,
    }
    figure.savefig(pdf_path, format="pdf", dpi=300, metadata=metadata)
    figure.savefig(
        svg_path,
        format="svg",
        dpi=300,
        metadata={"Date": FIXED_DATE.isoformat(), "Creator": "xir-testnet-lab"},
    )
    plt.close(figure)
    lookup = result_lookup(summary)
    csv_stream = io.StringIO(newline="")
    fields = (
        "code",
        "category",
        "route",
        "scenario",
        "boundary",
        "signed_tx_reuse",
        "effect_invariant",
        "validated",
        "planned",
    )
    writer = csv.DictWriter(csv_stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for scenario, code, _, category in SCENARIOS:
        for route in ("HL", "LH"):
            group = lookup[(route, scenario)]
            writer.writerow(
                {
                    "code": code,
                    "category": category,
                    "route": route,
                    "scenario": scenario,
                    "boundary": group["boundary"],
                    "signed_tx_reuse": SIGNED_TX_REUSE[scenario],
                    "effect_invariant": "exactly_one_destination_effect",
                    "validated": group["validated"],
                    "planned": group["repetitions"],
                }
            )
    csv_path.write_text(csv_stream.getvalue(), encoding="utf-8")
    source = {
        "schema_version": "xir-lab-native-faults-v1-figure-source-v1",
        "summary": str(summary_path),
        "summary_sha256": sha256(summary_path),
        "campaign_id": summary["campaign_id"],
        "validated_cases": summary["validated_cases"],
        "expected_cases": summary["expected_cases"],
        "renderer": {
            "python": sys.version.split()[0],
            "matplotlib": mpl.__version__,
        },
        "layout": {
            "lifecycle_axes": [0.06, 0.10, 0.55, 0.78],
            "matrix_axes": [0.67, 0.17, 0.28, 0.67],
            "nominal_content_region_occupancy": 0.6166,
            "font_roles": 3,
            "line_styles": 1,
            "palette": [NAVY, TEAL, AMBER],
        },
        "visual_semantics": {
            "not signed": "the failure occurs before a signed transaction exists",
            "same tx": "recovery preserves one nonce and transaction-hash lineage",
            "mined tx": "recovery reuses the already mined transaction lineage",
            "worker tx": "recovery preserves the submitted worker-action transaction lineage",
            "same raw": "both concurrent recovery processes reuse identical raw signed bytes, hash, and nonce",
            "matrix_cell": "validated/planned; validation includes exactly one destination effect",
        },
        "pdf_sha256": sha256(pdf_path),
        "svg_sha256": sha256(svg_path),
        "csv_sha256": sha256(csv_path),
    }
    (output_dir / "recovery-overview-source.json").write_text(
        json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = load_summary(args.summary, args.schema_root)
    source = render(summary, args.output_dir, args.summary)
    print(json.dumps(source, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
