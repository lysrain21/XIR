"""Deterministic Figure 8 family for multihop costs and deployment reachability."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, cast

import matplotlib
import numpy as np
import rfc8785

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_scalability import ROUTE_ORDER

MAIN_SIZE_MM = (190.0, 108.0)
APPENDIX_SIZE_MM = (190.0, 205.0)
DEPLOYMENT_SIZE_MM = (190.0, 72.0)
NAVY = "#16324F"
BLUE = "#2563A6"
AMBER = "#D98B2B"
GRAY = "#6B7280"
LIGHT = "#E8EDF2"
RED = "#B33A3A"
FONT_ROLES = (9.2, 7.8, 7.1)
ALLOWED_PALETTE = {
    NAVY.lower(),
    BLUE.lower(),
    AMBER.lower(),
    GRAY.lower(),
    LIGHT.lower(),
    RED.lower(),
    "#000000",
    "#ffffff",
    "#b0b0b0",
    "#cccccc",
    "#e4f3ee",
    "#f7f9fb",
    "#fff8ee",
}
SEMANTIC_ROLE_COLORS = {
    "xir-switching": BLUE.lower(),
    "xir-switching-stage": BLUE.lower(),
    "xir-equivalence": BLUE.lower(),
    "xir-observed": BLUE.lower(),
    "xir-gateway-placement": BLUE.lower(),
    "native-carrier-direction": AMBER.lower(),
    "native-prefix-stage": AMBER.lower(),
    "native-transport": AMBER.lower(),
    "control-homogeneous": GRAY.lower(),
    "control-theory": GRAY.lower(),
    "state-control": GRAY.lower(),
    "rejection-boundary": RED.lower(),
    "anomaly-not-equivalent": RED.lower(),
    "structural-upper-bound": NAVY.lower(),
}


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read figure input: {path}") from exc
    if not isinstance(value, dict):
        raise LocalTopologyError("figure input must be a JSON object")
    return cast(dict[str, Any], value)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _configure() -> None:
    matplotlib.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": FONT_ROLES[1],
            "text.color": "#000000",
            "axes.edgecolor": "#000000",
            "axes.labelcolor": "#000000",
            "axes.titlecolor": "#000000",
            "axes.titlesize": FONT_ROLES[0],
            "axes.labelsize": FONT_ROLES[1],
            "xtick.color": "#000000",
            "xtick.labelsize": FONT_ROLES[2],
            "ytick.color": "#000000",
            "ytick.labelsize": FONT_ROLES[2],
            "legend.fontsize": FONT_ROLES[2],
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-multihop-figure8-v1",
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def _rgba_hex(value: Any) -> str:
    return matplotlib.colors.to_hex(value, keep_alpha=False).lower()


def _register_semantic_artist(
    artist: Any,
    role: str,
    expected_color: str | None = None,
    *,
    color_source: str = "auto",
) -> Any:
    canonical = SEMANTIC_ROLE_COLORS.get(role)
    if canonical is None and role.startswith("native-protocol-expansion:"):
        canonical = AMBER.lower()
    if canonical is None:
        raise LocalTopologyError(f"Figure 8 semantic role is unregistered: {role}")
    if expected_color is not None and expected_color.lower() != canonical:
        raise LocalTopologyError(f"Figure 8 caller attempted a semantic color override: {role}")
    group = f"{role}:{id(artist)}"

    def register(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, (tuple, list)):
            for child in item:
                register(child)
            return
        item._xir_semantic_role = role
        item._xir_semantic_group = group
        item._xir_expected_color = canonical
        item._xir_semantic_color_source = color_source
        lines = getattr(item, "lines", None)
        if isinstance(lines, (tuple, list)):
            register(lines)

    register(artist)
    return artist


def _first_artist_color(artist: Any) -> str | None:
    source = getattr(artist, "_xir_semantic_color_source", "auto")
    if source == "edge":
        getter_order = ("get_edgecolor", "get_color", "get_facecolor")
    elif source == "face":
        getter_order = ("get_facecolor", "get_color", "get_edgecolor")
    else:
        getter_order = (
            ("get_color", "get_facecolor", "get_edgecolor")
            if isinstance(artist, matplotlib.patches.Patch)
            else ("get_color", "get_edgecolor", "get_facecolor")
        )
    for getter_name in getter_order:
        getter = getattr(artist, getter_name, None)
        if getter is None:
            continue
        try:
            raw = getter()
            if isinstance(raw, np.ndarray):
                if raw.size == 0:
                    continue
                raw = raw[0] if raw.ndim > 1 else raw
            rgba = matplotlib.colors.to_rgba(raw)
            if rgba[3] == 0:
                continue
            return _rgba_hex(rgba)
        except (TypeError, ValueError):
            continue
    return None


def _audit_figure_geometry_palette(
    fig: Any, *, expected_semantic_role_counts: dict[str, int] | None = None
) -> dict[str, Any]:
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    page = fig.bbox
    errors: list[str] = []
    tick_roles: dict[int, str] = {}
    for axis in fig.axes:
        tick_roles.update({id(item): "x" for item in axis.get_xticklabels()})
        tick_roles.update({id(item): "y" for item in axis.get_yticklabels()})
    text_boxes: list[tuple[str, Any, str | None]] = []
    for text_artist in fig.findobj(matplotlib.text.Text):
        if not text_artist.get_visible() or not text_artist.get_text().strip():
            continue
        bbox = text_artist.get_window_extent(renderer=renderer)
        if (
            bbox.x0 < page.x0 - 10
            or bbox.y0 < page.y0 - 10
            or bbox.x1 > page.x1 + 10
            or bbox.y1 > page.y1 + 10
        ):
            errors.append(
                "text-out-of-page:"
                f"{text_artist.get_text()[:40]}:"
                f"{bbox.x0:.1f},{bbox.y0:.1f},{bbox.x1:.1f},{bbox.y1:.1f}"
            )
        if float(text_artist.get_fontsize()) >= min(FONT_ROLES):
            text_boxes.append((text_artist.get_text(), bbox, tick_roles.get(id(text_artist))))
    for index, (left_text, left, left_tick) in enumerate(text_boxes):
        for right_text, right, right_tick in text_boxes[index + 1 :]:
            if left_tick is not None and right_tick is not None and left_tick != right_tick:
                # Orthogonal tick labels commonly touch at an axes corner; the
                # axes padding contract, not free-text overlap, governs them.
                continue
            width = max(0.0, min(left.x1, right.x1) - max(left.x0, right.x0))
            height = max(0.0, min(left.y1, right.y1) - max(left.y0, right.y0))
            intersection = width * height
            smaller = min(left.width * left.height, right.width * right.height)
            if smaller > 0 and intersection / smaller > 0.35:
                errors.append(f"text-overlap:{left_text[:24]}|{right_text[:24]}")
    axes_checks = []
    for index, axis in enumerate(fig.axes):
        bbox = axis.get_window_extent(renderer=renderer)
        inside = (
            bbox.x0 >= page.x0 and bbox.y0 >= page.y0 and bbox.x1 <= page.x1 and bbox.y1 <= page.y1
        )
        axes_checks.append({"axis": index, "inside_page": bool(inside)})
        if not inside:
            errors.append(f"axis-out-of-page:{index}")
    palette_seen: set[str] = set()
    semantic_roles: list[dict[str, str]] = []
    semantic_groups: dict[str, str] = {}
    for artist in fig.findobj():
        for getter_name in ("get_color", "get_edgecolor", "get_facecolor"):
            getter = getattr(artist, getter_name, None)
            if getter is None:
                continue
            try:
                raw = getter()
                values = raw if isinstance(raw, np.ndarray) and raw.ndim > 1 else [raw]
                for value in values:
                    color = _rgba_hex(value)
                    palette_seen.add(color)
                    if color not in ALLOWED_PALETTE:
                        errors.append(f"palette-role-unregistered:{color}")
            except (TypeError, ValueError):
                continue
        role = getattr(artist, "_xir_semantic_role", None)
        expected = SEMANTIC_ROLE_COLORS.get(str(role))
        if expected is None and isinstance(role, str) and role.startswith(
            "native-protocol-expansion:"
        ):
            expected = AMBER.lower()
        if isinstance(role, str) and isinstance(expected, str):
            actual = _first_artist_color(artist)
            if actual is None:
                errors.append(f"semantic-role-color-unreadable:{role}")
            else:
                semantic_roles.append(
                    {"role": role, "expected_color": expected, "actual_color": actual}
                )
                if actual != expected:
                    errors.append(f"semantic-role-color-mismatch:{role}:{actual}:{expected}")
                semantic_groups[str(getattr(artist, "_xir_semantic_group", id(artist)))] = role
    canonical_semantic_colors = set(SEMANTIC_ROLE_COLORS.values())
    for axis in fig.axes:
        direct_artists = [*axis.lines, *axis.patches, *axis.collections, *axis.texts]
        for artist in direct_artists:
            actual = _first_artist_color(artist)
            if (
                actual in canonical_semantic_colors
                and not isinstance(getattr(artist, "_xir_semantic_role", None), str)
            ):
                errors.append(
                    "semantic-color-artist-unregistered:"
                    f"{type(artist).__name__}:{actual}"
                )
    observed_counts = Counter(semantic_groups.values())
    if expected_semantic_role_counts is not None:
        expected_counts = Counter(expected_semantic_role_counts)
        if observed_counts != expected_counts:
            errors.append(
                "semantic-role-inventory-mismatch:"
                f"observed={dict(sorted(observed_counts.items()))}:"
                f"expected={dict(sorted(expected_counts.items()))}"
            )
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "axes_checks": axes_checks,
        "palette_seen": sorted(palette_seen),
        "semantic_roles": semantic_roles,
        "semantic_role_counts": dict(sorted(observed_counts.items())),
        "page_bounds_checked": True,
        "text_overlap_checked": True,
        "palette_roles_checked": True,
    }


def _save(
    fig: Any, stem: Path, *, expected_semantic_role_counts: dict[str, int]
) -> None:
    metadata = {
        "Creator": "xir-multihop-figure8-v1",
        "Producer": "matplotlib",
        "CreationDate": None,
        "ModDate": None,
    }
    audit = _audit_figure_geometry_palette(
        fig, expected_semantic_role_counts=expected_semantic_role_counts
    )
    if audit["valid"] is not True:
        raise LocalTopologyError("Figure 8 visual admission failed: " + ", ".join(audit["errors"]))
    fig.savefig(stem.with_suffix(".pdf"), metadata=metadata, dpi=300)
    fig.savefig(stem.with_suffix(".svg"), metadata={"Date": None})
    _write_json(stem.with_name(stem.name + "-visual-audit.json"), audit)
    plt.close(fig)


def load_figure_inputs(
    analysis_path: Path,
    gateway_path: Path,
    multihop_comparison_path: Path,
    gateway_comparison_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    for comparison_path, schema, input_path in (
        (
            multihop_comparison_path,
            "xir-lab-native-multihop-rebuild-comparison-v1",
            analysis_path,
        ),
        (
            gateway_comparison_path,
            "xir-lab-gateway-deployment-rebuild-comparison-v1",
            gateway_path,
        ),
    ):
        comparison = _read(comparison_path)
        byte_identical_files = cast(dict[str, str], comparison.get("byte_identical_files", {}))
        if (
            comparison.get("schema_version") != schema
            or comparison.get("valid") is not True
            or byte_identical_files.get(input_path.name) != _sha(input_path)
        ):
            raise LocalTopologyError(
                f"Figure 8 input is not bound to byte-identical rebuilds: {input_path.name}"
            )
    analysis = _read(analysis_path)
    gateway = _read(gateway_path)
    for input_path, validation_schema, manifest_schema in (
        (
            analysis_path,
            "xir-lab-native-multihop-analysis-validation-v1",
            "xir-lab-native-multihop-analysis-manifest-v1",
        ),
        (
            gateway_path,
            "xir-lab-gateway-deployment-validation-v1",
            "xir-lab-gateway-deployment-manifest-v1",
        ),
    ):
        validation_path = input_path.parent / "validation.json"
        manifest_path = input_path.parent / "manifest.json"
        validation = _read(validation_path)
        manifest = _read(manifest_path)
        files = {
            str(row["path"]): str(row["sha256"])
            for row in cast(list[dict[str, Any]], manifest.get("files", []))
        }
        manifest_semantic = dict(manifest)
        expected_manifest_semantic = str(manifest_semantic.pop("semantic_sha256", ""))
        if (
            validation.get("schema_version") != validation_schema
            or validation.get("valid") is not True
            or manifest.get("schema_version") != manifest_schema
            or hashlib.sha256(rfc8785.dumps(manifest_semantic)).hexdigest()
            != expected_manifest_semantic
            or files.get(input_path.name) != _sha(input_path)
            or files.get("validation.json") != _sha(validation_path)
        ):
            raise LocalTopologyError(f"Figure 8 input manifest/validation drift: {input_path.name}")
    if (
        analysis.get("schema_version") != "xir-lab-native-multihop-analysis-v1"
        or analysis.get("namespace") != "native-multihop-switching-v1"
        or analysis.get("phase") != "scale"
        or int(analysis.get("attempt_count", -1)) != 110_000
    ):
        raise LocalTopologyError("Figure 8 rejects non-final multihop analysis")
    if (
        gateway.get("schema_version") != "xir-lab-gateway-deployment-analysis-v1"
        or gateway.get("claim_boundary") != "structural_upper_bound_not_observed_xir_delivery"
    ):
        raise LocalTopologyError("deployment figure rejects non-frozen graph analysis")
    validate_figure8_cell_summary(analysis)
    equivalence_rows = cast(list[dict[str, Any]], analysis.get("equivalence", []))
    required_equivalence_metrics = {"latency_seconds", "gas", "calldata_bytes"}
    primary_equivalence = [
        row
        for row in equivalence_rows
        if row.get("sample_role")
        in {
            "primary_all_finite_clock_blocks_including_incidents",
            "primary_all_validated_effects",
        }
    ]
    if (
        len(primary_equivalence) != 3
        or {str(row.get("metric", "")) for row in primary_equivalence}
        != required_equivalence_metrics
    ):
        raise LocalTopologyError("Figure 8 requires three primary equivalence estimands")
    if any(
        str(row.get("estimand", ""))
        != "direct_transition_transaction_plus_approved_prior_verifier_"
        "call_slope_per_prefix_receipt"
        or row.get("source_metric")
        not in {
            "core_switch_latency_seconds",
            "core_switch_gas",
            "core_switch_calldata_bytes",
        }
        or int(row.get("n", -1)) != 30_000
        or int(row.get("matched_sequence_count", -1)) != 10_000
        or "ci_low" not in row
        or "ci_high" not in row
        or "lower_bound" not in row
        or "upper_bound" not in row
        or bool(row.get("equivalent")) != bool(row.get("tost_pass"))
        for row in primary_equivalence
    ):
        raise LocalTopologyError("Figure 8 equivalence estimand or sample count drift")
    gas_models = [
        row
        for row in cast(list[dict[str, Any]], analysis.get("models", []))
        if row.get("metric") == "gas" and row.get("sample_role") == "primary_all_validated_effects"
    ]
    if (
        len(gas_models) != 1
        or int(cast(dict[str, Any], gas_models[0].get("linear", {})).get("n", -1)) != 80_000
        or set(
            cast(
                dict[str, Any],
                cast(dict[str, Any], gas_models[0].get("linear", {})).get("coefficients", {}),
            )
        )
        != {"intercept", "hop_count", "switch_count", "starts_with_l"}
        or "switch_marginal" not in gas_models[0]
        or "quadratic_diagnostic" not in gas_models[0]
    ):
        raise LocalTopologyError("Figure 8 gas model formula or sample count drift")
    if len(cast(list[Any], analysis.get("transaction_summary", []))) != len(ROUTE_ORDER):
        raise LocalTopologyError("Figure 8 requires exact observed transaction summaries")
    if not cast(list[Any], analysis.get("stage_summary", [])):
        raise LocalTopologyError("Figure 8 requires explicit stage boundaries")
    stage_rows = cast(list[dict[str, Any]], analysis["stage_summary"])
    if any(
        not row.get("boundary_start")
        or not row.get("boundary_end")
        or "latency_ci_low" not in row
        or "latency_ci_high" not in row
        for row in stage_rows
    ):
        raise LocalTopologyError("Figure 8 stage boundary or interval is incomplete")
    diagnostics = {
        _stage_code(str(row["stage"]))
        for row in stage_rows
        if row.get("stage_level") == "component_diagnostic"
    }
    if not {"DVN", "COM", "EXE"}.issubset(diagnostics):
        raise LocalTopologyError("Figure 8 lacks LayerZero component diagnostics")
    if any(
        str(row.get("stage_level", "")).startswith("component_diagnostic")
        and (
            row.get("latency_interval_is_non_additive") is not True
            or "non_additive" not in str(row.get("timing_kind", ""))
        )
        for row in stage_rows
    ):
        raise LocalTopologyError("Figure 8 component diagnostics could fabricate additive latency")
    switch_diagnostics = [
        row for row in stage_rows if "switch_outbound_dispatch" in str(row.get("stage", ""))
    ]
    if len(switch_diagnostics) != sum(
        sum(left != right for left, right in zip(route, route[1:])) for route in ROUTE_ORDER
    ) or any(
        row.get("approved_prior_verifier_executes_inside_this_dispatch") is not True
        or row.get("latency_is_inclusive_non_additive_with_hop_transport") is not True
        or row.get("gas_is_inclusive_non_additive_with_hop_transport") is not True
        or int(row.get("n", -1)) != 10_000
        for row in switch_diagnostics
    ):
        raise LocalTopologyError(
            "Figure 8 lacks exact approved-verifier switched-dispatch diagnostics"
        )
    transition_rows = [row for row in stage_rows if "xir_transition" in str(row.get("stage", ""))]
    if len(transition_rows) != len(switch_diagnostics) or any(
        row.get("approved_verifier_work_in_this_transaction") is not False
        or int(row.get("n", -1)) != 10_000
        for row in transition_rows
    ):
        raise LocalTopologyError("Figure 8 transition/approved-verifier attribution drift")
    return analysis, gateway


def validate_figure8_cell_summary(analysis: dict[str, Any]) -> None:
    """Validate the exact producer/consumer contract for Figure 8 cell rows."""

    rows = cast(list[dict[str, Any]], analysis.get("cell_summary", []))
    expected = {
        (route, metric, sample_role)
        for route in ROUTE_ORDER
        for metric, sample_role in (
            ("latency_seconds", "primary_all_finite_clock_attempts_including_incidents"),
            ("latency_seconds", "interruption_free_complete_blocks_sensitivity"),
            ("gas", "primary_all_validated_effects"),
            ("calldata_bytes", "primary_all_validated_effects"),
        )
    }
    observed = [
        (str(row.get("route", "")), str(row.get("metric", "")), str(row.get("sample_role", "")))
        for row in rows
    ]
    if len(rows) != 44 or len(set(observed)) != 44 or set(observed) != expected:
        raise LocalTopologyError(
            "Figure 8 requires exact 11 routes x 4 metric/sample-role summaries"
        )


def _cell(
    analysis: dict[str, Any], route: str, metric: str, *, sample_role: str
) -> dict[str, Any]:
    rows = [
        row
        for row in cast(list[dict[str, Any]], analysis["cell_summary"])
        if row["route"] == route
        and row["metric"] == metric
        and row["sample_role"] == sample_role
    ]
    if len(rows) != 1:
        raise LocalTopologyError(
            f"missing Figure 8 cell: {route}:{metric}:{sample_role}"
        )
    return rows[0]


def _stage_code(name: str) -> str:
    if name == "root_create_mined":
        return "R"
    if name == "root_certificate_ready":
        return "C"
    if name == "destination_verify_deliver":
        return "D"
    if name == "destination_effect_observation":
        return "E"
    if "xir_transition" in name:
        return "X" + name.split("_")[1]
    if "switch_outbound_dispatch" in name:
        return "V" + name.split("_")[1]
    if "transport_and_ingress" in name:
        parts = name.split("_")
        return parts[2].upper() + parts[1]
    if "layerzero_" in name:
        return {
            "dvn_execute": "DVN",
            "commit_verification": "COM",
            "executor_execute": "EXE",
        }.get(name.split("layerzero_", 1)[1].removesuffix("_mined"), "LZ")
    return name[:3].upper()


def render_main_figure8(analysis: dict[str, Any], output: Path) -> list[dict[str, Any]]:
    _configure()
    fig, axes = plt.subplots(
        2,
        2,
        figsize=(MAIN_SIZE_MM[0] / 25.4, MAIN_SIZE_MM[1] / 25.4),
        gridspec_kw={"hspace": 0.54, "wspace": 0.34},
    )
    source_rows: list[dict[str, Any]] = []

    ax = axes[0, 0]
    for family, routes, color, marker in (
        ("homogeneous H (matched hops)", ("H", "HH", "HHH", "HHHH"), GRAY, "o"),
        ("alternating H-first", ("H", "HL", "HLH", "HLHL"), BLUE, "s"),
        ("alternating L-first symmetry", ("LHLH",), AMBER, "D"),
    ):
        x = [len(route) - 1 for route in routes]
        y = [
            _cell(
                analysis,
                route,
                "gas",
                sample_role="primary_all_validated_effects",
            )["mean"]
            / 1e6
            for route in routes
        ]
        line = ax.plot(x, y, marker=marker, color=color, linewidth=1.4, label=family)[0]
        _register_semantic_artist(
            line,
            {
                "homogeneous H (matched hops)": "control-homogeneous",
                "alternating H-first": "xir-switching",
                "alternating L-first symmetry": "native-carrier-direction",
            }[family],
            color,
        )
        for route, xx, yy in zip(routes, x, y, strict=True):
            annotation_offsets = {
                "HH": (4, -10),
                "HL": (4, 4),
                "HHH": (4, -10),
                "HLH": (4, 4),
                "HHHH": (-34, -13),
                "HLHL": (-32, -11),
                "LHLH": (-32, 8),
            }
            if route != "H":
                ax.annotate(
                    route,
                    (xx, yy),
                    xytext=annotation_offsets.get(route, (3, 3)),
                    textcoords="offset points",
                    fontsize=7.1,
                )
            source_rows.append(
                {
                    "panel": "a",
                    "route": route,
                    "hop_positions": xx,
                    "actual_switches": sum(left != right for left, right in zip(route, route[1:])),
                    "gas_million": yy,
                }
            )
    ax.set_title("(a) Matched-hop gas: same vs. alternating carrier", loc="left")
    ax.set_xlabel("Additional hop positions (alternating: carrier changes)")
    ax.set_ylabel("Mean gas (million)")
    ax.set_ylim(top=max(ax.get_ylim()[1], 0.218))
    ax.grid(axis="y", color=LIGHT, linewidth=0.7)
    ax.legend(frameon=False, ncol=2, loc="upper left")
    gas_model = next(
        row
        for row in cast(list[dict[str, Any]], analysis["models"])
        if row["metric"] == "gas" and row["sample_role"] == "primary_all_validated_effects"
    )
    gas_switch = cast(dict[str, Any], gas_model["switch_marginal"])
    gas_model_text = ax.text(
        0.99,
        0.03,
        (
            f"switch β={float(gas_switch['estimate']):,.0f} "
            f"[{float(gas_switch['ci_low']):,.0f}, {float(gas_switch['ci_high']):,.0f}], "
            f"R²={float(gas_model['linear']['r_squared']):.3f}; "
            f"quadratic flag={bool(gas_model['superlinear_anomaly'])}"
        ),
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=7.1,
        color=GRAY,
    )
    _register_semantic_artist(gas_model_text, "state-control", GRAY)
    source_rows.append(
        {
            "panel": "a_model",
            "formula": "y=beta0+beta_h*hop_count+beta_s*switch_count+beta_L*starts_with_L",
            "n": gas_model["linear"]["n"],
            "r_squared": gas_model["linear"]["r_squared"],
            "switch_estimate": gas_switch["estimate"],
            "switch_ci_low": gas_switch["ci_low"],
            "switch_ci_high": gas_switch["ci_high"],
            "quadratic_superlinear_anomaly": gas_model["superlinear_anomaly"],
        }
    )

    ax = axes[0, 1]
    transaction_rows = {
        str(row["route"]): row
        for row in cast(list[dict[str, Any]], analysis["transaction_summary"])
    }
    if set(transaction_rows) != set(ROUTE_ORDER):
        raise LocalTopologyError("Figure 8 transaction routes are incomplete")
    observed = [
        int(transaction_rows[route]["observed_physical_transactions_per_attempt"])
        for route in ROUTE_ORDER
    ]
    theory = [
        int(transaction_rows[route]["theoretical_physical_transactions_per_attempt"])
        for route in ROUTE_ORDER
    ]
    if observed != theory:
        raise LocalTopologyError("Figure 8 observed transaction accounting does not close")
    positions = np.arange(len(ROUTE_ORDER))
    theory_artist = ax.plot(
        positions, theory, color=GRAY, marker="o", linewidth=1.2, label="preregistered theory"
    )[0]
    _register_semantic_artist(theory_artist, "control-theory", GRAY)
    observed_artist = ax.scatter(
        positions,
        observed,
        facecolors="none",
        edgecolors=BLUE,
        linewidth=1.2,
        label="observed exact",
    )
    _register_semantic_artist(observed_artist, "xir-observed", BLUE)
    ax.set_xticks(positions, ROUTE_ORDER, rotation=45, ha="right")
    ax.set_ylabel("Physical transactions / attempt")
    ax.set_title("(b) Transaction accounting closes exactly", loc="left")
    ax.grid(axis="y", color=LIGHT, linewidth=0.7)
    ax.legend(frameon=False)
    transaction_formula = ax.text(
        0.99,
        0.03,
        r"coordinator $=h+s+2$; physical $=h+s+2+n_H+3n_L$",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=7.1,
        color=GRAY,
    )
    _register_semantic_artist(transaction_formula, "control-theory", GRAY)
    source_rows.extend(
        {"panel": "b", "route": route, "theory": expected, "observed": actual}
        for route, expected, actual in zip(ROUTE_ORDER, theory, observed, strict=True)
    )

    ax = axes[1, 0]
    chosen = ("HHHL", "HLHL")
    stage_rows = cast(list[dict[str, Any]], analysis["stage_summary"])
    for route_index, route in enumerate(chosen):
        stages = sorted(
            [
                row
                for row in stage_rows
                if row["route"] == route
                and row.get("stage_level", "route_boundary") == "route_boundary"
            ],
            key=lambda row: int(row["stage_order"]),
        )
        positions = np.arange(1, len(stages) + 1)
        values = [float(row["latency_median_seconds"]) for row in stages]
        lows = [
            float(row.get("latency_ci_low", value))
            for row, value in zip(stages, values, strict=True)
        ]
        highs = [
            float(row.get("latency_ci_high", value))
            for row, value in zip(stages, values, strict=True)
        ]
        color = BLUE if route == "HLHL" else AMBER
        stage_artist = ax.errorbar(
            positions,
            values,
            yerr=[
                [value - low for value, low in zip(values, lows, strict=True)],
                [high - value for value, high in zip(values, highs, strict=True)],
            ],
            marker="o",
            linewidth=1.1,
            capsize=2,
            color=color,
            label=route,
        )
        stage_role = "xir-switching-stage" if route == "HLHL" else "native-prefix-stage"
        _register_semantic_artist(
            stage_artist,
            stage_role,
            color,
        )
        for index, (position, value, row) in enumerate(
            zip(positions, values, stages, strict=True), start=1
        ):
            annotation = ax.annotate(
                _stage_code(str(row["stage"])),
                (position, value),
                xytext=(0, 5 if route_index == 0 else -9),
                textcoords="offset points",
                ha="center",
                fontsize=7.1,
                color=color,
            )
            _register_semantic_artist(annotation, stage_role, color)
            source_rows.append({"panel": "c", "route": route, "stage_number": index, **row})
    ax.set_xlabel("Observable phase in causal order (codes label each point)")
    ax.set_ylabel("Median interval (s), 95% MBB CI")
    ax.set_title("(c) Phase latency is shown without summing medians", loc="left")
    ax.grid(axis="y", color=LIGHT, linewidth=0.7)
    ax.legend(frameon=False, ncol=2)

    ax = axes[1, 1]
    equivalence = {
        str(row["metric"]): row
        for row in cast(list[dict[str, Any]], analysis["equivalence"])
        if row.get("sample_role")
        in {
            "primary_all_finite_clock_blocks_including_incidents",
            "primary_all_validated_effects",
        }
    }
    estimands = (
        ("Latency", "latency_seconds"),
        ("Gas", "gas"),
        ("Calldata", "calldata_bytes"),
    )
    for index, (label, metric) in enumerate(estimands):
        row = equivalence[metric]
        bound = float(row["upper_bound"])
        estimate = float(row["estimate"]) / bound
        low = float(row["ci_low"]) / bound
        high = float(row["ci_high"]) / bound
        equivalence_artist = ax.errorbar(
            estimate,
            index,
            xerr=[[estimate - low], [high - estimate]],
            fmt="o",
            color=BLUE if row["equivalent"] else RED,
            capsize=3,
        )
        _register_semantic_artist(
            equivalence_artist,
            "xir-equivalence" if row["equivalent"] else "anomaly-not-equivalent",
            BLUE if row["equivalent"] else RED,
        )
        source_rows.append(
            {
                "panel": "d",
                "label": label,
                "normalized_estimate": estimate,
                "normalized_low": low,
                "normalized_high": high,
                **row,
            }
        )
    ax.axvspan(-1, 1, color="#E4F3EE", zorder=-1)
    for threshold in (-1, 1, 0):
        threshold_artist = ax.axvline(threshold, color=GRAY, linewidth=0.8)
        _register_semantic_artist(threshold_artist, "control-theory", GRAY)
    ax.set_yticks(range(3), [label for label, _metric in estimands])
    ax.set_xlabel("Slope / preregistered equivalence bound")
    all_equivalent = all(bool(equivalence[metric]["equivalent"]) for _, metric in estimands)
    ax.set_title(
        "(d) Path-length equivalence established"
        if all_equivalent
        else "(d) Path-length equivalence not established",
        loc="left",
    )
    ax.set_xlim(-1.35, 1.35)
    ax.set_xticks((-1.0, -0.5, 0.0, 0.5, 1.0))
    ax.text(0, 2.55, "equivalence requires the full 90% CI inside ±1", ha="center", fontsize=7.1)
    fig.suptitle(
        (
            "Figure 8. XIR multihop scaling and path-length-independent switching"
            if all_equivalent
            else "Figure 8. XIR multihop scaling; path-length independence not established"
        ),
        fontsize=9.2,
        fontweight="bold",
        x=0.06,
        ha="left",
    )
    fig.subplots_adjust(left=0.075, right=0.985, top=0.89, bottom=0.15)
    main_expected = {
        "control-homogeneous": 1,
        "xir-switching": 1,
        "native-carrier-direction": 1,
        "state-control": 1,
        "control-theory": 5,
        "xir-observed": 1,
    }
    for route, role in (("HHHL", "native-prefix-stage"), ("HLHL", "xir-switching-stage")):
        route_stage_count = sum(
            1
            for row in stage_rows
            if row["route"] == route
            and row.get("stage_level", "route_boundary") == "route_boundary"
        )
        main_expected[role] = route_stage_count + 1
    main_expected["xir-equivalence"] = sum(
        1 for _, metric in estimands if bool(equivalence[metric]["equivalent"])
    )
    main_expected["anomaly-not-equivalent"] = sum(
        1 for _, metric in estimands if not bool(equivalence[metric]["equivalent"])
    )
    main_expected = {role: count for role, count in main_expected.items() if count}
    _save(fig, output, expected_semantic_role_counts=main_expected)
    return source_rows


def render_appendix_figure8(analysis: dict[str, Any], output: Path) -> list[dict[str, Any]]:
    _configure()
    fig = plt.figure(figsize=(APPENDIX_SIZE_MM[0] / 25.4, APPENDIX_SIZE_MM[1] / 25.4))
    ax = fig.add_axes((0.035, 0.045, 0.93, 0.91))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    ax.text(
        0,
        98,
        "Figure 8 companion. Component-, receipt-, and event-level execution",
        fontsize=9.2,
        fontweight="bold",
        va="top",
    )
    # Keep service text inside chain boxes and transport annotations in the
    # inter-chain gutters.  This geometry is intentionally asymmetric to the
    # old slide-style diagram: it remains readable at native manuscript size.
    chain_x = [8, 29, 50, 71, 92]
    rows: list[dict[str, Any]] = []
    for index, (label, x) in enumerate(zip("ABCDE", chain_x, strict=True)):
        box = FancyBboxPatch(
            (x - 7.0, 70),
            14.0,
            19,
            boxstyle="round,pad=0.6",
            facecolor="#F7F9FB",
            edgecolor=GRAY,
            linewidth=1.0,
        )
        ax.add_patch(box)
        _register_semantic_artist(box, "state-control", GRAY, color_source="edge")
        ax.text(x, 87, f"Chain {label}", ha="center", va="top", fontweight="bold")
        components = ["Gateway", "Registry", "H/L adapters"]
        if index > 0:
            components.append("Receiver")
        if 0 < index < 4:
            components.append("Switch recorder")
        for line, component in enumerate(components):
            component_artist = ax.text(
                x,
                83 - line * 3.0,
                component,
                ha="center",
                va="center",
                fontsize=7.1,
                color={
                    "Registry": GRAY,
                    "H/L adapters": AMBER,
                    "Gateway": BLUE,
                    "Receiver": BLUE,
                    "Switch recorder": BLUE,
                }[component],
            )
            component_role = (
                "state-control"
                if component == "Registry"
                else "native-transport"
                if component == "H/L adapters"
                else "xir-switching"
            )
            _register_semantic_artist(component_artist, component_role)
        service_box = FancyBboxPatch(
            (x - 7.0, 58.0),
            14.0,
            9.2,
            boxstyle="round,pad=0.35",
            facecolor="#FFF8EE",
            edgecolor=AMBER,
            linewidth=0.8,
        )
        ax.add_patch(service_box)
        _register_semantic_artist(
            service_box, "native-transport", AMBER, color_source="edge"
        )
        for service_y, service in zip(
            (65.6, 63.4, 61.2, 59.0),
            (
                "H: Mailbox / ISM",
                "validator / relayer",
                "L: Endpoint / ULN",
                "DVN / EXE / worker",
            ),
            strict=True,
        ):
            service_artist = ax.text(
                x, service_y, service, ha="center", va="center", fontsize=7.1, color=AMBER
            )
            _register_semantic_artist(service_artist, "native-transport", AMBER)
        rows.append({"kind": "component", "chain": label, "components": ";".join(components)})
    for hop in range(4):
        arrow = FancyArrowPatch(
            (chain_x[hop] + 7.0, 79),
            (chain_x[hop + 1] - 7.0, 79),
            arrowstyle="-|>",
            mutation_scale=10,
            color=AMBER,
            linewidth=1.5,
        )
        ax.add_patch(arrow)
        _register_semantic_artist(arrow, "native-transport", AMBER)
        hop_artist = ax.text(
            (chain_x[hop] + chain_x[hop + 1]) / 2, 82.3, f"hop {hop + 1}", ha="center", fontsize=7.1
            , color=AMBER
        )
        _register_semantic_artist(hop_artist, "native-transport", AMBER)
        receipt_artist = ax.text(
            (chain_x[hop] + chain_x[hop + 1]) / 2,
            75.3,
            f"append t{hop + 1}",
            ha="center",
            fontsize=7.1,
            color=GRAY,
        )
        _register_semantic_artist(receipt_artist, "state-control", GRAY)
    execution_contract = (
        (
            "Root",
            "A.Gateway.createRecord(R,payload,C,v) → finalized RootSigner certificate",
            BLUE,
        ),
        (
            "Native hop",
            "Outbound sendSource/forwardInFlight → H Mailbox.process | L DVN→commit→Executor → authenticated inbound callback",
            AMBER,
        ),
        (
            "XIR transition",
            "TransitionRecorder verifies trace/prefix; outbound checks administrator-approved prior ingress",
            BLUE,
        ),
        (
            "Final effect",
            "C/D/E Gateway.verifyTrace+deliver → Receiver.xirReceive → consumed[mid] and one NativeMultihopEffectApplied",
            BLUE,
        ),
    )
    for index, (stage, description, color) in enumerate(execution_contract):
        y = 56.2 - index * 2.35
        stage_role = "native-transport" if stage == "Native hop" else "xir-switching"
        stage_label = ax.text(
            1.2, y, f"{stage}:", fontsize=7.1, fontweight="bold", color=color
        )
        stage_description = ax.text(14.0, y, description, fontsize=7.1, color=color)
        _register_semantic_artist(stage_label, stage_role, color)
        _register_semantic_artist(stage_description, stage_role, color)
        rows.append(
            {
                "kind": "execution_contract",
                "stage": stage,
                "description": description,
            }
        )
    ax.text(
        1,
        46,
        "Experiment 1 — exact phase intervals (seconds; 95% CI remains in source CSV)",
        fontsize=7.8,
        fontweight="bold",
    )
    stage_rows = cast(list[dict[str, Any]], analysis["stage_summary"])
    for route_index, route in enumerate(("HHHH", "HLHL", "LHLH")):
        y = 41 - route_index * 7.0
        stages = sorted(
            [
                row
                for row in stage_rows
                if row["route"] == route
                and row.get("stage_level", "route_boundary") == "route_boundary"
            ],
            key=lambda row: int(row["stage_order"]),
        )
        ax.text(1, y, route, fontweight="bold", va="center")
        width = 89.0 / max(len(stages), 1)
        for index, row in enumerate(stages):
            stage_x = 7.5 + index * width
            name = str(row["stage"])
            color = BLUE if "xir_transition" in name else AMBER if "transport" in name else GRAY
            stage_patch = FancyBboxPatch(
                    (stage_x, y - 2.2),
                    width - 0.4,
                    4.4,
                    boxstyle="round,pad=0.1",
                    facecolor=color,
                    edgecolor=color,
                    alpha=0.16,
                )
            ax.add_patch(stage_patch)
            stage_role = (
                "xir-switching-stage"
                if "xir_transition" in name
                else "native-transport"
                if "transport" in name
                else "state-control"
            )
            _register_semantic_artist(stage_patch, stage_role, color, color_source="face")
            stage_code_artist = ax.text(
                stage_x + (width - 0.4) / 2,
                y + 0.7,
                _stage_code(name),
                ha="center",
                va="center",
                color=color,
                fontsize=7.1,
                fontweight="bold",
            )
            stage_value_artist = ax.text(
                stage_x + (width - 0.4) / 2,
                y - 0.9,
                f"{float(row['latency_median_seconds']):.2f}s",
                ha="center",
                va="center",
                color=color,
                fontsize=7.1,
            )
            _register_semantic_artist(stage_code_artist, stage_role, color)
            _register_semantic_artist(stage_value_artist, stage_role, color)
            rows.append(
                {
                    "kind": "stage",
                    "route": route,
                    "number": index + 1,
                    "stage": row["stage"],
                    "boundary_start": row["boundary_start"],
                    "boundary_end": row["boundary_end"],
                    "latency_median_seconds": row["latency_median_seconds"],
                    "latency_ci_low": row.get("latency_ci_low"),
                    "latency_ci_high": row.get("latency_ci_high"),
                    "gas_mean": row["gas_mean"],
                    "calldata_mean_bytes": row["calldata_mean_bytes"],
                }
            )

    ax.text(
        1,
        21.5,
        "LayerZero component diagnostics — independent, potentially overlapping intervals; never summed",
        fontsize=7.8,
        fontweight="bold",
    )
    diagnostics = sorted(
        [
            row
            for row in stage_rows
            if row["route"] == "LHLH" and row.get("stage_level") == "component_diagnostic"
        ],
        key=lambda row: (int(row["stage_order"]), int(row.get("component_order", 0))),
    )
    for index, row in enumerate(diagnostics[:6]):
        x = 2 + (index % 3) * 32
        y = 18 - (index // 3) * 3.2
        diagnostic_artist = ax.text(
            x,
            y,
            f"{_stage_code(str(row['stage']))}: {float(row['latency_median_seconds']):.2f}s · {float(row['gas_mean']):,.0f} gas",
            fontsize=7.1,
            color=AMBER,
        )
        _register_semantic_artist(diagnostic_artist, "native-transport", AMBER)
        rows.append({"kind": "layerzero_component_diagnostic", **row})

    ax.text(
        1,
        14.3,
        "Experiment 2 — transition and subsequent switched dispatch vs. prefix receipts",
        fontsize=7.8,
        fontweight="bold",
    )
    for index, route in enumerate(("HL", "HHL", "HHHL")):
        transition = next(
            row
            for row in stage_rows
            if row["route"] == route and "xir_transition" in str(row["stage"])
        )
        switched_dispatch = next(
            row
            for row in stage_rows
            if row["route"] == route
            and "switch_outbound_dispatch_with_approved_prior_verification" in str(row["stage"])
        )
        transition_artist = ax.text(
            2,
            11.0 - index * 3.0,
            (
                f"{route} · prefix={len(route) - 1}: transition "
                f"{float(transition['latency_median_seconds']):.3f}s/"
                f"{float(transition['gas_mean']):,.0f} gas; approved-verifier + dispatch "
                f"{float(switched_dispatch['latency_median_seconds']):.3f}s/"
                f"{float(switched_dispatch['gas_mean']):,.0f} gas"
            ),
            fontsize=7.1,
            color=BLUE,
        )
        _register_semantic_artist(transition_artist, "xir-switching", BLUE)
        rows.append(
            {"kind": "experiment2_transition", "prefix_receipts": len(route) - 1, **transition}
        )
        rows.append(
            {
                "kind": "experiment2_approved_verifier_dispatch",
                "prefix_receipts": len(route) - 1,
                **switched_dispatch,
            }
        )
    failure_artist = ax.text(
        1,
        1.0,
        "Codes R/C/Hn/Ln/Xn/D/E: root, certificate, native hop, XIR transition, delivery, effect; EXE: Executor.\n"
        "Fail-closed gate: missing event, trace, prefix, binding, exact effect, or review digest aborts publication.",
        fontsize=7.1,
        color=RED,
        va="bottom",
        linespacing=1.08,
    )
    _register_semantic_artist(failure_artist, "rejection-boundary", RED)
    appendix_expected: Counter[str] = Counter(
        {
            "xir-switching": 21,
            "state-control": 14,
            "native-transport": 40 + len(diagnostics[:6]),
            "rejection-boundary": 1,
        }
    )
    for route in ("HHHH", "HLHL", "LHLH"):
        for row in stage_rows:
            if (
                row["route"] != route
                or row.get("stage_level", "route_boundary") != "route_boundary"
            ):
                continue
            name = str(row["stage"])
            role = (
                "xir-switching-stage"
                if "xir_transition" in name
                else "native-transport"
                if "transport" in name
                else "state-control"
            )
            appendix_expected[role] += 3
    _save(
        fig,
        output,
        expected_semantic_role_counts=dict(appendix_expected),
    )
    return rows


def render_deployment_figure(gateway: dict[str, Any], output: Path) -> list[dict[str, Any]]:
    _configure()
    fig, axes = plt.subplots(
        1,
        2,
        figsize=(DEPLOYMENT_SIZE_MM[0] / 25.4, DEPLOYMENT_SIZE_MM[1] / 25.4),
        gridspec_kw={"wspace": 0.3},
    )
    placement = cast(dict[str, Any], gateway["gateway_placement"])
    rounds = cast(list[dict[str, Any]], placement["rounds"])
    x = [
        int(row["step"])
        for row in rounds
        if row.get("selected_node") is not None or row["step"] == 0
    ]
    y = [
        float(row["reachability_rate"]) * 100
        for row in rounds
        if row.get("selected_node") is not None or row["step"] == 0
    ]
    gateway_artist = axes[0].plot(
        x, y, color=BLUE, marker="o", label="compatible-Gateway greedy"
    )[0]
    _register_semantic_artist(gateway_artist, "xir-gateway-placement", BLUE)
    upper_bound_artist = axes[0].axhline(
        float(gateway["frozen"]["all_compatible_rate"]) * 100,
        color=NAVY,
        linestyle="--",
        linewidth=1,
        label="96.863% structural upper bound",
    )
    _register_semantic_artist(upper_bound_artist, "structural-upper-bound", NAVY)
    homogeneous_artist = axes[0].axhline(
        float(gateway["frozen"]["homogeneous_pairs"]) / 81510 * 100,
        color=GRAY,
        linestyle=":",
        linewidth=1,
        label="homogeneous baseline",
    )
    _register_semantic_artist(homogeneous_artist, "control-homogeneous", GRAY)
    axes[0].set_xlabel("Selected internal Gateway vertices")
    axes[0].set_ylabel("Structurally reachable ordered pairs (%)")
    axes[0].set_title("(a) Frozen-graph Gateway placement", loc="left")
    axes[0].legend(frameon=False)
    axes[0].grid(axis="y", color=LIGHT)
    curves = cast(list[dict[str, Any]], gateway["protocol_expansion"])
    for protocol in ("hyperlane", "layerzero", "wormhole", "ccip", "axelar", "relay"):
        color = AMBER
        by_scenario = {
            scenario: [
                row for row in curves if row["protocol"] == protocol and row["scenario"] == scenario
            ]
            for scenario in ("optimistic", "central", "conservative")
        }
        central = by_scenario["central"]
        steps = [int(row["added_nodes"]) for row in central]
        if not central or any(
            [int(row["added_nodes"]) for row in by_scenario[scenario]] != steps
            for scenario in ("optimistic", "conservative")
        ):
            raise LocalTopologyError(f"protocol counterfactual scenarios do not align: {protocol}")
        central_values = [float(row["reachability_rate"]) * 100 for row in central]
        optimistic = [float(row["reachability_rate"]) * 100 for row in by_scenario["optimistic"]]
        conservative = [
            float(row["reachability_rate"]) * 100 for row in by_scenario["conservative"]
        ]
        expansion_band = axes[1].fill_between(
            steps,
            np.minimum(optimistic, conservative),
            np.maximum(optimistic, conservative),
            color=color,
            alpha=0.09,
            linewidth=0,
        )
        _register_semantic_artist(
            expansion_band, f"native-protocol-expansion:{protocol}", color
        )
        protocol_artist = axes[1].plot(
            steps, central_values, color=color, linewidth=1.1, label=protocol
        )[0]
        _register_semantic_artist(
            protocol_artist, f"native-protocol-expansion:{protocol}", color
        )
    counterfactual_bound = axes[1].axhline(
        float(gateway["frozen"]["all_compatible_rate"]) * 100,
        color=NAVY,
        linestyle="--",
        linewidth=1,
    )
    _register_semantic_artist(
        counterfactual_bound, "structural-upper-bound", NAVY
    )
    axes[1].set_xlabel("Counterfactually added protocol endpoints")
    axes[1].set_ylabel("Same-protocol reachability (%)")
    axes[1].set_title("(b) Protocol expansion scenarios", loc="left")
    axes[1].legend(frameon=False, ncol=2)
    axes[1].grid(axis="y", color=LIGHT)
    fig.subplots_adjust(left=0.075, right=0.95, top=0.88, bottom=0.18)
    deployment_expected = {
        "xir-gateway-placement": 1,
        "structural-upper-bound": 2,
        "control-homogeneous": 1,
        **{
            f"native-protocol-expansion:{protocol}": 2
            for protocol in ("hyperlane", "layerzero", "wormhole", "ccip", "axelar", "relay")
        },
    }
    _save(fig, output, expected_semantic_role_counts=deployment_expected)
    return [{"kind": "gateway", **row} for row in rounds] + [
        {"kind": "protocol_curve", **row} for row in curves
    ]


def _write_caption_suggestions(
    *, analysis: dict[str, Any], gateway: dict[str, Any], output_path: Path
) -> None:
    """Generate captions from validated sources rather than hand-entered results."""

    placement = cast(dict[str, Any], gateway["gateway_placement"])
    frozen = cast(dict[str, Any], gateway["frozen"])
    lines = [
        "# Source-generated caption suggestions",
        "",
        "## Main Figure 8",
        "",
        (
            f"Multihop carrier-switching costs over {int(analysis['attempt_count']):,} "
            "matched attempts (11 routes). Panels report observed gas, calldata, "
            "end-to-end latency, exact observed/theoretical physical-transaction "
            "counts, registered stage boundaries, and the preregistered "
            "path-length equivalence estimands. Intervals use complete matched "
            "sequence blocks; component diagnostics inside one native delivery "
            "are non-additive."
        ),
        "",
        "## Appendix Figure 8",
        "",
        (
            "Component-level A--E execution anatomy. Each route records root "
            "creation and certificate readiness, every H/L native transport and "
            "authenticated ingress, approved prior-verifier carrier transitions, "
            "final trace/bundle verification, destination delivery, and the exact "
            "application effect. DVN, commit-verification, and Executor intervals "
            "are diagnostic overlapping worker intervals and must not be summed."
        ),
        "",
        "## Deployment reachability",
        "",
        (
            f"Frozen-graph deployment analysis over {int(frozen['node_count']):,} "
            f"networks and {int(frozen['ordered_pair_denominator']):,} ordered "
            f"pairs. Deterministic greedy placement reaches its terminal value "
            f"at k={int(placement['terminal_k'])}; the horizontal reference is "
            f"the {float(frozen['all_compatible_rate']) * 100:.3f}% structural "
            "upper bound, not observed XIR delivery. Six-protocol curves are "
            "counterfactual central scenarios with optimistic--conservative "
            "bands and do not imply equivalent security or operational products."
        ),
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_figure_files(output_root: Path) -> dict[str, Any]:
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    expected_names = {
        "figure8-multihop-main.pdf",
        "figure8-multihop-main.svg",
        "figure8-multihop-detail.pdf",
        "figure8-multihop-detail.svg",
        "gateway-deployment-reachability.pdf",
        "gateway-deployment-reachability.svg",
        "figure8-source.csv",
        "figure8-source.json",
        "CAPTION_SUGGESTIONS.md",
        "figure8-multihop-main-visual-audit.json",
        "figure8-multihop-detail-visual-audit.json",
        "gateway-deployment-reachability-visual-audit.json",
    }
    if {path.name for path in files} != expected_names:
        raise LocalTopologyError("Figure 8 pre-manifest file inventory is not exact")
    pdfs = [path for path in files if path.suffix == ".pdf"]
    svgs = [path for path in files if path.suffix == ".svg"]
    font_checks: list[dict[str, Any]] = []
    expected_sizes = {
        "figure8-multihop-main.pdf": MAIN_SIZE_MM,
        "figure8-multihop-detail.pdf": APPENDIX_SIZE_MM,
        "gateway-deployment-reachability.pdf": DEPLOYMENT_SIZE_MM,
    }
    size_checks: list[dict[str, Any]] = []
    for pdf in pdfs:
        completed = subprocess.run(
            ["pdffonts", str(pdf)], check=True, capture_output=True, text=True
        )
        output = completed.stdout
        lines = output.splitlines()
        if len(lines) < 3 or "emb" not in lines[0]:
            raise LocalTopologyError(f"Figure 8 PDF font inventory is invalid: {pdf.name}")
        embedded_column = lines[0].index("emb")
        fonts = lines[2:]
        if (
            not fonts
            or "Type 3" in output
            or any(line[embedded_column : embedded_column + 3].strip() != "yes" for line in fonts)
        ):
            raise LocalTopologyError(f"Figure 8 PDF font gate failed: {pdf.name}")
        font_checks.append({"file": pdf.name, "embedded": True, "type3": False})
        raster_inventory = subprocess.run(
            ["pdfimages", "-list", str(pdf)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if len(raster_inventory) > 2:
            raise LocalTopologyError(f"Figure 8 PDF contains raster images: {pdf.name}")
        xml = subprocess.run(
            ["pdftohtml", "-xml", "-i", "-stdout", str(pdf)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        sizes = [float(value) for value in re.findall(r'<fontspec[^>]*size="([0-9.]+)"', xml)]
        if not sizes or min(sizes) < min(FONT_ROLES) - 0.11:
            raise LocalTopologyError(f"Figure 8 rendered font is below 7.1 pt: {pdf.name}")
        info = subprocess.run(
            ["pdfinfo", str(pdf)], check=True, capture_output=True, text=True
        ).stdout
        match = re.search(r"Page size:\s+([0-9.]+) x ([0-9.]+) pts", info)
        if match is None or pdf.name not in expected_sizes:
            raise LocalTopologyError(f"Figure 8 PDF size is unauditable: {pdf.name}")
        width, height = float(match.group(1)), float(match.group(2))
        expected_width, expected_height = expected_sizes[pdf.name]
        if (
            abs(width - expected_width / 25.4 * 72) > 0.03
            or abs(height - expected_height / 25.4 * 72) > 0.03
        ):
            raise LocalTopologyError(f"Figure 8 native PDF size changed: {pdf.name}")
        size_checks.append(
            {
                "file": pdf.name,
                "page_size_points": [width, height],
                "native_size_mm": [expected_width, expected_height],
            }
        )
    for svg in svgs:
        text = svg.read_text(encoding="utf-8")
        if "<image" in text or 'href="http' in text or "<text" in text:
            raise LocalTopologyError(f"Figure 8 SVG is not self-contained: {svg.name}")
    source_rows = json.loads((output_root / "figure8-source.json").read_text(encoding="utf-8"))
    with (output_root / "figure8-source.csv").open(newline="", encoding="utf-8") as stream:
        csv_rows = list(csv.DictReader(stream))
    if not isinstance(source_rows, list) or not source_rows or len(csv_rows) != len(source_rows):
        raise LocalTopologyError("Figure 8 source rows do not reconcile")
    fields = sorted({key for row in source_rows for key in row})
    expected_csv_rows = [
        {field: "" if row.get(field) is None else str(row.get(field, "")) for field in fields}
        for row in source_rows
    ]
    if csv_rows != expected_csv_rows:
        raise LocalTopologyError("Figure 8 CSV/JSON values differ")
    visual_audits = []
    for path in sorted(output_root.glob("*-visual-audit.json")):
        audit = _read(path)
        if audit.get("valid") is not True or not all(
            audit.get(key) is True
            for key in ("page_bounds_checked", "text_overlap_checked", "palette_roles_checked")
        ):
            raise LocalTopologyError(f"Figure 8 visual audit failed: {path.name}")
        visual_audits.append({"file": path.name, "sha256": _sha(path)})
    if len(visual_audits) != 3:
        raise LocalTopologyError("Figure 8 visual audit inventory is incomplete")
    return {
        "valid": True,
        "main_size_mm": list(MAIN_SIZE_MM),
        "appendix_size_mm": list(APPENDIX_SIZE_MM),
        "deployment_size_mm": list(DEPLOYMENT_SIZE_MM),
        "minimum_font_pt": min(FONT_ROLES),
        "font_roles_pt": list(FONT_ROLES),
        "vector_only": True,
        "font_checks": font_checks,
        "size_checks": size_checks,
        "full_two_column_width_mm": 190.0,
        "source_row_count": len(source_rows),
        "source_csv_sha256": _sha(output_root / "figure8-source.csv"),
        "source_json_sha256": _sha(output_root / "figure8-source.json"),
        "visual_audits": visual_audits,
    }


def build_figure8_family(
    *,
    analysis_path: Path,
    gateway_path: Path,
    multihop_comparison_path: Path,
    gateway_comparison_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    analysis, gateway = load_figure_inputs(
        analysis_path,
        gateway_path,
        multihop_comparison_path,
        gateway_comparison_path,
    )
    output_root.mkdir(parents=True, exist_ok=False)
    rows = []
    rows.extend(render_main_figure8(analysis, output_root / "figure8-multihop-main"))
    rows.extend(render_appendix_figure8(analysis, output_root / "figure8-multihop-detail"))
    rows.extend(render_deployment_figure(gateway, output_root / "gateway-deployment-reachability"))
    _write_csv(output_root / "figure8-source.csv", rows)
    _write_json(output_root / "figure8-source.json", rows)
    _write_caption_suggestions(
        analysis=analysis,
        gateway=gateway,
        output_path=output_root / "CAPTION_SUGGESTIONS.md",
    )
    validation = validate_figure_files(output_root)
    _write_json(output_root / "visual-validation.json", validation)
    manifest = {
        "schema_version": "xir-lab-multihop-figure8-manifest-v1",
        "namespace": "native-multihop-switching-v1",
        "analysis_sha256": _sha(analysis_path),
        "gateway_sha256": _sha(gateway_path),
        "multihop_rebuild_comparison_sha256": _sha(multihop_comparison_path),
        "gateway_rebuild_comparison_sha256": _sha(gateway_comparison_path),
        "files": [],
    }
    for path in sorted(output_root.iterdir()):
        if path.is_file():
            cast(list[dict[str, Any]], manifest["files"]).append(
                {"path": path.name, "bytes": path.stat().st_size, "sha256": _sha(path)}
            )
    manifest["semantic_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _write_json(output_root / "manifest.json", manifest)
    return manifest


def verify_figure8_publication(root: Path) -> dict[str, Any]:
    """Recompute a Figure 8 publication's manifest and automated visual gates."""

    manifest = _read(root / "manifest.json")
    semantic = dict(manifest)
    expected_semantic = str(semantic.pop("semantic_sha256", ""))
    rows = cast(list[dict[str, Any]], manifest.get("files", []))
    expected_inventory = {
        str(row["path"]): str(row["sha256"])
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    actual_inventory = {
        path.name: _sha(path)
        for path in sorted(root.iterdir())
        if path.is_file() and path.name != "manifest.json"
    }
    if (
        manifest.get("schema_version") != "xir-lab-multihop-figure8-manifest-v1"
        or manifest.get("namespace") != "native-multihop-switching-v1"
        or hashlib.sha256(
            json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != expected_semantic
        or len(rows) != len(expected_inventory)
        or actual_inventory != expected_inventory
        or any(
            int(row.get("bytes", -1)) != (root / str(row.get("path"))).stat().st_size
            for row in rows
        )
    ):
        raise LocalTopologyError("Figure 8 publication manifest is invalid")
    stored_validation = _read(root / "visual-validation.json")
    with tempfile.TemporaryDirectory(prefix="xir-figure8-reverify-") as temporary:
        verification_root = Path(temporary)
        for name in expected_inventory:
            if name == "visual-validation.json":
                continue
            shutil.copyfile(root / name, verification_root / name)
        recomputed_validation = validate_figure_files(verification_root)
    if stored_validation != recomputed_validation:
        raise LocalTopologyError("Figure 8 persisted visual validation differs from recomputation")
    return manifest


def _build_figure8_comparison(first: Path, second: Path) -> dict[str, Any]:
    verify_figure8_publication(first)
    verify_figure8_publication(second)
    first_inventory = {
        path.name: _sha(path) for path in sorted(first.iterdir()) if path.is_file()
    }
    second_inventory = {
        path.name: _sha(path) for path in sorted(second.iterdir()) if path.is_file()
    }
    if first_inventory != second_inventory:
        raise LocalTopologyError("Figure 8 independent publications differ")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-multihop-figure8-comparison-v1",
        "valid": True,
        "byte_identical_files": first_inventory,
        "file_count": len(first_inventory),
    }
    document["semantic_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return document


def compare_figure8_publications(*, first: Path, second: Path, output_path: Path) -> dict[str, Any]:
    document = _build_figure8_comparison(first, second)
    _write_json(output_path, document)
    return document


def verify_figure8_comparison(
    *, first: Path, second: Path, comparison_path: Path
) -> dict[str, Any]:
    expected = _build_figure8_comparison(first, second)
    actual = _read(comparison_path)
    if actual != expected:
        raise LocalTopologyError("persisted Figure 8 comparison differs from recomputation")
    return actual
