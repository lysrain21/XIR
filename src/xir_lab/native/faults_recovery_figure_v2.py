"""Final-revision controlled-recovery figure and lineage publication.

This renderer accepts only the frozen 60-case ``native-faults-v1`` result and
two byte-identical offline rebuilds.  It validates the administrator-bound
deployment before creating output.  The figure stays compact; complete
nonce, transaction-hash, raw-signed-transaction SHA-256, and application
effect lineages remain in the accompanying CSV and JSON sources.
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
from typing import Any, cast

import jsonschema

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.faults_handoff_v1 import (
    REQUIRED_CASE_CHECKS,
    concurrent_identity_valid,
    verify_publication,
)
from xir_lab.native.faults_v1 import (
    FINAL_REVISION_SOURCE_SHA256,
    final_revision_deployment_contract_valid,
    final_revision_source_lock_valid,
)

INPUT_CAMPAIGN = "native-faults-v1-frozen"
OUTPUT_NAMESPACE = "native-faults-v1-recovery-figure-v2"
DEPLOYMENT_SCOPE = "prior-verifier-final-revision-shared-idle"
FIGURE_1_SHA256 = "f2b694773e3db3312a745e40098995e075738df4de04f9bd5844a0da27ec3746"

WIDTH_MM = 131.6
HEIGHT_MM = 57.0
WIDTH_INCHES = WIDTH_MM / 25.4
HEIGHT_INCHES = HEIGHT_MM / 25.4
PANEL_HEIGHT = 0.72
PANEL_WIDTH = 0.4291667
LEFT_PANEL = (0.045, 0.14, PANEL_WIDTH, PANEL_HEIGHT)
RIGHT_PANEL = (0.5258333, 0.14, PANEL_WIDTH, PANEL_HEIGHT)
OCCUPANCY = 2 * PANEL_WIDTH * PANEL_HEIGHT
OCCUPANCY_TARGET = 0.618
OCCUPANCY_TOLERANCE = 0.015
FONT_ROLES = (8.6, 7.5, 7.1)

NAVY = "#16324F"
TEAL = "#1B8A83"
AMBER = "#D98B2B"
PALETTE = {
    "neutral": NAVY,
    "coordinator_and_validated": TEAL,
    "worker_and_retry": AMBER,
}

SCENARIOS = (
    ("pre_intent", "C1", "before intent", "coordinator"),
    ("post_intent_pre_sign", "C2", "intent → sign", "coordinator"),
    ("post_sign_pre_broadcast", "C3", "sign → broadcast", "coordinator"),
    (
        "post_broadcast_pre_acknowledgement",
        "C4",
        "broadcast → ack",
        "coordinator",
    ),
    (
        "post_acknowledgement_pre_mining",
        "C5",
        "ack → mine",
        "coordinator",
    ),
    ("post_mining_pre_persistence", "C6", "mine → persist", "coordinator"),
    (
        "post_persistence_pre_stage_commit",
        "C7",
        "persist → commit",
        "coordinator",
    ),
    ("worker_action_post_submit", "W1", "worker submit", "worker"),
    (
        "transient_retry_after_broadcast",
        "R1",
        "transient retry",
        "retry",
    ),
    ("concurrent_retry", "R2", "concurrent retry", "retry"),
)
SCENARIO_INDEX = {name: (code, label, category) for name, code, label, category in SCENARIOS}
ROUTES = ("HL", "LH")


class FaultsRecoveryFigureError(ValueError):
    """Raised when final-revision input or visual contracts fail."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FaultsRecoveryFigureError(message)


def _read_json(path: Path) -> Any:
    _require(path.is_file(), f"missing JSON input: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_object(path: Path) -> dict[str, Any]:
    document = _read_json(path)
    _require(isinstance(document, dict), f"expected JSON object: {path}")
    return cast(dict[str, Any], document)


def _write_json(path: Path, document: Any) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _lab_root(repository_root: Path) -> Path:
    candidates = (repository_root / "xir-testnet-lab", repository_root)
    for candidate in candidates:
        if (candidate / "schemas").is_dir() and (candidate / "src" / "xir_lab").is_dir():
            return candidate
    raise FaultsRecoveryFigureError("cannot locate xir-testnet-lab from repository root")


def _paper_root(repository_root: Path) -> Path:
    candidates = (repository_root, repository_root.parent)
    for candidate in candidates:
        if (candidate / "main" / "figures").is_dir():
            return candidate
    raise FaultsRecoveryFigureError("cannot locate paper main/figures directory")


def _validate_schema(document: Any, schema_path: Path) -> None:
    schema = _read_object(schema_path)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise FaultsRecoveryFigureError(
            f"{schema_path.name} violation at {location}: {errors[0].message}"
        )


def _verify_publication(path: Path, label: str) -> str:
    try:
        return verify_publication(path)
    except (LocalTopologyError, KeyError, TypeError, ValueError) as error:
        raise FaultsRecoveryFigureError(f"{label} publication is invalid: {error}") from error


def _tree_digests(path: Path) -> dict[str, str]:
    return {
        str(item.relative_to(path)): sha256(item)
        for item in sorted(path.rglob("*"))
        if item.is_file()
    }


def _validate_environment(
    environment: dict[str, Any], *, deployment_sha256: str, label: str
) -> None:
    _require(
        environment.get("schema_version") == "xir-lab-native-faults-v1-environment-v1",
        f"{label} environment schema is not native-faults-v1",
    )
    _require(environment.get("controlled_campaign") is True, f"{label} is not controlled")
    _require(
        environment.get("natural_interruptions_included") is False,
        f"{label} includes natural interruptions",
    )
    _require(
        environment.get("deployment_scope") == DEPLOYMENT_SCOPE,
        f"{label} does not use the final-revision deployment scope",
    )
    _require(
        environment.get("final_revision_source_sha256") == FINAL_REVISION_SOURCE_SHA256,
        f"{label} does not bind the final source revision",
    )
    provenance_digest = environment.get("overlay_provenance_sha256")
    _require(
        isinstance(provenance_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", provenance_digest) is not None,
        f"{label} does not bind overlay provenance",
    )
    _require(
        environment.get("overlay_deployment_sha256", deployment_sha256) == deployment_sha256,
        f"{label} environment deployment digest differs",
    )


def _fault_event(result: dict[str, Any]) -> dict[str, Any]:
    events = [
        item
        for item in cast(list[dict[str, Any]], result.get("fault_events", []))
        if item.get("event_type") == "fault_injected"
    ]
    _require(len(events) == 1, f"{result.get('case_key')} must contain one injected event")
    return events[0]


def _case_row(result: dict[str, Any]) -> dict[str, Any]:
    scenario = str(result["scenario"])
    code, _label, category = SCENARIO_INDEX[scenario]
    injected = _fault_event(result)
    injected_details = cast(dict[str, Any], injected.get("details", {}))
    concurrent = result.get("concurrent_recovery_identity")
    worker = result.get("worker_lineage")
    return {
        "case_key": result["case_key"],
        "attempt_id": result["attempt_id"],
        "route": result["route"],
        "scenario": scenario,
        "code": code,
        "category": category,
        "repetition": result["repetition"],
        "actor": result["actor"],
        "boundary": result["boundary"],
        "signal": result["signal"],
        "nonce_lineage": result["nonce_lineage"],
        "transaction_lineage": result["transaction_lineage"],
        "raw_transaction_lineage": result["raw_transaction_lineage"],
        "injected_nonce": injected_details.get("nonce"),
        "injected_transaction_hash": injected_details.get("transaction_hash"),
        "injected_raw_sha256": injected_details.get("raw_sha256"),
        "worker_lineage": worker,
        "concurrent_recovery_identity": concurrent,
        "application_event_transaction_hashes": result["application_event_transaction_hashes"],
        "all_checks_valid": all(
            bool(value) for value in cast(dict[str, Any], result["checks"]).values()
        ),
        "valid": result["valid"],
    }


def _validate_cases(
    *, cases: list[dict[str, Any]], groups: list[dict[str, Any]], schema_root: Path
) -> list[dict[str, Any]]:
    _require(len(cases) == 60, "final recovery source must contain exactly 60 cases")
    expected = {
        (route, scenario, repetition)
        for route in ROUTES
        for scenario, *_ in SCENARIOS
        for repetition in range(3)
    }
    observed: set[tuple[str, str, int]] = set()
    case_keys: set[str] = set()
    attempt_ids: set[str] = set()
    for result in cases:
        _validate_schema(result, schema_root / "native-faults-v1-case-result.schema.json")
        key = (str(result["route"]), str(result["scenario"]), int(result["repetition"]))
        observed.add(key)
        case_keys.add(str(result["case_key"]))
        attempt_ids.add(str(result["attempt_id"]))
        checks = cast(dict[str, Any], result["checks"])
        _require(
            REQUIRED_CASE_CHECKS <= set(checks) and all(bool(value) for value in checks.values()),
            f"case invariants failed: {result['case_key']}",
        )
        _require(len(result["nonce_lineage"]) == 1, "case nonce lineage is not singular")
        _require(
            len(result["transaction_lineage"]) == 1,
            "case transaction-hash lineage is not singular",
        )
        _require(
            len(result["raw_transaction_lineage"]) == 1,
            "case raw-signed SHA lineage is not singular",
        )
        _require(
            len(result["application_event_transaction_hashes"]) == 1,
            "case does not contain exactly one destination effect",
        )
        if result["scenario"] == "concurrent_retry":
            _require(concurrent_identity_valid(result), "concurrent retry identity differs")
            identity = cast(dict[str, Any], result["concurrent_recovery_identity"])
            injected = cast(dict[str, Any], identity["injected"])
            _require(
                injected["raw_sha256"] == result["raw_transaction_lineage"][0],
                "concurrent raw identity differs from durable lineage",
            )
        if result["scenario"] == "worker_action_post_submit":
            worker = result.get("worker_lineage")
            _require(
                isinstance(worker, dict) and worker.get("valid") is True, "worker lineage invalid"
            )
            worker_document = cast(dict[str, Any], worker)
            actions = worker_document.get("actions")
            _require(
                isinstance(actions, list) and len(actions) == 3, "worker lineage is incomplete"
            )
            action_rows = cast(list[Any], actions)
            _require(
                all(
                    isinstance(action, dict)
                    and isinstance(action.get("raw_sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", action["raw_sha256"]) is not None
                    for action in action_rows
                ),
                "worker action raw SHA lineage is incomplete",
            )
    _require(observed == expected, "route/scenario/repetition matrix differs from 2 x 10 x 3")
    _require(len(case_keys) == 60, "case keys are not unique")
    _require(len(attempt_ids) == 60, "logical attempt identifiers are not unique")

    _require(len(groups) == 20, "summary must contain 20 route/scenario groups")
    indexed = {(str(group["route"]), str(group["scenario"])): group for group in groups}
    _require(
        set(indexed) == {(route, scenario) for route in ROUTES for scenario, *_ in SCENARIOS},
        "summary group matrix differs from 2 x 10",
    )
    for group in groups:
        for field in (
            "repetitions",
            "validated",
            "faults_injected",
            "application_events",
            "unique_tx_lineage",
            "unique_raw_tx_lineage",
        ):
            _require(int(group[field]) == 3, f"summary group {field} is not 3")
    return [
        _case_row(result)
        for result in sorted(
            cases,
            key=lambda result: (
                ROUTES.index(str(result["route"])),
                tuple(item[0] for item in SCENARIOS).index(str(result["scenario"])),
                int(result["repetition"]),
            ),
        )
    ]


def load_final_recovery_source(
    *,
    repository_root: Path,
    source_publication: Path,
    rebuild_a_publication: Path,
    rebuild_b_publication: Path,
    deployment_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Verify final source/rebuild/deployment inputs and return frozen rows."""

    lab_root = _lab_root(repository_root)
    paper_root = _paper_root(repository_root)
    schema_root = lab_root / "schemas"
    deployment = _read_object(deployment_path)
    _require(
        final_revision_deployment_contract_valid(deployment),
        "refusing old or non-separated final deployment",
    )
    _require(
        final_revision_source_lock_valid(lab_root),
        "repository does not match the final-revision source lock",
    )
    deployment_digest = sha256(deployment_path)

    publications = (
        ("frozen source", source_publication),
        ("rebuild A", rebuild_a_publication),
        ("rebuild B", rebuild_b_publication),
    )
    manifests = [_verify_publication(path, label) for label, path in publications]
    _require(len(set(manifests)) == 1, "frozen source and rebuild manifests differ")
    trees = [_tree_digests(path) for _, path in publications]
    _require(trees[0] == trees[1] == trees[2], "frozen source and rebuild bytes differ")

    summary = _read_object(source_publication / "summary.json")
    validation = _read_object(source_publication / "validation.json")
    cases_value = _read_json(source_publication / "case-results.json")
    _require(isinstance(cases_value, list), "case-results.json must contain an array")
    cases = cast(list[dict[str, Any]], cases_value)
    _validate_schema(summary, schema_root / "native-faults-v1-summary.schema.json")
    _validate_schema(validation, schema_root / "native-faults-v1-validation.schema.json")
    _require(summary.get("campaign_id") == INPUT_CAMPAIGN, "refusing smoke/non-frozen source")
    _require(validation.get("campaign_id") == INPUT_CAMPAIGN, "validation is not frozen")
    _require(summary.get("deployment_sha256") == deployment_digest, "deployment digest differs")
    _require(
        summary.get("expected_cases") == 60
        and summary.get("observed_cases") == 60
        and summary.get("validated_cases") == 60
        and summary.get("failed_cases") == 0
        and summary.get("valid") is True,
        "recovery denominator is not exactly 60/60",
    )
    _require(validation.get("valid") is True, "recovery validation is false")
    counts = cast(dict[str, Any], validation["counts"])
    for field in (
        "valid_results",
        "stable_logical_attempt_id",
        "single_nonce_lineage",
        "single_transaction_lineage",
        "single_raw_transaction_lineage",
        "one_destination_effect",
    ):
        _require(int(counts[field]) == 60, f"validation count {field} is not 60")
    _require(
        int(counts["concurrent_recovery_cases"])
        == int(counts["concurrent_recovery_shared_signed_identity"])
        == 6,
        "concurrent recovery does not preserve one raw signed identity",
    )
    _require(
        int(counts["worker_recovery_cases"]) == int(counts["worker_action_recovered"]) == 6,
        "worker recovery count differs",
    )
    environments = [_read_object(path / "environment.json") for _, path in publications]
    for (label, _), environment in zip(publications, environments, strict=True):
        _validate_environment(environment, deployment_sha256=deployment_digest, label=label)
    _require(environments[0] == environments[1] == environments[2], "environment rebuild differs")

    rows = _validate_cases(
        cases=cases,
        groups=cast(list[dict[str, Any]], summary["groups"]),
        schema_root=schema_root,
    )
    figure_one = paper_root / "main" / "figures" / "protocol-xir-reachability-topology.pdf"
    _require(sha256(figure_one) == FIGURE_1_SHA256, "frozen Figure 1 changed")
    provenance = {
        "input_campaign": INPUT_CAMPAIGN,
        "deployment_scope": DEPLOYMENT_SCOPE,
        "deployment_sha256": deployment_digest,
        "deployment_schema": deployment["schema_version"],
        "runner_root_signer_separated": deployment["runner"] != deployment["root_signer"],
        "prior_verifier_bindings": deployment["prior_verifier_bindings"],
        "final_revision_source_sha256": FINAL_REVISION_SOURCE_SHA256,
        "source_manifest_sha256": manifests[0],
        "rebuild_a_manifest_sha256": manifests[1],
        "rebuild_b_manifest_sha256": manifests[2],
        "source_summary_sha256": sha256(source_publication / "summary.json"),
        "source_case_results_sha256": sha256(source_publication / "case-results.json"),
        "figure_1_sha256": FIGURE_1_SHA256,
        "natural_interruptions_included": False,
        "statistics_recomputed": False,
    }
    return rows, cast(list[dict[str, Any]], summary["groups"]), provenance


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    if value is None:
        return ""
    return value


def _write_source_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0])
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})


def _matplotlib() -> tuple[Any, Any]:
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": FONT_ROLES[2],
            "axes.titlesize": FONT_ROLES[0],
            "axes.labelsize": FONT_ROLES[1],
            "xtick.labelsize": FONT_ROLES[2],
            "ytick.labelsize": FONT_ROLES[2],
            "pdf.fonttype": 42,
            "pdf.compression": 9,
            "svg.fonttype": "path",
            "svg.hashsalt": "xir-native-faults-v1-recovery-figure-v2",
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )
    import matplotlib.pyplot as plt

    return matplotlib, plt


def _panel_frame(axis: Any, label: str, title: str) -> None:
    from matplotlib.patches import Rectangle

    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1)
    axis.axis("off")
    axis.add_patch(Rectangle((0, 0), 1, 1, facecolor="white", edgecolor=NAVY, linewidth=0.70))
    axis.text(
        0.035,
        0.94,
        label,
        color=TEAL,
        fontsize=FONT_ROLES[0],
        fontweight="bold",
        va="top",
    )
    axis.text(
        0.13,
        0.94,
        title,
        color=NAVY,
        fontsize=FONT_ROLES[0],
        fontweight="bold",
        va="top",
    )


def _marker(axis: Any, x: float, y: float, code: str, color: str) -> None:
    from matplotlib.patches import Circle

    axis.add_patch(Circle((x, y), 0.034, facecolor="white", edgecolor=color, linewidth=0.85))
    axis.text(
        x,
        y,
        code,
        color=color,
        fontsize=FONT_ROLES[2],
        fontweight="bold",
        ha="center",
        va="center",
    )


def _draw_lifecycle(axis: Any) -> None:
    from matplotlib.patches import FancyArrowPatch

    _panel_frame(axis, "(a)", "Durable fault map")
    stages = ("plan", "intent", "sign", "send", "ack", "mine", "save", "commit")
    stage_x = [0.07 + index * (0.86 / 7) for index in range(8)]
    stage_y = 0.70
    axis.add_patch(
        FancyArrowPatch(
            (stage_x[0], stage_y),
            (stage_x[-1], stage_y),
            arrowstyle="-|>",
            mutation_scale=7,
            linewidth=0.85,
            color=NAVY,
        )
    )
    for index, (x, stage) in enumerate(zip(stage_x, stages, strict=True)):
        axis.plot([x, x], [stage_y - 0.025, stage_y + 0.025], color=NAVY, linewidth=0.70)
        axis.text(
            x,
            stage_y + (0.065 if index % 2 == 0 else 0.13),
            stage,
            color=NAVY,
            fontsize=FONT_ROLES[2],
            ha="left" if index == 0 else "right" if index == 7 else "center",
            va="bottom",
        )
    for index in range(7):
        x = (stage_x[index] + stage_x[index + 1]) / 2
        axis.plot([x, x], [0.575, 0.675], color=TEAL, linewidth=0.70)
        _marker(axis, x, 0.55, f"C{index + 1}", TEAL)

    axis.text(0.04, 0.37, "Worker", color=NAVY, fontsize=FONT_ROLES[1], fontweight="bold")
    axis.add_patch(
        FancyArrowPatch(
            (0.22, 0.375),
            (0.92, 0.375),
            arrowstyle="-|>",
            mutation_scale=7,
            linewidth=0.85,
            color=NAVY,
        )
    )
    for x, label in ((0.28, "sign"), (0.55, "submit"), (0.84, "finalize")):
        axis.text(x, 0.42, label, color=NAVY, fontsize=FONT_ROLES[2], ha="center")
    _marker(axis, 0.66, 0.375, "W1", AMBER)

    axis.text(0.04, 0.18, "Retry", color=NAVY, fontsize=FONT_ROLES[1], fontweight="bold")
    _marker(axis, 0.31, 0.19, "R1", AMBER)
    axis.text(0.37, 0.19, "transient", color=NAVY, fontsize=FONT_ROLES[2], va="center")
    _marker(axis, 0.68, 0.19, "R2", AMBER)
    axis.text(0.74, 0.19, "concurrent", color=NAVY, fontsize=FONT_ROLES[2], va="center")


def _draw_matrix(axis: Any, groups: list[dict[str, Any]]) -> None:
    from matplotlib.patches import Rectangle

    _panel_frame(axis, "(b)", "Recovery matrix")
    indexed = {(str(item["route"]), str(item["scenario"])): item for item in groups}
    scenarios = [item[0] for item in SCENARIOS]
    codes = [item[1] for item in SCENARIOS]
    x0 = 0.115
    width = 0.845 / 10
    header_y = 0.75
    for column, (scenario, code) in enumerate(zip(scenarios, codes, strict=True)):
        category = SCENARIO_INDEX[scenario][2]
        color = TEAL if category == "coordinator" else AMBER
        axis.text(
            x0 + (column + 0.5) * width,
            header_y,
            code,
            color=color,
            fontsize=FONT_ROLES[2],
            fontweight="bold",
            ha="center",
            va="center",
        )
    for row, route in enumerate(ROUTES):
        y = 0.57 - row * 0.23
        axis.text(
            0.065,
            y,
            route,
            color=NAVY,
            fontsize=FONT_ROLES[1],
            fontweight="bold",
            ha="center",
            va="center",
        )
        for column, scenario in enumerate(scenarios):
            group = indexed[(route, scenario)]
            validated = int(group["validated"])
            planned = int(group["repetitions"])
            left = x0 + column * width + 0.004
            axis.add_patch(
                Rectangle(
                    (left, y - 0.065),
                    width - 0.008,
                    0.13,
                    facecolor=TEAL,
                    edgecolor=TEAL,
                    linewidth=0.65,
                    alpha=0.15,
                )
            )
            axis.text(
                left + (width - 0.008) / 2,
                y,
                f"{validated}/{planned}",
                color=TEAL,
                fontsize=FONT_ROLES[2],
                fontweight="bold",
                ha="center",
                va="center",
            )
    axis.text(
        0.115,
        0.105,
        "60/60 controlled recoveries validated",
        color=NAVY,
        fontsize=FONT_ROLES[2],
        va="bottom",
    )
    axis.text(
        0.115,
        0.035,
        "One signed lineage and one effect per case",
        color=NAVY,
        fontsize=FONT_ROLES[2],
        va="bottom",
    )


def _render(*, pdf_path: Path, svg_path: Path, groups: list[dict[str, Any]]) -> dict[str, Any]:
    matplotlib, plt = _matplotlib()
    figure = plt.figure(figsize=(WIDTH_INCHES, HEIGHT_INCHES))
    lifecycle = figure.add_axes(LEFT_PANEL)
    matrix = figure.add_axes(RIGHT_PANEL)
    _draw_lifecycle(lifecycle)
    _draw_matrix(matrix, groups)

    from matplotlib.text import Text

    used_sizes = sorted(
        {
            float(item.get_fontsize())
            for item in figure.findobj(match=Text)
            if item.get_text().strip()
        }
    )
    _require(used_sizes == sorted(FONT_ROLES), f"unexpected font roles: {used_sizes}")
    _require(min(used_sizes) >= 7.1, "visible text is below 7.1 pt")
    pdf_metadata = {
        "Title": "Controlled recovery at durable boundaries",
        "Creator": "XIR deterministic native-faults-v1 renderer",
        "CreationDate": None,
        "ModDate": None,
    }
    svg_metadata = {
        "Title": "Controlled recovery at durable boundaries",
        "Creator": "XIR deterministic native-faults-v1 renderer",
        "Date": None,
    }
    figure.savefig(pdf_path, format="pdf", dpi=300, metadata=pdf_metadata)
    figure.savefig(svg_path, format="svg", metadata=svg_metadata)
    plt.close(figure)
    return {
        "python": sys.version.split()[0],
        "matplotlib": matplotlib.__version__,
        "visible_font_sizes": used_sizes,
    }


def _pdf_audit(path: Path) -> dict[str, Any]:
    font_output = subprocess.run(
        ["pdffonts", str(path)], check=True, capture_output=True, text=True
    ).stdout
    fonts = []
    for line in font_output.splitlines()[2:]:
        columns = line.split()
        if len(columns) >= 8:
            fonts.append(
                {
                    "name": columns[0],
                    "embedded": columns[-5] == "yes",
                    "truetype": "TrueType" in line,
                }
            )
    _require(bool(fonts), "PDF contains no auditable font")
    _require(all(item["embedded"] for item in fonts), "PDF fonts are not embedded")
    _require(all(item["truetype"] for item in fonts), "PDF fonts are not TrueType")
    _require(b"/FontFile2" in path.read_bytes(), "PDF does not contain FontFile2")

    info = subprocess.run(["pdfinfo", str(path)], check=True, capture_output=True, text=True).stdout
    match = re.search(r"Page size:\s+([0-9.]+) x ([0-9.]+) pts", info)
    _require(match is not None, "cannot parse PDF page size")
    assert match is not None
    width, height = float(match.group(1)), float(match.group(2))
    _require(abs(width - WIDTH_INCHES * 72) <= 0.02, "PDF width is not 131.6 mm")
    _require(abs(height - HEIGHT_INCHES * 72) <= 0.02, "PDF height is not 57.0 mm")
    _require(height <= 58 / 25.4 * 72 + 0.02, "PDF height exceeds 58 mm")
    images = subprocess.run(
        ["pdfimages", "-list", str(path)], check=True, capture_output=True, text=True
    ).stdout
    raster_rows = [line for line in images.splitlines() if re.match(r"\s*1\s+\d+\s+", line)]
    _require(not raster_rows, "PDF contains a raster image")
    return {
        "page_size_points": [width, height],
        "native_width_mm": WIDTH_MM,
        "native_height_mm": HEIGHT_MM,
        "fonts": fonts,
        "all_fonts_embedded": True,
        "all_fonts_truetype": True,
        "fontfile2_present": True,
        "raster_images": 0,
    }


def _svg_audit(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    hrefs = re.findall(r"(?:xlink:)?href=\"([^\"]+)\"", content)
    checks = {
        "text_converted_to_paths": "<text" not in content,
        "no_external_images": "<image" not in content,
        "only_internal_hrefs": all(value.startswith("#") for value in hrefs),
    }
    _require(all(checks.values()), "SVG is not self-contained")
    return {**checks, "internal_href_count": len(hrefs)}


def _visual_audit(pdf_path: Path, svg_path: Path, renderer: dict[str, Any]) -> dict[str, Any]:
    _require(abs(OCCUPANCY - OCCUPANCY_TARGET) <= 1e-6, "panel area is not 0.618")
    return {
        "schema_version": "xir-native-faults-v1-recovery-visual-audit-v2",
        "native_width_mm": WIDTH_MM,
        "native_height_mm": HEIGHT_MM,
        "panel_boxes": {"lifecycle": list(LEFT_PANEL), "matrix": list(RIGHT_PANEL)},
        "occupancy_formula": "2 * panel_width * panel_height",
        "internal_whitespace_included": True,
        "nominal_content_region_occupancy": OCCUPANCY,
        "occupancy_target": OCCUPANCY_TARGET,
        "occupancy_tolerance": OCCUPANCY_TOLERANCE,
        "font_roles": list(FONT_ROLES),
        "minimum_native_font_points": min(renderer["visible_font_sizes"]),
        "line_styles": ["solid"],
        "palette": PALETTE,
        "pdf": _pdf_audit(pdf_path),
        "svg": _svg_audit(svg_path),
    }


def _write_report(path: Path) -> None:
    path.write_text(
        "\n".join(
            (
                "# Native faults v1 recovery figure v2",
                "",
                "The figure shows ten preregistered durable-boundary scenarios and the exact 2 x 10 x 3 denominator.",
                "The source table retains every logical ID, nonce, transaction hash, raw signed-transaction SHA-256, concurrent recovery identity, worker-action lineage, and application-effect transaction hash.",
                "Natural interruptions are excluded. The input deployment uses administrator-approved prior-verifier bindings and distinct runner and root-signer accounts.",
                "",
            )
        ),
        encoding="utf-8",
    )


def _build_artifact(
    *,
    rows: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    provenance: dict[str, Any],
    output_directory: Path,
) -> dict[str, Any]:
    output_directory.mkdir(parents=True, exist_ok=False)
    stem = "recovery-overview-v2"
    pdf_path = output_directory / f"{stem}.pdf"
    svg_path = output_directory / f"{stem}.svg"
    csv_path = output_directory / f"{stem}-source.csv"
    json_path = output_directory / f"{stem}-source.json"
    _write_source_csv(csv_path, rows)
    renderer = _render(pdf_path=pdf_path, svg_path=svg_path, groups=groups)
    source = {
        "schema_version": "xir-native-faults-v1-recovery-figure-source-v2",
        "namespace": OUTPUT_NAMESPACE,
        "question": "Do controlled failures preserve one signed lineage and one destination effect?",
        "denominator": {
            "cases": 60,
            "routes": list(ROUTES),
            "scenarios": 10,
            "repetitions_per_route_scenario": 3,
        },
        "lineage_scope": {
            "logical_attempt_id": True,
            "nonce": True,
            "transaction_hash": True,
            "raw_signed_transaction_sha256": True,
            "worker_action": True,
            "concurrent_retry_children": 2,
            "destination_effect_transaction_hash": True,
            "raw_signed_bytes_published": False,
        },
        "provenance": provenance,
        "groups": groups,
        "cases": rows,
        "renderer": renderer,
        "output_sha256": {
            "pdf": sha256(pdf_path),
            "svg": sha256(svg_path),
            "csv": sha256(csv_path),
        },
        "renderer_source_sha256": sha256(Path(__file__)),
    }
    _write_json(json_path, source)
    visual = _visual_audit(pdf_path, svg_path, renderer)
    _write_json(output_directory / "visual-audit.json", visual)
    checks = {
        "only_final_frozen_60_case_source": provenance["input_campaign"] == INPUT_CAMPAIGN,
        "source_and_two_rebuilds_byte_identical": provenance["source_manifest_sha256"]
        == provenance["rebuild_a_manifest_sha256"]
        == provenance["rebuild_b_manifest_sha256"],
        "natural_interruptions_excluded": provenance["natural_interruptions_included"] is False,
        "final_source_lock_valid": provenance["final_revision_source_sha256"]
        == FINAL_REVISION_SOURCE_SHA256,
        "administrator_prior_verifier_binding_present": bool(provenance["prior_verifier_bindings"]),
        "runner_root_signer_separated": provenance["runner_root_signer_separated"] is True,
        "exact_60_case_denominator": len(rows) == 60,
        "all_cases_valid": all(row["valid"] and row["all_checks_valid"] for row in rows),
        "one_nonce_hash_raw_lineage_per_case": all(
            len(row["nonce_lineage"])
            == len(row["transaction_lineage"])
            == len(row["raw_transaction_lineage"])
            == 1
            for row in rows
        ),
        "one_destination_effect_per_case": all(
            len(row["application_event_transaction_hashes"]) == 1 for row in rows
        ),
        "native_width_131_6_mm": visual["native_width_mm"] == 131.6,
        "native_height_at_most_58_mm": visual["native_height_mm"] <= 58.0,
        "minimum_font_at_least_7_1_pt": visual["minimum_native_font_points"] >= 7.1,
        "font_roles_at_most_3": len(visual["font_roles"]) <= 3,
        "line_styles_at_most_3": len(visual["line_styles"]) <= 3,
        "palette_has_three_groups": len(visual["palette"]) == 3,
        "occupancy_within_tolerance": abs(
            visual["nominal_content_region_occupancy"] - OCCUPANCY_TARGET
        )
        <= OCCUPANCY_TOLERANCE,
        "pdf_fonts_embedded_truetype": visual["pdf"]["all_fonts_embedded"]
        and visual["pdf"]["all_fonts_truetype"],
        "svg_self_contained": all(
            value for key, value in visual["svg"].items() if key != "internal_href_count"
        ),
        "frozen_figure_1_unchanged": provenance["figure_1_sha256"] == FIGURE_1_SHA256,
    }
    _require(all(checks.values()), f"recovery figure validation failed: {checks}")
    _write_json(
        output_directory / "validation.json",
        {
            "schema_version": "xir-native-faults-v1-recovery-figure-validation-v2",
            "namespace": OUTPUT_NAMESPACE,
            "valid": True,
            "checks": checks,
        },
    )
    _write_report(output_directory / "REPORT.md")
    (output_directory / "CAPTION_SUGGESTION.md").write_text(
        "**Controlled recovery at durable boundaries.** Panel (a) places seven coordinator, one worker, and two retry faults along the durable lifecycle. Panel (b) reports validated/planned cases for both carrier orders. All 60 controlled cases preserve one logical attempt, one nonce/hash/raw-signed lineage, and exactly one destination effect.\n",
        encoding="utf-8",
    )
    source_semantic = hashlib.sha256(
        json.dumps(source, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return {
        "source_semantic_sha256": source_semantic,
        "files": {
            path.name: sha256(path) for path in sorted(output_directory.iterdir()) if path.is_file()
        },
    }


def build_two_rebuild_publication(
    *,
    repository_root: Path,
    source_publication: Path,
    rebuild_a_publication: Path,
    rebuild_b_publication: Path,
    deployment_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Render twice, require byte identity, and publish one immutable copy."""

    _require(not output_root.exists(), f"refusing to overwrite namespace: {output_root}")
    rows, groups, provenance = load_final_recovery_source(
        repository_root=repository_root,
        source_publication=source_publication,
        rebuild_a_publication=rebuild_a_publication,
        rebuild_b_publication=rebuild_b_publication,
        deployment_path=deployment_path,
    )
    output_root.mkdir(parents=True)
    rebuilds = [
        _build_artifact(
            rows=rows,
            groups=groups,
            provenance=provenance,
            output_directory=output_root / name,
        )
        for name in ("rebuild-a", "rebuild-b")
    ]
    _require(rebuilds[0] == rebuilds[1], "figure rebuilds are not byte-identical")
    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-native-faults-v1-recovery-rebuild-comparison-v2",
        "namespace": OUTPUT_NAMESPACE,
        "valid": True,
        "source_semantic_sha256": rebuilds[0]["source_semantic_sha256"],
        "byte_identical_files": rebuilds[0]["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    manifest = {
        "schema_version": "xir-native-faults-v1-recovery-figure-manifest-v2",
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
        "pdf_sha256": rebuilds[0]["files"]["recovery-overview-v2.pdf"],
        "svg_sha256": rebuilds[0]["files"]["recovery-overview-v2.svg"],
        "csv_sha256": rebuilds[0]["files"]["recovery-overview-v2-source.csv"],
        "valid": True,
    }
