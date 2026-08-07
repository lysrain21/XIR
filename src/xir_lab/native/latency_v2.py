"""Dependence-aware latency analysis for the immutable native run-003 scale phase."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import platform
import random
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import fmean
from typing import Any, Iterable, Sequence, cast

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from jsonschema import Draft202012Validator, FormatChecker

ROUTE_ORDER = ("HH", "LL", "HL", "LH")
METRIC_ORDER = ("mean", "median", "p95", "p99")
INTERRUPTION_DIRECTORY = re.compile(r"^(\d{8}T\d{6}Z)-")
FIGURE_METRICS = ("median", "p95", "p99")
FIGURE_COLORS = {"full": "#184E77", "clean-prefix": "#D97706"}
FIGURE_TEXT = "#263238"
FIGURE_GRID = "#D8E2E8"


class LatencyAnalysisError(RuntimeError):
    """Raised when a frozen source or statistical invariant is violated."""


@dataclass(frozen=True)
class AttemptLatency:
    attempt_id: str
    route: str
    route_sequence: int
    started_at: float
    finished_at: float

    @property
    def latency_seconds(self) -> float:
        return self.finished_at - self.started_at


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise LatencyAnalysisError(f"expected a JSON object: {path}")
    return cast(dict[str, Any], document)


def validate_json(document: dict[str, Any], schema_path: Path) -> None:
    schema = load_json(schema_path)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(document),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(item) for item in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise LatencyAnalysisError(f"schema validation failed for {schema_path.name}: {detail}")


def resolve_repo_path(repository_root: Path, configured_path: str) -> Path:
    root = repository_root.resolve()
    path = (root / configured_path).resolve()
    if path != root and root not in path.parents:
        raise LatencyAnalysisError(f"configured path escapes repository root: {path}")
    if not path.is_file():
        raise LatencyAnalysisError(f"configured source is missing: {path}")
    return path


def read_attempts(database_path: Path) -> list[AttemptLatency]:
    uri = f"file:{database_path.resolve()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        rows = connection.execute(
            """
            SELECT attempt_id, phase, route, route_sequence, status,
                   started_at, finished_at
            FROM attempts
            ORDER BY route_sequence, route, attempt_id
            """
        ).fetchall()
    finally:
        connection.close()
    attempts: list[AttemptLatency] = []
    for row in rows:
        if str(row["phase"]) != "scale":
            raise LatencyAnalysisError("latency source contains a non-scale attempt")
        if str(row["status"]) != "succeeded" or row["finished_at"] is None:
            raise LatencyAnalysisError("latency source contains a non-successful attempt")
        attempt = AttemptLatency(
            attempt_id=str(row["attempt_id"]),
            route=str(row["route"]),
            route_sequence=int(row["route_sequence"]),
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]),
        )
        if not math.isfinite(attempt.latency_seconds) or attempt.latency_seconds <= 0:
            raise LatencyAnalysisError(f"attempt has invalid latency: {attempt.attempt_id}")
        attempts.append(attempt)
    return attempts


def attempt_semantic_digest(attempts: Iterable[AttemptLatency]) -> str:
    rows = [
        {
            "attempt_id": item.attempt_id,
            "route": item.route,
            "route_sequence": item.route_sequence,
            "started_at": item.started_at,
            "finished_at": item.finished_at,
        }
        for item in sorted(
            attempts,
            key=lambda item: (
                item.route_sequence,
                ROUTE_ORDER.index(item.route),
                item.attempt_id,
            ),
        )
    ]
    return semantic_digest(rows)


def nearest_rank(values: Sequence[float], proportion: float) -> float:
    if not values:
        raise LatencyAnalysisError("cannot compute a percentile of an empty sample")
    if not 0 < proportion <= 1:
        raise LatencyAnalysisError("percentile proportion must be in (0, 1]")
    ordered = sorted(values)
    return _nearest_rank_ordered(ordered, proportion)


def _nearest_rank_ordered(ordered: Sequence[float], proportion: float) -> float:
    """Return a nearest-rank percentile from an already ordered sample."""

    if not ordered:
        raise LatencyAnalysisError("cannot compute a percentile of an empty sample")
    if not 0 < proportion <= 1:
        raise LatencyAnalysisError("percentile proportion must be in (0, 1]")
    index = max(
        0,
        min(len(ordered) - 1, math.ceil(proportion * len(ordered)) - 1),
    )
    return ordered[index]


def summarize_latency(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise LatencyAnalysisError("cannot summarize an empty latency sample")
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        sample_median = ordered[midpoint]
    else:
        sample_median = (ordered[midpoint - 1] + ordered[midpoint]) / 2
    return {
        "mean": fmean(values),
        "median": sample_median,
        "p95": _nearest_rank_ordered(ordered, 0.95),
        "p99": _nearest_rank_ordered(ordered, 0.99),
        "minimum": ordered[0],
        "maximum": ordered[-1],
    }


def derive_seed(master_seed: int, sample_id: str, route: str) -> int:
    material = f"native-latency-v2|{master_seed}|{sample_id}|{route}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def moving_block_resample(
    values: Sequence[float],
    *,
    block_length: int,
    generator: random.Random,
) -> list[float]:
    count = len(values)
    if not 1 < block_length <= count:
        raise LatencyAnalysisError(
            "moving-block length must be greater than one and no larger than the sample"
        )
    last_start = count - block_length
    sampled: list[float] = []
    while len(sampled) < count:
        start = generator.randrange(last_start + 1)
        sampled.extend(values[start : start + block_length])
    return sampled[:count]


def bootstrap_latency(
    values: Sequence[float],
    *,
    block_length: int,
    repetitions: int,
    confidence_level: float,
    seed: int,
) -> tuple[dict[str, dict[str, float]], list[dict[str, float]], str]:
    if repetitions < 1:
        raise LatencyAnalysisError("bootstrap repetitions must be positive")
    generator = random.Random(seed)
    estimates = summarize_latency(values)
    replicate_rows: list[dict[str, float]] = []
    distributions: dict[str, list[float]] = {metric: [] for metric in METRIC_ORDER}
    replicate_hasher = hashlib.sha256()
    for repetition in range(1, repetitions + 1):
        sample = moving_block_resample(
            values,
            block_length=block_length,
            generator=generator,
        )
        summary = summarize_latency(sample)
        row = {
            "repetition": float(repetition),
            **{metric: summary[metric] for metric in METRIC_ORDER},
        }
        replicate_rows.append(row)
        replicate_hasher.update(canonical_json(row))
        replicate_hasher.update(b"\n")
        for metric in METRIC_ORDER:
            distributions[metric].append(summary[metric])
    alpha = 1 - confidence_level
    intervals = {
        metric: {
            "estimate": estimates[metric],
            "lower": nearest_rank(distributions[metric], alpha / 2),
            "upper": nearest_rank(distributions[metric], 1 - alpha / 2),
        }
        for metric in METRIC_ORDER
    }
    return intervals, replicate_rows, replicate_hasher.hexdigest()


def grouped_attempts(
    attempts: Iterable[AttemptLatency],
) -> dict[str, list[AttemptLatency]]:
    groups: dict[str, list[AttemptLatency]] = {route: [] for route in ROUTE_ORDER}
    for attempt in attempts:
        if attempt.route not in groups:
            raise LatencyAnalysisError(f"unexpected route: {attempt.route}")
        groups[attempt.route].append(attempt)
    for route in ROUTE_ORDER:
        groups[route].sort(key=lambda item: (item.started_at, item.route_sequence, item.attempt_id))
    return groups


def validate_route_sequences(
    groups: dict[str, list[AttemptLatency]],
    expected_per_route: int,
) -> None:
    for route in ROUTE_ORDER:
        rows = groups[route]
        if len(rows) != expected_per_route:
            raise LatencyAnalysisError(
                f"route {route} has {len(rows)} attempts, expected {expected_per_route}"
            )
        sequences = sorted(item.route_sequence for item in rows)
        if sequences != list(range(expected_per_route)):
            raise LatencyAnalysisError(f"route {route} does not have an exact sequence prefix")


def clean_prefix(
    attempts: Sequence[AttemptLatency],
    *,
    boundary_epoch: float,
) -> tuple[list[AttemptLatency], int]:
    by_coordinate = {(attempt.route_sequence, attempt.route): attempt for attempt in attempts}
    sequence = 0
    while all(
        (sequence, route) in by_coordinate
        and by_coordinate[(sequence, route)].finished_at < boundary_epoch
        for route in ROUTE_ORDER
    ):
        sequence += 1
    maximum_included_sequence = sequence - 1
    selected = [
        attempt for attempt in attempts if attempt.route_sequence <= maximum_included_sequence
    ]
    if any(attempt.finished_at >= boundary_epoch for attempt in selected):
        raise LatencyAnalysisError("clean prefix contains an attempt crossing the boundary")
    return selected, maximum_included_sequence


def parse_boundary(timestamp: str) -> float:
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise LatencyAnalysisError(f"invalid interruption boundary: {timestamp}") from error


def boundary_is_first_documented(event_path: Path, boundary_utc: str) -> bool:
    directory = event_path.parent
    parent = directory.parent
    documented: list[tuple[datetime, Path]] = []
    for candidate in parent.iterdir():
        if not candidate.is_dir():
            continue
        match = INTERRUPTION_DIRECTORY.match(candidate.name)
        if match is None or not (candidate / "event.json").is_file():
            continue
        documented.append((datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ"), candidate))
    if not documented:
        return False
    documented.sort(key=lambda item: (item[0], item[1].name))
    configured = datetime.fromisoformat(boundary_utc.replace("Z", "+00:00"))
    first_naive = documented[0][0]
    return directory == documented[0][1] and first_naive == configured.replace(tzinfo=None)


def accepted_analysis_semantic_valid(document: dict[str, Any]) -> bool:
    expected = document.get("semantic_sha256")
    payload = dict(document)
    payload.pop("semantic_sha256", None)
    return isinstance(expected, str) and semantic_digest(payload) == expected


def accepted_route_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = document.get("per_route")
    if not isinstance(rows, list):
        raise LatencyAnalysisError("accepted analysis has no per_route rows")
    return {str(row["route"]): cast(dict[str, Any], row) for row in rows}


def _metric_matches_accepted(route_summary: dict[str, float], accepted: dict[str, Any]) -> bool:
    mapping = {
        "mean": "latency_seconds_mean",
        "median": "latency_seconds_median",
        "p95": "latency_seconds_p95",
        "p99": "latency_seconds_p99",
        "minimum": "latency_seconds_min",
        "maximum": "latency_seconds_max",
    }
    return all(
        math.isclose(
            route_summary[metric],
            float(accepted[field]),
            rel_tol=0,
            abs_tol=1e-12,
        )
        for metric, field in mapping.items()
    )


def analyze_sample(
    *,
    sample_id: str,
    role: str,
    attempts: Sequence[AttemptLatency],
    full_denominator: int,
    selection_rule: dict[str, Any],
    bootstrap_config: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    groups = grouped_attempts(attempts)
    counts = {route: len(groups[route]) for route in ROUTE_ORDER}
    if len(set(counts.values())) != 1:
        raise LatencyAnalysisError(f"sample {sample_id} is not route balanced: {counts}")
    route_results: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    replicate_rows: list[dict[str, Any]] = []
    for route in ROUTE_ORDER:
        values = [attempt.latency_seconds for attempt in groups[route]]
        seed = derive_seed(
            int(bootstrap_config["master_seed"]),
            sample_id,
            route,
        )
        intervals, route_replicates, replicate_digest = bootstrap_latency(
            values,
            block_length=int(bootstrap_config["block_length_attempts_per_route"]),
            repetitions=int(bootstrap_config["repetitions"]),
            confidence_level=float(bootstrap_config["confidence_level"]),
            seed=seed,
        )
        route_result = {
            "route": route,
            "included_attempts": len(values),
            "excluded_attempts": full_denominator // len(ROUTE_ORDER) - len(values),
            "minimum_seconds": min(values),
            "maximum_seconds": max(values),
            **intervals,
            "bootstrap_seed": seed,
            "bootstrap_replicate_sha256": replicate_digest,
        }
        route_results.append(route_result)
        for row in route_replicates:
            replicate_rows.append(
                {
                    "sample_id": sample_id,
                    "route": route,
                    "bootstrap_seed": seed,
                    "repetition": int(row["repetition"]),
                    **{metric: row[metric] for metric in METRIC_ORDER},
                }
            )
    sample = {
        "sample_id": sample_id,
        "role": role,
        "selection_rule": selection_rule,
        "included_attempts": len(attempts),
        "excluded_attempts": full_denominator - len(attempts),
        "route_balanced": True,
        "per_route": route_results,
    }
    summary_rows = [
        _flatten_summary_row(
            sample_id=sample_id,
            role=role,
            route_result=route_result,
        )
        for route_result in route_results
    ]
    return sample, summary_rows, replicate_rows


def _flatten_summary_row(
    *,
    sample_id: str,
    role: str,
    route_result: dict[str, Any],
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "sample_id": sample_id,
        "sample_role": role,
        "route": route_result["route"],
        "included_attempts": route_result["included_attempts"],
        "excluded_attempts": route_result["excluded_attempts"],
        "minimum_seconds": route_result["minimum_seconds"],
        "maximum_seconds": route_result["maximum_seconds"],
    }
    for metric in METRIC_ORDER:
        row[f"{metric}_estimate"] = route_result[metric]["estimate"]
        row[f"{metric}_ci_lower"] = route_result[metric]["lower"]
        row[f"{metric}_ci_upper"] = route_result[metric]["upper"]
    row["bootstrap_seed"] = route_result["bootstrap_seed"]
    return row


def figure_source_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the long-form source table consumed by the latency figure."""

    rows: list[dict[str, Any]] = []
    for sample_key in ("primary_sample", "sensitivity_sample"):
        sample = document[sample_key]
        for route_result in sample["per_route"]:
            for metric in FIGURE_METRICS:
                interval = route_result[metric]
                rows.append(
                    {
                        "sample_id": sample["sample_id"],
                        "sample_role": sample["role"],
                        "route": route_result["route"],
                        "metric": metric,
                        "estimate_seconds": interval["estimate"],
                        "ci_lower_seconds": interval["lower"],
                        "ci_upper_seconds": interval["upper"],
                        "included_attempts": route_result["included_attempts"],
                        "excluded_attempts": route_result["excluded_attempts"],
                    }
                )
    return rows


def write_latency_figure(path: Path, document: dict[str, Any]) -> None:
    """Render a deterministic, paper-ready interval and sensitivity figure."""

    samples = (document["primary_sample"], document["sensitivity_sample"])
    by_sample = {
        sample["sample_id"]: {row["route"]: row for row in sample["per_route"]}
        for sample in samples
    }
    with plt.rc_context(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8,
            "axes.titlesize": 9,
            "axes.labelsize": 8,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "legend.fontsize": 7,
            "text.color": FIGURE_TEXT,
            "axes.labelcolor": FIGURE_TEXT,
            "axes.edgecolor": FIGURE_TEXT,
            "xtick.color": FIGURE_TEXT,
            "ytick.color": FIGURE_TEXT,
            "axes.linewidth": 0.6,
            "pdf.fonttype": 42,
            "savefig.facecolor": "white",
            "figure.facecolor": "white",
        }
    ):
        figure, axes = plt.subplots(
            1,
            3,
            figsize=(7.2, 2.45),
            sharey=True,
            gridspec_kw={"wspace": 0.23},
        )
        offsets = {"full": -0.11, "clean-prefix": 0.11}
        markers = {"full": "o", "clean-prefix": "D"}
        labels = {"full": "Full (n=40,000)", "clean-prefix": "Clean prefix (n=14,616)"}
        base_y = list(range(len(ROUTE_ORDER)))
        for axis, metric in zip(axes, FIGURE_METRICS, strict=True):
            for sample_id in ("full", "clean-prefix"):
                route_rows = by_sample[sample_id]
                estimates = [route_rows[route][metric]["estimate"] for route in ROUTE_ORDER]
                lower = [route_rows[route][metric]["lower"] for route in ROUTE_ORDER]
                upper = [route_rows[route][metric]["upper"] for route in ROUTE_ORDER]
                y_values = [value + offsets[sample_id] for value in base_y]
                axis.errorbar(
                    estimates,
                    y_values,
                    xerr=(
                        [estimate - bound for estimate, bound in zip(estimates, lower)],
                        [bound - estimate for estimate, bound in zip(estimates, upper)],
                    ),
                    fmt=markers[sample_id],
                    color=FIGURE_COLORS[sample_id],
                    markersize=3.8,
                    capsize=2.2,
                    elinewidth=1.0,
                    markeredgewidth=0,
                    label=labels[sample_id],
                )
            axis.set_title(metric.upper())
            axis.set_xlabel("Latency (s)")
            axis.set_yticks(base_y, ROUTE_ORDER)
            axis.invert_yaxis()
            axis.grid(axis="x", color=FIGURE_GRID, linewidth=0.5)
            axis.set_axisbelow(True)
            axis.spines[["top", "right"]].set_visible(False)
            axis.tick_params(width=0.6, length=2.5)
        figure.legend(
            *axes[0].get_legend_handles_labels(),
            loc="upper center",
            bbox_to_anchor=(0.5, 1.01),
            ncol=2,
            frameon=False,
        )
        figure.text(
            0.5,
            0.015,
            "Dot = estimate; line = 95% route-stratified moving-block bootstrap interval",
            ha="center",
            va="bottom",
            fontsize=7,
            color=FIGURE_TEXT,
        )
        figure.subplots_adjust(left=0.08, right=0.985, bottom=0.24, top=0.79)
        figure.savefig(
            path,
            bbox_inches="tight",
            metadata={
                "Creator": "XIR deterministic latency-v2 analysis",
                "CreationDate": None,
                "ModDate": None,
            },
        )
        plt.close(figure)


def build_analysis(
    *,
    repository_root: Path,
    config: dict[str, Any],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, bool],
]:
    source_config = cast(dict[str, Any], config["source"])
    denominator = cast(dict[str, Any], config["denominator"])
    bootstrap_config = cast(dict[str, Any], config["bootstrap"])
    prefix_config = cast(dict[str, Any], config["clean_prefix"])
    database_path = resolve_repo_path(repository_root, source_config["database_path"])
    accepted_path = resolve_repo_path(
        repository_root,
        source_config["accepted_analysis_path"],
    )
    reconciliation_path = resolve_repo_path(
        repository_root,
        source_config["reconciliation_path"],
    )
    boundary_path = resolve_repo_path(
        repository_root,
        prefix_config["boundary_source_path"],
    )
    database_sha_before = sha256_file(database_path)
    accepted_sha = sha256_file(accepted_path)
    reconciliation_sha = sha256_file(reconciliation_path)
    boundary_sha = sha256_file(boundary_path)
    source_hash_checks = {
        "source_database_sha256_matches": (database_sha_before == source_config["database_sha256"]),
        "accepted_analysis_sha256_matches": (
            accepted_sha == source_config["accepted_analysis_sha256"]
        ),
        "reconciliation_sha256_matches": (
            reconciliation_sha == source_config["reconciliation_sha256"]
        ),
        "boundary_source_sha256_matches": (boundary_sha == prefix_config["boundary_source_sha256"]),
    }
    if not all(source_hash_checks.values()):
        raise LatencyAnalysisError(f"frozen source hash mismatch: {source_hash_checks}")
    accepted = load_json(accepted_path)
    reconciliation = load_json(reconciliation_path)
    attempts = read_attempts(database_path)
    groups = grouped_attempts(attempts)
    validate_route_sequences(groups, int(denominator["attempts_per_route"]))
    boundary_epoch = parse_boundary(str(prefix_config["boundary_utc"]))
    sensitivity_attempts, maximum_sequence = clean_prefix(
        attempts,
        boundary_epoch=boundary_epoch,
    )
    full_sample, _, full_replicates = analyze_sample(
        sample_id="full",
        role="primary",
        attempts=attempts,
        full_denominator=int(denominator["logical_attempts"]),
        selection_rule={
            "rule_id": "all-reconciled-scale-attempts-v1",
            "description": "All 40,000 reconciled scale attempts; natural interruptions remain included.",
        },
        bootstrap_config=bootstrap_config,
    )
    sensitivity_sample, _, sensitivity_replicates = analyze_sample(
        sample_id="clean-prefix",
        role="sensitivity",
        attempts=sensitivity_attempts,
        full_denominator=int(denominator["logical_attempts"]),
        selection_rule={
            "rule_id": prefix_config["rule_id"],
            "description": prefix_config["description"],
            "boundary_utc": prefix_config["boundary_utc"],
            "boundary_operator": "finished_at < boundary",
            "maximum_included_route_sequence": maximum_sequence,
        },
        bootstrap_config=bootstrap_config,
    )
    summary_rows = [
        _flatten_summary_row(
            sample_id=sample["sample_id"],
            role=sample["role"],
            route_result=route_result,
        )
        for sample in (full_sample, sensitivity_sample)
        for route_result in sample["per_route"]
    ]
    replicate_rows = full_replicates + sensitivity_replicates
    primary_by_route = {row["route"]: row for row in full_sample["per_route"]}
    sensitivity_by_route = {row["route"]: row for row in sensitivity_sample["per_route"]}
    comparison = []
    for route in ROUTE_ORDER:
        comparison.append(
            {
                "route": route,
                "sensitivity_minus_primary_seconds": {
                    metric: (
                        sensitivity_by_route[route][metric]["estimate"]
                        - primary_by_route[route][metric]["estimate"]
                    )
                    for metric in METRIC_ORDER
                },
            }
        )
    accepted_routes = accepted_route_map(accepted)
    primary_matches = {
        route: _metric_matches_accepted(
            {
                "mean": primary_by_route[route]["mean"]["estimate"],
                "median": primary_by_route[route]["median"]["estimate"],
                "p95": primary_by_route[route]["p95"]["estimate"],
                "p99": primary_by_route[route]["p99"]["estimate"],
                "minimum": primary_by_route[route]["minimum_seconds"],
                "maximum": primary_by_route[route]["maximum_seconds"],
            },
            accepted_routes[route],
        )
        for route in ROUTE_ORDER
    }
    accepted_semantic_valid = accepted_analysis_semantic_valid(accepted)
    accepted_semantic_matches_config = (
        accepted.get("semantic_sha256") == source_config["accepted_semantic_sha256"]
    )
    source_attempt_digest = attempt_semantic_digest(attempts)
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-latency-v2-analysis-v1",
        "namespace": config["namespace"],
        "source": {
            "run_id": source_config["run_id"],
            "database_sha256": database_sha_before,
            "database_bytes": database_path.stat().st_size,
            "attempt_rows_semantic_sha256": source_attempt_digest,
            "accepted_analysis_sha256": accepted_sha,
            "accepted_semantic_sha256": accepted.get("semantic_sha256"),
            "reconciliation_sha256": reconciliation_sha,
            "network_reads_required": False,
        },
        "method": {
            **bootstrap_config,
            "stratification": "route",
            "resampling": "overlapping non-circular contiguous blocks sampled with replacement and truncated to the original route sample size",
            "primary_role": "The full sample is the primary result.",
            "sensitivity_role": "The clean prefix is a separately labeled interruption-free sensitivity and does not replace the primary result.",
        },
        "primary_sample": full_sample,
        "sensitivity_sample": sensitivity_sample,
        "comparison": comparison,
        "reconciliation": {
            "original_denominator": reconciliation.get("denominator"),
            "accepted_analysis_semantic_valid": accepted_semantic_valid,
            "accepted_semantic_matches_config": accepted_semantic_matches_config,
            "primary_route_values_match_accepted": primary_matches,
            "source_database_unchanged": None,
        },
    }
    database_sha_after = sha256_file(database_path)
    document["reconciliation"]["source_database_unchanged"] = (
        database_sha_after == database_sha_before
    )
    document["semantic_sha256"] = semantic_digest(document)
    source_pointer = {
        "schema_version": "xir-lab-native-latency-v2-source-pointers-v1",
        "namespace": config["namespace"],
        "copy_policy": "No frozen raw input is copied or modified; paths and SHA-256 digests identify immutable sources.",
        "sources": [
            {
                "role": "latency_database",
                "path": source_config["database_path"],
                "bytes": database_path.stat().st_size,
                "sha256": database_sha_before,
                "read_mode": "SQLite mode=ro, immutable=1, query_only=ON",
            },
            {
                "role": "accepted_analysis",
                "path": source_config["accepted_analysis_path"],
                "bytes": accepted_path.stat().st_size,
                "sha256": accepted_sha,
                "semantic_sha256": accepted.get("semantic_sha256"),
            },
            {
                "role": "accepted_reconciliation",
                "path": source_config["reconciliation_path"],
                "bytes": reconciliation_path.stat().st_size,
                "sha256": reconciliation_sha,
                "valid": reconciliation.get("valid"),
            },
            {
                "role": "first_natural_interruption_record",
                "path": prefix_config["boundary_source_path"],
                "bytes": boundary_path.stat().st_size,
                "sha256": boundary_sha,
                "boundary_utc": prefix_config["boundary_utc"],
            },
        ],
    }
    checks = {
        **source_hash_checks,
        "attempt_denominator_exact": len(attempts) == int(denominator["logical_attempts"]),
        "full_routes_balanced": all(
            len(groups[route]) == int(denominator["attempts_per_route"]) for route in ROUTE_ORDER
        ),
        "accepted_analysis_semantic_self_valid": accepted_semantic_valid,
        "accepted_semantic_sha256_matches_config": accepted_semantic_matches_config,
        "accepted_reconciliation_valid": reconciliation.get("valid") is True,
        "accepted_reconciliation_denominator_exact": (
            reconciliation.get("denominator", {}).get("logical_attempts")
            == int(denominator["logical_attempts"])
            and reconciliation.get("denominator", {}).get("per_route")
            == int(denominator["attempts_per_route"])
        ),
        "primary_route_values_match_accepted": all(primary_matches.values()),
        "boundary_is_first_documented_interruption": boundary_is_first_documented(
            boundary_path,
            str(prefix_config["boundary_utc"]),
        ),
        "clean_prefix_is_nonempty_strict_subset": (0 < len(sensitivity_attempts) < len(attempts)),
        "clean_prefix_routes_balanced": len(
            {len(rows) for rows in grouped_attempts(sensitivity_attempts).values()}
        )
        == 1,
        "clean_prefix_all_finished_before_boundary": all(
            attempt.finished_at < boundary_epoch for attempt in sensitivity_attempts
        ),
        "clean_prefix_is_exact_sequence_prefix": (
            {attempt.route_sequence for attempt in sensitivity_attempts}
            == set(range(maximum_sequence + 1))
        ),
        "source_database_unchanged": database_sha_after == database_sha_before,
        "analysis_semantic_sha256_self_valid": (
            semantic_digest(
                {key: value for key, value in document.items() if key != "semantic_sha256"}
            )
            == document["semantic_sha256"]
        ),
        "summary_rows_exact": len(summary_rows) == 8,
        "bootstrap_replicate_rows_exact": len(replicate_rows)
        == 2 * len(ROUTE_ORDER) * int(bootstrap_config["repetitions"]),
    }
    return document, summary_rows, replicate_rows, source_pointer, checks


def git_environment(repository_root: Path) -> dict[str, Any]:
    implementation_root = repository_root / "xir-testnet-lab"
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=implementation_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=implementation_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    return {
        "schema_version": "xir-lab-native-latency-v2-environment-v1",
        "namespace": "native-latency-v2",
        "network_reads_required": False,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "sqlite_version": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "generator_repository_revision": revision,
        "generator_working_tree_dirty": dirty,
        "command_contract": "build twice from frozen source and config; compare semantic and generated-file digests",
    }


def report_markdown(document: dict[str, Any]) -> str:
    method = document["method"]
    primary = document["primary_sample"]
    sensitivity = document["sensitivity_sample"]
    prefix_rule = sensitivity["selection_rule"]
    lines = [
        "# Native latency v2 statistical report",
        "",
        "## Result",
        "",
        f"The primary sample retains all `{primary['included_attempts']}` reconciled scale attempts. "
        "The clean-prefix sensitivity includes "
        f"`{sensitivity['included_attempts']}` attempts and excludes "
        f"`{sensitivity['excluded_attempts']}` attempts after the frozen boundary.",
        "",
        "| Sample | Route | Included | Excluded | Median (95% CI), s | P95 (95% CI), s | P99 (95% CI), s |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for sample in (primary, sensitivity):
        for row in sample["per_route"]:
            lines.append(
                f"| {sample['sample_id']} | {row['route']} | "
                f"{row['included_attempts']} | {row['excluded_attempts']} | "
                f"{row['median']['estimate']:.3f} "
                f"[{row['median']['lower']:.3f}, {row['median']['upper']:.3f}] | "
                f"{row['p95']['estimate']:.3f} "
                f"[{row['p95']['lower']:.3f}, {row['p95']['upper']:.3f}] | "
                f"{row['p99']['estimate']:.3f} "
                f"[{row['p99']['lower']:.3f}, {row['p99']['upper']:.3f}] |"
            )
    lines.extend(
        [
            "",
            "## Dependence-aware interval method",
            "",
            f"The analysis uses `{method['method']}` independently within each route. "
            f"Attempts are ordered by `{', '.join(method['ordering'])}`. Each replicate samples "
            f"overlapping contiguous blocks of `{method['block_length_attempts_per_route']}` "
            f"route observations, with `{method['repetitions']}` repetitions, a fixed master seed "
            f"of `{method['master_seed']}`, and a "
            f"`{100 * method['confidence_level']:.1f}%` empirical percentile interval.",
            "",
            str(method["block_length_rationale"]),
            "",
            "## Interruption-free sensitivity rule",
            "",
            str(prefix_rule["description"]),
            "",
            f"The first documented natural-interruption boundary is "
            f"`{prefix_rule['boundary_utc']}`. The maximum included route sequence is "
            f"`{prefix_rule['maximum_included_route_sequence']}`. All four routes contain the same "
            "matched sequence prefix; attempts that straddle the boundary are excluded.",
            "",
            "## Interpretation",
            "",
            "The full sample is the primary 40,000-attempt long-running workload result at one "
            "operating point. The clean prefix is a sensitivity estimate for the period before the "
            "first documented natural interruption. Neither result is a load sweep or a scalability "
            "measurement.",
            "",
            "## Reconciliation",
            "",
            f"Source database SHA-256: `{document['source']['database_sha256']}`.",
            "",
            f"Accepted analysis semantic SHA-256: "
            f"`{document['source']['accepted_semantic_sha256']}`.",
            "",
            f"Latency-v2 semantic SHA-256: `{document['semantic_sha256']}`.",
            "",
            "All primary point estimates reproduce the accepted run-003 analysis before confidence "
            "intervals are added. The source database is opened read-only and its SHA-256 digest is "
            "checked before and after analysis.",
            "",
        ]
    )
    return "\n".join(lines)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise LatencyAnalysisError(f"cannot write empty CSV: {path}")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_artifact(
    *,
    repository_root: Path,
    config_path: Path,
    schema_root: Path,
    output_directory: Path,
) -> dict[str, Any]:
    if output_directory.exists():
        raise LatencyAnalysisError(f"refusing to overwrite latency-v2 output: {output_directory}")
    config = load_json(config_path)
    validate_json(config, schema_root / "native-latency-v2-config.schema.json")
    document, summary_rows, replicate_rows, source_pointer, checks = build_analysis(
        repository_root=repository_root,
        config=config,
    )
    latency_figure_rows = figure_source_rows(document)
    validate_json(document, schema_root / "native-latency-v2-analysis.schema.json")
    output_directory.mkdir(parents=True)
    write_json(output_directory / "config.json", config)
    write_json(output_directory / "analysis.json", document)
    write_csv(output_directory / "per-route.csv", summary_rows)
    write_csv(
        output_directory / "paper-source-latency-intervals.csv",
        latency_figure_rows,
    )
    write_csv(output_directory / "bootstrap-replicates.csv", replicate_rows)
    write_json(output_directory / "source-pointer-manifest.json", source_pointer)
    write_json(
        output_directory / "environment.json",
        git_environment(repository_root),
    )
    (output_directory / "report.md").write_text(
        report_markdown(document),
        encoding="utf-8",
    )
    figure_path = output_directory / "latency-intervals.pdf"
    write_latency_figure(figure_path, document)
    checks = {
        **checks,
        "config_schema_valid": True,
        "analysis_schema_valid": True,
        "no_network_reads_required": document["source"]["network_reads_required"] is False,
        "paper_figure_source_rows_exact": len(latency_figure_rows)
        == 2 * len(ROUTE_ORDER) * len(FIGURE_METRICS),
        "paper_figure_nonempty": figure_path.stat().st_size > 0,
    }
    validation = {
        "schema_version": "xir-lab-native-latency-v2-validation-v1",
        "namespace": config["namespace"],
        "valid": all(checks.values()),
        "checks": checks,
        "errors": [name for name, passed in checks.items() if not passed],
    }
    validate_json(
        validation,
        schema_root / "native-latency-v2-validation.schema.json",
    )
    write_json(output_directory / "validation.json", validation)
    if not validation["valid"]:
        raise LatencyAnalysisError(f"native latency v2 validation failed: {validation['errors']}")
    return {
        "analysis_semantic_sha256": document["semantic_sha256"],
        "files": {
            path.name: sha256_file(path)
            for path in sorted(output_directory.iterdir())
            if path.is_file()
        },
    }
