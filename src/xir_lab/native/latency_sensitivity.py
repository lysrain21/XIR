"""Deterministic block-length sensitivity for native-latency-v2 medians."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import shutil
from pathlib import Path
from typing import Any, Sequence

from xir_lab.native.latency_v2 import (
    ROUTE_ORDER,
    LatencyAnalysisError,
    grouped_attempts,
    nearest_rank,
    read_attempts,
    sha256_file,
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed(master_seed: int, route: str, block_length: int) -> int:
    material = (
        f"native-latency-v2-block-sensitivity|{master_seed}|{route}|{block_length}"
    ).encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def block_median_interval(
    values: Sequence[float],
    *,
    block_length: int,
    repetitions: int,
    confidence_level: float,
    seed: int,
) -> dict[str, float | int]:
    """Return a non-circular moving-block percentile interval for the median."""

    count = len(values)
    if not 1 < block_length <= count:
        raise LatencyAnalysisError("invalid sensitivity block length")
    if repetitions < 1 or not 0 < confidence_level < 1:
        raise LatencyAnalysisError("invalid sensitivity bootstrap configuration")
    generator = random.Random(seed)
    last_start = count - block_length
    block_count = math.ceil(count / block_length)
    medians: list[float] = []
    for _ in range(repetitions):
        sample: list[float] = []
        for _ in range(block_count):
            start = generator.randrange(last_start + 1)
            sample.extend(values[start : start + block_length])
        sample = sample[:count]
        sample.sort()
        midpoint = count // 2
        median = (
            sample[midpoint]
            if count % 2
            else (sample[midpoint - 1] + sample[midpoint]) / 2
        )
        medians.append(median)
    ordered = sorted(values)
    midpoint = count // 2
    estimate = (
        ordered[midpoint]
        if count % 2
        else (ordered[midpoint - 1] + ordered[midpoint]) / 2
    )
    alpha = 1 - confidence_level
    return {
        "attempts": count,
        "block_length": block_length,
        "repetitions": repetitions,
        "estimate": estimate,
        "lower": nearest_rank(medians, alpha / 2),
        "upper": nearest_rank(medians, 1 - alpha / 2),
    }


def _validate_config(config: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "namespace",
        "source",
        "routes",
        "attempts_per_route",
        "metric",
        "confidence_level",
        "block_lengths",
        "repetitions",
        "master_seed",
        "primary_block_length",
        "rationale",
    }
    if set(config) != required:
        raise LatencyAnalysisError("unexpected block-sensitivity configuration fields")
    if tuple(config["routes"]) != ROUTE_ORDER:
        raise LatencyAnalysisError("route order differs from the frozen latency analysis")
    if config["metric"] != "median":
        raise LatencyAnalysisError("block sensitivity is frozen to the median")
    lengths = [int(value) for value in config["block_lengths"]]
    if lengths != [32, 64, 128] or int(config["primary_block_length"]) != 64:
        raise LatencyAnalysisError("block sensitivity must use 32/64/128 around primary 64")


def build_sensitivity_artifact(
    *, repository_root: Path, config_path: Path, output_directory: Path
) -> dict[str, Any]:
    """Build one deterministic sensitivity artifact from the immutable database."""

    config = json.loads(config_path.read_text(encoding="utf-8"))
    _validate_config(config)
    database = (repository_root / config["source"]["database_path"]).resolve()
    if repository_root.resolve() not in database.parents or not database.is_file():
        raise LatencyAnalysisError("configured sensitivity database is unavailable")
    before = sha256_file(database)
    if before != config["source"]["database_sha256"]:
        raise LatencyAnalysisError("sensitivity database digest mismatch")
    attempts = read_attempts(database)
    groups = grouped_attempts(attempts)
    expected = int(config["attempts_per_route"])
    rows: list[dict[str, Any]] = []
    for route in ROUTE_ORDER:
        values = [attempt.latency_seconds for attempt in groups[route]]
        if len(values) != expected:
            raise LatencyAnalysisError(f"{route} sensitivity denominator mismatch")
        for block_length in config["block_lengths"]:
            result = block_median_interval(
                values,
                block_length=int(block_length),
                repetitions=int(config["repetitions"]),
                confidence_level=float(config["confidence_level"]),
                seed=_seed(int(config["master_seed"]), route, int(block_length)),
            )
            rows.append({"route": route, **result})
    if sha256_file(database) != before:
        raise LatencyAnalysisError("sensitivity source database changed during analysis")
    output_directory.mkdir(parents=True, exist_ok=False)
    csv_path = output_directory / "block-length-sensitivity.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    semantic = {
        "schema_version": "xir-lab-native-latency-v2-block-sensitivity-result-v1",
        "namespace": config["namespace"],
        "database_sha256": before,
        "confidence_level": config["confidence_level"],
        "metric": "median",
        "primary_block_length": 64,
        "rationale": config["rationale"],
        "rows": rows,
    }
    semantic_sha256 = hashlib.sha256(_canonical_json(semantic).encode("utf-8")).hexdigest()
    semantic["semantic_sha256"] = semantic_sha256
    _write_json(output_directory / "summary.json", semantic)
    report_lines = [
        "# Native latency v2 block-length sensitivity",
        "",
        str(config["rationale"]),
        "",
        "| Route | Block | Median (95% interval), s |",
        "| --- | ---: | ---: |",
    ]
    for row in rows:
        report_lines.append(
            f"| {row['route']} | {row['block_length']} | "
            f"{row['estimate']:.3f} [{row['lower']:.3f}, {row['upper']:.3f}] |"
        )
    report_lines.extend(
        [
            "",
            "All rows use 10,000 attempts per route and 2,000 deterministic moving-block bootstrap repetitions.",
            "The source database was opened read-only and retained its frozen SHA-256 digest.",
            "",
        ]
    )
    (output_directory / "REPORT.md").write_text("\n".join(report_lines), encoding="utf-8")
    files = {
        path.name: sha256_file(path)
        for path in sorted(output_directory.iterdir())
        if path.is_file()
    }
    return {"semantic_sha256": semantic_sha256, "files": files}


def build_two_rebuild_publication(
    *, repository_root: Path, config_path: Path, output_root: Path
) -> dict[str, Any]:
    """Build twice, require byte identity, and publish one immutable copy."""

    if output_root.exists():
        raise LatencyAnalysisError(f"refusing to overwrite sensitivity namespace: {output_root}")
    output_root.mkdir(parents=True)
    run_a = build_sensitivity_artifact(
        repository_root=repository_root,
        config_path=config_path,
        output_directory=output_root / "rebuild-a",
    )
    run_b = build_sensitivity_artifact(
        repository_root=repository_root,
        config_path=config_path,
        output_directory=output_root / "rebuild-b",
    )
    if run_a != run_b:
        raise LatencyAnalysisError("block-sensitivity rebuilds differ")
    publication = output_root / "publication"
    shutil.copytree(output_root / "rebuild-a", publication)
    comparison = {
        "schema_version": "xir-lab-native-latency-v2-block-sensitivity-rebuild-v1",
        "valid": True,
        "semantic_sha256": run_a["semantic_sha256"],
        "generated_file_sha256": run_a["files"],
    }
    _write_json(publication / "rebuild-comparison.json", comparison)
    manifest_files = {
        path.name: {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
        for path in sorted(publication.iterdir())
        if path.is_file()
    }
    manifest = {
        "schema_version": "xir-lab-native-latency-v2-block-sensitivity-manifest-v1",
        "namespace": "native-latency-v2-block-sensitivity",
        "semantic_sha256": run_a["semantic_sha256"],
        "files": manifest_files,
        "valid": True,
    }
    _write_json(publication / "manifest.json", manifest)
    return {**comparison, "publication": str(publication)}
