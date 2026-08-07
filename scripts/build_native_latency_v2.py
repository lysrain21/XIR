#!/usr/bin/env python3
"""Build, independently rebuild, and freeze native-latency-v2 artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from xir_lab.native.latency_v2 import (
    LatencyAnalysisError,
    build_artifact,
    load_json,
    sha256_file,
    validate_json,
    write_json,
)


def file_record(path: Path, publication_root: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(publication_root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def verify_manifest(document: dict[str, Any], publication_root: Path) -> list[str]:
    errors: list[str] = []
    observed_paths: set[str] = set()
    for row in document["files"]:
        relative = str(row["path"])
        if relative in observed_paths:
            errors.append(f"duplicate manifest path: {relative}")
            continue
        observed_paths.add(relative)
        path = (publication_root / relative).resolve()
        if publication_root.resolve() not in path.parents:
            errors.append(f"manifest path escapes publication root: {relative}")
        elif not path.is_file():
            errors.append(f"manifest file missing: {relative}")
        elif path.stat().st_size != int(row["bytes"]):
            errors.append(f"manifest byte count mismatch: {relative}")
        elif sha256_file(path) != row["sha256"]:
            errors.append(f"manifest digest mismatch: {relative}")
    expected = {
        path.relative_to(publication_root).as_posix()
        for path in publication_root.iterdir()
        if path.is_file()
        and path.name not in {"manifest.json", "manifest.json.sha256", "manifest-verification.json"}
    }
    if observed_paths != expected:
        errors.append(
            "manifest path set mismatch: "
            f"missing={sorted(expected - observed_paths)}, "
            f"unexpected={sorted(observed_paths - expected)}"
        )
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    repository_root = args.repository_root.resolve()
    output_root = args.output_root.resolve()
    if output_root.exists():
        raise LatencyAnalysisError(f"refusing to overwrite latency-v2 namespace: {output_root}")
    output_root.mkdir(parents=True)
    build_a = output_root / "rebuild-a"
    build_b = output_root / "rebuild-b"
    result_a = build_artifact(
        repository_root=repository_root,
        config_path=args.config.resolve(),
        schema_root=args.schema_root.resolve(),
        output_directory=build_a,
    )
    result_b = build_artifact(
        repository_root=repository_root,
        config_path=args.config.resolve(),
        schema_root=args.schema_root.resolve(),
        output_directory=build_b,
    )
    compared_names = sorted(set(result_a["files"]) | set(result_b["files"]))
    comparisons = {
        name: result_a["files"].get(name) == result_b["files"].get(name) for name in compared_names
    }
    rebuild = {
        "schema_version": "xir-lab-native-latency-v2-offline-rebuild-v1",
        "namespace": "native-latency-v2",
        "network_reads_required": False,
        "rebuild_a_semantic_sha256": result_a["analysis_semantic_sha256"],
        "rebuild_b_semantic_sha256": result_b["analysis_semantic_sha256"],
        "semantic_equal": (
            result_a["analysis_semantic_sha256"] == result_b["analysis_semantic_sha256"]
        ),
        "generated_file_digests_equal": comparisons,
        "equal": (
            result_a["analysis_semantic_sha256"] == result_b["analysis_semantic_sha256"]
            and all(comparisons.values())
        ),
    }
    if not rebuild["equal"]:
        raise LatencyAnalysisError(f"offline rebuild mismatch: {rebuild}")
    publication = output_root / "publication"
    publication.mkdir()
    for source in sorted(build_a.iterdir()):
        if source.is_file():
            shutil.copy2(source, publication / source.name)
    write_json(publication / "offline-rebuild-verification.json", rebuild)
    validation_path = publication / "validation.json"
    validation = load_json(validation_path)
    validation["checks"]["offline_rebuild_semantic_equal"] = rebuild["semantic_equal"]
    validation["checks"]["offline_rebuild_generated_files_equal"] = all(comparisons.values())
    validation["valid"] = all(validation["checks"].values())
    validation["errors"] = [name for name, passed in validation["checks"].items() if not passed]
    validate_json(
        validation,
        args.schema_root.resolve() / "native-latency-v2-validation.schema.json",
    )
    write_json(validation_path, validation)
    if not validation["valid"]:
        raise LatencyAnalysisError(f"publication validation failed: {validation['errors']}")
    manifest_paths = sorted(
        path
        for path in publication.iterdir()
        if path.is_file()
        and path.name not in {"manifest.json", "manifest.json.sha256", "manifest-verification.json"}
    )
    manifest = {
        "schema_version": "xir-lab-native-latency-v2-manifest-v1",
        "namespace": "native-latency-v2",
        "semantic_sha256": result_a["analysis_semantic_sha256"],
        "files": [file_record(path, publication) for path in manifest_paths],
    }
    validate_json(
        manifest,
        args.schema_root.resolve() / "native-latency-v2-manifest.schema.json",
    )
    manifest_path = publication / "manifest.json"
    write_json(manifest_path, manifest)
    manifest_digest = sha256_file(manifest_path)
    (publication / "manifest.json.sha256").write_text(
        f"{manifest_digest}  manifest.json\n",
        encoding="ascii",
    )
    manifest_errors = verify_manifest(manifest, publication)
    manifest_verification = {
        "schema_version": "xir-lab-native-latency-v2-manifest-verification-v1",
        "namespace": "native-latency-v2",
        "valid": not manifest_errors,
        "errors": manifest_errors,
        "manifest_sha256": manifest_digest,
        "file_count": len(manifest["files"]),
    }
    write_json(
        publication / "manifest-verification.json",
        manifest_verification,
    )
    if manifest_errors:
        raise LatencyAnalysisError(f"latency-v2 manifest verification failed: {manifest_errors}")
    print(
        json.dumps(
            {
                "namespace": "native-latency-v2",
                "valid": True,
                "semantic_sha256": result_a["analysis_semantic_sha256"],
                "manifest_sha256": manifest_digest,
                "publication": str(publication),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
