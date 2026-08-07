#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from xir_lab.native.ablation_freeze_v2 import (
    attempt_counts,
    secret_scan,
    sha256_file,
    sqlite_backup,
)


def _copy_sources(arguments: argparse.Namespace, output: Path) -> None:
    sources = {
        "config.json": arguments.config,
        "profile.json": arguments.profile,
        "deployment.json": arguments.deployment,
        "base-deployment.json": arguments.base_deployment,
        "plan.json": arguments.plan,
        "operational-incidents.json": arguments.operational_incidents,
        "incident-pre-resume.json": arguments.incident_pre_resume,
        "incident-post-resume.json": arguments.incident_post_resume,
        "incident-runner.traceback.log": arguments.incident_traceback,
        "ablation-analysis.py": arguments.analysis_source,
        "analyze-native-ablation-v2.py": arguments.analyzer_script,
        "operational-incidents.schema.json": arguments.operational_incident_schema,
    }
    for name, source in sources.items():
        if not source.is_file():
            raise FileNotFoundError(source)
        shutil.copyfile(source, output / name)


def _manifest(output: Path, *, attempt_counts: dict[str, int]) -> dict[str, Any]:
    files = [
        {
            "path": str(path.relative_to(output)),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file() and not path.name.startswith("frozen-source-manifest")
    ]
    findings = secret_scan(output)
    return {
        "schema_version": "xir-lab-native-ablation-v2-frozen-source-manifest",
        "namespace": "native-ablation-v2",
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attempt_counts": attempt_counts,
        "expected_attempts": 8000,
        "runner_sqlite_quick_check": "ok",
        "layerzero_sqlite_quick_check": "ok",
        "secret_scan_findings": findings,
        "files": files,
        "valid": attempt_counts == {"succeeded": 8000} and not findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in (
        "config",
        "profile",
        "deployment",
        "base-deployment",
        "plan",
        "operational-incidents",
        "incident-pre-resume",
        "incident-post-resume",
        "incident-traceback",
        "analysis-source",
        "analyzer-script",
        "operational-incident-schema",
        "runner-state",
        "layerzero-state",
        "output-root",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_root
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"frozen source output is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    _copy_sources(args, output)
    sqlite_backup(args.runner_state, output / "runner.sqlite")
    sqlite_backup(args.layerzero_state, output / "worker.sqlite")
    counts = attempt_counts(output / "runner.sqlite")
    manifest = _manifest(output, attempt_counts=counts)
    manifest_path = output / "frozen-source-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "frozen-source-manifest.sha256").write_text(
        f"{sha256_file(manifest_path)}  frozen-source-manifest.json\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True))
    if not manifest["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
