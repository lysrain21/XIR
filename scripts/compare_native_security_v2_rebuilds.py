#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

CORE_FILES = ("case-results.json", "summary.json", "paper-table.csv", "REPORT.md")
REBUILD_FILES = CORE_FILES + (
    "offline-validation.json",
    "security-classification.json",
    "paper-classification-table.csv",
    "SECURITY-CLASSIFICATION.md",
    "profile-inactive-lineage.json",
    "paper-profile-inactive-lineage.csv",
    "paper-security-results.csv",
    "secret-scan.json",
    "SHA256SUMS",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", type=Path, required=True)
    parser.add_argument("--rebuild-a", type=Path, required=True)
    parser.add_argument("--rebuild-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    errors: list[str] = []
    core_sha256: dict[str, str] = {}
    for name in CORE_FILES:
        paths = (args.online / name, args.rebuild_a / name, args.rebuild_b / name)
        if not all(path.is_file() for path in paths):
            errors.append(f"missing core artifact: {name}")
            continue
        values = [_digest(path) for path in paths]
        core_sha256[name] = values[0]
        if len(set(values)) != 1:
            errors.append(f"core rebuild mismatch: {name}")
    rebuild_sha256: dict[str, str] = {}
    for name in REBUILD_FILES:
        first = args.rebuild_a / name
        second = args.rebuild_b / name
        if not first.is_file() or not second.is_file():
            errors.append(f"missing rebuilt artifact: {name}")
            continue
        rebuild_sha256[name] = _digest(first)
        if _digest(first) != _digest(second):
            errors.append(f"offline rebuild mismatch: {name}")
    for root in (args.rebuild_a, args.rebuild_b):
        validation = json.loads((root / "offline-validation.json").read_text())
        secret_scan = json.loads((root / "secret-scan.json").read_text())
        if validation.get("valid") is not True:
            errors.append(f"offline validation failed: {root}")
        if secret_scan.get("valid") is not True:
            errors.append(f"secret scan failed: {root}")
    result = {
        "schema_version": "xir-lab-native-security-v2-rebuild-comparison-v1",
        "online": str(args.online),
        "rebuild_a": str(args.rebuild_a),
        "rebuild_b": str(args.rebuild_b),
        "core_sha256": core_sha256,
        "rebuild_sha256": rebuild_sha256,
        "errors": errors,
        "valid": not errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
