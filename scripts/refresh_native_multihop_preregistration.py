#!/usr/bin/env python3
"""Refresh exact implementation and review-context digests before read-only review."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from xir_lab.localnet.topology import LocalTopologyError


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _implementation_files(
    *, repository_root: Path, preregistration: dict[str, Any]
) -> dict[str, str]:
    policy = cast(
        dict[str, Any], preregistration.get("implementation_source_policy", {})
    )
    patterns = policy.get("include_globs")
    if (
        policy.get("schema_version")
        != "xir-lab-native-multihop-implementation-source-policy-v1"
        or policy.get("exact_file_set") is not True
        or not isinstance(patterns, list)
        or not patterns
    ):
        raise LocalTopologyError("implementation source policy is invalid")
    paths: set[Path] = set()
    for pattern in cast(list[str], patterns):
        matches = {path for path in repository_root.glob(pattern) if path.is_file()}
        if not matches:
            raise LocalTopologyError(f"implementation source glob is empty: {pattern}")
        paths.update(matches)
    return {
        path.relative_to(repository_root).as_posix(): _sha256(path)
        for path in sorted(paths)
    }


def refresh(
    *, workspace_root: Path, repository_root: Path, preregistration_path: Path
) -> dict[str, Any]:
    preregistration = cast(
        dict[str, Any], json.loads(preregistration_path.read_text(encoding="utf-8"))
    )
    preregistration["implementation_source_sha256"] = _implementation_files(
        repository_root=repository_root, preregistration=preregistration
    )
    inputs = cast(dict[str, Any], preregistration.get("inputs", {}))
    config = cast(dict[str, Any], inputs.get("config", {}))
    config_path = config.get("path")
    if not isinstance(config_path, str) or not config_path:
        raise LocalTopologyError("preregistration config binding is invalid")
    resolved_config = (workspace_root / config_path).resolve()
    if workspace_root.resolve() not in resolved_config.parents or not resolved_config.is_file():
        raise LocalTopologyError("preregistration config path is outside the workspace")
    config["sha256"] = _sha256(resolved_config)
    context = cast(
        dict[str, str], preregistration.get("review_context_sha256", {})
    )
    if not context:
        raise LocalTopologyError("review context manifest is empty")
    preregistration["review_context_sha256"] = {
        relative: _sha256(workspace_root / relative) for relative in sorted(context)
    }
    preregistration_path.write_text(
        json.dumps(preregistration, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return preregistration


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    args = parser.parse_args()
    document = refresh(
        workspace_root=args.workspace_root,
        repository_root=args.repository_root,
        preregistration_path=args.preregistration,
    )
    print(
        "implementation_files="
        f"{len(cast(dict[str, str], document['implementation_source_sha256']))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
