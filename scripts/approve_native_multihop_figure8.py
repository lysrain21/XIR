#!/usr/bin/env python3
"""Create the explicit human visual-approval artifact after inspecting real Figure 8."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_figures import verify_figure8_comparison


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--figure-a", type=Path, required=True)
    parser.add_argument("--figure-b", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.reviewer.strip():
        raise LocalTopologyError("visual approval output/reviewer is invalid")
    verify_figure8_comparison(
        first=args.figure_a, second=args.figure_b, comparison_path=args.comparison
    )
    document = {
        "schema_version": "xir-lab-native-multihop-figure8-visual-approval-v1",
        "approved": True,
        "reviewer": args.reviewer.strip(),
        "approved_utc_ns": time.time_ns(),
        "figure_a_manifest_sha256": _sha(args.figure_a / "manifest.json"),
        "figure_b_manifest_sha256": _sha(args.figure_b / "manifest.json"),
        "comparison_sha256": _sha(args.comparison),
    }
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
