#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.publication import render_report, sha256_file


def load(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit(f"document root is not an object: {path}")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--reconciliation", type=Path, required=True)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-pointer", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reconciliation = load(args.reconciliation)
    analysis = load(args.analysis)
    if reconciliation.get("valid") is not True or analysis.get("reconciled") is not True:
        raise SystemExit("report requires reconciled native results")
    report = render_report(
        profile=load(args.profile),
        provenance=load(args.provenance),
        deployment=load(args.deployment),
        reconciliation=reconciliation,
        analysis=analysis,
        manifest_sha256=sha256_file(args.manifest),
        evidence_pointer=args.evidence_pointer,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
