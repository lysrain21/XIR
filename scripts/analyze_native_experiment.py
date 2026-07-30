#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.analysis import analyze_native_phase, write_analysis


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("smoke", "rehearsal", "scale"))
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--reconciliation", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    args = parser.parse_args()
    reconciliation = json.loads(
        args.reconciliation.read_text(encoding="utf-8")
    )
    document, rows = analyze_native_phase(
        phase=args.phase,
        runner_state_path=args.runner_state,
        reconciliation=reconciliation,
        resource_path=args.resources,
    )
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    write_analysis(
        output_json=args.output_json,
        output_csv=args.output_csv,
        document=document,
        rows=rows,
    )


if __name__ == "__main__":
    main()
