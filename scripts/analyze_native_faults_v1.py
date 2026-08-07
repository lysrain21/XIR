#!/usr/bin/env python3
"""Rebuild native-faults-v1 aggregates from the frozen recovery ledger."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.faults_v1 import FaultLedger, freeze_fault_results, git_identity


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fault-ledger", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--environment-source", type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    if args.environment_source is None:
        cases = FaultLedger(args.fault_ledger).cases()
        completed_at = max(str(case["updated_at"]) for case in cases)
        environment = {
            **git_identity(repository),
            "generated_at": completed_at,
            "fault_ledger": str(args.fault_ledger),
            "offline_rebuild": True,
            "natural_interruptions_included": False,
        }
    else:
        environment = json.loads(args.environment_source.read_text(encoding="utf-8"))
        environment.pop("schema_version", None)
    summary = freeze_fault_results(
        ledger=FaultLedger(args.fault_ledger),
        config_path=args.config,
        deployment_path=args.deployment,
        output_root=args.output_root,
        environment=environment,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
