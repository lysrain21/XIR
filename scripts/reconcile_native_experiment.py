#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.analysis import reconcile_native_phase


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("smoke", "rehearsal", "scale"))
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--layerzero-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = reconcile_native_phase(
        phase=args.phase,
        profile_path=args.profile,
        deployment_path=args.deployment,
        runner_state_path=args.runner_state,
        layerzero_state_path=args.layerzero_state,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not document["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
