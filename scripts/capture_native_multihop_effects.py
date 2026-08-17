#!/usr/bin/env python3
"""Capture before/after exact-one receiver evidence for one multihop phase."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.multihop_effects import capture_effect_baseline, reconcile_effects


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("baseline", "reconcile"))
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--phase", choices=("smoke", "publication_smoke", "scale"))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--runner-state", type=Path)
    parser.add_argument("--trace-state", type=Path)
    args = parser.parse_args()
    if args.action == "baseline":
        if args.config is None or args.phase is None:
            parser.error("baseline requires --config and --phase")
        result = capture_effect_baseline(
            repository_root=args.repository_root,
            profile_path=args.profile,
            deployment_path=args.deployment,
            config_path=args.config,
            phase=args.phase,
            output_path=args.output,
        )
    else:
        if (
            args.config is None
            or args.phase is None
            or args.baseline is None
            or args.runner_state is None
            or args.trace_state is None
        ):
            parser.error(
                "reconcile requires --config, --phase, --baseline, --runner-state, and --trace-state"
            )
        result = reconcile_effects(
            repository_root=args.repository_root,
            profile_path=args.profile,
            deployment_path=args.deployment,
            config_path=args.config,
            phase=args.phase,
            baseline_path=args.baseline,
            runner_state_path=args.runner_state,
            trace_state_path=args.trace_state,
            output_path=args.output,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
