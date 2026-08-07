#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.security_baseline_v1 import (
    analyze_baseline_campaign,
    validate_baseline_publication,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--layerzero-state", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    if not args.validate_only:
        analysis = analyze_baseline_campaign(
            config_path=args.config,
            profile_path=args.profile,
            deployment_path=args.deployment,
            runner_state_path=args.runner_state,
            layerzero_state_path=args.layerzero_state,
            output_root=args.output_root,
        )
        if not analysis["validation"]["valid"]:
            raise SystemExit(1)
    result = validate_baseline_publication(args.output_root)
    (args.output_root / "publication-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
