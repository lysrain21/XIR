#!/usr/bin/env python3
"""Build a deterministic five-chain multihop experiment plan."""

from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.multihop_scalability import build_multihop_plan, write_multihop_plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--phase", choices=("smoke", "publication_smoke", "scale"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = build_multihop_plan(config_path=args.config, phase=args.phase)
    digest = write_multihop_plan(args.output, plan)
    print(f"plan_sha256={plan['plan_sha256']}")
    print(f"file_sha256={digest}")
    print(f"logical_attempts={plan['logical_attempts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
