#!/usr/bin/env python3
"""Build compact latency and run-003 coordinator-cost appendix figures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.appendix_figures_v2 import build_two_rebuild_publication


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--latency-output-root", type=Path, required=True)
    parser.add_argument("--cost-output-root", type=Path, required=True)
    args = parser.parse_args()
    repository_root = args.repository_root.resolve()
    result = {
        "latency": build_two_rebuild_publication(
            repository_root=repository_root,
            output_root=args.latency_output_root.resolve(),
            kind="latency",
        ),
        "cost": build_two_rebuild_publication(
            repository_root=repository_root,
            output_root=args.cost_output_root.resolve(),
            kind="cost",
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
