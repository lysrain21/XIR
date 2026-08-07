#!/usr/bin/env python3
"""Build the frozen 32/64/128 latency block-length sensitivity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.latency_sensitivity import build_two_rebuild_publication


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_two_rebuild_publication(
        repository_root=args.repository_root.resolve(),
        config_path=args.config.resolve(),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
