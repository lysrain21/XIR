#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.gateway_deployment import compare_gateway_publications


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publication-a", type=Path, required=True)
    parser.add_argument("--publication-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compare_gateway_publications(
        publication_a=args.publication_a,
        publication_b=args.publication_b,
        output_path=args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
