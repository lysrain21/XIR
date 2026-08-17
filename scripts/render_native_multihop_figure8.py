#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.multihop_figures import build_figure8_family


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--gateway", type=Path, required=True)
    parser.add_argument("--multihop-comparison", type=Path, required=True)
    parser.add_argument("--gateway-comparison", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    build_figure8_family(
        analysis_path=args.analysis,
        gateway_path=args.gateway,
        multihop_comparison_path=args.multihop_comparison,
        gateway_comparison_path=args.gateway_comparison,
        output_root=args.output_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
