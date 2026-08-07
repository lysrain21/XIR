#!/usr/bin/env python3
"""Build native-width main and appendix latency publications."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.latency_figures_v2 import build_two_rebuild_publication


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--latency-publication", type=Path, required=True)
    parser.add_argument("--sensitivity-publication", type=Path, required=True)
    parser.add_argument("--main-output-root", type=Path, required=True)
    parser.add_argument("--appendix-output-root", type=Path, required=True)
    args = parser.parse_args()
    common = {
        "repository_root": args.repository_root.resolve(),
        "latency_publication": args.latency_publication.resolve(),
        "sensitivity_publication": args.sensitivity_publication.resolve(),
    }
    result = {
        "main": build_two_rebuild_publication(
            **common, output_root=args.main_output_root.resolve(), kind="main"
        ),
        "appendix": build_two_rebuild_publication(
            **common, output_root=args.appendix_output_root.resolve(), kind="appendix"
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
