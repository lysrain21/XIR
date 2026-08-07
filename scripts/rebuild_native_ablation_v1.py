#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.ablation_v1 import rebuild_ablation_publication


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = rebuild_ablation_publication(
        source_root=args.source_root, output_root=args.output_root
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
