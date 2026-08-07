#!/usr/bin/env python3
"""Validate and build the deterministic native-faults-v1 handoff."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.faults_handoff_v1 import build_handoff


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-publish", type=Path, required=True)
    parser.add_argument("--rebuild-a-publish", type=Path, required=True)
    parser.add_argument("--rebuild-b-publish", type=Path, required=True)
    parser.add_argument("--figure-dir", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = build_handoff(
        frozen_publish=args.frozen_publish,
        rebuild_a_publish=args.rebuild_a_publish,
        rebuild_b_publish=args.rebuild_b_publish,
        figure_dir=args.figure_dir,
        output=args.output,
        schema_root=args.schema_root,
    )
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
