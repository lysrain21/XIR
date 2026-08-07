#!/usr/bin/env python3
"""Render the final native-faults-v1 recovery figure and lineage sources."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.faults_recovery_figure_v2 import build_two_rebuild_publication


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--source-publication", type=Path, required=True)
    parser.add_argument("--rebuild-a-publication", type=Path, required=True)
    parser.add_argument("--rebuild-b-publication", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_two_rebuild_publication(
        repository_root=args.repository_root.resolve(),
        source_publication=args.source_publication.resolve(),
        rebuild_a_publication=args.rebuild_a_publication.resolve(),
        rebuild_b_publication=args.rebuild_b_publication.resolve(),
        deployment_path=args.deployment.resolve(),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
