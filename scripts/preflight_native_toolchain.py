#!/usr/bin/env python3
"""Resolve and freeze the native protocol libclang prerequisite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.localnet.toolchain_preflight import write_toolchain_preflight


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = write_toolchain_preflight(output_path=args.output)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
