#!/usr/bin/env python3
"""Atomically synchronize one exact public multihop inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import cast

from xir_lab.native.multihop_sync import sync_exact_publication, verify_publication_handoff


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    handoff, files = verify_publication_handoff(
        runtime_root=args.runtime_root, handoff_path=args.handoff
    )
    handoff_relative = args.handoff.resolve().relative_to(args.runtime_root.resolve()).as_posix()
    files = sorted([*files, handoff_relative])
    inventory = cast(dict[str, object], handoff["files"])
    expected = {str(key): str(value) for key, value in inventory.items()}
    expected[handoff_relative] = hashlib.sha256(args.handoff.read_bytes()).hexdigest()
    result = sync_exact_publication(
        runtime_root=args.runtime_root,
        relative_files=files,
        destination=args.destination,
        expected_sha256=expected,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
