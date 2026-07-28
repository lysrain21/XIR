#!/usr/bin/env python3
"""Fail when a tracked file violates the local publication boundary."""

from __future__ import annotations

import subprocess
from pathlib import Path

from xir_lab.publication import validate_publishable_file


def main() -> None:
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    paths = tuple(root / item.decode() for item in output.split(b"\0") if item)
    for path in paths:
        validate_publishable_file(root, path)
    print(f"publishable tracked tree: {len(paths)} files")


if __name__ == "__main__":
    main()
