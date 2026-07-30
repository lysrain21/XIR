#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.publication import (
    freeze_manifest,
    sha256_file,
    verify_manifest,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    args = parser.parse_args()
    digest_path = args.output.with_suffix(args.output.suffix + ".sha256")
    document = freeze_manifest(
        runtime_root=args.runtime_root,
        repository_root=args.repository_root,
        excluded={args.output, digest_path, *args.exclude},
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    digest_path.write_text(
        f"{sha256_file(args.output)}  {args.output.name}\n", encoding="ascii"
    )
    errors = verify_manifest(document, args.runtime_root)
    verification = {
        "schema_version": "xir-lab-native-manifest-verification-v1",
        "valid": not errors,
        "errors": errors,
        "manifest_sha256": sha256_file(args.output),
    }
    print(json.dumps(verification, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
