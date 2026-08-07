#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.runner import NativeExperimentRunner


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("smoke", "rehearsal", "scale"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--root-signer-key-file", type=Path)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--batch-attempts", type=int, default=256)
    parser.add_argument("--submission-stop-file", type=Path)
    args = parser.parse_args()
    runner = NativeExperimentRunner(
        repository_root=Path(__file__).resolve().parents[1],
        runtime_root=args.runtime_root,
        profile_path=args.profile,
        deployment_path=args.deployment,
        private_key=args.key_file.read_text(encoding="utf-8").strip(),
        root_signer_private_key=(
            args.root_signer_key_file.read_text(encoding="utf-8").strip()
            if args.root_signer_key_file is not None
            else None
        ),
        state_path=args.state,
        raw_root=args.raw_root,
        concurrency=args.concurrency,
        batch_attempts=args.batch_attempts,
        submission_stop_file=args.submission_stop_file,
    )
    runner.run_phase(args.phase)


if __name__ == "__main__":
    main()
