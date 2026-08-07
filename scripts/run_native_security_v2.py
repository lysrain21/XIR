#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xir_lab.native.security_v2 import NativeSecurityV2Campaign, NativeSecurityV2Runner


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the final-revision native security-v2 campaign."
    )
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--runner-key-file", type=Path, required=True)
    parser.add_argument("--root-signer-key-file", type=Path, required=True)
    parser.add_argument("--deployer-key-file", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--runner-state", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--repetition-limit", type=int)
    parser.add_argument("--attempt-namespace")
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    runner = NativeSecurityV2Runner(
        repository_root=repository,
        runtime_root=args.runtime_root,
        profile_path=args.profile,
        deployment_path=args.deployment,
        private_key=args.runner_key_file.read_text(encoding="utf-8").strip(),
        root_signer_private_key=args.root_signer_key_file.read_text(encoding="utf-8").strip(),
        state_path=args.runner_state,
        raw_root=args.output_root / "native-preparation-receipts",
        timeout_seconds=args.timeout_seconds,
        concurrency=args.concurrency,
        batch_attempts=max(args.concurrency, 32),
    )
    campaign = NativeSecurityV2Campaign(
        runner=runner,
        config_path=args.config,
        deployment_path=args.deployment,
        deployer_private_key=args.deployer_key_file.read_text(encoding="utf-8").strip(),
        state_path=args.state,
        output_root=args.output_root,
        concurrency=args.concurrency,
        repetition_limit=args.repetition_limit,
        attempt_namespace=args.attempt_namespace,
    )
    summary = campaign.run()
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
