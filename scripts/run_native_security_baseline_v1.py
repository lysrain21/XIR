#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.security_baseline_v1 import (
    NativeSecurityBaselineRunner,
    build_baseline_plan,
    load_baseline_config,
    write_baseline_plan,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("dry-run", "campaign"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ablation-config", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--runner-key-file", type=Path)
    parser.add_argument("--root-signer-key-file", type=Path)
    parser.add_argument("--registry-owner-key-file", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    config, _ = load_baseline_config(args.config)
    plan = build_baseline_plan(args.config)
    digest = write_baseline_plan(args.plan, plan)
    if args.phase == "dry-run":
        print(f"plan={args.plan} sha256={digest} attempts={len(plan)}")
        return
    required = {
        "ablation_config": args.ablation_config,
        "runtime_root": args.runtime_root,
        "profile": args.profile,
        "deployment": args.deployment,
        "runner_key_file": args.runner_key_file,
        "root_signer_key_file": args.root_signer_key_file,
        "registry_owner_key_file": args.registry_owner_key_file,
        "state": args.state,
        "raw_root": args.raw_root,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error("campaign requires " + ", ".join(sorted(missing)))
    runner = NativeSecurityBaselineRunner(
        baseline_config_path=args.config,
        registry_owner_private_key=_path(args.registry_owner_key_file)
        .read_text(encoding="utf-8")
        .strip(),
        config_path=_path(args.ablation_config),
        repository_root=Path(__file__).resolve().parents[1],
        runtime_root=_path(args.runtime_root),
        profile_path=_path(args.profile),
        deployment_path=_path(args.deployment),
        private_key=_path(args.runner_key_file).read_text(encoding="utf-8").strip(),
        root_signer_private_key=_path(args.root_signer_key_file)
        .read_text(encoding="utf-8")
        .strip(),
        state_path=_path(args.state),
        raw_root=_path(args.raw_root),
        concurrency=int(config["concurrency"]),
        batch_attempts=10,
    )
    runner.run_baseline_campaign()


def _path(value: Path | None) -> Path:
    if value is None:
        raise AssertionError("required path checked above")
    return value


if __name__ == "__main__":
    main()
