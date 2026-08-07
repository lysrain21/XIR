#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xir_lab.native.ablation_v1 import (
    AblationPhase,
    NativeAblationRunner,
    build_ablation_plan,
    load_ablation_config,
    write_plan,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("dry-run", "smoke", "scale"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--runner-key-file", type=Path)
    parser.add_argument("--root-signer-key-file", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    config, _ = load_ablation_config(args.config)
    if config["namespace"] != "native-ablation-v2":
        parser.error("v2 runner requires the native-ablation-v2 namespace")
    plan_phase: AblationPhase = "smoke" if args.phase in {"dry-run", "smoke"} else "scale"
    entries = build_ablation_plan(config_path=args.config, phase=plan_phase)
    digest = write_plan(args.plan, entries, namespace="native-ablation-v2")
    if args.phase == "dry-run":
        print(f"plan={args.plan} sha256={digest} attempts={len(entries)}")
        return
    required = {
        "runtime_root": args.runtime_root,
        "profile": args.profile,
        "deployment": args.deployment,
        "runner_key_file": args.runner_key_file,
        "root_signer_key_file": args.root_signer_key_file,
        "state": args.state,
        "raw_root": args.raw_root,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error("execution requires " + ", ".join(sorted(missing)))
    runner = NativeAblationRunner(
        config_path=args.config,
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
        batch_attempts=max(int(config["concurrency"]), 16),
    )
    runner.run_ablation_phase(plan_phase)


def _path(value: Path | None) -> Path:
    if value is None:
        raise AssertionError("required path was checked above")
    return value


if __name__ == "__main__":
    main()
