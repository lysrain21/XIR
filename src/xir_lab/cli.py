"""Fail-closed command boundaries for the XIR Testnet Lab workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from xir_lab import __version__
from xir_lab.execute.live_commands import (
    LIVE_COMMAND_TYPES,
    LiveCommandError,
    LiveCommandPaths,
    dispatch_live,
    load_live_context,
)
from xir_lab.live import live_feature_status

COMMANDS = (
    "plan",
    "preflight",
    "deploy",
    "configure",
    "pilot-run",
    "run",
    "collect",
    "reconcile",
    "analyze",
    "closeout",
    "publish",
)
STATUS_SCHEMA = "xir-lab-command-status-v1"


class StructuredInputError(ValueError):
    """Raised when a command's structured input cannot be validated."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xir-lab",
        description="Zero-write command surface for XIR Testnet Lab.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        subparser = subparsers.add_parser(command)
        subparser.add_argument(
            "--config",
            type=Path,
            help="Optional JSON configuration to validate and identify.",
        )
        subparser.add_argument(
            "--run-dir",
            type=Path,
            help="Optional existing run directory to identify; it is never created here.",
        )
        subparser.add_argument(
            "--profile",
            type=Path,
            help="Exact execution profile required by guarded live commands.",
        )
        subparser.add_argument(
            "--preflight",
            type=Path,
            help="Exact operation-scoped preflight required by guarded live commands.",
        )
        subparser.add_argument(
            "--approval",
            type=Path,
            help="Exact signed operation approval required by guarded live commands.",
        )
        subparser.add_argument(
            "--confirmation-id",
            help="Exact confirmation ID emitted by the first state-changing invocation.",
        )
        subparser.add_argument(
            "--live",
            action="store_true",
            help="Request the guarded public-testnet command path.",
        )
    return parser


def _load_config(path: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    if path is None:
        return None, None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StructuredInputError(f"cannot read config: {path}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StructuredInputError(f"config is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise StructuredInputError("config root must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _status(
    *,
    command: str,
    outcome: str,
    reason_code: str,
    config_path: Path | None,
    config_digest: str | None,
    run_dir: Path | None,
    mode: str = "offline_zero_write",
    implementation_status: str = "command_boundary",
    extra_inputs: dict[str, Any] | None = None,
    confirmation: dict[str, Any] | None = None,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    inputs = {
        "config_path": str(config_path.resolve()) if config_path is not None else None,
        "config_sha256": config_digest,
        "run_dir": str(run_dir.resolve()) if run_dir is not None else None,
    }
    if extra_inputs is not None:
        inputs.update(extra_inputs)
    document: dict[str, Any] = {
        "schema_version": STATUS_SCHEMA,
        "tool_version": __version__,
        "command": command,
        "outcome": outcome,
        "reason_code": reason_code,
        "mode": mode,
        "implementation_status": implementation_status,
        "inputs": inputs,
        "effects": {
            "wallets_created": 0,
            "funding_operations": 0,
            "signing_operations": 0,
            "deployments": 0,
            "broadcasts": 0,
        },
    }
    if confirmation is not None:
        document["confirmation"] = confirmation
        document["confirmation_id"] = confirmation_id
    return document


def _required_live_path(value: Path | None, label: str) -> Path:
    if value is None:
        raise LiveCommandError(f"live command requires --{label}")
    return value


def _run_live(namespace: argparse.Namespace, command: str) -> tuple[dict[str, Any], int]:
    if command not in LIVE_COMMAND_TYPES:
        raise LiveCommandError(f"unsupported live command: {command}")
    paths = LiveCommandPaths(
        config=_required_live_path(namespace.config, "config"),
        profile=_required_live_path(namespace.profile, "profile"),
        run_dir=_required_live_path(namespace.run_dir, "run-dir"),
        preflight=_required_live_path(namespace.preflight, "preflight"),
        approval=_required_live_path(namespace.approval, "approval"),
    )
    context = load_live_context(command, paths)
    result = dispatch_live(
        context,
        confirmation_id=namespace.confirmation_id,
    )
    extra_inputs = {
        "profile_path": str(paths.profile.resolve()),
        "profile_sha256": context.profile_sha256,
        "preflight_path": str(paths.preflight.resolve()),
        "preflight_sha256": context.preflight.source_sha256,
        "approval_path": str(paths.approval.resolve()),
        "approval_payload_sha256": context.approval.payload_sha256,
        "operation_id": context.approval.operation_id,
        "operation_type": context.operation_type,
    }
    document = _status(
        command=command,
        outcome=result.outcome,
        reason_code=result.reason_code,
        config_path=paths.config,
        config_digest=context.config.source_sha256,
        run_dir=paths.run_dir,
        mode="public_testnet_live_guarded",
        implementation_status=result.implementation_status,
        extra_inputs=extra_inputs,
        confirmation=context.confirmation,
        confirmation_id=context.confirmation_id,
    )
    if result.outcome == "not_executed":
        return document, 0
    return document, 3 if result.outcome == "confirmation_required" else 2


def run(argv: Sequence[str] | None = None) -> int:
    """Run one command and emit exactly one machine-readable status document."""

    namespace = _parser().parse_args(argv)
    command = str(namespace.command)
    config_path: Path | None = namespace.config
    run_dir: Path | None = namespace.run_dir
    if bool(namespace.live):
        feature = live_feature_status()
        if not feature.enabled:
            document = _status(
                command=command,
                outcome="blocked",
                reason_code=feature.reason_code,
                config_path=config_path,
                config_digest=None,
                run_dir=run_dir,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 2
        try:
            document, exit_code = _run_live(namespace, command)
        except LiveCommandError as exc:
            document = _status(
                command=command,
                outcome="blocked",
                reason_code=str(exc),
                config_path=config_path,
                config_digest=None,
                run_dir=run_dir,
                mode="public_testnet_live_guarded",
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 2
        print(json.dumps(document, indent=2, sort_keys=True))
        return exit_code
    try:
        _, config_digest = _load_config(config_path)
        if run_dir is not None and not run_dir.is_dir():
            raise StructuredInputError(f"run directory does not exist: {run_dir}")
    except StructuredInputError as exc:
        document = _status(
            command=command,
            outcome="invalid_input",
            reason_code=str(exc),
            config_path=config_path,
            config_digest=None,
            run_dir=run_dir,
        )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 2

    document = _status(
        command=command,
        outcome="not_executed",
        reason_code="command_boundary_ready",
        config_path=config_path,
        config_digest=config_digest,
        run_dir=run_dir,
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def main() -> None:
    """Console-script entry point."""

    raise SystemExit(run(sys.argv[1:]))
