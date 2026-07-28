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

COMMANDS = (
    "plan",
    "preflight",
    "deploy",
    "run",
    "collect",
    "reconcile",
    "analyze",
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
            "--live",
            action="store_true",
            help="Request live behavior. The zero-write build rejects this flag.",
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
) -> dict[str, Any]:
    return {
        "schema_version": STATUS_SCHEMA,
        "tool_version": __version__,
        "command": command,
        "outcome": outcome,
        "reason_code": reason_code,
        "mode": "offline_zero_write",
        "implementation_status": "command_boundary",
        "inputs": {
            "config_path": str(config_path.resolve()) if config_path is not None else None,
            "config_sha256": config_digest,
            "run_dir": str(run_dir.resolve()) if run_dir is not None else None,
        },
        "effects": {
            "wallets_created": 0,
            "funding_operations": 0,
            "signing_operations": 0,
            "deployments": 0,
            "broadcasts": 0,
        },
    }


def run(argv: Sequence[str] | None = None) -> int:
    """Run one command and emit exactly one machine-readable status document."""

    namespace = _parser().parse_args(argv)
    command = str(namespace.command)
    config_path: Path | None = namespace.config
    run_dir: Path | None = namespace.run_dir
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

    if bool(namespace.live):
        document = _status(
            command=command,
            outcome="blocked",
            reason_code="live_execution_not_authorized_in_zero_write_build",
            config_path=config_path,
            config_digest=config_digest,
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
