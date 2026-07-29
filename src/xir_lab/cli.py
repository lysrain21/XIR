"""Fail-closed command boundaries for the XIR Testnet Lab workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
from xir_lab.localnet.compose import render_compose
from xir_lab.localnet.identities import (
    LocalIdentityError,
    initialize_local_identities,
)
from xir_lab.localnet.preflight import (
    HostSnapshot,
    NodeObservation,
    build_local_preflight,
    collect_node_observations,
)
from xir_lab.localnet.report import (
    build_local_scale_report_from_evidence,
    validate_local_scale_report,
)
from xir_lab.localnet.scale import (
    build_local_scale_plan,
    validate_local_scale_execution_gate,
)
from xir_lab.localnet.topology import (
    LocalTopologyError,
    load_identity_manifest,
    load_topology,
)
from xir_lab.localnet.workload import (
    deploy_local_workloads,
    execute_local_phase,
    require_reconciled_local_phase,
)

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
LOCAL_COMMANDS = (
    "local-init",
    "local-render",
    "local-preflight",
    "local-plan",
    "local-deploy",
    "local-run",
    "local-report-build",
    "local-report-validate",
)


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
    local_init = subparsers.add_parser("local-init")
    local_init.add_argument("--topology", type=Path, required=True)
    local_init.add_argument("--runtime-root", type=Path, required=True)

    local_render = subparsers.add_parser("local-render")
    local_render.add_argument("--topology", type=Path, required=True)
    local_render.add_argument("--identity-manifest", type=Path, required=True)

    local_preflight = subparsers.add_parser("local-preflight")
    local_preflight.add_argument("--topology", type=Path, required=True)
    local_preflight.add_argument("--identity-manifest", type=Path, required=True)
    local_preflight.add_argument(
        "--mode",
        choices=("render", "smoke", "scale"),
        required=True,
    )
    local_preflight.add_argument("--observations", type=Path)
    local_preflight.add_argument(
        "--collect-network-health",
        action="store_true",
        help="Read all twelve private Docker-bridge validator RPCs.",
    )
    local_preflight.add_argument("--output", type=Path)

    local_plan = subparsers.add_parser("local-plan")
    local_plan.add_argument("--topology", type=Path, required=True)
    local_plan.add_argument("--profile", type=Path, required=True)
    local_plan.add_argument("--smoke-freeze-sha256")
    local_plan.add_argument("--rehearsal-freeze-sha256")
    local_plan.add_argument("--measured-limits-sha256")
    local_plan.add_argument("--output", type=Path)

    local_deploy = subparsers.add_parser("local-deploy")
    local_deploy.add_argument("--topology", type=Path, required=True)
    local_deploy.add_argument("--identity-manifest", type=Path, required=True)
    local_deploy.add_argument("--runtime-root", type=Path, required=True)
    local_deploy.add_argument("--artifact", type=Path, required=True)

    local_run = subparsers.add_parser("local-run")
    local_run.add_argument("--topology", type=Path, required=True)
    local_run.add_argument("--identity-manifest", type=Path, required=True)
    local_run.add_argument("--runtime-root", type=Path, required=True)
    local_run.add_argument("--profile", type=Path, required=True)
    local_run.add_argument("--deployment", type=Path, required=True)
    local_run.add_argument("--artifact", type=Path, required=True)
    local_run.add_argument(
        "--phase",
        choices=("smoke", "rehearsal", "scale"),
        required=True,
    )
    local_run.add_argument("--batch-size", type=int, default=25)
    local_run.add_argument("--plan", type=Path)
    local_run.add_argument("--preflight", type=Path)

    local_report_build = subparsers.add_parser("local-report-build")
    local_report_build.add_argument("--topology", type=Path, required=True)
    local_report_build.add_argument("--identity-manifest", type=Path, required=True)
    local_report_build.add_argument("--runtime-root", type=Path, required=True)
    local_report_build.add_argument("--plan", type=Path, required=True)
    local_report_build.add_argument("--scale-command", type=Path, required=True)
    local_report_build.add_argument("--measured-limits", type=Path, required=True)
    local_report_build.add_argument("--scale-resources", type=Path, required=True)
    local_report_build.add_argument("--output", type=Path, required=True)

    local_report = subparsers.add_parser("local-report-validate")
    local_report.add_argument("--report", type=Path, required=True)
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


def _local_status(
    *,
    command: str,
    outcome: str,
    reason_code: str,
    details: dict[str, Any] | None = None,
    local_files_created: int = 0,
    local_private_keys_created: int = 0,
) -> dict[str, Any]:
    return {
        "schema_version": "xir-lab-local-command-status-v1",
        "tool_version": __version__,
        "command": command,
        "outcome": outcome,
        "reason_code": reason_code,
        "environment": "controlled-local-qbft",
        "details": details or {},
        "effects": {
            "public_network_calls": 0,
            "public_signatures": 0,
            "public_broadcasts": 0,
            "containers_started": 0,
            "local_files_created": local_files_created,
            "local_private_keys_created": local_private_keys_created,
        },
    }


def _observations(path: Path | None) -> tuple[NodeObservation, ...]:
    if path is None:
        return ()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read local node observations: {path}") from exc
    if not isinstance(value, list):
        raise LocalTopologyError("local node observations must be an array")
    try:
        return tuple(NodeObservation(**item) for item in value)
    except (TypeError, KeyError) as exc:
        raise LocalTopologyError("local node observation shape is invalid") from exc


def _hex_digest(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise LocalTopologyError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _run_local(namespace: argparse.Namespace, command: str) -> tuple[dict[str, Any], int]:
    repository_root = Path(__file__).resolve().parents[2]
    if command == "local-init":
        topology = load_topology(namespace.topology)
        runtime_root = namespace.runtime_root.resolve()
        manifest_path = initialize_local_identities(
            topology,
            runtime_root=runtime_root,
            repository_root=repository_root,
        )
        manifest = load_identity_manifest(manifest_path, topology=topology)
        compose_bytes, compose_sha256 = render_compose(topology, manifest)
        compose_path = runtime_root / "compose.yaml"
        compose_path.write_bytes(compose_bytes)
        return (
            _local_status(
                command=command,
                outcome="initialized",
                reason_code="local_identity_and_compose_frozen",
                details={
                    "runtime_root": str(runtime_root),
                    "identity_manifest_path": str(manifest_path),
                    "identity_manifest_sha256": manifest.payload_sha256,
                    "compose_path": str(compose_path),
                    "compose_sha256": compose_sha256,
                },
                local_files_created=19,
                local_private_keys_created=14,
            ),
            0,
        )
    if command == "local-render":
        topology = load_topology(namespace.topology)
        manifest = load_identity_manifest(
            namespace.identity_manifest,
            topology=topology,
        )
        compose_bytes, compose_sha256 = render_compose(topology, manifest)
        return (
            _local_status(
                command=command,
                outcome="rendered",
                reason_code="deterministic_compose_ready",
                details={
                    "topology_sha256": topology.source_sha256,
                    "identity_manifest_sha256": manifest.payload_sha256,
                    "compose_sha256": compose_sha256,
                    "compose_yaml": compose_bytes.decode("utf-8"),
                },
            ),
            0,
        )
    if command == "local-preflight":
        topology = load_topology(namespace.topology)
        manifest = load_identity_manifest(
            namespace.identity_manifest,
            topology=topology,
        )
        storage_path = namespace.identity_manifest.resolve().parent
        if topology.validator_data_storage == "docker-volume":
            raw_storage_path = os.environ.get("XIR_LOCAL_VALIDATOR_STORAGE_PATH")
            if raw_storage_path is None:
                raise LocalTopologyError(
                    "docker-volume preflight requires "
                    "XIR_LOCAL_VALIDATOR_STORAGE_PATH"
                )
            storage_path = Path(raw_storage_path).resolve()
            if not storage_path.is_dir():
                raise LocalTopologyError(
                    "validator storage preflight path does not exist"
                )
        report = build_local_preflight(
            topology=topology,
            manifest=manifest,
            mode=namespace.mode,
            host=HostSnapshot.collect(storage_path),
            observations=(
                collect_node_observations(topology=topology, manifest=manifest)
                if namespace.collect_network_health
                else _observations(namespace.observations)
            ),
        )
        if namespace.output is not None:
            namespace.output.parent.mkdir(parents=True, exist_ok=True)
            namespace.output.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return (
            _local_status(
                command=command,
                outcome="pass" if report["eligible"] else "blocked",
                reason_code=(
                    "local_preflight_passed"
                    if report["eligible"]
                    else "local_preflight_failed"
                ),
                details={
                    "preflight": report,
                    "output_path": (
                        str(namespace.output.resolve())
                        if namespace.output is not None
                        else None
                    ),
                },
                local_files_created=int(namespace.output is not None),
            ),
            0 if report["eligible"] else 2,
        )
    if command == "local-plan":
        topology = load_topology(namespace.topology)
        plan = build_local_scale_plan(
            profile_path=namespace.profile,
            topology_sha256=topology.source_sha256,
            smoke_freeze_sha256=_hex_digest(
                namespace.smoke_freeze_sha256,
                "smoke freeze",
            ),
            rehearsal_freeze_sha256=_hex_digest(
                namespace.rehearsal_freeze_sha256,
                "rehearsal freeze",
            ),
            measured_limits_sha256=_hex_digest(
                namespace.measured_limits_sha256,
                "measured limits",
            ),
        )
        if namespace.output is not None:
            namespace.output.parent.mkdir(parents=True, exist_ok=True)
            namespace.output.write_text(
                json.dumps(plan, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return (
            _local_status(
                command=command,
                outcome="eligible" if plan["eligible"] else "planned",
                reason_code=(
                    "local_scale_progression_complete"
                    if plan["eligible"]
                    else "local_scale_progression_incomplete"
                ),
                details={
                    "plan": plan,
                    "output_path": (
                        str(namespace.output.resolve())
                        if namespace.output is not None
                        else None
                    ),
                },
                local_files_created=int(namespace.output is not None),
            ),
            0,
        )
    if command == "local-deploy":
        topology = load_topology(namespace.topology)
        manifest = load_identity_manifest(
            namespace.identity_manifest,
            topology=topology,
        )
        deployment_path = deploy_local_workloads(
            topology=topology,
            manifest=manifest,
            runtime_root=namespace.runtime_root.resolve(),
            artifact_path=namespace.artifact,
        )
        return (
            _local_status(
                command=command,
                outcome="deployed",
                reason_code="local_workload_contracts_deployed",
                details={"deployment_path": str(deployment_path)},
                local_files_created=1,
            ),
            0,
        )
    if command == "local-run":
        topology = load_topology(namespace.topology)
        manifest = load_identity_manifest(
            namespace.identity_manifest,
            topology=topology,
        )
        runtime_root = namespace.runtime_root.resolve()
        if namespace.phase == "rehearsal":
            require_reconciled_local_phase(
                runtime_root=runtime_root,
                phase="smoke",
            )
        if namespace.phase == "scale":
            if namespace.plan is None or namespace.preflight is None:
                raise LocalTopologyError(
                    "scale phase requires --plan and --preflight"
                )
            require_reconciled_local_phase(
                runtime_root=runtime_root,
                phase="smoke",
            )
            require_reconciled_local_phase(
                runtime_root=runtime_root,
                phase="rehearsal",
            )
            validate_local_scale_execution_gate(
                plan_path=namespace.plan,
                preflight_path=namespace.preflight,
                profile_path=namespace.profile,
                runtime_root=runtime_root,
                topology_sha256=topology.source_sha256,
                identity_manifest_sha256=manifest.payload_sha256,
            )
        summary = execute_local_phase(
            topology=topology,
            manifest=manifest,
            runtime_root=runtime_root,
            profile_path=namespace.profile,
            deployment_path=namespace.deployment,
            artifact_path=namespace.artifact,
            phase=namespace.phase,
            batch_size=namespace.batch_size,
        )
        return (
            _local_status(
                command=command,
                outcome="complete",
                reason_code=f"local_{namespace.phase}_reconciled",
                details={"summary": summary},
                local_files_created=1,
            ),
            0,
        )
    if command == "local-report-validate":
        try:
            document = json.loads(namespace.report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalTopologyError(f"cannot read local scale report: {namespace.report}") from exc
        if not isinstance(document, dict):
            raise LocalTopologyError("local scale report root must be an object")
        validate_local_scale_report(document)
        return (
            _local_status(
                command=command,
                outcome="pass",
                reason_code="local_scale_report_valid",
                details={"report_path": str(namespace.report.resolve())},
            ),
            0,
        )
    if command == "local-report-build":
        topology = load_topology(namespace.topology)
        manifest = load_identity_manifest(
            namespace.identity_manifest,
            topology=topology,
        )
        report = build_local_scale_report_from_evidence(
            topology=topology,
            manifest=manifest,
            plan_path=namespace.plan,
            scale_command_path=namespace.scale_command,
            measured_limits_path=namespace.measured_limits,
            scale_resources_path=namespace.scale_resources,
            runtime_root=namespace.runtime_root.resolve(),
        )
        namespace.output.parent.mkdir(parents=True, exist_ok=True)
        namespace.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return (
            _local_status(
                command=command,
                outcome="complete",
                reason_code="local_scale_report_built",
                details={
                    "report_path": str(namespace.output.resolve()),
                    "report": report,
                },
                local_files_created=1,
            ),
            0,
        )
    raise LocalTopologyError(f"unsupported local command: {command}")


def run(argv: Sequence[str] | None = None) -> int:
    """Run one command and emit exactly one machine-readable status document."""

    namespace = _parser().parse_args(argv)
    command = str(namespace.command)
    if command in LOCAL_COMMANDS:
        try:
            document, exit_code = _run_local(namespace, command)
        except (LocalTopologyError, LocalIdentityError, OSError) as exc:
            document = _local_status(
                command=command,
                outcome="blocked",
                reason_code=str(exc),
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 2
        print(json.dumps(document, indent=2, sort_keys=True))
        return exit_code
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
