"""Fail-closed operation-scoped live command preparation and dispatch."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Protocol, cast

import rfc8785

from xir_lab.config.loaders import (
    ApprovalEnvelope,
    ConfigError,
    LabConfig,
    load_approval_envelope,
    load_lab_config,
)
from xir_lab.config.profiles import ExecutionProfile, ProfileError, load_execution_profile
from xir_lab.evidence.store import EvidenceStore, StoreError
from xir_lab.execute.approvals import (
    ApprovalError,
    ApprovalVerifier,
    PinnedApprovalKey,
)
from xir_lab.preflight.operations import (
    OperationPreflight,
    OperationPreflightError,
    OperationScope,
    load_operation_preflight,
)

LiveOperationType = Literal["deployment", "configuration", "pilot", "closeout"]

STATE_CHANGING_COMMANDS = frozenset({"deploy", "configure", "pilot-run", "closeout"})
LIVE_COMMAND_TYPES: dict[str, LiveOperationType] = {
    "deploy": "deployment",
    "configure": "configuration",
    "pilot-run": "pilot",
    "collect": "pilot",
    "reconcile": "pilot",
    "analyze": "pilot",
    "closeout": "closeout",
}
PREFLIGHT_SCOPES: dict[LiveOperationType, OperationScope] = {
    "deployment": "deployment",
    "configuration": "configuration",
    "pilot": "experiment",
    "closeout": "closeout",
}


class LiveCommandError(ValueError):
    """Raised before any signer or write-RPC dependency is constructed."""


@dataclass(frozen=True)
class LiveCommandPaths:
    config: Path
    profile: Path
    run_dir: Path
    preflight: Path
    approval: Path


@dataclass(frozen=True)
class LiveCommandContext:
    command: str
    operation_type: LiveOperationType
    config: LabConfig
    profile: ExecutionProfile
    preflight: OperationPreflight
    approval: ApprovalEnvelope
    paths: LiveCommandPaths
    profile_sha256: str
    confirmation: dict[str, Any]
    confirmation_id: str


@dataclass(frozen=True)
class LiveDispatchResult:
    outcome: str
    reason_code: str
    implementation_status: str


class LiveStateChangeBackend(Protocol):
    def execute(self, context: LiveCommandContext) -> LiveDispatchResult:
        """Execute one already correlated and exactly confirmed operation."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise LiveCommandError(f"cannot read required input: {path}") from exc
    return digest.hexdigest()


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveCommandError(f"cannot read approval document: {path}") from exc
    if not isinstance(value, dict):
        raise LiveCommandError("approval document root must be an object")
    return cast(dict[str, Any], value)


def _approval_public_key(config: LabConfig) -> str:
    authorities = [item for item in config.signers if item.role == "approval-authority"]
    if len(authorities) != 1:
        raise LiveCommandError("configuration must pin exactly one approval authority")
    identity = authorities[0].public_identity
    prefix = "ed25519:"
    if not identity.startswith(prefix):
        raise LiveCommandError("approval authority identity is not Ed25519")
    public_key_hex = identity.removeprefix(prefix)
    if len(public_key_hex) != 64:
        raise LiveCommandError("approval authority public key has an invalid length")
    try:
        bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise LiveCommandError("approval authority public key is not hexadecimal") from exc
    return public_key_hex


def _require_correlated_inputs(
    *,
    operation_type: LiveOperationType,
    config: LabConfig,
    profile: ExecutionProfile,
    profile_sha256: str,
    preflight: OperationPreflight,
    approval: ApprovalEnvelope,
) -> None:
    payload = approval.payload
    if preflight.operation_type != operation_type:
        raise LiveCommandError("preflight operation type does not match command")
    if approval.operation_type != operation_type:
        raise LiveCommandError("approval operation type does not match command")
    if approval.operation_id != preflight.operation_id:
        raise LiveCommandError("approval and preflight operation IDs differ")
    if approval.approval_id != preflight.approval_id:
        raise LiveCommandError("approval and preflight approval IDs differ")
    if payload["config_sha256"] != config.source_sha256:
        raise LiveCommandError("approval config digest does not match exact config bytes")
    if payload["profile_sha256"] != profile_sha256:
        raise LiveCommandError("approval profile digest does not match exact profile bytes")
    if payload["network_identity_sha256"] != preflight.document["network_identity_sha256"]:
        raise LiveCommandError("approval and preflight network identity digests differ")

    requirements = {
        item.operation_type: item for item in config.approval_requirements
    }
    requirement = requirements[operation_type]
    if (
        payload["expected_pre_state_sha256"]
        != requirement.expected_pre_state_sha256
        or payload["authorized_transition_sha256"]
        != requirement.authorized_transition_sha256
    ):
        raise LiveCommandError("approval state transition differs from configuration")

    signer_addresses = {
        item.role: item.public_identity
        for item in config.signers
        if item.role in {"deployer", "runner"}
    }
    if payload["addresses"] != {
        "deployer_administrator": signer_addresses["deployer"],
        "runner": signer_addresses["runner"],
    }:
        raise LiveCommandError("approval addresses differ from configured signer identities")

    approved_networks = {
        (item["network_id"], item["chain_id"])
        for item in cast(list[dict[str, Any]], payload["networks"])
    }
    configured_networks = {
        (item.network_id, item.chain_id) for item in config.networks
    }
    if approved_networks != configured_networks:
        raise LiveCommandError("approval network identities differ from configuration")

    approved_limits = cast(dict[str, int], payload["per_chain_limits"])
    config_limits = {str(item.chain_id): item.max_run_wei for item in config.budgets}
    if set(approved_limits) != set(config_limits) or any(
        approved_limits[chain_id] > config_limits[chain_id]
        for chain_id in config_limits
    ):
        raise LiveCommandError("approval per-chain limit exceeds configured run budget")

    if operation_type == "pilot":
        if profile.profile_mode != "live" or profile.profile_kind != "pilot":
            raise LiveCommandError("pilot command requires a concrete live pilot profile")
        expected_counts = {
            "pair_slots": profile.counts.planned_pair_slots,
            "designated_attempts": profile.counts.planned_designated_attempts,
            "warmup_attempts": profile.counts.planned_warmup_attempts,
        }
        if payload["planned_counts"] != expected_counts:
            raise LiveCommandError("approval counts differ from the live pilot profile")
        if (
            payload["condition_scope"] != list(profile.conditions)
            or payload["allow_partial_conditions"]
            != profile.live_limits.allow_partial_conditions
        ):
            raise LiveCommandError("approval condition scope differs from live profile")
        if preflight.document["profile_sha256"] != profile_sha256:
            raise LiveCommandError("preflight profile digest differs from exact profile bytes")
        if preflight.document["deployment_sha256"] != payload["deployment_sha256"]:
            raise LiveCommandError("preflight deployment digest differs from approval")
    elif not profile.executable:
        raise LiveCommandError("live command requires a concrete executable profile")


def _transaction_bounds(
    operation_type: LiveOperationType,
    profile: ExecutionProfile,
    preflight: OperationPreflight,
    approval: ApprovalEnvelope,
) -> dict[str, int]:
    if operation_type == "deployment":
        count = len(cast(list[Any], preflight.document["creations"]))
        return {"minimum": count, "maximum": count}
    if operation_type in {"configuration", "closeout"}:
        count = len(cast(list[Any], preflight.document["contracts"]))
        return {"minimum": 1, "maximum": count}
    designated = profile.counts.planned_designated_attempts
    retries = cast(int, approval.payload["max_retries_per_lineage"])
    return {
        "minimum": designated,
        "maximum": designated * (1 + retries),
    }


def _build_confirmation(
    *,
    command: str,
    operation_type: LiveOperationType,
    config: LabConfig,
    profile: ExecutionProfile,
    profile_sha256: str,
    preflight: OperationPreflight,
    approval: ApprovalEnvelope,
) -> tuple[dict[str, Any], str]:
    signers = {
        item.role: {
            "signer_id": item.signer_id,
            "address": item.public_identity,
        }
        for item in config.signers
        if item.role in {"deployer", "runner"}
    }
    requirement = next(
        item for item in config.approval_requirements
        if item.operation_type == operation_type
    )
    summary: dict[str, Any] = {
        "schema_version": "xir-lab-live-confirmation-v1",
        "command": command,
        "operation_type": operation_type,
        "operation_id": approval.operation_id,
        "approval_id": approval.approval_id,
        "approval_payload_sha256": approval.payload_sha256,
        "config_sha256": config.source_sha256,
        "profile_sha256": profile_sha256,
        "preflight_sha256": preflight.source_sha256,
        "signers": signers,
        "chains": [
            {
                "network_id": item.network_id,
                "chain_id": item.chain_id,
            }
            for item in config.networks
        ],
        "transaction_count_bound": _transaction_bounds(
            operation_type, profile, preflight, approval
        ),
        "per_chain_value_fee_budget_wei": approval.payload["per_chain_limits"],
        "state_transition": {
            "expected_pre_state_sha256": requirement.expected_pre_state_sha256,
            "authorized_transition_sha256": requirement.authorized_transition_sha256,
        },
        "stop_policy": profile.live_limits.stop_policy,
        "effects": {
            "signatures": 0,
            "broadcasts": 0,
        },
    }
    confirmation_id = "confirm_" + hashlib.sha256(rfc8785.dumps(summary)).hexdigest()
    return summary, confirmation_id


def load_live_context(command: str, paths: LiveCommandPaths) -> LiveCommandContext:
    """Load and correlate every required input without constructing live dependencies."""

    operation_type = LIVE_COMMAND_TYPES.get(command)
    if operation_type is None:
        raise LiveCommandError(f"unsupported live command: {command}")
    if not paths.run_dir.is_dir():
        raise LiveCommandError(f"durable operation directory does not exist: {paths.run_dir}")
    database_path = paths.run_dir / "evidence.sqlite"
    if not database_path.is_file():
        raise LiveCommandError("durable operation directory lacks evidence.sqlite")

    root = Path(__file__).resolve().parents[3]
    try:
        config = load_lab_config(
            paths.config,
            schema_path=root / "schemas" / "lab-config-v1.schema.json",
        )
        profile = load_execution_profile(paths.profile)
        profile_sha256 = _sha256_file(paths.profile)
        preflight = load_operation_preflight(
            paths.preflight,
            scope=PREFLIGHT_SCOPES[operation_type],
        )
        approval = load_approval_envelope(
            paths.approval,
            schema_path=root / "schemas" / "approval-envelope-v1.schema.json",
        )
        _require_correlated_inputs(
            operation_type=operation_type,
            config=config,
            profile=profile,
            profile_sha256=profile_sha256,
            preflight=preflight,
            approval=approval,
        )
        store = EvidenceStore(database_path, paths.run_dir / "raw")
        store.integrity_check()
        approval_document = _read_json_object(paths.approval)
        payload = approval.payload
        verifier = ApprovalVerifier(
            store=store,
            pinned_keys=(
                PinnedApprovalKey(
                    issuer_id=cast(str, payload["issuer_id"]),
                    approval_key_id=cast(str, payload["approval_key_id"]),
                    public_key_hex=_approval_public_key(config),
                ),
            ),
        )
        verified = verifier.verify(approval_document)
    except (
        ApprovalError,
        ConfigError,
        OperationPreflightError,
        ProfileError,
        StoreError,
    ) as exc:
        raise LiveCommandError(str(exc)) from exc
    if (
        verified.operation_type != operation_type
        or verified.operation_id != preflight.operation_id
    ):
        raise LiveCommandError("verified approval does not authorize this operation")

    confirmation, confirmation_id = _build_confirmation(
        command=command,
        operation_type=operation_type,
        config=config,
        profile=profile,
        profile_sha256=profile_sha256,
        preflight=preflight,
        approval=approval,
    )
    return LiveCommandContext(
        command=command,
        operation_type=operation_type,
        config=config,
        profile=profile,
        preflight=preflight,
        approval=approval,
        paths=paths,
        profile_sha256=profile_sha256,
        confirmation=confirmation,
        confirmation_id=confirmation_id,
    )


def _state_change_dispatcher(_: LiveCommandContext) -> LiveDispatchResult:
    return LiveDispatchResult(
        outcome="blocked",
        reason_code="operation_backend_not_implemented",
        implementation_status="confirmed_dispatch_boundary",
    )


def dispatch_deploy(context: LiveCommandContext) -> LiveDispatchResult:
    return _state_change_dispatcher(context)


def dispatch_configure(context: LiveCommandContext) -> LiveDispatchResult:
    return _state_change_dispatcher(context)


def dispatch_pilot_run(context: LiveCommandContext) -> LiveDispatchResult:
    return _state_change_dispatcher(context)


def dispatch_collect(_: LiveCommandContext) -> LiveDispatchResult:
    return LiveDispatchResult(
        outcome="not_executed",
        reason_code="collect_dispatcher_ready",
        implementation_status="read_only_dispatch_boundary",
    )


def dispatch_reconcile(_: LiveCommandContext) -> LiveDispatchResult:
    return LiveDispatchResult(
        outcome="not_executed",
        reason_code="reconcile_dispatcher_ready",
        implementation_status="read_only_dispatch_boundary",
    )


def dispatch_analyze(_: LiveCommandContext) -> LiveDispatchResult:
    return LiveDispatchResult(
        outcome="not_executed",
        reason_code="analyze_dispatcher_ready",
        implementation_status="read_only_dispatch_boundary",
    )


def dispatch_closeout(context: LiveCommandContext) -> LiveDispatchResult:
    return _state_change_dispatcher(context)


DISPATCHERS: dict[str, Callable[[LiveCommandContext], LiveDispatchResult]] = {
    "deploy": dispatch_deploy,
    "configure": dispatch_configure,
    "pilot-run": dispatch_pilot_run,
    "collect": dispatch_collect,
    "reconcile": dispatch_reconcile,
    "analyze": dispatch_analyze,
    "closeout": dispatch_closeout,
}


def dispatch_live(
    context: LiveCommandContext,
    *,
    confirmation_id: str | None,
    state_change_backend: LiveStateChangeBackend | None = None,
) -> LiveDispatchResult:
    """Dispatch a validated live command without bypassing exact confirmation."""

    if context.command in STATE_CHANGING_COMMANDS:
        if confirmation_id is None:
            return LiveDispatchResult(
                outcome="confirmation_required",
                reason_code="exact_confirmation_required",
                implementation_status="zero_signature_confirmation",
            )
        if confirmation_id != context.confirmation_id:
            raise LiveCommandError("confirmation ID is stale or does not match operation inputs")
        if state_change_backend is not None:
            return state_change_backend.execute(context)
    return DISPATCHERS[context.command](context)
