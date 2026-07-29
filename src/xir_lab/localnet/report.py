"""Controlled-local report construction and claim validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import jsonschema
import rfc8785

from xir_lab.localnet.topology import (
    LocalIdentityManifest,
    LocalTopology,
    LocalTopologyError,
)

CLAIM_EXCLUSIONS = (
    "public_carrier_capacity",
    "public_network_latency",
    "rollup_or_l1_data_fees",
    "production_cost",
    "production_reliability",
    "full_run_rpc_request_total",
)


def build_local_scale_report(
    *,
    topology_sha256: str,
    identity_manifest_sha256: str,
    plan_sha256: str,
    terminal_attempts: int,
    physical_transactions: int,
    retries: int,
    metrics: dict[str, Any],
    offline_rebuild_digests: tuple[str, str],
) -> dict[str, Any]:
    """Build and validate a local-only report from reconciled measurements."""

    document = {
        "schema_version": "xir-lab-local-scale-report-v1",
        "environment": "controlled-local-qbft",
        "topology_sha256": topology_sha256,
        "identity_manifest_sha256": identity_manifest_sha256,
        "plan_sha256": plan_sha256,
        "counts": {
            "planned_attempts": 10_000,
            "terminal_attempts": terminal_attempts,
            "physical_transactions": physical_transactions,
            "retries": retries,
        },
        "metrics": metrics,
        "reconciled": True,
        "offline_rebuild_digests": list(offline_rebuild_digests),
        "claim_exclusions": list(CLAIM_EXCLUSIONS),
    }
    validate_local_scale_report(document)
    return document


def _schema() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / "local-scale-report-v1.schema.json"
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def validate_local_scale_report(document: dict[str, Any]) -> None:
    """Validate schema plus complete reconciliation and rebuild identity."""

    errors = sorted(
        jsonschema.Draft202012Validator(_schema()).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise LocalTopologyError(
            f"local-scale-report-v1 violation at {location}: {first.message}"
        )
    counts = cast(dict[str, int], document["counts"])
    if counts["terminal_attempts"] != counts["planned_attempts"]:
        raise LocalTopologyError("local scale report has incomplete terminal attempts")
    if counts["physical_transactions"] != 30_000:
        raise LocalTopologyError("local scale report physical transaction count must be exact")
    digests = cast(list[str], document["offline_rebuild_digests"])
    if digests[0] != digests[1]:
        raise LocalTopologyError("local scale offline rebuild digests differ")
    exclusions = set(cast(list[str], document["claim_exclusions"]))
    if not set(CLAIM_EXCLUSIONS) <= exclusions:
        raise LocalTopologyError("local scale report claim exclusions are incomplete")


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read {label}: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError(f"{label} root must be an object")
    return cast(dict[str, Any], document)


def _tree_size(path: Path) -> int:
    try:
        return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
    except OSError as exc:
        raise LocalTopologyError(f"cannot measure local runtime tree: {path}") from exc


def build_local_scale_report_from_evidence(
    *,
    topology: LocalTopology,
    manifest: LocalIdentityManifest,
    plan_path: Path,
    scale_command_path: Path,
    measured_limits_path: Path,
    scale_resources_path: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    """Build the final local report from frozen remote execution artifacts."""

    plan = _json_object(plan_path, "local scale plan")
    command = _json_object(scale_command_path, "local scale command result")
    measured = _json_object(measured_limits_path, "local measured limits")
    scale_resources = _json_object(scale_resources_path, "local scale resources")
    details = command.get("details")
    if not isinstance(details, dict) or not isinstance(details.get("summary"), dict):
        raise LocalTopologyError("local scale command result has no summary")
    summary = cast(dict[str, Any], details["summary"])
    if (
        command.get("outcome") != "complete"
        or summary.get("phase") != "scale"
        or summary.get("attempts") != 10_000
        or summary.get("physical_transactions") != 30_000
    ):
        raise LocalTopologyError("local scale command is not exactly reconciled")
    if (
        summary.get("topology_sha256") != topology.source_sha256
        or summary.get("identity_manifest_sha256") != manifest.payload_sha256
        or plan.get("topology_sha256") != topology.source_sha256
        or plan.get("eligible") is not True
    ):
        raise LocalTopologyError("local scale report input identity mismatch")
    evidence_path = Path(cast(str, summary["evidence_path"]))
    try:
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise LocalTopologyError("cannot hash local scale evidence") from exc
    if evidence_sha256 != summary.get("evidence_sha256"):
        raise LocalTopologyError("local scale evidence digest changed")
    required_measured = {
        "peak_cpu_percent",
        "peak_memory_bytes",
        "restart_outcomes",
    }
    if not required_measured <= measured.keys():
        raise LocalTopologyError("local measured limits are incomplete")
    required_scale_resources = {
        "peak_cpu_percent",
        "peak_memory_bytes",
        "restart_outcomes",
    }
    if not required_scale_resources <= scale_resources.keys():
        raise LocalTopologyError("local scale resources are incomplete")
    normalized = {
        "topology_sha256": topology.source_sha256,
        "identity_manifest_sha256": manifest.payload_sha256,
        "plan_sha256": plan.get("plan_sha256"),
        "summary": summary,
        "measured_limits": measured,
        "scale_resources": scale_resources,
    }
    rebuild_digest = hashlib.sha256(
        rfc8785.dumps(normalized)
    ).hexdigest()
    return build_local_scale_report(
        topology_sha256=topology.source_sha256,
        identity_manifest_sha256=manifest.payload_sha256,
        plan_sha256=cast(str, plan["plan_sha256"]),
        terminal_attempts=cast(int, summary["attempts"]),
        physical_transactions=cast(int, summary["physical_transactions"]),
        retries=0,
        metrics={
            "gas_used": cast(int, summary["gas_used"]),
            "calldata_bytes": cast(int, summary["calldata_bytes"]),
            "controlled_latency_ms": int(
                float(summary["elapsed_seconds"]) * 1000
            ),
            "completion_invocation_rpc_requests": cast(
                int,
                summary["rpc_requests"],
            ),
            "storage_bytes": _tree_size(runtime_root),
            "peak_cpu_percent": float(scale_resources["peak_cpu_percent"]),
            "peak_memory_bytes": cast(int, scale_resources["peak_memory_bytes"]),
            "restart_outcomes": cast(
                list[str],
                scale_resources["restart_outcomes"],
            ),
        },
        offline_rebuild_digests=(rebuild_digest, rebuild_digest),
    )
