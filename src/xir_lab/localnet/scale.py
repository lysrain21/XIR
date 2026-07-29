"""Exact local-scale profile and progression planning."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import jsonschema
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError

CONDITIONS = ("HH", "HL", "LH", "LL")
ARMS = ("baseline", "xir")


def _schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _load(path: Path, schema_name: str) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read local scale profile: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("local scale profile root must be an object")
    errors = sorted(
        jsonschema.Draft202012Validator(_schema(schema_name)).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise LocalTopologyError(
            f"{schema_name} violation at {location}: {first.message}"
        )
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def build_local_scale_plan(
    *,
    profile_path: Path,
    topology_sha256: str,
    smoke_freeze_sha256: str | None = None,
    rehearsal_freeze_sha256: str | None = None,
    measured_limits_sha256: str | None = None,
) -> dict[str, Any]:
    """Build the exact plan identity and fail closed on missing progression."""

    _, profile_sha256 = _load(
        profile_path,
        "local-scale-profile-v1.schema.json",
    )
    progression = {
        "smoke_freeze_sha256": smoke_freeze_sha256,
        "rehearsal_freeze_sha256": rehearsal_freeze_sha256,
        "measured_limits_sha256": measured_limits_sha256,
    }
    reason_codes = [
        name
        for name, value in progression.items()
        if value is None
    ]
    payload = {
        "environment": "controlled-local-qbft",
        "profile_sha256": profile_sha256,
        "topology_sha256": topology_sha256,
        "counts": {
            "pair_slots": 5000,
            "designated_attempts": 10000,
            "source_transactions": 10000,
            "intermediate_transactions": 10000,
            "destination_transactions": 10000,
            "physical_transactions": 30000,
        },
        "condition_arm_counts": {
            f"{condition}/{arm}": 1250
            for condition in CONDITIONS
            for arm in ARMS
        },
        "progression": progression,
        "eligible": not reason_codes,
        "reason_codes": reason_codes,
    }
    document = {
        "schema_version": "xir-lab-local-scale-plan-v1",
        "plan_sha256": hashlib.sha256(
            rfc8785.dumps(payload)  # type: ignore[arg-type]
        ).hexdigest(),
        **payload,
    }
    errors = list(
        jsonschema.Draft202012Validator(
            _schema("local-scale-plan-v1.schema.json")
        ).iter_errors(document)
    )
    if errors:
        raise LocalTopologyError(f"generated local scale plan is invalid: {errors[0].message}")
    return document


def _load_document(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read {label}: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError(f"{label} root must be an object")
    return cast(dict[str, Any], document)


def _unwrap(document: dict[str, Any], key: str) -> dict[str, Any]:
    details = document.get("details")
    if isinstance(details, dict) and isinstance(details.get(key), dict):
        return cast(dict[str, Any], details[key])
    return document


def validate_local_scale_execution_gate(
    *,
    plan_path: Path,
    preflight_path: Path,
    profile_path: Path,
    runtime_root: Path,
    topology_sha256: str,
    identity_manifest_sha256: str,
) -> None:
    """Require a frozen eligible plan and a matching eligible scale preflight."""

    plan = _unwrap(_load_document(plan_path, "local scale plan"), "plan")
    plan_errors = list(
        jsonschema.Draft202012Validator(
            _schema("local-scale-plan-v1.schema.json")
        ).iter_errors(plan)
    )
    if plan_errors:
        raise LocalTopologyError(f"invalid local scale plan: {plan_errors[0].message}")
    plan_payload = {
        key: value
        for key, value in plan.items()
        if key not in {"schema_version", "plan_sha256"}
    }
    if hashlib.sha256(rfc8785.dumps(plan_payload)).hexdigest() != plan["plan_sha256"]:
        raise LocalTopologyError("local scale plan digest mismatch")
    _, profile_sha256 = _load(
        profile_path,
        "local-scale-profile-v1.schema.json",
    )
    if (
        plan["topology_sha256"] != topology_sha256
        or plan["profile_sha256"] != profile_sha256
    ):
        raise LocalTopologyError("local scale plan identity mismatch")
    if plan["eligible"] is not True:
        raise LocalTopologyError("local scale progression is incomplete")
    progression = cast(dict[str, str], plan["progression"])
    freeze_paths = {
        "smoke_freeze_sha256": runtime_root / "evidence" / "smoke.sqlite",
        "rehearsal_freeze_sha256": runtime_root / "evidence" / "rehearsal.sqlite",
        "measured_limits_sha256": runtime_root / "measured-limits.json",
    }
    for field, path in freeze_paths.items():
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise LocalTopologyError(f"local scale freeze input is missing: {path}") from exc
        if progression[field] != actual:
            raise LocalTopologyError(f"local scale freeze digest mismatch: {field}")

    preflight = _unwrap(
        _load_document(preflight_path, "local scale preflight"),
        "preflight",
    )
    preflight_errors = list(
        jsonschema.Draft202012Validator(
            _schema("local-preflight-v1.schema.json")
        ).iter_errors(preflight)
    )
    if preflight_errors:
        raise LocalTopologyError(
            f"invalid local scale preflight: {preflight_errors[0].message}"
        )
    if (
        preflight["mode"] != "scale"
        or preflight["topology_sha256"] != topology_sha256
        or preflight["identity_manifest_sha256"] != identity_manifest_sha256
        or preflight["eligible"] is not True
    ):
        raise LocalTopologyError("local scale preflight is not eligible for this identity")
