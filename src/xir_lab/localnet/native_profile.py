"""Frozen planning for the official Hyperlane/LayerZero local experiment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError

NativePhase = Literal["smoke", "rehearsal", "scale"]
NATIVE_ROUTES = ("HH", "HL", "LH", "LL")


@dataclass(frozen=True)
class NativeAttempt:
    attempt_id: str
    phase: NativePhase
    route: str
    route_sequence: int
    first_protocol: str
    second_protocol: str
    execution_class: str
    xir: bool
    payload_bytes: int
    payload_sha256: str


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _schema(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((_root() / "schemas" / name).read_text(encoding="utf-8")),
    )


def _validated_document(path: Path, schema_name: str) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError(f"cannot read native-stack document: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("native-stack document root must be an object")
    errors = sorted(
        jsonschema.Draft202012Validator(_schema(schema_name)).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise LocalTopologyError(
            f"{schema_name} violation at {location}: {first.message}"
        )
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def load_native_profile(path: Path) -> tuple[dict[str, Any], str]:
    profile, digest = _validated_document(path, "native-stack-profile-v1.schema.json")
    lock_path = _root() / cast(dict[str, str], profile["component_lock"])["relative_path"]
    try:
        lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise LocalTopologyError(f"native component lock is missing: {lock_path}") from exc
    if lock_digest != cast(dict[str, str], profile["component_lock"])["sha256"]:
        raise LocalTopologyError("native component lock digest mismatch")
    chains = cast(list[dict[str, Any]], profile["chains"])
    for field in ("chain_id", "hyperlane_domain", "layerzero_eid"):
        values = [int(chain[field]) for chain in chains]
        if len(values) != len(set(values)):
            raise LocalTopologyError(f"native profile has duplicate {field}")
    return profile, digest


def _payload(seed: str, phase: NativePhase, sequence: int, size: int) -> bytes:
    material = f"xir-native-v1:{seed}:{phase}:{sequence}".encode()
    result = bytearray()
    counter = 0
    while len(result) < size:
        result.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(result[:size])


def native_application_payload(
    *, profile_path: Path, phase: NativePhase, sequence: int
) -> bytes:
    """Materialize the matched payload shared by all four routes at a sequence."""

    profile, _ = load_native_profile(profile_path)
    payload_config = cast(dict[str, int], profile["payload"])
    size = payload_config["minimum_bytes"] + (
        sequence % payload_config["size_bucket_count"]
    ) * payload_config["size_step_bytes"]
    return _payload(cast(str, profile["fixed_seed"]), phase, sequence, size)


def build_native_attempts(
    *, profile_path: Path, phase: NativePhase
) -> tuple[NativeAttempt, ...]:
    profile, _ = load_native_profile(profile_path)
    progression = cast(dict[str, Any], profile["progression"])
    per_route = int(progression[f"{phase}_attempts_per_route"])
    payload_config = cast(dict[str, int], profile["payload"])
    routes = cast(dict[str, dict[str, Any]], profile["routes"])
    attempts: list[NativeAttempt] = []
    for sequence in range(per_route):
        size = payload_config["minimum_bytes"] + (
            sequence % payload_config["size_bucket_count"]
        ) * payload_config["size_step_bytes"]
        payload = _payload(
            cast(str, profile["fixed_seed"]), phase, sequence, size
        )
        for route in NATIVE_ROUTES:
            route_config = routes[route]
            attempt_id = "native_" + hashlib.sha256(
                rfc8785.dumps(
                    {
                        "version": 1,
                        "profile_id": profile["profile_id"],
                        "phase": phase,
                        "route": route,
                        "route_sequence": sequence,
                    }
                )
            ).hexdigest()[:32]
            attempts.append(
                NativeAttempt(
                    attempt_id=attempt_id,
                    phase=phase,
                    route=route,
                    route_sequence=sequence,
                    first_protocol=cast(str, route_config["first_protocol"]),
                    second_protocol=cast(str, route_config["second_protocol"]),
                    execution_class=cast(str, route_config["execution_class"]),
                    xir=cast(bool, route_config["xir"]),
                    payload_bytes=len(payload),
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
    return tuple(attempts)


def build_native_plan(
    *,
    profile_path: Path,
    topology_sha256: str,
    phase: NativePhase,
    smoke_reconciliation_sha256: str | None = None,
    rehearsal_reconciliation_sha256: str | None = None,
    measured_limits_sha256: str | None = None,
) -> dict[str, Any]:
    profile, profile_sha256 = load_native_profile(profile_path)
    progression = cast(dict[str, Any], profile["progression"])
    per_route = int(progression[f"{phase}_attempts_per_route"])
    qualification = {
        "smoke_reconciliation_sha256": smoke_reconciliation_sha256,
        "rehearsal_reconciliation_sha256": rehearsal_reconciliation_sha256,
        "measured_limits_sha256": measured_limits_sha256,
    }
    required = {
        "smoke": (),
        "rehearsal": ("smoke_reconciliation_sha256",),
        "scale": (
            "smoke_reconciliation_sha256",
            "rehearsal_reconciliation_sha256",
            "measured_limits_sha256",
        ),
    }[phase]
    reason_codes = [field for field in required if qualification[field] is None]
    route_counts = {route: per_route for route in NATIVE_ROUTES}
    payload = {
        "phase": phase,
        "profile_sha256": profile_sha256,
        "topology_sha256": topology_sha256,
        "component_lock_sha256": cast(dict[str, str], profile["component_lock"])[
            "sha256"
        ],
        "route_counts": route_counts,
        "logical_attempts": per_route * 4,
        "expected_xir_transitions": per_route * 2,
        "expected_application_effects": per_route * 4,
        "physical_transaction_accounting": "derived-from-complete-protocol-evidence",
        "qualification": qualification,
        "eligible": not reason_codes,
        "reason_codes": reason_codes,
    }
    document = {
        "schema_version": "xir-lab-native-stack-plan-v1",
        "plan_sha256": hashlib.sha256(
            rfc8785.dumps(payload)  # type: ignore[arg-type]
        ).hexdigest(),
        **payload,
    }
    errors = list(
        jsonschema.Draft202012Validator(
            _schema("native-stack-plan-v1.schema.json")
        ).iter_errors(document)
    )
    if errors:
        raise LocalTopologyError(f"generated native-stack plan is invalid: {errors[0].message}")
    return document
