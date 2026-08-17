"""Frozen planning primitives for the five-chain multihop switching study.

This module is deliberately separate from the accepted three-chain native runner.
It defines the preregistered route universe, deterministic matched attempts, and
the transaction/stage accounting that a later executor must reconcile exactly.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError

MultihopPhase = Literal["smoke", "publication_smoke", "scale"]

ROUTE_ORDER = (
    "H",
    "L",
    "HH",
    "HHH",
    "HHHH",
    "HL",
    "HLH",
    "HLHL",
    "LHLH",
    "HHL",
    "HHHL",
)
CHAIN_LABELS = ("A", "B", "C", "D", "E")


@dataclass(frozen=True)
class MultihopAttempt:
    """One preregistered route execution and its exact accounting contract."""

    attempt_id: str
    phase: MultihopPhase
    route: str
    route_sequence: int
    route_protocols: tuple[str, ...]
    chain_labels: tuple[str, ...]
    hop_count: int
    switch_count: int
    receipt_count: int
    payload_bytes: int
    payload_sha256: str
    expected_coordinator_transactions: int
    expected_physical_transactions: int
    expected_stages: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        document = asdict(self)
        document["route_protocols"] = list(self.route_protocols)
        document["chain_labels"] = list(self.chain_labels)
        document["expected_stages"] = list(self.expected_stages)
        return document


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
        raise LocalTopologyError(f"cannot read multihop document: {path}") from exc
    if not isinstance(document, dict):
        raise LocalTopologyError("multihop document root must be an object")
    errors = sorted(
        jsonschema.Draft202012Validator(_schema(schema_name)).iter_errors(document),
        key=lambda error: [str(part) for part in error.path],
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise LocalTopologyError(
            f"{schema_name} violation at {location}: {first.message}"
        )
    return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()


def load_multihop_profile(
    path: Path, *, component_lock_path_override: Path | None = None
) -> tuple[dict[str, Any], str]:
    """Load and cross-check the five-chain profile and component lock."""

    profile, digest = _validated_document(
        path, "native-multihop-switching-v1-profile.schema.json"
    )
    chains = cast(list[dict[str, Any]], profile["chains"])
    if tuple(str(chain["label"]) for chain in chains) != CHAIN_LABELS:
        raise LocalTopologyError("five-chain profile must be ordered A/B/C/D/E")
    for field in (
        "network_id",
        "chain_id",
        "rpc_url",
        "hyperlane_domain",
        "layerzero_eid",
    ):
        values = [chain[field] for chain in chains]
        if len(values) != len(set(values)):
            raise LocalTopologyError(f"five-chain profile has duplicate {field}")
    lock = cast(dict[str, str], profile["component_lock"])
    lock_path = (
        _root() / lock["relative_path"]
        if component_lock_path_override is None
        else component_lock_path_override
    )
    try:
        observed = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise LocalTopologyError(f"native component lock is missing: {lock_path}") from exc
    if observed != lock["sha256"]:
        raise LocalTopologyError("native component lock digest mismatch")
    return profile, digest


def load_multihop_config(
    path: Path,
    *,
    profile_path_override: Path | None = None,
    component_lock_path_override: Path | None = None,
    source_root_override: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Load the preregistration and bind it to the exact local source tree."""

    config, digest = _validated_document(
        path, "native-multihop-switching-v1-config.schema.json"
    )
    if tuple(cast(list[str], config["route_order"])) != ROUTE_ORDER:
        raise LocalTopologyError("multihop route order differs from the preregistration")
    profile_path = (
        _root() / cast(str, config["profile"])
        if profile_path_override is None
        else profile_path_override
    )
    profile, _ = load_multihop_profile(
        profile_path, component_lock_path_override=component_lock_path_override
    )
    if config["payload_schedule"] != profile["payload"]:
        raise LocalTopologyError("config payload schedule differs from five-chain profile")
    source_locks = cast(dict[str, str], config["source_sha256"])
    for relative, expected in source_locks.items():
        source_path = (source_root_override or _root()) / relative
        try:
            observed = hashlib.sha256(source_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise LocalTopologyError(f"locked multihop source is missing: {relative}") from exc
        if observed != expected:
            raise LocalTopologyError(f"locked multihop source digest mismatch: {relative}")
    return config, digest


def switch_count(route: str) -> int:
    """Count carrier changes in an H/L route."""

    if not route or any(protocol not in {"H", "L"} for protocol in route):
        raise LocalTopologyError(f"invalid multihop route: {route}")
    return sum(left != right for left, right in zip(route, route[1:]))


def expected_coordinator_transactions(route: str) -> int:
    """Return h+s+2: root, h dispatches, s transitions, final delivery."""

    return len(route) + switch_count(route) + 2


def expected_physical_transactions(route: str) -> int:
    """Add one H delivery or three L worker transactions per native hop."""

    return expected_coordinator_transactions(route) + route.count("H") + 3 * route.count("L")


def expected_stage_sequence(route: str) -> tuple[str, ...]:
    """Describe every coordinator and carrier transaction in causal order."""

    switch_count(route)
    stages = ["root_create"]
    for index, protocol in enumerate(route, start=1):
        if index > 1 and route[index - 2] != protocol:
            stages.append(f"hop_{index}_xir_transition")
        stages.append(f"hop_{index}_{protocol.lower()}_dispatch")
        if protocol == "H":
            stages.append(f"hop_{index}_hyperlane_process")
        else:
            stages.extend(
                (
                    f"hop_{index}_layerzero_dvn_execute",
                    f"hop_{index}_layerzero_commit_verification",
                    f"hop_{index}_layerzero_executor_execute",
                )
            )
    stages.append("destination_verify_deliver")
    if len(stages) != expected_physical_transactions(route):
        raise AssertionError("stage sequence and physical transaction theory diverged")
    return tuple(stages)


def _payload(seed: str, phase: MultihopPhase, sequence: int, size: int) -> bytes:
    material = f"xir-multihop-v1:{seed}:{phase}:{sequence}".encode()
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:size])


def build_multihop_attempt(
    *,
    config: dict[str, Any],
    phase: MultihopPhase,
    route_sequence: int,
    route: str,
) -> MultihopAttempt:
    """Build one route entry from the frozen plan descriptor."""

    if route not in ROUTE_ORDER:
        raise LocalTopologyError(f"route is outside frozen multihop order: {route}")
    per_route = int(cast(dict[str, int], config["attempts_per_route"])[phase])
    if route_sequence < 0 or route_sequence >= per_route:
        raise LocalTopologyError("route sequence is outside the frozen phase denominator")
    schedule = cast(dict[str, int], config["payload_schedule"])
    size = schedule["minimum_bytes"] + (
        route_sequence % schedule["size_bucket_count"]
    ) * schedule["size_step_bytes"]
    payload = _payload(
        cast(str, config["fixed_seed"]), phase, route_sequence, size
    )
    attempt_id = "mh_" + hashlib.sha256(
        rfc8785.dumps(
            {
                "namespace": config["namespace"],
                "phase": phase,
                "route": route,
                "route_sequence": route_sequence,
            }
        )
    ).hexdigest()[:32]
    return MultihopAttempt(
        attempt_id=attempt_id,
        phase=phase,
        route=route,
        route_sequence=route_sequence,
        route_protocols=tuple(route),
        chain_labels=CHAIN_LABELS[: len(route) + 1],
        hop_count=len(route),
        switch_count=switch_count(route),
        receipt_count=len(route),
        payload_bytes=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        expected_coordinator_transactions=expected_coordinator_transactions(route),
        expected_physical_transactions=expected_physical_transactions(route),
        expected_stages=expected_stage_sequence(route),
    )


def iter_multihop_attempts(
    *,
    config_path: Path,
    phase: MultihopPhase,
    profile_path_override: Path | None = None,
    component_lock_path_override: Path | None = None,
    source_root_override: Path | None = None,
) -> Iterator[MultihopAttempt]:
    """Yield the exact plan without materializing the 110,000-row scale set."""

    config, _ = load_multihop_config(
        config_path,
        profile_path_override=profile_path_override,
        component_lock_path_override=component_lock_path_override,
        source_root_override=source_root_override,
    )
    per_route = int(cast(dict[str, int], config["attempts_per_route"])[phase])
    for sequence in range(per_route):
        offset = sequence % len(ROUTE_ORDER)
        route_block = ROUTE_ORDER[offset:] + ROUTE_ORDER[:offset]
        for route in route_block:
            yield build_multihop_attempt(
                config=config,
                phase=phase,
                route_sequence=sequence,
                route=route,
            )


def build_multihop_attempts(
    *, config_path: Path, phase: MultihopPhase
) -> tuple[MultihopAttempt, ...]:
    """Materialize attempts for bounded smoke/rehearsal checks."""

    return tuple(iter_multihop_attempts(config_path=config_path, phase=phase))


def build_multihop_plan(*, config_path: Path, phase: MultihopPhase) -> dict[str, Any]:
    """Materialize and schema-check the exact formal plan."""

    config, config_sha256 = load_multihop_config(config_path)
    profile_path = _root() / cast(str, config["profile"])
    _, profile_sha256 = load_multihop_profile(profile_path)
    per_route = int(cast(dict[str, int], config["attempts_per_route"])[phase])
    logical_attempts = per_route * len(ROUTE_ORDER)
    payload: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-switching-plan-v1",
        "namespace": "native-multihop-switching-v1",
        "phase": phase,
        "config_sha256": config_sha256,
        "profile_sha256": profile_sha256,
        "route_counts": {route: per_route for route in ROUTE_ORDER},
        "logical_attempts": logical_attempts,
        "expected_application_effects": logical_attempts,
        "generation": {
            "ordering": "route_sequence_then_rotated_frozen_route_order",
            "route_order": list(ROUTE_ORDER),
            "route_sequence_start": 0,
            "route_sequence_stop_exclusive": per_route,
            "attempt_id_derivation": "sha256-rfc8785-namespace-phase-route-sequence-prefix32",
            "payload_matching_unit": "same-phase-and-route-sequence",
        },
    }
    document = {
        **payload,
        "plan_sha256": hashlib.sha256(rfc8785.dumps(payload)).hexdigest(),
    }
    errors = sorted(
        jsonschema.Draft202012Validator(
            _schema("native-multihop-switching-v1-plan.schema.json")
        ).iter_errors(document),
        key=lambda error: [str(part) for part in error.path],
    )
    if errors:
        raise LocalTopologyError(f"generated multihop plan is invalid: {errors[0].message}")
    return document


def write_multihop_plan(path: Path, plan: dict[str, Any]) -> str:
    """Write a deterministic plan and return its file digest."""

    encoded = json.dumps(plan, indent=2, sort_keys=True).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def load_multihop_plan(
    *, path: Path, config_path: Path, phase: MultihopPhase
) -> tuple[dict[str, Any], str]:
    """Load and independently reconcile a materialized phase descriptor."""

    plan, file_sha256 = _validated_document(
        path, "native-multihop-switching-v1-plan.schema.json"
    )
    config, config_sha256 = load_multihop_config(config_path)
    semantic = dict(plan)
    expected_semantic = str(semantic.pop("plan_sha256"))
    per_route = int(cast(dict[str, int], config["attempts_per_route"])[phase])
    if (
        hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != expected_semantic
        or plan["phase"] != phase
        or plan["config_sha256"] != config_sha256
        or cast(dict[str, int], plan["route_counts"])
        != {route: per_route for route in ROUTE_ORDER}
        or int(plan["logical_attempts"]) != per_route * len(ROUTE_ORDER)
        or int(plan["expected_application_effects"])
        != per_route * len(ROUTE_ORDER)
    ):
        raise LocalTopologyError("multihop materialized plan differs from config")
    return plan, file_sha256
