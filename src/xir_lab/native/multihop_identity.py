"""Release contracts for formal and pilot native multihop campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from xir_lab.localnet.topology import LocalTopologyError

DEPLOYMENT_NAMESPACE = "native-multihop-switching-v1"
FORMAL_ROLE = "formal_measurement"
PILOT_ROLE = "pilot_diagnostic_only"


@dataclass(frozen=True)
class CampaignIdentity:
    key: str
    evidence_namespace: str
    scale_attempts_per_route: int
    scale_attempt_count: int
    scale_role: str
    incident_denominator: str
    claim_eligible: bool
    global_lease_root: Path


FORMAL = CampaignIdentity(
    key="formal",
    evidence_namespace="native-multihop-switching-v1",
    scale_attempts_per_route=10_000,
    scale_attempt_count=110_000,
    scale_role=FORMAL_ROLE,
    incident_denominator="all_110000_validated_effects",
    claim_eligible=True,
    global_lease_root=Path(
        "/run/lock/xir-lab-runtime-leases/native-multihop-switching-v1"
    ),
)
PILOT = CampaignIdentity(
    key="pilot",
    evidence_namespace="native-multihop-switching-pilot-v1",
    scale_attempts_per_route=100,
    scale_attempt_count=1_100,
    scale_role=PILOT_ROLE,
    incident_denominator="all_1100_validated_effects",
    claim_eligible=False,
    global_lease_root=Path(
        "/run/lock/xir-lab-runtime-leases/native-multihop-switching-pilot-v1"
    ),
)


def config_identity(config: dict[str, Any]) -> CampaignIdentity:
    if config.get("namespace") != DEPLOYMENT_NAMESPACE:
        raise LocalTopologyError("multihop config deployment namespace is invalid")
    roles = cast(dict[str, str], config.get("result_roles", {}))
    role = roles.get("scale")
    if role == FORMAL_ROLE:
        identity = FORMAL
    elif role == PILOT_ROLE:
        identity = PILOT
    else:
        raise LocalTopologyError(f"unsupported multihop scale role: {role}")
    attempts = cast(dict[str, int], config.get("attempts_per_route", {}))
    incident = cast(dict[str, Any], config.get("incident_policy", {}))
    if (
        attempts.get("smoke") != 1
        or attempts.get("publication_smoke") != 2
        or attempts.get("scale") != identity.scale_attempts_per_route
        or roles.get("smoke") != "development_gate_only"
        or roles.get("publication_smoke") != "publication_gate_not_formal_estimate"
        or roles.get("gateway_analysis") != "frozen_graph_analysis"
        or incident.get("primary_denominator") != identity.incident_denominator
    ):
        raise LocalTopologyError("multihop config differs from its release contract")
    return identity


def evidence_namespace(config: dict[str, Any]) -> str:
    """Read evidence identity from a full config or a legacy bounded fixture."""

    roles = config.get("result_roles")
    role = roles.get("scale") if isinstance(roles, dict) else FORMAL_ROLE
    if role == PILOT_ROLE:
        return PILOT.evidence_namespace
    if role == FORMAL_ROLE:
        return FORMAL.evidence_namespace
    raise LocalTopologyError(f"unsupported multihop scale role: {role}")


def phase_attempt_count(config: dict[str, Any], phase: str, *, route_count: int = 11) -> int:
    attempts = config.get("attempts_per_route")
    if isinstance(attempts, dict) and phase in attempts:
        return int(attempts[phase]) * route_count
    defaults = {"smoke": 11, "publication_smoke": 22, "scale": 110_000}
    if phase not in defaults:
        raise LocalTopologyError(f"unknown multihop phase: {phase}")
    return defaults[phase]


def phase_role(config: dict[str, Any], phase: str) -> str:
    roles = config.get("result_roles")
    if isinstance(roles, dict) and phase in roles:
        return str(roles[phase])
    defaults = {
        "smoke": "development_gate_only",
        "publication_smoke": "publication_gate_not_formal_estimate",
        "scale": FORMAL_ROLE,
    }
    if phase not in defaults:
        raise LocalTopologyError(f"unknown multihop phase role: {phase}")
    return defaults[phase]
