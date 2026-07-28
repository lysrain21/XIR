"""On-chain carrier identity, security-path, quote, and simulation preflight."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.preflight.quotes import FIXED_LEGS

ProtocolName = Literal["hyperlane", "layerzero-v2"]

FIXED_CARRIER_ROUTES = tuple(
    (local, remote, protocol)
    for local, remote in FIXED_LEGS
    for protocol in ("hyperlane", "layerzero-v2")
)
OFFICIAL_DISCOVERY_HOSTS = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "docs.hyperlane.xyz",
        "docs.layerzero.network",
        "metadata.layerzero-api.com",
    }
)


class CarrierPreflightError(ValueError):
    """Raised when carrier discovery or fixed-route coverage is ambiguous."""


@dataclass(frozen=True)
class RegistryCandidate:
    protocol: ProtocolName
    local_network: str
    remote_network: str
    endpoint_address: str
    remote_selector: int
    peer_address: str
    local_adapter_address: str
    source_url: str
    source_sha256: str
    expected_endpoint_runtime_sha256: str | None = None


@dataclass(frozen=True)
class HyperlaneState:
    runtime_code_sha256: str
    local_domain: int
    ism_address: str
    hook_address: str
    payment_required_wei: int
    enrolled_remote_peer: str
    security_config_sha256: str
    quoted_payment_wei: int


@dataclass(frozen=True)
class LayerZeroState:
    runtime_code_sha256: str
    local_eid: int
    supported_remote_eid: bool
    send_library: str
    receive_library: str
    dvns: tuple[str, ...]
    executor: str
    enforced_options_sha256: str
    configured_peer: str
    security_config_sha256: str
    quoted_payment_wei: int


class CarrierStateProvider(Protocol):
    def hyperlane_state(self, candidate: RegistryCandidate) -> HyperlaneState:
        """Recollect Hyperlane public state using read-only calls."""

    def layerzero_state(self, candidate: RegistryCandidate) -> LayerZeroState:
        """Recollect LayerZero public state using read-only calls."""


@dataclass(frozen=True)
class CarrierRouteObservation:
    route_id: str
    protocol: str
    local_network: str
    remote_network: str
    endpoint_address: str
    remote_selector: int
    peer_address: str
    runtime_code_sha256: str | None
    security_config_sha256: str | None
    quote_wei: int | None
    status: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class CarrierRouteSuite:
    observations: tuple[CarrierRouteObservation, ...]
    outcome: str
    allow_partial_conditions: bool
    effects: dict[str, int]


@dataclass(frozen=True)
class UnsignedSimulationRequest:
    simulation_id: str
    category: Literal["deployment", "configuration", "pilot"]
    network_id: str
    condition: str | None
    arm: str | None
    destination: str | None
    value_wei: int
    calldata_sha256: str
    gas_limit: int
    sender: str | None = None
    calldata_hex: str | None = None


@dataclass(frozen=True)
class UnsignedCallTemplate:
    simulation_id: str
    category: Literal["deployment", "configuration", "pilot"]
    network_id: str
    condition: str | None
    arm: str | None
    destination: str | None
    sender: str | None
    value_wei: int
    calldata: bytes
    gas_limit: int


@dataclass(frozen=True)
class SimulationResult:
    simulation_id: str
    success: bool
    raw_sha256: str
    reason_code: str


class SimulationProvider(Protocol):
    def simulate(self, request: UnsignedSimulationRequest) -> SimulationResult:
        """Run eth_call/estimate-style validation without signing."""


def _address(value: str, label: str) -> None:
    try:
        valid = len(value) == 42 and value.startswith("0x") and int(value, 16) != 0
    except ValueError:
        valid = False
    if not valid:
        raise CarrierPreflightError(f"{label} is not a nonzero EVM address")


def validate_registry_candidates(
    candidates: tuple[RegistryCandidate, ...],
) -> tuple[RegistryCandidate, ...]:
    """Accept official registry data as discovery input, never execution authority."""

    observed = {
        (item.local_network, item.remote_network, item.protocol)
        for item in candidates
    }
    if len(candidates) != 4 or observed != set(FIXED_CARRIER_ROUTES):
        raise CarrierPreflightError("registry candidates must cover exactly four fixed routes")
    for candidate in candidates:
        host = candidate.source_url.split("/", 3)[2] if "://" in candidate.source_url else ""
        if host not in OFFICIAL_DISCOVERY_HOSTS:
            raise CarrierPreflightError("registry candidate source is not an approved official host")
        _address(candidate.endpoint_address, "endpoint")
        _address(candidate.peer_address, "peer")
        _address(candidate.local_adapter_address, "local adapter")
        if candidate.remote_selector <= 0:
            raise CarrierPreflightError("remote selector must be positive")
        if len(candidate.source_sha256) != 64:
            raise CarrierPreflightError("registry source digest is invalid")
        if (
            candidate.expected_endpoint_runtime_sha256 is not None
            and len(candidate.expected_endpoint_runtime_sha256) != 64
        ):
            raise CarrierPreflightError("expected endpoint runtime digest is invalid")
    return candidates


def registry_candidate_digest(
    candidates: tuple[RegistryCandidate, ...],
) -> str:
    validated = validate_registry_candidates(candidates)
    return hashlib.sha256(
        rfc8785.dumps(
            [
                {
                    "protocol": item.protocol,
                    "local_network": item.local_network,
                    "remote_network": item.remote_network,
                    "endpoint_address": item.endpoint_address.lower(),
                    "remote_selector": item.remote_selector,
                    "peer_address": item.peer_address.lower(),
                    "local_adapter_address": item.local_adapter_address.lower(),
                    "source_sha256": item.source_sha256,
                    "expected_endpoint_runtime_sha256": (
                        item.expected_endpoint_runtime_sha256
                    ),
                }
                for item in sorted(
                    validated,
                    key=lambda candidate: (
                        candidate.local_network,
                        candidate.remote_network,
                        candidate.protocol,
                    ),
                )
            ]
        )
    ).hexdigest()


def collect_carrier_routes(
    *,
    candidates: tuple[RegistryCandidate, ...],
    providers: dict[ProtocolName, CarrierStateProvider],
    maximum_quote_wei: dict[str, int],
    allow_partial_conditions: bool,
    expected_candidate_sha256: str | None = None,
) -> CarrierRouteSuite:
    """Recollect every candidate from chain and block the entire pilot on one defect."""

    validate_registry_candidates(candidates)
    if (
        expected_candidate_sha256 is not None
        and registry_candidate_digest(candidates) != expected_candidate_sha256
    ):
        raise CarrierPreflightError("registry candidate addresses changed after freeze")
    if set(providers) != {"hyperlane", "layerzero-v2"}:
        raise CarrierPreflightError("both carrier state providers are required")
    observations: list[CarrierRouteObservation] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (item.local_network, item.remote_network, item.protocol),
    ):
        route_id = (
            f"{candidate.protocol}:{candidate.local_network}:{candidate.remote_network}"
        )
        reasons: list[str] = []
        runtime: str | None = None
        security: str | None = None
        quote: int | None = None
        try:
            if candidate.protocol == "hyperlane":
                state = providers["hyperlane"].hyperlane_state(candidate)
                runtime = state.runtime_code_sha256
                security = state.security_config_sha256
                quote = state.quoted_payment_wei
                _address(state.ism_address, "Hyperlane ISM")
                _address(state.hook_address, "Hyperlane hook")
                if state.local_domain <= 0:
                    reasons.append("hyperlane_domain_invalid")
                if state.enrolled_remote_peer.lower() != candidate.peer_address.lower():
                    reasons.append("hyperlane_peer_mismatch")
                if state.payment_required_wei > state.quoted_payment_wei:
                    reasons.append("hyperlane_payment_exceeds_quote")
            else:
                state_lz = providers["layerzero-v2"].layerzero_state(candidate)
                runtime = state_lz.runtime_code_sha256
                security = state_lz.security_config_sha256
                quote = state_lz.quoted_payment_wei
                for value, label in (
                    (state_lz.send_library, "LayerZero send library"),
                    (state_lz.receive_library, "LayerZero receive library"),
                    (state_lz.executor, "LayerZero executor"),
                ):
                    _address(value, label)
                if not state_lz.dvns:
                    reasons.append("layerzero_dead_dvn_path")
                else:
                    for dvn in state_lz.dvns:
                        _address(dvn, "LayerZero DVN")
                if state_lz.local_eid <= 0 or not state_lz.supported_remote_eid:
                    reasons.append("layerzero_remote_eid_unsupported")
                if state_lz.configured_peer.lower() != candidate.peer_address.lower():
                    reasons.append("layerzero_peer_mismatch")
        except Exception:
            reasons.append("carrier_state_unavailable")
        if runtime is None or runtime == "0" * 64:
            reasons.append("carrier_runtime_code_missing")
        elif (
            candidate.expected_endpoint_runtime_sha256 is not None
            and runtime != candidate.expected_endpoint_runtime_sha256
        ):
            reasons.append("carrier_runtime_code_mismatch")
        if security is None or security == "0" * 64:
            reasons.append("carrier_security_unknown")
        maximum = maximum_quote_wei.get(route_id)
        if quote is None:
            reasons.append("carrier_quote_unknown")
        elif maximum is None or quote > maximum:
            reasons.append("carrier_quote_out_of_bounds")
        unique = tuple(sorted(set(reasons)))
        observations.append(
            CarrierRouteObservation(
                route_id=route_id,
                protocol=candidate.protocol,
                local_network=candidate.local_network,
                remote_network=candidate.remote_network,
                endpoint_address=candidate.endpoint_address,
                remote_selector=candidate.remote_selector,
                peer_address=candidate.peer_address,
                runtime_code_sha256=runtime,
                security_config_sha256=security,
                quote_wei=quote,
                status="pass" if not unique else "fail",
                reason_codes=unique or ("carrier_route_ready",),
            )
        )
    all_pass = all(item.status == "pass" for item in observations)
    return CarrierRouteSuite(
        observations=tuple(observations),
        outcome="pass" if all_pass else "blocked",
        allow_partial_conditions=allow_partial_conditions,
        effects={
            "signing_operations": 0,
            "deployments": 0,
            "configurations": 0,
            "broadcasts": 0,
        },
    )


def validate_unsigned_simulations(
    *,
    requests: tuple[UnsignedSimulationRequest, ...],
    provider: SimulationProvider,
) -> tuple[SimulationResult, ...]:
    """Require all deployment/configuration and eight pilot cells to simulate."""

    deployment_networks = {
        item.network_id for item in requests if item.category == "deployment"
    }
    configuration_networks = {
        item.network_id for item in requests if item.category == "configuration"
    }
    pilot_cells = {
        (item.condition, item.arm)
        for item in requests
        if item.category == "pilot"
    }
    expected_networks = {"op-sepolia", "arbitrum-sepolia", "base-sepolia"}
    expected_cells = {
        (condition, arm)
        for condition in ("HH", "HL", "LH", "LL")
        for arm in ("baseline", "xir")
    }
    if (
        deployment_networks != expected_networks
        or configuration_networks != expected_networks
        or pilot_cells != expected_cells
    ):
        raise CarrierPreflightError("unsigned simulations lack complete fixed-route coverage")
    identifiers = [item.simulation_id for item in requests]
    if len(identifiers) != len(set(identifiers)):
        raise CarrierPreflightError("duplicate simulation ID")
    results: list[SimulationResult] = []
    for request in sorted(requests, key=lambda item: item.simulation_id):
        if request.value_wei < 0 or request.gas_limit <= 0:
            raise CarrierPreflightError("simulation value/gas bounds are invalid")
        if len(request.calldata_sha256) != 64:
            raise CarrierPreflightError("simulation calldata digest is invalid")
        result = provider.simulate(request)
        expected_digest = hashlib.sha256(
            rfc8785.dumps(
                {
                    "simulation_id": request.simulation_id,
                    "success": result.success,
                    "reason_code": result.reason_code,
                }
            )
        ).hexdigest()
        if result.simulation_id != request.simulation_id:
            raise CarrierPreflightError("simulation provider changed simulation ID")
        if result.raw_sha256 != expected_digest:
            raise CarrierPreflightError("simulation raw digest mismatch")
        if not result.success:
            raise CarrierPreflightError(
                f"unsigned simulation failed: {request.simulation_id}"
            )
        results.append(result)
    return tuple(results)


def build_unsigned_call_simulations(
    templates: tuple[UnsignedCallTemplate, ...],
) -> tuple[UnsignedSimulationRequest, ...]:
    """Materialize complete, digest-bound call inputs without invoking a signer."""

    requests = tuple(
        UnsignedSimulationRequest(
            simulation_id=item.simulation_id,
            category=item.category,
            network_id=item.network_id,
            condition=item.condition,
            arm=item.arm,
            destination=item.destination,
            value_wei=item.value_wei,
            calldata_sha256=hashlib.sha256(item.calldata).hexdigest(),
            gas_limit=item.gas_limit,
            sender=item.sender,
            calldata_hex="0x" + item.calldata.hex(),
        )
        for item in templates
    )
    deployment_networks = {
        item.network_id for item in requests if item.category == "deployment"
    }
    configuration_networks = {
        item.network_id for item in requests if item.category == "configuration"
    }
    pilot_cells = {
        (item.condition, item.arm)
        for item in requests
        if item.category == "pilot"
    }
    expected_networks = {"op-sepolia", "arbitrum-sepolia", "base-sepolia"}
    expected_cells = {
        (condition, arm)
        for condition in ("HH", "HL", "LH", "LL")
        for arm in ("baseline", "xir")
    }
    if (
        deployment_networks != expected_networks
        or configuration_networks != expected_networks
        or pilot_cells != expected_cells
    ):
        raise CarrierPreflightError("unsigned call templates lack complete fixed-route coverage")
    if len({item.simulation_id for item in requests}) != len(requests):
        raise CarrierPreflightError("duplicate simulation ID")
    for request in requests:
        if request.value_wei < 0 or request.gas_limit <= 0:
            raise CarrierPreflightError("simulation value/gas bounds are invalid")
        if request.category != "deployment" and request.destination is None:
            raise CarrierPreflightError("call simulation destination is unavailable")
    return requests


def freeze_carrier_snapshot(
    suite: CarrierRouteSuite,
    *,
    observed_at: datetime,
    validity_seconds: int,
    store: EvidenceStore | None = None,
) -> tuple[dict[str, Any], str]:
    if validity_seconds <= 0:
        raise CarrierPreflightError("carrier snapshot validity must be positive")
    observed = observed_at.astimezone(UTC)
    valid_until = observed.timestamp() + validity_seconds
    document: dict[str, Any] = {
        "schema_version": "xir-lab-carrier-snapshot-v1",
        "observed_at": observed.isoformat(),
        "valid_until": datetime.fromtimestamp(valid_until, tz=UTC).isoformat(),
        "outcome": suite.outcome,
        "allow_partial_conditions": suite.allow_partial_conditions,
        "routes": [
            {
                "route_id": item.route_id,
                "protocol": item.protocol,
                "local_network": item.local_network,
                "remote_network": item.remote_network,
                "endpoint_address": item.endpoint_address,
                "remote_selector": item.remote_selector,
                "peer_address": item.peer_address,
                "runtime_code_sha256": item.runtime_code_sha256,
                "security_config_sha256": item.security_config_sha256,
                "quote_wei": item.quote_wei,
                "status": item.status,
                "reason_codes": list(item.reason_codes),
            }
            for item in suite.observations
        ],
        "effects": suite.effects,
    }
    raw = rfc8785.dumps(document)
    digest = hashlib.sha256(raw).hexdigest()
    if store is not None:
        stored = store.put_raw(
            raw,
            media_type="application/json",
            metadata={"kind": "carrier-snapshot", "public_facts_only": True},
        )
        if stored != digest:
            raise CarrierPreflightError("carrier snapshot digest changed during storage")
    return document, digest


def carrier_snapshot_digest(suite: CarrierRouteSuite, *, observed_at: datetime) -> str:
    return freeze_carrier_snapshot(
        suite,
        observed_at=observed_at,
        validity_seconds=1,
    )[1]


def freeze_simulation_snapshot(
    results: tuple[SimulationResult, ...],
    *,
    observed_at: datetime,
    validity_seconds: int,
    store: EvidenceStore | None = None,
) -> tuple[dict[str, Any], str]:
    if not results or validity_seconds <= 0:
        raise CarrierPreflightError("simulation snapshot inputs are invalid")
    if len({item.simulation_id for item in results}) != len(results):
        raise CarrierPreflightError("simulation snapshot contains duplicate IDs")
    observed = observed_at.astimezone(UTC)
    document: dict[str, Any] = {
        "schema_version": "xir-lab-simulation-snapshot-v1",
        "observed_at": observed.isoformat(),
        "valid_until": datetime.fromtimestamp(
            observed.timestamp() + validity_seconds,
            tz=UTC,
        ).isoformat(),
        "outcome": "pass" if all(item.success for item in results) else "blocked",
        "simulations": [
            {
                "simulation_id": item.simulation_id,
                "success": item.success,
                "raw_sha256": item.raw_sha256,
                "reason_code": item.reason_code,
            }
            for item in sorted(results, key=lambda item: item.simulation_id)
        ],
        "effects": {
            "signing_operations": 0,
            "deployments": 0,
            "configurations": 0,
            "broadcasts": 0,
        },
    }
    raw = rfc8785.dumps(document)
    digest = hashlib.sha256(raw).hexdigest()
    if store is not None:
        stored = store.put_raw(
            raw,
            media_type="application/json",
            metadata={"kind": "unsigned-simulation-snapshot", "public_facts_only": True},
        )
        if stored != digest:
            raise CarrierPreflightError("simulation snapshot digest changed during storage")
    return document, digest
