from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rfc8785

from xir_lab.evidence.store import EvidenceStore
from xir_lab.preflight.carriers import (
    CarrierPreflightError,
    HyperlaneState,
    LayerZeroState,
    RegistryCandidate,
    SimulationResult,
    UnsignedCallTemplate,
    UnsignedSimulationRequest,
    build_unsigned_call_simulations,
    collect_carrier_routes,
    freeze_carrier_snapshot,
    freeze_simulation_snapshot,
    registry_candidate_digest,
    validate_registry_candidates,
    validate_unsigned_simulations,
)

DIGEST = "11" * 32


def _candidates() -> tuple[RegistryCandidate, ...]:
    return tuple(
        RegistryCandidate(
            protocol=protocol,  # type: ignore[arg-type]
            local_network=local,
            remote_network=remote,
            endpoint_address=f"0x{index + 1:040x}",
            remote_selector=index + 100,
            peer_address=f"0x{index + 10:040x}",
            local_adapter_address=f"0x{index + 20:040x}",
            source_url=(
                "https://github.com/hyperlane-xyz/hyperlane-registry"
                if protocol == "hyperlane"
                else "https://docs.layerzero.network/v2/deployments"
            ),
            source_sha256=DIGEST,
        )
        for index, (local, remote, protocol) in enumerate(
            (
                ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
                ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
                ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
                ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
            )
        )
    )


class FixtureCarrier:
    def __init__(self) -> None:
        self.unsupported_eid = False
        self.empty_dvns = False
        self.peer_mismatch = False
        self.quote = 100
        self.unavailable_protocol: str | None = None

    def hyperlane_state(self, candidate: RegistryCandidate) -> HyperlaneState:
        if self.unavailable_protocol == "hyperlane":
            raise ConnectionError("fixture")
        return HyperlaneState(
            runtime_code_sha256="21" * 32,
            local_domain=1,
            ism_address="0x" + "21" * 20,
            hook_address="0x" + "22" * 20,
            payment_required_wei=90,
            enrolled_remote_peer=(
                "0x" + "ff" * 20 if self.peer_mismatch else candidate.peer_address
            ),
            security_config_sha256="22" * 32,
            quoted_payment_wei=self.quote,
        )

    def layerzero_state(self, candidate: RegistryCandidate) -> LayerZeroState:
        if self.unavailable_protocol == "layerzero-v2":
            raise ConnectionError("fixture")
        return LayerZeroState(
            runtime_code_sha256="31" * 32,
            local_eid=1,
            supported_remote_eid=not self.unsupported_eid,
            send_library="0x" + "31" * 20,
            receive_library="0x" + "32" * 20,
            dvns=() if self.empty_dvns else ("0x" + "33" * 20,),
            executor="0x" + "34" * 20,
            enforced_options_sha256="32" * 32,
            configured_peer=(
                "0x" + "ff" * 20 if self.peer_mismatch else candidate.peer_address
            ),
            security_config_sha256="33" * 32,
            quoted_payment_wei=self.quote,
        )


def _maximums(candidates: tuple[RegistryCandidate, ...]) -> dict[str, int]:
    return {
        f"{item.protocol}:{item.local_network}:{item.remote_network}": 120
        for item in candidates
    }


def test_official_candidates_are_discovery_only_and_all_routes_are_recollected() -> None:
    candidates = _candidates()
    provider = FixtureCarrier()
    suite = collect_carrier_routes(
        candidates=candidates,
        providers={"hyperlane": provider, "layerzero-v2": provider},
        maximum_quote_wei=_maximums(candidates),
        allow_partial_conditions=False,
    )
    assert suite.outcome == "pass"
    assert len(suite.observations) == 4
    assert set(suite.effects.values()) == {0}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("unsupported_eid", "layerzero_remote_eid_unsupported"),
        ("empty_dvns", "layerzero_dead_dvn_path"),
        ("peer", "peer_mismatch"),
        ("quote", "carrier_quote_out_of_bounds"),
        ("unavailable", "carrier_state_unavailable"),
    ),
)
def test_dead_security_peer_quote_and_unavailable_route_block_whole_pilot(
    mutation: str,
    reason: str,
) -> None:
    candidates = _candidates()
    provider = FixtureCarrier()
    if mutation == "unsupported_eid":
        provider.unsupported_eid = True
    elif mutation == "empty_dvns":
        provider.empty_dvns = True
    elif mutation == "peer":
        provider.peer_mismatch = True
    elif mutation == "quote":
        provider.quote = 121
    else:
        provider.unavailable_protocol = "hyperlane"
    suite = collect_carrier_routes(
        candidates=candidates,
        providers={"hyperlane": provider, "layerzero-v2": provider},
        maximum_quote_wei=_maximums(candidates),
        allow_partial_conditions=False,
    )
    assert suite.outcome == "blocked"
    assert any(
        any(reason in item_reason for item_reason in item.reason_codes)
        for item in suite.observations
    )
    assert not suite.allow_partial_conditions


def test_changed_or_unofficial_registry_candidate_is_never_authority() -> None:
    candidates = list(_candidates())
    candidates[0] = replace(candidates[0], source_url="https://example.test/registry")
    with pytest.raises(CarrierPreflightError, match="official"):
        validate_registry_candidates(tuple(candidates))

    original = _candidates()
    frozen = registry_candidate_digest(original)
    changed = list(original)
    changed[0] = replace(changed[0], endpoint_address="0x" + "fe" * 20)
    provider = FixtureCarrier()
    with pytest.raises(CarrierPreflightError, match="changed"):
        collect_carrier_routes(
            candidates=tuple(changed),
            providers={"hyperlane": provider, "layerzero-v2": provider},
            maximum_quote_wei=_maximums(tuple(changed)),
            allow_partial_conditions=False,
            expected_candidate_sha256=frozen,
        )


def test_frozen_endpoint_runtime_mismatch_blocks_route() -> None:
    candidates = list(_candidates())
    candidates[0] = replace(
        candidates[0],
        expected_endpoint_runtime_sha256="ff" * 32,
    )
    provider = FixtureCarrier()
    suite = collect_carrier_routes(
        candidates=tuple(candidates),
        providers={"hyperlane": provider, "layerzero-v2": provider},
        maximum_quote_wei=_maximums(tuple(candidates)),
        allow_partial_conditions=False,
    )
    assert suite.outcome == "blocked"
    assert any(
        "carrier_runtime_code_mismatch" in item.reason_codes
        for item in suite.observations
    )


def _simulations() -> tuple[UnsignedSimulationRequest, ...]:
    requests: list[UnsignedSimulationRequest] = []
    for category in ("deployment", "configuration"):
        requests.extend(
            UnsignedSimulationRequest(
                simulation_id=f"{category}-{network}",
                category=category,  # type: ignore[arg-type]
                network_id=network,
                condition=None,
                arm=None,
                destination=None if category == "deployment" else "0x" + "11" * 20,
                value_wei=0,
                calldata_sha256=DIGEST,
                gas_limit=100_000,
            )
            for network in ("op-sepolia", "arbitrum-sepolia", "base-sepolia")
        )
    requests.extend(
        UnsignedSimulationRequest(
            simulation_id=f"pilot-{condition}-{arm}",
            category="pilot",
            network_id="op-sepolia",
            condition=condition,
            arm=arm,
            destination="0x" + "11" * 20,
            value_wei=1,
            calldata_sha256=DIGEST,
            gas_limit=200_000,
        )
        for condition in ("HH", "HL", "LH", "LL")
        for arm in ("baseline", "xir")
    )
    return tuple(requests)


class FixtureSimulation:
    def __init__(self, failed: str | None = None) -> None:
        self.failed = failed

    def simulate(self, request: UnsignedSimulationRequest) -> SimulationResult:
        success = request.simulation_id != self.failed
        reason = "simulation_pass" if success else "simulation_revert"
        raw = hashlib.sha256(
            rfc8785.dumps(
                {
                    "simulation_id": request.simulation_id,
                    "success": success,
                    "reason_code": reason,
                }
            )
        ).hexdigest()
        return SimulationResult(request.simulation_id, success, raw, reason)


def test_unsigned_simulations_cover_deploy_configure_and_all_eight_pilot_cells() -> None:
    results = validate_unsigned_simulations(
        requests=_simulations(),
        provider=FixtureSimulation(),
    )
    assert len(results) == 14


def test_unsigned_call_builder_binds_real_calldata_and_complete_coverage() -> None:
    templates: list[UnsignedCallTemplate] = []
    for category in ("deployment", "configuration"):
        for network in ("op-sepolia", "arbitrum-sepolia", "base-sepolia"):
            templates.append(
                UnsignedCallTemplate(
                    simulation_id=f"{category}-{network}",
                    category=category,  # type: ignore[arg-type]
                    network_id=network,
                    condition=None,
                    arm=None,
                    destination=(
                        None if category == "deployment" else "0x" + "11" * 20
                    ),
                    sender="0x" + "22" * 20,
                    value_wei=0,
                    calldata=f"{category}-{network}".encode(),
                    gas_limit=100_000,
                )
            )
    for condition in ("HH", "HL", "LH", "LL"):
        for arm in ("baseline", "xir"):
            templates.append(
                UnsignedCallTemplate(
                    simulation_id=f"pilot-{condition}-{arm}",
                    category="pilot",
                    network_id="op-sepolia",
                    condition=condition,
                    arm=arm,
                    destination="0x" + "11" * 20,
                    sender="0x" + "22" * 20,
                    value_wei=1,
                    calldata=f"{condition}-{arm}".encode(),
                    gas_limit=200_000,
                )
            )
    requests = build_unsigned_call_simulations(tuple(templates))
    assert len(requests) == 14
    assert all(
        request.calldata_hex is not None
        and hashlib.sha256(bytes.fromhex(request.calldata_hex[2:])).hexdigest()
        == request.calldata_sha256
        for request in requests
    )


def test_missing_or_failed_simulation_blocks() -> None:
    with pytest.raises(CarrierPreflightError, match="coverage"):
        validate_unsigned_simulations(
            requests=_simulations()[:-1],
            provider=FixtureSimulation(),
        )
    with pytest.raises(CarrierPreflightError, match="failed"):
        validate_unsigned_simulations(
            requests=_simulations(),
            provider=FixtureSimulation("pilot-HH-baseline"),
        )


def test_carrier_snapshot_has_a_validity_window_and_content_address(
    tmp_path: Path,
) -> None:
    candidates = _candidates()
    provider = FixtureCarrier()
    suite = collect_carrier_routes(
        candidates=candidates,
        providers={"hyperlane": provider, "layerzero-v2": provider},
        maximum_quote_wei=_maximums(candidates),
        allow_partial_conditions=False,
    )
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    document, digest = freeze_carrier_snapshot(
        suite,
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
        validity_seconds=60,
        store=store,
    )
    assert document["valid_until"] == "2026-07-28T00:01:00+00:00"
    assert store.read_raw(digest) == rfc8785.dumps(document)


def test_simulation_snapshot_has_validity_window_and_content_address(
    tmp_path: Path,
) -> None:
    results = validate_unsigned_simulations(
        requests=_simulations(),
        provider=FixtureSimulation(),
    )
    store = EvidenceStore(tmp_path / "evidence.sqlite", tmp_path / "raw")
    store.initialize()
    document, digest = freeze_simulation_snapshot(
        results,
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
        validity_seconds=60,
        store=store,
    )
    assert document["outcome"] == "pass"
    assert document["valid_until"] == "2026-07-28T00:01:00+00:00"
    assert store.read_raw(digest) == rfc8785.dumps(document)
