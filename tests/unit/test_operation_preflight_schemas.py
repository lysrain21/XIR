from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.preflight.operations import (
    OperationPreflightError,
    load_operation_preflight,
)

NETWORKS = ("op-sepolia", "arbitrum-sepolia", "base-sepolia")
DIGEST = "11" * 32
ADMIN = "0x" + "aa" * 20
RUNNER = "0x" + "bb" * 20


def _common(schema: str, operation: str) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "operation_type": operation,
        "operation_id": f"{operation}-fixture",
        "approval_id": "approval-fixture",
        "network_identity_sha256": DIGEST,
    }


def _deployment() -> dict[str, Any]:
    document = _common("xir-lab-preflight-deployment-v1", "deployment")
    document["creations"] = [
        {
            "creation_id": f"create-{network}",
            "network_id": network,
            "creation_bytecode_sha256": "22" * 32,
            "constructor_args_sha256": "33" * 32,
            "deployer_address": ADMIN,
            "deployer_nonce": index,
            "factory_address": None,
            "predicted_address": None,
        }
        for index, network in enumerate(NETWORKS)
    ]
    return document


def _configuration() -> dict[str, Any]:
    document = _common(
        "xir-lab-preflight-configuration-v1",
        "configuration",
    )
    document["contracts"] = [
        {
            "contract_id": f"gateway-{network}",
            "network_id": network,
            "address": f"0x{index + 1:040x}",
            "runtime_code_sha256": "22" * 32,
            "administrator": ADMIN,
            "expected_current_state_sha256": "33" * 32,
            "authorized_transition_sha256": "44" * 32,
        }
        for index, network in enumerate(NETWORKS)
    ]
    return document


def _experiment() -> dict[str, Any]:
    document = _common("xir-lab-preflight-experiment-v1", "primary")
    document["deployment_sha256"] = "22" * 32
    document["profile_sha256"] = "33" * 32
    document["contracts"] = [
        {
            "contract_id": f"gateway-{network}",
            "network_id": network,
            "address": f"0x{index + 1:040x}",
            "runtime_code_sha256": "44" * 32,
            "administrator": ADMIN,
            "active_runner": RUNNER,
            "outbound_paused": False,
            "route_profile_state_sha256": "55" * 32,
        }
        for index, network in enumerate(NETWORKS)
    ]
    document["carrier_routes"] = [
        {
            "route_id": f"{protocol}-{local}-{remote}",
            "protocol": protocol,
            "local_network": local,
            "remote_network": remote,
            "endpoint_address": f"0x{index + 10:040x}",
            "peer_address": f"0x{index + 20:040x}",
            "remote_selector": index + 1,
            "security_config_sha256": "66" * 32,
        }
        for index, (local, remote, protocol) in enumerate(
            (
                ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
                ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
                ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
                ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
            )
        )
    ]
    return document


def _closeout() -> dict[str, Any]:
    document = _common("xir-lab-preflight-closeout-v1", "closeout")
    document["contracts"] = [
        {
            "contract_id": f"gateway-{network}",
            "network_id": network,
            "address": f"0x{index + 1:040x}",
            "runtime_code_sha256": "22" * 32,
            "administrator": ADMIN,
            "expected_current_state_sha256": "33" * 32,
            "authorized_action": "pause",
        }
        for index, network in enumerate(NETWORKS)
    ]
    return document


def _write(tmp_path: Path, name: str, document: dict[str, Any]) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_each_lifecycle_phase_has_a_distinct_valid_schema(tmp_path: Path) -> None:
    cases = (
        ("deployment", _deployment()),
        ("configuration", _configuration()),
        ("experiment", _experiment()),
        ("closeout", _closeout()),
    )
    for scope, document in cases:
        loaded = load_operation_preflight(
            _write(tmp_path, scope, document),
            scope=scope,  # type: ignore[arg-type]
        )
        assert loaded.scope == scope
        assert len(loaded.source_sha256) == 64


def test_first_deployment_needs_creation_inputs_not_future_runtime(
    tmp_path: Path,
) -> None:
    document = _deployment()
    assert load_operation_preflight(
        _write(tmp_path, "deployment", document),
        scope="deployment",
    )
    changed = copy.deepcopy(document)
    changed["creations"][0]["runtime_code_sha256"] = "99" * 32
    with pytest.raises(OperationPreflightError, match="schema violation"):
        load_operation_preflight(
            _write(tmp_path, "deployment-runtime", changed),
            scope="deployment",
        )


def test_configuration_and_experiment_require_existing_runtime_state(
    tmp_path: Path,
) -> None:
    configuration = _configuration()
    del configuration["contracts"][0]["runtime_code_sha256"]
    with pytest.raises(OperationPreflightError, match="runtime_code_sha256"):
        load_operation_preflight(
            _write(tmp_path, "configuration", configuration),
            scope="configuration",
        )

    experiment = _experiment()
    del experiment["contracts"][0]["active_runner"]
    with pytest.raises(OperationPreflightError, match="active_runner"):
        load_operation_preflight(
            _write(tmp_path, "experiment", experiment),
            scope="experiment",
        )


def test_closeout_checks_current_admin_state_not_creation_inputs(
    tmp_path: Path,
) -> None:
    document = _closeout()
    document["contracts"][0]["creation_bytecode_sha256"] = "99" * 32
    with pytest.raises(OperationPreflightError, match="schema violation"):
        load_operation_preflight(
            _write(tmp_path, "closeout", document),
            scope="closeout",
        )


def test_operation_schema_cannot_authorize_another_lifecycle_phase(
    tmp_path: Path,
) -> None:
    with pytest.raises(OperationPreflightError, match="configuration schema"):
        load_operation_preflight(
            _write(tmp_path, "wrong-scope", _deployment()),
            scope="configuration",
        )


def test_fixed_route_coverage_and_deterministic_factory_fields_are_semantic(
    tmp_path: Path,
) -> None:
    deployment = _deployment()
    deployment["creations"][0]["factory_address"] = ADMIN
    with pytest.raises(OperationPreflightError, match="appear together"):
        load_operation_preflight(
            _write(tmp_path, "factory", deployment),
            scope="deployment",
        )

    experiment = _experiment()
    experiment["carrier_routes"][3] = copy.deepcopy(
        experiment["carrier_routes"][2]
    )
    experiment["carrier_routes"][3]["route_id"] = "duplicate-edge"
    with pytest.raises(OperationPreflightError, match="both carriers"):
        load_operation_preflight(
            _write(tmp_path, "route", experiment),
            scope="experiment",
        )
