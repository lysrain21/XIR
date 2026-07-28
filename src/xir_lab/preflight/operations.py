"""Schema-backed operation-specific preflight expectations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema

OperationScope = Literal["deployment", "configuration", "experiment", "closeout"]

SCHEMA_BY_SCOPE: dict[OperationScope, str] = {
    "deployment": "preflight-deployment-v1.schema.json",
    "configuration": "preflight-configuration-v1.schema.json",
    "experiment": "preflight-experiment-v1.schema.json",
    "closeout": "preflight-closeout-v1.schema.json",
}
FIXED_NETWORKS = frozenset(
    {"op-sepolia", "arbitrum-sepolia", "base-sepolia"}
)
FIXED_EDGES = frozenset(
    {
        ("op-sepolia", "arbitrum-sepolia", "hyperlane"),
        ("op-sepolia", "arbitrum-sepolia", "layerzero-v2"),
        ("arbitrum-sepolia", "base-sepolia", "hyperlane"),
        ("arbitrum-sepolia", "base-sepolia", "layerzero-v2"),
    }
)


class OperationPreflightError(ValueError):
    """Raised when an operation requests state from the wrong lifecycle phase."""


@dataclass(frozen=True)
class OperationPreflight:
    scope: OperationScope
    operation_type: str
    operation_id: str
    approval_id: str
    source_sha256: str
    document: dict[str, Any]


def _schema_path(scope: OperationScope) -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / SCHEMA_BY_SCOPE[scope]


def load_operation_preflight(
    path: Path, *, scope: OperationScope
) -> OperationPreflight:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationPreflightError(f"cannot read operation preflight: {path}") from exc
    if not isinstance(document, dict):
        raise OperationPreflightError("operation preflight root must be an object")
    value = cast(dict[str, Any], document)
    schema = json.loads(_schema_path(scope).read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise OperationPreflightError(
            f"{scope} schema violation at {location}: {first.message}"
        )
    _validate_semantics(value, scope)
    return OperationPreflight(
        scope=scope,
        operation_type=cast(str, value["operation_type"]),
        operation_id=cast(str, value["operation_id"]),
        approval_id=cast(str, value["approval_id"]),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        document=value,
    )


def _validate_semantics(
    document: dict[str, Any], scope: OperationScope
) -> None:
    records_key = "creations" if scope == "deployment" else "contracts"
    records = cast(list[dict[str, Any]], document[records_key])
    id_key = "creation_id" if scope == "deployment" else "contract_id"
    identifiers = [cast(str, item[id_key]) for item in records]
    if len(identifiers) != len(set(identifiers)):
        raise OperationPreflightError(f"duplicate {id_key}")
    networks = {cast(str, item["network_id"]) for item in records}
    if networks != FIXED_NETWORKS:
        raise OperationPreflightError(
            f"{scope} records must cover all three fixed-route networks"
        )
    address_key = "deployer_address" if scope == "deployment" else "address"
    if any(int(cast(str, item[address_key]), 16) == 0 for item in records):
        raise OperationPreflightError(f"{scope} contains a zero address")
    if scope == "deployment":
        for item in records:
            predicted = item["predicted_address"]
            if predicted is None:
                raise OperationPreflightError(
                    "every direct or factory creation must bind a predicted address"
                )
    if scope == "experiment":
        routes = cast(list[dict[str, Any]], document["carrier_routes"])
        route_ids = [cast(str, item["route_id"]) for item in routes]
        if len(route_ids) != len(set(route_ids)):
            raise OperationPreflightError("duplicate route_id")
        edges = {
            (
                cast(str, item["local_network"]),
                cast(str, item["remote_network"]),
                cast(str, item["protocol"]),
            )
            for item in routes
        }
        if edges != FIXED_EDGES:
            raise OperationPreflightError(
                "experiment preflight must cover both carriers on both fixed legs"
            )
