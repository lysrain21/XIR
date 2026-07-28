"""Versioned stage-template loading and fixed-route semantic validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema

Condition = Literal["HH", "HL", "LH", "LL"]
Arm = Literal["baseline", "xir"]
Bucket = Literal["source", "intermediate", "destination"]
Protocol = Literal["hyperlane", "layerzero-v2"]

EXPECTED_PROTOCOLS: dict[Condition, tuple[Protocol, Protocol]] = {
    "HH": ("hyperlane", "hyperlane"),
    "HL": ("hyperlane", "layerzero-v2"),
    "LH": ("layerzero-v2", "hyperlane"),
    "LL": ("layerzero-v2", "layerzero-v2"),
}
EXPECTED_TRANSACTIONS = (
    (0, 11_155_420, "source"),
    (1, 421_614, "intermediate"),
    (2, 84_532, "destination"),
)
COMMON_LABELS = (
    frozenset({"source_application_preparation", "carrier_one_dispatch"}),
    frozenset({"carrier_one_receive", "carrier_two_forward"}),
    frozenset({"carrier_two_receive", "destination_application_effect"}),
)
BASELINE_ONLY_LABELS: tuple[str | None, ...] = (
    None,
    "intermediate_baseline_control",
    None,
)
XIR_ONLY_LABELS = (
    "xir_record_encode",
    "xir_intermediate_verification",
    "xir_destination_verification",
)


class StageTemplateError(ValueError):
    """Raised when a stage template could change the preregistered experiment."""


@dataclass(frozen=True)
class PhysicalTransactionTemplate:
    transaction_template_id: str
    ordinal: int
    chain_id: int
    accounting_bucket: Bucket
    funding_attribution: str
    logical_labels: tuple[str, ...]


@dataclass(frozen=True)
class StageTemplate:
    template_id: str
    template_version: int
    condition: Condition
    arm: Arm
    ordered_chain_ids: tuple[int, ...]
    carrier_sequence: tuple[Protocol, ...]
    physical_transaction_templates: tuple[PhysicalTransactionTemplate, ...]


@dataclass(frozen=True)
class StageTemplateSet:
    template_set_id: str
    templates: tuple[StageTemplate, ...]


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / "stage-template-set-v1.schema.json"


def _schema_validate(document: dict[str, Any]) -> None:
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise StageTemplateError(f"schema validation failed at {location}: {first.message}")


def _semantic_validate(template_set: StageTemplateSet) -> None:
    cells: dict[tuple[Condition, Arm], StageTemplate] = {}
    ids: set[str] = set()
    transaction_ids: set[str] = set()
    for template in template_set.templates:
        cell = (template.condition, template.arm)
        if cell in cells:
            raise StageTemplateError(f"duplicate condition/arm template: {cell}")
        cells[cell] = template
        if template.template_id in ids:
            raise StageTemplateError(f"duplicate template ID: {template.template_id}")
        ids.add(template.template_id)
        if template.carrier_sequence != EXPECTED_PROTOCOLS[template.condition]:
            raise StageTemplateError(
                f"carrier sequence does not match {template.condition}: {template.template_id}"
            )
        observed_shape = tuple(
            (transaction.ordinal, transaction.chain_id, transaction.accounting_bucket)
            for transaction in template.physical_transaction_templates
        )
        if observed_shape != EXPECTED_TRANSACTIONS:
            raise StageTemplateError(
                f"physical transactions do not map once to fixed buckets: {template.template_id}"
            )
        for index, transaction in enumerate(template.physical_transaction_templates):
            if transaction.transaction_template_id in transaction_ids:
                raise StageTemplateError(
                    f"duplicate transaction template ID: {transaction.transaction_template_id}"
                )
            transaction_ids.add(transaction.transaction_template_id)
            labels = frozenset(transaction.logical_labels)
            required = COMMON_LABELS[index]
            if template.arm == "baseline":
                baseline_only = BASELINE_ONLY_LABELS[index]
                expected = required | ({baseline_only} if baseline_only is not None else set())
                if labels != expected:
                    raise StageTemplateError(
                        f"baseline labels are not minimal at ordinal {index}: "
                        f"{template.template_id}"
                    )
            elif labels != required | {XIR_ONLY_LABELS[index]}:
                raise StageTemplateError(
                    f"XIR labels are incomplete at ordinal {index}: {template.template_id}"
                )

    expected_cells = {
        (condition, arm)
        for condition in cast(tuple[Condition, ...], ("HH", "HL", "LH", "LL"))
        for arm in cast(tuple[Arm, ...], ("baseline", "xir"))
    }
    if set(cells) != expected_cells:
        raise StageTemplateError("template set must contain all eight condition/arm cells")


def load_stage_template_set(path: Path) -> StageTemplateSet:
    """Load and semantically pin all eight preregistered route templates."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageTemplateError(f"cannot read stage templates: {path}") from exc
    if not isinstance(document, dict):
        raise StageTemplateError("stage template root must be an object")
    _schema_validate(document)
    templates: list[StageTemplate] = []
    for item in cast(list[dict[str, Any]], document["templates"]):
        transactions = tuple(
            PhysicalTransactionTemplate(
                **{
                    **transaction,
                    "logical_labels": tuple(
                        cast(list[str], transaction["logical_labels"])
                    ),
                }
            )
            for transaction in cast(
                list[dict[str, Any]], item["physical_transaction_templates"]
            )
        )
        templates.append(
            StageTemplate(
                **{
                    **item,
                    "ordered_chain_ids": tuple(
                        cast(list[int], item["ordered_chain_ids"])
                    ),
                    "carrier_sequence": tuple(
                        cast(list[Protocol], item["carrier_sequence"])
                    ),
                    "physical_transaction_templates": transactions,
                }
            )
        )
    result = StageTemplateSet(
        template_set_id=cast(str, document["template_set_id"]),
        templates=tuple(templates),
    )
    _semantic_validate(result)
    return result
