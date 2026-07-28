from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.config.stages import StageTemplateError, load_stage_template_set

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "configs" / "stages" / "v1.json"


def _document() -> dict[str, Any]:
    return json.loads(TEMPLATES.read_text(encoding="utf-8"))


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "stages.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_all_eight_templates_are_fixed_and_multi_label() -> None:
    template_set = load_stage_template_set(TEMPLATES)
    assert len(template_set.templates) == 8
    assert {
        (template.condition, template.arm) for template in template_set.templates
    } == {
        ("HH", "baseline"),
        ("HH", "xir"),
        ("HL", "baseline"),
        ("HL", "xir"),
        ("LH", "baseline"),
        ("LH", "xir"),
        ("LL", "baseline"),
        ("LL", "xir"),
    }
    assert all(
        len(transaction.logical_labels) >= 2
        for template in template_set.templates
        for transaction in template.physical_transaction_templates
    )


def test_xir_labels_share_common_accounting_buckets() -> None:
    template_set = load_stage_template_set(TEMPLATES)
    xir = next(
        template
        for template in template_set.templates
        if template.condition == "HL" and template.arm == "xir"
    )
    intermediate = xir.physical_transaction_templates[1]
    assert intermediate.accounting_bucket == "intermediate"
    assert "xir_intermediate_verification" in intermediate.logical_labels
    assert "carrier_two_forward" in intermediate.logical_labels


def test_rejects_carrier_order_substitution(tmp_path: Path) -> None:
    document = _document()
    document["templates"][2]["carrier_sequence"] = [
        "layerzero-v2",
        "hyperlane",
    ]
    with pytest.raises(StageTemplateError, match="carrier sequence"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_wrong_accounting_bucket(tmp_path: Path) -> None:
    document = _document()
    document["templates"][0]["physical_transaction_templates"][1][
        "accounting_bucket"
    ] = "source"
    with pytest.raises(StageTemplateError, match="fixed buckets"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_xir_work_in_baseline(tmp_path: Path) -> None:
    document = _document()
    labels = document["templates"][0]["physical_transaction_templates"][0][
        "logical_labels"
    ]
    labels.append("xir_record_encode")
    with pytest.raises(StageTemplateError, match="baseline labels"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_missing_xir_verification(tmp_path: Path) -> None:
    document = copy.deepcopy(_document())
    labels = document["templates"][1]["physical_transaction_templates"][2][
        "logical_labels"
    ]
    labels.remove("xir_destination_verification")
    with pytest.raises(StageTemplateError, match="XIR labels"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_route_substitution(tmp_path: Path) -> None:
    document = _document()
    document["templates"][0]["ordered_chain_ids"] = [11155420, 84532, 421614]
    with pytest.raises(StageTemplateError, match="schema validation"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_arm_substitution_that_duplicates_a_cell(tmp_path: Path) -> None:
    document = _document()
    document["templates"][1]["arm"] = "baseline"
    with pytest.raises(StageTemplateError, match="duplicate condition/arm"):
        load_stage_template_set(_write(tmp_path, document))


def test_rejects_ambiguous_stage_or_transaction_count(tmp_path: Path) -> None:
    document = _document()
    document["templates"][0]["physical_transaction_templates"].append(
        copy.deepcopy(
            document["templates"][0]["physical_transaction_templates"][-1]
        )
    )
    with pytest.raises(StageTemplateError, match="schema validation"):
        load_stage_template_set(_write(tmp_path, document))
