from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "pilot-public-identities-20260728.json"
SCHEMA = ROOT / "schemas" / "lab-public-identities-v1.schema.json"


def test_public_live_identities_are_schema_valid_distinct_and_path_free() -> None:
    document: dict[str, Any] = json.loads(CONFIG.read_text(encoding="utf-8"))
    schema: dict[str, Any] = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)

    signers = document["signers"]
    assert {item["role"] for item in signers} == {
        "deployer",
        "runner",
        "approval-authority",
    }
    evm_addresses = [
        item["public_identity"]
        for item in signers
        if item["kind"] == "external-evm-signer"
    ]
    assert len({address.lower() for address in evm_addresses}) == 2
    assert all("/" not in item["reference"] for item in signers)
    assert document["verification"]["private_material_recorded"] is False
