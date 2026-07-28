from __future__ import annotations

import json
from pathlib import Path

import pytest

from xir_lab.publication import (
    LocalPublicationPackager,
    PublicationError,
    validate_claim_template,
)


def _claim() -> dict[str, object]:
    return {
        "claim_id": "XIR-PRIMARY-001",
        "template_id": "primary-overhead-v1",
        "scope": {
            "run_id": "run-1",
            "profile_id": "primary-v1",
            "networks": ["op-sepolia", "arbitrum-sepolia", "base-sepolia"],
            "conditions": ["HH", "HL", "LH", "LL"],
            "eligible_sample_count": 0,
            "finality_policy": "l2-finalized",
            "observation_window": "fixture",
        },
        "limitations": [
            "testnet_only",
            "not_production_capacity",
            "no_private_carrier_inference",
            "no_cross_chain_native_fee_total",
        ],
    }


def test_structured_claim_gate_checks_scope_template_and_limitations() -> None:
    validate_claim_template(_claim())
    missing = _claim()
    missing["limitations"] = ["testnet_only"]
    with pytest.raises(PublicationError, match="limitations"):
        validate_claim_template(missing)
    changed = _claim()
    changed["template_id"] = "free-form"
    with pytest.raises(PublicationError, match="approved"):
        validate_claim_template(changed)


def test_local_packages_are_deterministic_licensed_and_never_uploaded(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("sanitized source")
    (root / "data.json").write_text(json.dumps({"synthetic": True}))
    packager = LocalPublicationPackager()
    first = packager.build(
        repository_root=root,
        github_files=(root / "README.md",),
        research_data_files=(root / "data.json",),
        destination=tmp_path / "first",
    )
    second = packager.build(
        repository_root=root,
        github_files=(root / "README.md",),
        research_data_files=(root / "data.json",),
        destination=tmp_path / "second",
    )
    assert first == second
    assert first.uploaded is False
    manifest = json.loads(
        (tmp_path / "first" / "package-manifest.json").read_text()
    )
    assert manifest["uploaded"] is False
    assert manifest["research_data_release"]["doi"] is None
    assert manifest["github_release"]["bytes"] > 0


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        ("private-spool/signed.bin", b"signed bytes"),
        ("results/request.log", b'private_key="11' + b"11" * 31 + b'"'),
        ("results/rpc.log", b"https://user:password@example.invalid"),
    ],
)
def test_secret_spool_and_authenticated_endpoint_block_packaging(
    tmp_path: Path,
    relative: str,
    content: bytes,
) -> None:
    root = tmp_path / "repo"
    path = root / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    with pytest.raises(PublicationError, match="private|secret"):
        LocalPublicationPackager().build(
            repository_root=root,
            github_files=(path,),
            research_data_files=(),
            destination=tmp_path / "blocked",
        )
