from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from xir_lab.provenance import ProvenanceError, validate_manifest

SCHEMA = Path(__file__).resolve().parents[2] / "schemas/provenance-manifest-v1.schema.json"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _manifest(source: bytes, destination: bytes, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "destination_path": "contracts/src/XIRTypes.sol",
        "destination_sha256": _sha256(destination),
        "source_path": "experiments/contracts/evm/src/XIRTypes.sol",
        "source_sha256": _sha256(source),
        "source_revision_unavailable_reason": "paper workspace is not a Git checkout",
        "license": "MIT",
        "extracted_on": "2026-07-25",
        "modification_status": "unmodified",
        "modifications": [],
    }
    entry.update(overrides)
    return {
        "schema_version": "xir-lab-provenance-manifest-v1",
        "source_workspace": {"name": "fixture"},
        "entries": [entry],
    }


def _write_fixture(
    tmp_path: Path,
    manifest: dict[str, Any],
    *,
    source: bytes,
    destination: bytes,
) -> tuple[Path, Path, Path]:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    source_path = source_root / "experiments/contracts/evm/src/XIRTypes.sol"
    destination_path = destination_root / "contracts/src/XIRTypes.sol"
    source_path.parent.mkdir(parents=True)
    destination_path.parent.mkdir(parents=True)
    source_path.write_bytes(source)
    destination_path.write_bytes(destination)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path, source_root, destination_root


def _validate(
    manifest_path: Path,
    source_root: Path,
    destination_root: Path,
) -> dict[str, Any]:
    return validate_manifest(
        manifest_path,
        schema_path=SCHEMA,
        source_root=source_root,
        destination_root=destination_root,
    )


def test_unmodified_exact_copy_is_valid(tmp_path: Path) -> None:
    content = b"// SPDX-License-Identifier: MIT\n"
    manifest = _manifest(content, content)
    manifest_path, source_root, destination_root = _write_fixture(
        tmp_path,
        manifest,
        source=content,
        destination=content,
    )

    result = _validate(manifest_path, source_root, destination_root)
    assert result["outcome"] == "valid"
    assert result["entry_count"] == 1


def test_source_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    content = b"source"
    manifest = _manifest(content, content, source_sha256="0" * 64)
    manifest_path, source_root, destination_root = _write_fixture(
        tmp_path,
        manifest,
        source=content,
        destination=content,
    )

    with pytest.raises(ProvenanceError, match="source digest mismatch"):
        _validate(manifest_path, source_root, destination_root)


def test_revision_or_unavailable_reason_is_required(tmp_path: Path) -> None:
    content = b"source"
    manifest = _manifest(content, content)
    del manifest["entries"][0]["source_revision_unavailable_reason"]
    manifest_path, source_root, destination_root = _write_fixture(
        tmp_path,
        manifest,
        source=content,
        destination=content,
    )

    with pytest.raises(ProvenanceError, match="manifest schema violation"):
        _validate(manifest_path, source_root, destination_root)


def test_modified_copy_requires_a_description(tmp_path: Path) -> None:
    source = b"source"
    destination = b"modified"
    manifest = _manifest(
        source,
        destination,
        modification_status="modified",
        modifications=[],
    )
    manifest_path, source_root, destination_root = _write_fixture(
        tmp_path,
        manifest,
        source=source,
        destination=destination,
    )

    with pytest.raises(ProvenanceError, match="must describe at least one modification"):
        _validate(manifest_path, source_root, destination_root)


def test_paths_cannot_escape_their_roots(tmp_path: Path) -> None:
    content = b"source"
    manifest = _manifest(content, content, source_path="../secret")
    manifest_path, source_root, destination_root = _write_fixture(
        tmp_path,
        manifest,
        source=content,
        destination=content,
    )

    with pytest.raises(ProvenanceError, match="must not be absolute or escape"):
        _validate(manifest_path, source_root, destination_root)
