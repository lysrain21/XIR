"""Exact-byte provenance validation for files extracted from the paper workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema

PROVENANCE_SCHEMA_VERSION = "xir-lab-provenance-manifest-v1"


class ProvenanceError(ValueError):
    """Raised when source provenance is incomplete or fails exact-byte validation."""


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of the exact file bytes."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except OSError as exc:
        raise ProvenanceError(f"cannot read JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProvenanceError(f"invalid JSON file: {path}") from exc


def _safe_relative_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ProvenanceError(f"{field} must be a non-empty relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise ProvenanceError(f"{field} must not be absolute or escape its root: {value}")
    return Path(*pure.parts)


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProvenanceError(f"{label} must be an object")
    return value


def validate_manifest(
    manifest_path: Path,
    *,
    schema_path: Path,
    source_root: Path,
    destination_root: Path,
) -> dict[str, Any]:
    """Validate schema, exact digests, safe paths, and modification declarations."""

    manifest = _load_json(manifest_path)
    schema = _load_json(schema_path)
    try:
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(manifest)
    except jsonschema.ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path)
        raise ProvenanceError(f"manifest schema violation at {location or '<root>'}: {exc.message}") from exc

    document = _require_mapping(manifest, "manifest")
    if document.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ProvenanceError("unsupported provenance schema version")

    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise ProvenanceError("entries must be an array")

    seen_destinations: set[str] = set()
    checked_entries: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(raw_entries):
        entry = _require_mapping(raw_entry, f"entries[{index}]")
        destination_relative = _safe_relative_path(
            entry.get("destination_path"),
            f"entries[{index}].destination_path",
        )
        source_relative = _safe_relative_path(
            entry.get("source_path"),
            f"entries[{index}].source_path",
        )
        destination_key = destination_relative.as_posix()
        if destination_key in seen_destinations:
            raise ProvenanceError(f"duplicate destination_path: {destination_key}")
        seen_destinations.add(destination_key)

        source = source_root / source_relative
        destination = destination_root / destination_relative
        if not source.is_file():
            raise ProvenanceError(f"source file is missing: {source_relative.as_posix()}")
        if not destination.is_file():
            raise ProvenanceError(f"destination file is missing: {destination_relative.as_posix()}")

        source_digest = sha256_file(source)
        destination_digest = sha256_file(destination)
        if source_digest != entry.get("source_sha256"):
            raise ProvenanceError(f"source digest mismatch: {source_relative.as_posix()}")
        if destination_digest != entry.get("destination_sha256"):
            raise ProvenanceError(f"destination digest mismatch: {destination_relative.as_posix()}")

        extracted_on = entry.get("extracted_on")
        if not isinstance(extracted_on, str):
            raise ProvenanceError(f"entries[{index}].extracted_on must be a date")
        try:
            date.fromisoformat(extracted_on)
        except ValueError as exc:
            raise ProvenanceError(f"entries[{index}].extracted_on is not an ISO date") from exc

        status = entry.get("modification_status")
        modifications = entry.get("modifications")
        if not isinstance(modifications, list):
            raise ProvenanceError(f"entries[{index}].modifications must be an array")
        if status == "unmodified":
            if modifications:
                raise ProvenanceError("unmodified entries must have an empty modifications array")
            if source_digest != destination_digest:
                raise ProvenanceError(f"unmodified destination differs from source: {destination_key}")
        elif status == "modified":
            if not modifications:
                raise ProvenanceError("modified entries must describe at least one modification")
        else:
            raise ProvenanceError(f"unknown modification_status: {status}")

        checked_entries.append(
            {
                "destination_path": destination_key,
                "source_path": source_relative.as_posix(),
                "source_sha256": source_digest,
                "destination_sha256": destination_digest,
                "modification_status": status,
            }
        )

    return {
        "schema_version": "xir-lab-provenance-validation-v1",
        "outcome": "valid",
        "entry_count": len(checked_entries),
        "entries": checked_entries,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate an XIR Lab provenance manifest.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--destination-root", type=Path, required=True)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(argv)
    try:
        result = validate_manifest(
            namespace.manifest,
            schema_path=namespace.schema,
            source_root=namespace.source_root,
            destination_root=namespace.destination_root,
        )
    except ProvenanceError as exc:
        result = {
            "schema_version": "xir-lab-provenance-validation-v1",
            "outcome": "invalid",
            "reason": str(exc),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
