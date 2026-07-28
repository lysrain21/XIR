"""Local-only publication gates and deterministic package construction."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785


class PublicationError(RuntimeError):
    """Raised when a local release fails hygiene or claim gates."""


@dataclass(frozen=True)
class PackageArtifact:
    name: str
    bytes: int
    sha256: str
    license: str


@dataclass(frozen=True)
class LocalPackageManifest:
    github: PackageArtifact
    research_data: PackageArtifact
    uploaded: bool


_SECRET_PATTERNS = (
    re.compile(rb"private[_ -]?key\s*[:=]\s*[\"']?[0-9a-fA-F]{32,}"),
    re.compile(rb"mnemonic\s*[:=]\s*[\"']?[a-z]+(?:\s+[a-z]+){5,}"),
    re.compile(rb"bearer\s+[A-Za-z0-9._~-]{16,}", re.IGNORECASE),
    re.compile(rb"https?://[^/\s:@]+:[^/\s@]+@"),
)


def validate_claim_template(document: dict[str, Any]) -> None:
    claim_id = document.get("claim_id")
    if not isinstance(claim_id, str) or re.fullmatch(
        r"[A-Z][A-Z0-9]+(?:-[A-Z0-9]+){2,}", claim_id
    ) is None:
        raise PublicationError("claim_id is missing or not structured")
    scope = document.get("scope")
    required_scope = {
        "run_id",
        "profile_id",
        "networks",
        "conditions",
        "eligible_sample_count",
        "finality_policy",
        "observation_window",
    }
    if not isinstance(scope, dict) or not required_scope <= set(scope):
        raise PublicationError("claim scope is incomplete")
    if scope["conditions"] != ["HH", "HL", "LH", "LL"]:
        raise PublicationError("claim conditions changed preregistered scope")
    limitations = document.get("limitations")
    required_limits = {
        "testnet_only",
        "not_production_capacity",
        "no_private_carrier_inference",
        "no_cross_chain_native_fee_total",
    }
    if not isinstance(limitations, list) or not required_limits <= set(limitations):
        raise PublicationError("mandatory structured limitations are missing")
    if document.get("template_id") not in {
        "primary-overhead-v1",
        "scale-pipeline-v1",
        "unavailable-result-v1",
    }:
        raise PublicationError("claim template is not approved")


class LocalPublicationPackager:
    def build(
        self,
        *,
        repository_root: Path,
        github_files: tuple[Path, ...],
        research_data_files: tuple[Path, ...],
        destination: Path,
    ) -> LocalPackageManifest:
        destination.mkdir(parents=True, exist_ok=False)
        github = self._archive(
            repository_root,
            github_files,
            destination / "github-release.tar.gz",
            "MIT-and-CC-BY-4.0",
        )
        data = self._archive(
            repository_root,
            research_data_files,
            destination / "research-data-release.tar.gz",
            "CC-BY-4.0",
        )
        document = {
            "schema_version": "xir-lab-local-publication-packages-v1",
            "uploaded": False,
            "github_release": github.__dict__,
            "research_data_release": {
                **data.__dict__,
                "provider_url": None,
                "doi": None,
                "link_metadata_status": "pending_separate_publication_authorization",
            },
        }
        (destination / "package-manifest.json").write_bytes(
            rfc8785.dumps(document) + b"\n"  # type: ignore[arg-type]
        )
        return LocalPackageManifest(github, data, False)

    def _archive(
        self,
        root: Path,
        files: tuple[Path, ...],
        destination: Path,
        license_name: str,
    ) -> PackageArtifact:
        resolved_root = root.resolve()
        entries: list[tuple[str, bytes]] = []
        for path in sorted(files, key=lambda item: item.as_posix()):
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(resolved_root)
            except ValueError as exc:
                raise PublicationError("package file escapes repository root") from exc
            if (
                "private-spool" in relative.parts
                or "keystore" in relative.parts
                or relative.suffix == ".bin"
            ):
                raise PublicationError("private or reusable signed material in package")
            data = resolved.read_bytes()
            for pattern in _SECRET_PATTERNS:
                if pattern.search(data):
                    raise PublicationError(
                        f"secret-bearing content blocks publication: {relative}"
                    )
            entries.append((relative.as_posix(), data))
        raw = io.BytesIO()
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name, data in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(data))
        encoded = raw.getvalue()
        destination.write_bytes(encoded)
        return PackageArtifact(
            destination.name,
            len(encoded),
            hashlib.sha256(encoded).hexdigest(),
            license_name,
        )
