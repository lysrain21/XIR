"""Exact, secret-free, atomic synchronization of multihop publication files."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import cast

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_freeze_v2 import secret_scan
from xir_lab.native.gateway_deployment import compare_gateway_publications
from xir_lab.native.multihop_figures import verify_figure8_comparison
from xir_lab.native.multihop_publication import (
    verify_multihop_handoff,
    verify_prior_phase_handoffs,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _secret_scan_inventory(runtime_root: Path, relative_files: list[str]) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="xir-multihop-public-scan-") as temporary:
        root = Path(temporary)
        for relative in relative_files:
            source = runtime_root / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return secret_scan(root)


def _verify_phase_tree(runtime_root: Path, phase: str) -> dict[str, object]:
    root = runtime_root / "runs" / phase
    return verify_multihop_handoff(
        frozen_source_root=root / "frozen-source",
        source_publication=root / "source-publication",
        rebuild_a=root / "rebuild-a",
        rebuild_b=root / "rebuild-b",
        comparison_path=root / "rebuild-comparison.json",
        review_closure_path=root / "frozen-source/review-closure.json",
        handoff_path=root / "final-handoff.json",
    )


def _verify_nested_phase_chain(
    runtime_root: Path, phase_handoffs: dict[str, dict[str, object]]
) -> dict[str, dict[str, str]]:
    """Recompute smoke -> publication-smoke -> scale predecessor bindings."""

    smoke_path = runtime_root / "runs/smoke/final-handoff.json"
    publication_smoke_path = runtime_root / "runs/publication_smoke/final-handoff.json"
    smoke_prior = verify_prior_phase_handoffs(
        phase="smoke", smoke_handoff_path=None, publication_smoke_handoff_path=None
    )
    publication_smoke_prior = verify_prior_phase_handoffs(
        phase="publication_smoke",
        smoke_handoff_path=smoke_path,
        publication_smoke_handoff_path=None,
    )
    scale_prior = verify_prior_phase_handoffs(
        phase="scale",
        smoke_handoff_path=smoke_path,
        publication_smoke_handoff_path=publication_smoke_path,
    )
    expected = {
        "smoke": smoke_prior,
        "publication_smoke": publication_smoke_prior,
        "scale": scale_prior,
    }
    for phase, prior in expected.items():
        if phase_handoffs[phase].get("prior_phase_handoffs") != prior:
            raise LocalTopologyError(f"{phase} nested predecessor chain is invalid")
    return scale_prior


def _verify_visual_approval(runtime_root: Path, approval_path: Path) -> dict[str, object]:
    approval_value = json.loads(approval_path.read_text(encoding="utf-8"))
    if not isinstance(approval_value, dict):
        raise LocalTopologyError("Figure 8 human visual approval must be an object")
    approval = cast(dict[str, object], approval_value)
    approved_utc_ns = approval.get("approved_utc_ns")
    if (
        approval.get("schema_version")
        != "xir-lab-native-multihop-figure8-visual-approval-v1"
        or approval.get("approved") is not True
        or not str(approval.get("reviewer", "")).strip()
        or not isinstance(approved_utc_ns, int)
        or approved_utc_ns <= 0
    ):
        raise LocalTopologyError("Figure 8 human visual approval is absent or invalid")
    figure_a = runtime_root / "figure-a"
    figure_b = runtime_root / "figure-b"
    comparison = runtime_root / "figure-comparison.json"
    verify_figure8_comparison(
        first=figure_a, second=figure_b, comparison_path=comparison
    )
    expected = {
        "figure_a_manifest_sha256": _sha(figure_a / "manifest.json"),
        "figure_b_manifest_sha256": _sha(figure_b / "manifest.json"),
        "comparison_sha256": _sha(comparison),
    }
    if any(approval.get(key) != value for key, value in expected.items()):
        raise LocalTopologyError("Figure 8 visual approval binding differs from real outputs")
    return approval


def _verify_gateway_and_figure_inputs(runtime_root: Path) -> None:
    """Replay Gateway semantics and bind both Figure trees to current inputs."""

    with tempfile.TemporaryDirectory(prefix="xir-gateway-comparison-reverify-") as temp:
        gateway_comparison = Path(temp) / "comparison.json"
        compare_gateway_publications(
            publication_a=runtime_root / "gateway-a",
            publication_b=runtime_root / "gateway-b",
            output_path=gateway_comparison,
        )
        if gateway_comparison.read_bytes() != (
            runtime_root / "gateway-comparison.json"
        ).read_bytes():
            raise LocalTopologyError("Gateway comparison differs from semantic replay")
    expected = {
        "analysis_sha256": _sha(
            runtime_root / "runs/scale/source-publication/analysis.json"
        ),
        "gateway_sha256": _sha(runtime_root / "gateway-a/analysis.json"),
        "multihop_rebuild_comparison_sha256": _sha(
            runtime_root / "runs/scale/rebuild-comparison.json"
        ),
        "gateway_rebuild_comparison_sha256": _sha(
            runtime_root / "gateway-comparison.json"
        ),
    }
    for name in ("figure-a", "figure-b"):
        manifest = json.loads(
            (runtime_root / name / "manifest.json").read_text(encoding="utf-8")
        )
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise LocalTopologyError(f"{name} is not bound to current Gateway inputs")


def build_publication_handoff(
    *, runtime_root: Path, relative_files: list[str], approval_path: Path, output_path: Path
) -> dict[str, object]:
    """Bind the exact public inventory to the human-inspected Figure 8 output."""

    if output_path.exists() or not relative_files or relative_files != sorted(set(relative_files)):
        raise LocalTopologyError("final publication handoff output/inventory is invalid")
    _verify_visual_approval(runtime_root, approval_path)
    _verify_gateway_and_figure_inputs(runtime_root)
    phase_handoffs = {
        phase: _verify_phase_tree(runtime_root, phase)
        for phase in ("smoke", "publication_smoke", "scale")
    }
    predecessor = _verify_nested_phase_chain(runtime_root, phase_handoffs)
    scale_handoff = json.loads(
        (runtime_root / "runs/scale/final-handoff.json").read_text(encoding="utf-8")
    )
    if scale_handoff.get("prior_phase_handoffs") != predecessor:
        raise LocalTopologyError("scale handoff predecessor chain is invalid")
    if scale_handoff != phase_handoffs["scale"]:
        raise LocalTopologyError("scale handoff differs from full phase recomputation")
    inventory: dict[str, str] = {}
    for relative in relative_files:
        path = (runtime_root / relative).resolve()
        if runtime_root.resolve() not in path.parents or not path.is_file():
            raise LocalTopologyError("publication handoff source inventory is invalid")
        inventory[relative] = _sha(path)
    if _secret_scan_inventory(runtime_root, relative_files):
        raise LocalTopologyError("publication handoff inventory contains sensitive material")
    document: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-final-publication-handoff-v1",
        "namespace": "native-multihop-switching-v1",
        "all_gates_pass": True,
        "visual_approval_sha256": _sha(approval_path),
        "prior_phase_handoffs": predecessor,
        "scale_handoff_sha256": _sha(runtime_root / "runs/scale/final-handoff.json"),
        "phase_handoff_sha256": {
            phase: _sha(runtime_root / "runs" / phase / "final-handoff.json")
            for phase in ("smoke", "publication_smoke", "scale")
        },
        "files": inventory,
    }
    semantic = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    document["semantic_sha256"] = hashlib.sha256(semantic).hexdigest()
    output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def verify_publication_handoff(
    *, runtime_root: Path, handoff_path: Path
) -> tuple[dict[str, object], list[str]]:
    document = json.loads(handoff_path.read_text(encoding="utf-8"))
    semantic = dict(document)
    expected_semantic = str(semantic.pop("semantic_sha256", ""))
    files = document.get("files")
    if (
        document.get("schema_version")
        != "xir-lab-native-multihop-final-publication-handoff-v1"
        or document.get("namespace") != "native-multihop-switching-v1"
        or document.get("all_gates_pass") is not True
        or not isinstance(files, dict)
        or hashlib.sha256(
            json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != expected_semantic
    ):
        raise LocalTopologyError("final publication handoff semantic identity is invalid")
    relative_files = sorted(str(name) for name in files)
    if relative_files != list(files):
        raise LocalTopologyError("final publication handoff inventory is not sorted")
    for relative in relative_files:
        path = (runtime_root / relative).resolve()
        if (
            runtime_root.resolve() not in path.parents
            or not path.is_file()
            or _sha(path) != files[relative]
        ):
            raise LocalTopologyError(f"final publication handoff file drift: {relative}")
    _verify_visual_approval(
        runtime_root, runtime_root / "figure8-visual-approval.json"
    )
    _verify_gateway_and_figure_inputs(runtime_root)
    phase_handoffs = {
        phase: _verify_phase_tree(runtime_root, phase)
        for phase in ("smoke", "publication_smoke", "scale")
    }
    predecessor = _verify_nested_phase_chain(runtime_root, phase_handoffs)
    scale_handoff = phase_handoffs["scale"]
    expected_phase_hashes = {
        phase: _sha(runtime_root / "runs" / phase / "final-handoff.json")
        for phase in ("smoke", "publication_smoke", "scale")
    }
    if (
        document.get("prior_phase_handoffs") != predecessor
        or scale_handoff.get("prior_phase_handoffs") != predecessor
        or document.get("phase_handoff_sha256") != expected_phase_hashes
        or document.get("scale_handoff_sha256") != expected_phase_hashes["scale"]
        or document.get("visual_approval_sha256")
        != _sha(runtime_root / "figure8-visual-approval.json")
    ):
        raise LocalTopologyError("final publication handoff evidence chain is invalid")
    if _secret_scan_inventory(runtime_root, relative_files):
        raise LocalTopologyError("final publication handoff contains sensitive material")
    return document, relative_files


def sync_exact_publication(
    *, runtime_root: Path, relative_files: list[str], destination: Path,
    expected_sha256: dict[str, str] | None = None,
) -> dict[str, str]:
    if destination.exists() or destination.is_symlink():
        raise LocalTopologyError("local publication destination already exists")
    if not relative_files or relative_files != sorted(set(relative_files)):
        raise LocalTopologyError("public synchronization inventory is not exact and sorted")
    staging = destination.with_name(f".{destination.name}.staging-{os.getpid()}")
    if staging.exists():
        raise LocalTopologyError("public synchronization staging path already exists")
    staging.mkdir(parents=True)
    manifest: dict[str, str] = {}
    try:
        for relative in relative_files:
            source = (runtime_root / relative).resolve()
            if runtime_root.resolve() not in source.parents or not source.is_file():
                raise LocalTopologyError("public synchronization source is invalid")
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            manifest[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
            if expected_sha256 is not None and manifest[relative] != expected_sha256.get(relative):
                raise LocalTopologyError("public synchronization differs from frozen handoff")
        findings = secret_scan(staging)
        if findings:
            raise LocalTopologyError(
                "public synchronization contains sensitive material: " + ", ".join(findings)
            )
        actual = sorted(
            path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()
        )
        if actual != relative_files:
            raise LocalTopologyError("public synchronization inventory differs after copy")
        sums = "".join(f"{manifest[name]}  {name}\n" for name in relative_files)
        (staging / "SHA256SUMS").write_text(sums, encoding="ascii")
        os.rename(staging, destination)
    except BaseException:
        if staging.exists():
            import shutil

            shutil.rmtree(staging)
        raise
    return manifest
