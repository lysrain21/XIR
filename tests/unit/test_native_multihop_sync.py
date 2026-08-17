from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_sync import (
    _verify_visual_approval,
    build_publication_handoff,
    sync_exact_publication,
    verify_publication_handoff,
)


def _write_handoff(path: Path, payload: dict[str, object]) -> dict[str, object]:
    document = dict(payload)
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    return document


def test_sync_requires_new_destination_and_exact_inventory(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "publication").mkdir(parents=True)
    (runtime / "publication/result.json").write_text("{}\n", encoding="utf-8")
    destination = tmp_path / "public-run"
    result = sync_exact_publication(
        runtime_root=runtime,
        relative_files=["publication/result.json"],
        destination=destination,
    )
    assert set(result) == {"publication/result.json"}
    assert sorted(
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    ) == ["SHA256SUMS", "publication/result.json"]
    with pytest.raises(LocalTopologyError, match="already exists"):
        sync_exact_publication(
            runtime_root=runtime,
            relative_files=["publication/result.json"],
            destination=destination,
        )


def test_sync_rejects_sensitive_input_without_publishing(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "private.key").write_text("secret\n", encoding="utf-8")
    destination = tmp_path / "public-run"
    with pytest.raises(LocalTopologyError, match="sensitive"):
        sync_exact_publication(
            runtime_root=runtime,
            relative_files=["private.key"],
            destination=destination,
        )
    assert not destination.exists()


def test_visual_approval_rejects_bound_manifest_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for root_name in ("figure-a", "figure-b"):
        root = tmp_path / root_name
        root.mkdir()
        (root / "manifest.json").write_text(f"{root_name}\n", encoding="utf-8")
    comparison = tmp_path / "figure-comparison.json"
    comparison.write_text("comparison\n", encoding="utf-8")
    approval = tmp_path / "figure8-visual-approval.json"
    approval.write_text(
        json.dumps(
            {
                "schema_version": "xir-lab-native-multihop-figure8-visual-approval-v1",
                "approved": True,
                "reviewer": "human",
                "approved_utc_ns": 1,
                "figure_a_manifest_sha256": "00" * 32,
                "figure_b_manifest_sha256": hashlib.sha256(
                    (tmp_path / "figure-b/manifest.json").read_bytes()
                ).hexdigest(),
                "comparison_sha256": hashlib.sha256(comparison.read_bytes()).hexdigest(),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_sync.verify_figure8_comparison",
        lambda **_kwargs: {"valid": True},
    )
    with pytest.raises(LocalTopologyError, match="binding differs"):
        _verify_visual_approval(tmp_path, approval)


def test_final_handoff_recomputes_phase_chain_and_rejects_self_resigned_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    smoke_path = runtime / "runs/smoke/final-handoff.json"
    smoke = _write_handoff(
        smoke_path,
        {
            "schema_version": "xir-lab-native-multihop-final-handoff-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "smoke",
            "role": "development_gate_only",
            "all_gates_pass": True,
            "attempt_count": 11,
            "prior_phase_handoffs": {},
        },
    )
    smoke_predecessor = {
        "smoke": {
            "file_sha256": hashlib.sha256(smoke_path.read_bytes()).hexdigest(),
            "semantic_sha256": smoke["semantic_sha256"],
        }
    }
    publication_smoke_path = runtime / "runs/publication_smoke/final-handoff.json"
    publication_smoke = _write_handoff(
        publication_smoke_path,
        {
            "schema_version": "xir-lab-native-multihop-final-handoff-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "publication_smoke",
            "role": "publication_gate_not_formal_estimate",
            "all_gates_pass": True,
            "attempt_count": 22,
            "prior_phase_handoffs": smoke_predecessor,
        },
    )
    predecessor = {
        "smoke": {
            "file_sha256": hashlib.sha256(smoke_path.read_bytes()).hexdigest(),
            "semantic_sha256": smoke["semantic_sha256"],
        },
        "publication_smoke": {
            "file_sha256": hashlib.sha256(publication_smoke_path.read_bytes()).hexdigest(),
            "semantic_sha256": publication_smoke["semantic_sha256"],
        },
    }
    scale_path = runtime / "runs/scale/final-handoff.json"
    scale = _write_handoff(
        scale_path,
        {
            "schema_version": "xir-lab-native-multihop-final-handoff-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "scale",
            "role": "formal_measurement",
            "all_gates_pass": True,
            "attempt_count": 110_000,
            "prior_phase_handoffs": predecessor,
        },
    )
    result = runtime / "runs/scale/source-publication/result.json"
    result.parent.mkdir(parents=True)
    result.write_text("{}\n", encoding="utf-8")
    approval = runtime / "figure8-visual-approval.json"
    approval.write_text("approved\n", encoding="utf-8")
    phase_documents = {
        "smoke": smoke,
        "publication_smoke": publication_smoke,
        "scale": scale,
    }
    monkeypatch.setattr(
        "xir_lab.native.multihop_sync._verify_phase_tree",
        lambda _root, phase: phase_documents[phase],
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_sync._verify_visual_approval",
        lambda _root, _path: {"approved": True},
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_sync._verify_gateway_and_figure_inputs",
        lambda _root: None,
    )
    output = runtime / "final-publication-handoff.json"
    relative = sorted(
        [
            "figure8-visual-approval.json",
            "runs/publication_smoke/final-handoff.json",
            "runs/scale/final-handoff.json",
            "runs/scale/source-publication/result.json",
            "runs/smoke/final-handoff.json",
        ]
    )
    build_publication_handoff(
        runtime_root=runtime,
        relative_files=relative,
        approval_path=approval,
        output_path=output,
    )
    verify_publication_handoff(runtime_root=runtime, handoff_path=output)

    tampered_smoke = dict(smoke)
    tampered_smoke["attempt_count"] = 12
    tampered_smoke.pop("semantic_sha256")
    _write_handoff(smoke_path, tampered_smoke)
    with pytest.raises(LocalTopologyError, match="file drift|evidence chain"):
        verify_publication_handoff(runtime_root=runtime, handoff_path=output)
