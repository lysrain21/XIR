#!/usr/bin/env python3
"""Build a claim-ineligible, secret-free final handoff for the 1,100-attempt pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.gateway_deployment import compare_gateway_publications
from xir_lab.native.multihop_identity import PILOT
from xir_lab.native.multihop_publication import verify_multihop_handoff
from xir_lab.native.multihop_sync import (
    _secret_scan_inventory,
    _verify_nested_phase_chain,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_phase(runtime_root: Path, phase: str) -> dict[str, Any]:
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


def build_pilot_handoff(
    *, runtime_root: Path, relative_files: list[str], output_path: Path
) -> dict[str, Any]:
    if output_path.exists() or relative_files != sorted(set(relative_files)):
        raise LocalTopologyError("pilot final handoff output/inventory is invalid")
    phase_handoffs = {
        phase: _verify_phase(runtime_root, phase)
        for phase in ("smoke", "publication_smoke", "scale")
    }
    predecessor = _verify_nested_phase_chain(
        runtime_root,
        phase_handoffs,
        expected_namespace=PILOT.evidence_namespace,
    )
    scale = phase_handoffs["scale"]
    if (
        scale.get("namespace") != PILOT.evidence_namespace
        or scale.get("role") != PILOT.scale_role
        or int(scale.get("attempt_count", -1)) != PILOT.scale_attempt_count
        or scale.get("prior_phase_handoffs") != predecessor
    ):
        raise LocalTopologyError("pilot scale handoff is not the 1,100-attempt pilot")
    with __import__("tempfile").TemporaryDirectory(prefix="xir-pilot-gateway-") as temp:
        comparison = Path(temp) / "comparison.json"
        compare_gateway_publications(
            publication_a=runtime_root / "gateway-a",
            publication_b=runtime_root / "gateway-b",
            output_path=comparison,
        )
        if comparison.read_bytes() != (runtime_root / "gateway-comparison.json").read_bytes():
            raise LocalTopologyError("pilot Gateway rebuild comparison differs")
    inventory: dict[str, str] = {}
    for relative in relative_files:
        path = (runtime_root / relative).resolve()
        if runtime_root.resolve() not in path.parents or not path.is_file():
            raise LocalTopologyError("pilot handoff inventory path is invalid")
        inventory[relative] = _sha(path)
    if _secret_scan_inventory(runtime_root, relative_files):
        raise LocalTopologyError("pilot handoff inventory contains sensitive material")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-pilot-publication-handoff-v1",
        "namespace": PILOT.evidence_namespace,
        "role": PILOT.scale_role,
        "claim_eligible": False,
        "all_gates_pass": True,
        "attempt_count": PILOT.scale_attempt_count,
        "prior_phase_handoffs": predecessor,
        "phase_handoff_sha256": {
            phase: _sha(runtime_root / "runs" / phase / "final-handoff.json")
            for phase in ("smoke", "publication_smoke", "scale")
        },
        "gateway_comparison_sha256": _sha(runtime_root / "gateway-comparison.json"),
        "files": inventory,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--file-list", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = build_pilot_handoff(
        runtime_root=args.runtime_root,
        relative_files=args.file_list.read_text(encoding="utf-8").splitlines(),
        output_path=args.output,
    )
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
