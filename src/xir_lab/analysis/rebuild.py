"""One-shot network-independent rebuild of normalized and report artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import rfc8785

from xir_lab.analysis.export import NormalizedExporter
from xir_lab.analysis.invariants import InvariantReport
from xir_lab.analysis.reconcile import ReconciliationReport
from xir_lab.analysis.reports import PrimaryReportBuilder
from xir_lab.evidence.store import EvidenceStore


@dataclass(frozen=True)
class RebuildResult:
    normalized_semantic_digest: str
    primary_manifest_digest: str
    complete_semantic_digest: str


class OfflineRebuilder:
    def __init__(self, *, store: EvidenceStore, schema_root: Path) -> None:
        self.store = store
        self.exporter = NormalizedExporter(store=store, schema_root=schema_root)
        self.primary = PrimaryReportBuilder(store=store)

    def rebuild(
        self,
        *,
        run_id: str,
        freeze_id: str,
        reconciliation: ReconciliationReport,
        invariants: InvariantReport,
        destination: Path,
    ) -> RebuildResult:
        destination.mkdir(parents=True, exist_ok=False)
        normalized = self.exporter.export(
            run_id=run_id,
            reconciliation=reconciliation,
            invariants=invariants,
            destination=destination / "normalized",
        )
        primary_digest = self.primary.build(
            run_id=run_id,
            freeze_id=freeze_id,
            destination=destination / "primary",
        )
        complete = hashlib.sha256(
            rfc8785.dumps(
                {
                    "normalized_semantic_digest": normalized.semantic_digest,
                    "primary_manifest_digest": primary_digest,
                }
            )
        ).hexdigest()
        return RebuildResult(
            normalized.semantic_digest,
            primary_digest,
            complete,
        )
