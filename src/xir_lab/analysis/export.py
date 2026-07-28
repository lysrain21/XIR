"""Deterministic normalized JSON and analysis-only CSV export."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import rfc8785

from xir_lab.analysis.invariants import InvariantReport
from xir_lab.analysis.reconcile import ReconciliationReport
from xir_lab.evidence.store import EvidenceStore


class ExportError(RuntimeError):
    """Raised when unvalidated evidence is requested for formal export."""


@dataclass(frozen=True)
class ExportedArtifact:
    name: str
    sha256: str
    row_count: int


@dataclass(frozen=True)
class ExportManifest:
    run_id: str
    artifacts: tuple[ExportedArtifact, ...]
    semantic_digest: str


class NormalizedExporter:
    def __init__(self, *, store: EvidenceStore, schema_root: Path) -> None:
        self.store = store
        self.schema_root = schema_root

    def export(
        self,
        *,
        run_id: str,
        reconciliation: ReconciliationReport,
        invariants: InvariantReport,
        destination: Path,
    ) -> ExportManifest:
        if (
            reconciliation.run_id != run_id
            or invariants.run_id != run_id
            or not reconciliation.valid
            or not invariants.valid
        ):
            raise ExportError("formal export requires valid reconciliation and invariants")
        destination.mkdir(parents=True, exist_ok=False)
        datasets = self._datasets(run_id, reconciliation, invariants)
        artifacts: list[ExportedArtifact] = []
        semantic_material: dict[str, str] = {}
        for name, document in datasets.items():
            schema = json.loads(
                (self.schema_root / f"normalized-{name}-v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.Draft202012Validator(schema).validate(document)
            encoded = rfc8785.dumps(document)
            json_name = f"{name}.json"
            (destination / json_name).write_bytes(encoded + b"\n")
            digest = hashlib.sha256(encoded).hexdigest()
            artifacts.append(
                ExportedArtifact(json_name, digest, len(document["rows"]))
            )
            semantic_material[json_name] = digest
            csv_bytes = _csv(document["rows"])
            csv_name = f"{name}.csv"
            (destination / csv_name).write_bytes(csv_bytes)
            artifacts.append(
                ExportedArtifact(
                    csv_name,
                    hashlib.sha256(csv_bytes).hexdigest(),
                    len(document["rows"]),
                )
            )
        semantic_digest = hashlib.sha256(
            rfc8785.dumps(semantic_material)
        ).hexdigest()
        manifest_document = {
            "schema_version": "xir-lab-normalized-export-manifest-v1",
            "run_id": run_id,
            "artifacts": [
                {
                    "name": item.name,
                    "sha256": item.sha256,
                    "row_count": item.row_count,
                }
                for item in sorted(artifacts, key=lambda item: item.name)
            ],
            "semantic_digest": semantic_digest,
            "source_of_truth": "sqlite",
            "csv_role": "analysis_convenience_only",
        }
        manifest_bytes = rfc8785.dumps(manifest_document)  # type: ignore[arg-type]
        (destination / "manifest.json").write_bytes(manifest_bytes + b"\n")
        return ExportManifest(
            run_id,
            tuple(sorted(artifacts, key=lambda item: item.name)),
            semantic_digest,
        )

    def _datasets(
        self,
        run_id: str,
        reconciliation: ReconciliationReport,
        invariants: InvariantReport,
    ) -> dict[str, dict[str, Any]]:
        with self.store.connect(read_only=True) as connection:
            attempts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT attempt.attempt_id, condition.carrier_sequence AS condition,
                           attempt.pair_id, attempt.arm, attempt.attempt_kind,
                           attempt.original_attempt_kind, attempt.retry_of,
                           attempt.schedule_index, attempt.batch_index, attempt.state
                    FROM attempts AS attempt
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY attempt.attempt_id
                    """,
                    (run_id,),
                )
            ]
            stages = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT stage.stage_id, stage.attempt_id, stage.ordinal,
                           stage.stage_name, stage.stage_template_id,
                           stage.chain_id, stage.accounting_bucket,
                           stage.logical_labels_json, stage.state
                    FROM stages AS stage
                    JOIN attempts AS attempt
                      ON attempt.attempt_id = stage.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY stage.attempt_id, stage.ordinal
                    """,
                    (run_id,),
                )
            ]
            resources = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT resource.*, stage.attempt_id,
                           stage.accounting_bucket
                    FROM transaction_resources AS resource
                    JOIN transactions AS transaction_record
                      ON transaction_record.transaction_id =
                         resource.transaction_id
                    JOIN intents AS intent
                      ON intent.intent_id = transaction_record.intent_id
                    JOIN stages AS stage ON stage.stage_id = intent.stage_id
                    JOIN attempts AS attempt
                      ON attempt.attempt_id = stage.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY resource.transaction_id
                    """,
                    (run_id,),
                )
            ]
            pairs = [
                {
                    **dict(row),
                    "reasons": json.loads(str(row["reasons_json"])),
                }
                for row in connection.execute(
                    """
                    SELECT decision.pair_id, decision.baseline_attempt_id,
                           decision.xir_attempt_id, decision.eligible,
                           decision.reasons_json
                    FROM pair_eligibility_decisions AS decision
                    JOIN pairs AS pair_record
                      ON pair_record.pair_id = decision.pair_id
                    JOIN conditions AS condition
                      ON condition.condition_id = pair_record.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY decision.pair_id
                    """,
                    (run_id,),
                )
            ]
            outcomes = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT outcome.*
                    FROM attempt_outcome_observations AS outcome
                    JOIN attempts AS attempt
                      ON attempt.attempt_id = outcome.attempt_id
                    JOIN conditions AS condition
                      ON condition.condition_id = attempt.condition_id
                    WHERE condition.run_id = ?
                    ORDER BY outcome.attempt_id, outcome.outcome_kind
                    """,
                    (run_id,),
                )
            ]
        validation = [
            {
                "validator": "reconciliation",
                "valid": reconciliation.valid,
                "checked": reconciliation.planned,
                "issue_count": len(reconciliation.issues),
            },
            {
                "validator": "evidence_invariants",
                "valid": invariants.valid,
                "checked": invariants.checked_attempts,
                "issue_count": len(invariants.issues),
            },
        ]
        return {
            "attempts": _document("attempts", run_id, attempts),
            "stages": _document("stages", run_id, stages),
            "resources": _document("resources", run_id, resources),
            "matched-pairs": _document("matched-pairs", run_id, pairs),
            "outcomes": _document("outcomes", run_id, outcomes),
            "validation": _document("validation", run_id, validation),
        }


def _document(name: str, run_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": f"xir-lab-normalized-{name}-v1",
        "run_id": run_id,
        "rows": rows,
    }


def _csv(rows: list[dict[str, Any]]) -> bytes:
    if not rows:
        return b""
    fields = sorted({key for row in rows for key in row})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: (
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                    if isinstance(value, (dict, list))
                    else value
                )
                for key, value in row.items()
            }
        )
    return buffer.getvalue().encode()
