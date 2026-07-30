"""Evidence freezing and report rendering for the native protocol-stack run."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semantic_sha256(document: Any) -> str:
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def freeze_manifest(
    *, runtime_root: Path, repository_root: Path, excluded: set[Path]
) -> dict[str, Any]:
    runtime = runtime_root.resolve()
    repository = repository_root.resolve()
    excluded_resolved = {path.resolve() for path in excluded}
    entries: list[dict[str, Any]] = []
    for path in sorted(runtime.rglob("*")):
        if not path.is_file() or path.resolve() in excluded_resolved:
            continue
        relative = path.relative_to(runtime)
        sensitive = "private" in relative.parts or relative.suffix == ".key"
        entries.append(
            {
                "path": relative.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "classification": (
                    "sensitive-retained-not-published"
                    if sensitive
                    else "retained-experiment-artifact"
                ),
            }
        )
    ignored = {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "cache",
        "out",
        "lib",
    }
    source_entries = []
    for path in sorted(repository.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or any(part in ignored for part in path.relative_to(repository).parts)
        ):
            continue
        source_entries.append(
            f"{sha256_file(path)}  {path.relative_to(repository).as_posix()}"
        )
    return {
        "schema_version": "xir-lab-native-evidence-manifest-v1",
        "run_id": runtime.name,
        "frozen_at": datetime.now(UTC).isoformat(),
        "runtime_root": str(runtime),
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "source_tree_sha256": hashlib.sha256(
            "\n".join(source_entries).encode()
        ).hexdigest(),
        "source_file_count": len(source_entries),
        "artifact_file_count": len(entries),
        "artifact_total_bytes": sum(int(entry["bytes"]) for entry in entries),
        "artifacts": entries,
    }


def verify_manifest(document: dict[str, Any], runtime_root: Path) -> list[str]:
    errors = []
    for entry in document["artifacts"]:
        path = runtime_root / str(entry["path"])
        if not path.is_file():
            errors.append(f"missing:{entry['path']}")
        elif path.stat().st_size != int(entry["bytes"]):
            errors.append(f"size:{entry['path']}")
        elif sha256_file(path) != str(entry["sha256"]):
            errors.append(f"sha256:{entry['path']}")
    return errors


def render_report(
    *,
    profile: dict[str, Any],
    provenance: dict[str, Any],
    deployment: dict[str, Any],
    reconciliation: dict[str, Any],
    analysis: dict[str, Any],
    manifest_sha256: str,
    evidence_pointer: str,
) -> str:
    rows = []
    for row in analysis["per_route"]:
        rows.append(
            "| {route} | {logical_attempts} | {success_rate:.3f} | "
            "{latency_seconds_mean:.3f} | {latency_seconds_p95:.3f} | "
            "{coordinator_gas_used} | {xir} |".format(**row)
        )
    components = "\n".join(
        f"- {item['component_id']}: `{item['commit']}`"
        for item in provenance["components"]
    )
    observed = reconciliation["observed"]
    extrema = analysis["resource_extrema"]
    return f"""# Native Hyperlane–LayerZero–XIR Experiment Report

## Result

The controlled local experiment reconciled `{reconciliation['denominator']['logical_attempts']}`
designated two-hop attempts for phase `{analysis['phase']}`. Reconciliation
status is `{str(reconciliation['valid']).lower()}`. HH and LL are homogeneous
native-protocol routes without XIR; HL and LH use exactly one XIR transition.

| Route | Attempts | Success rate | Mean latency (s) | P95 latency (s) | Coordinator gas | XIR |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

Total application effects: `{observed['cumulative_effects']}`. Total XIR
transitions: `{observed['cumulative_xir_transitions']}`. Observed protocol
messages: Hyperlane `{observed['protocol_messages']['hyperlane']}`, LayerZero
V2 `{observed['protocol_messages']['layerzero_v2']}`. Observed unique physical
transactions: `{observed['physical_transactions']['cumulative_unique']}`.
The phase wall time was `{analysis['phase_wall_seconds']:.3f}` seconds and the
logical-attempt throughput was
`{analysis['throughput_logical_attempts_per_second']:.6f} attempts/s`.

## Deployment and provenance

The topology is three retained Besu QBFT chains, four validators per chain,
with chain IDs `{profile['chains'][0]['chain_id']}`,
`{profile['chains'][1]['chain_id']}`, and
`{profile['chains'][2]['chain_id']}`. Component source identities:

{components}

Hyperlane uses official Mailbox, MerkleTreeHook, one-of-one message-ID
multisig ISM, validator agents, and relayer. LayerZero uses official
EndpointV2, ULN302, DVN, Executor, price/fee, treasury, and proxy contracts.
LayerZero's private-chain off-chain roles are performed by the auditable
self-hosted XIR research worker; this is not a LayerZero Labs managed service.
Deployment manifest schema: `{deployment['schema_version']}`.

## Resource and reliability evidence

Resource samples: `{analysis['resource_samples']}`; explicit sampling gaps:
`{analysis['resource_sampling_gaps']}`; observed dedicated-process restarts:
`{analysis['observed_process_restarts']}`. Minimum available host memory:
`{extrema['minimum_memory_available_bytes']}` bytes; minimum GPFS free space:
`{extrema['minimum_gpfs_free_bytes']}` bytes; minimum Docker filesystem free
space: `{extrema['minimum_docker_free_bytes']}` bytes.

## Evidence and reproducibility

Raw receipts, protocol databases, checkpoint files, logs, signed-action
lineage, runner databases, resource samples, build outputs, and deployment
evidence are retained at `{evidence_pointer}`. The SHA-256 evidence-manifest
digest is `{manifest_sha256}`. Analysis is generated only after exact
reconciliation and is rebuilt twice offline with equal semantic digests.

## Interpretation limits

- These are controlled single-host local-chain measurements, not public-network
  throughput, fee, decentralization, security, or reliability measurements.
- The Hyperlane and LayerZero off-chain service boundaries differ; results do
  not measure vendor-operated service performance.
- Hyperlane's pinned agent schema requires an `interchainGasPaymaster` address
  even with gas enforcement disabled. The pinned IGP implementation requires
  Cancun opcodes unavailable on the retained London chains, so the unused
  config field transparently aliases the deployed official ProtocolFee hook;
  no IGP is claimed, invoked, or included in protocol-cost results.
- Protocol family, direction, and XIR presence are partly confounded by the
  four-route design. Route-level results are primary; pooled results are
  descriptive.
- Coordinator gas excludes protocol-agent gas; complete physical-transaction
  evidence and receipts are retained separately.
"""
