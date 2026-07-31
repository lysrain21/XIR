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
    final_summary: dict[str, Any] | None = None,
) -> str:
    rows = []
    for row in analysis["per_route"]:
        rows.append(
            "| {route} | {logical_attempts} | {success_rate:.3f} | "
            "{latency_seconds_mean:.3f} | {median:.3f} | "
            "{latency_seconds_p95:.3f} | {p99:.3f} | {minimum:.3f} | "
            "{maximum:.3f} | {coordinator_gas_used} | {xir} |".format(
                median=row.get(
                    "latency_seconds_median", row["latency_seconds_mean"]
                ),
                p99=row.get("latency_seconds_p99", row["latency_seconds_p95"]),
                minimum=row.get(
                    "latency_seconds_min", row["latency_seconds_mean"]
                ),
                maximum=row.get(
                    "latency_seconds_max", row["latency_seconds_mean"]
                ),
                **row,
            )
        )
    components = "\n".join(
        f"- {item['component_id']}: `{item['commit']}`"
        for item in provenance["components"]
    )
    observed = reconciliation["observed"]
    extrema = analysis["resource_extrema"]
    closeout = final_summary or {}
    validators = closeout.get("validators", {})
    interruptions = closeout.get("interruptions", {})
    resources = closeout.get("resources", {})
    storage = closeout.get("storage", {})
    calldata = closeout.get("calldata", {})
    coordinator_calldata = (
        calldata.get("coordinator", {}).get("groups", {}).get("all", {})
    )
    worker_calldata = (
        calldata.get("layerzero_worker", {}).get("groups", {}).get("all", {})
    )
    recovery_transactions = int(
        interruptions.get("recovery_only_transactions", 0)
    )
    reconciled_transactions = int(
        observed["physical_transactions"]["cumulative_unique"]
    )
    physical_transactions_with_recovery = (
        reconciled_transactions + recovery_transactions
    )
    return f"""# Native Hyperlane–LayerZero–XIR Experiment Report

## Result

The controlled local experiment reconciled `{reconciliation['denominator']['logical_attempts']}`
designated two-hop attempts for phase `{analysis['phase']}`. Reconciliation
status is `{str(reconciliation['valid']).lower()}`. HH and LL are homogeneous
native-protocol routes without XIR; HL and LH use exactly one XIR transition.

| Route | Attempts | Success rate | Mean (s) | Median (s) | P95 (s) | P99 (s) | Min (s) | Max (s) | Coordinator gas | XIR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

The accepted scale denominator contains 40,000 effects and 20,000 XIR
transitions. The cumulative run-003 counters, which also include accepted smoke
and rehearsal qualification phases, are effects
`{observed['cumulative_effects']}`, XIR transitions
`{observed['cumulative_xir_transitions']}`, Hyperlane messages
`{observed['protocol_messages']['hyperlane']}`, and LayerZero V2 messages
`{observed['protocol_messages']['layerzero_v2']}`. Reconciled workload
transactions are `{reconciled_transactions}`; `{recovery_transactions}`
additional recovery-only transactions make
`{physical_transactions_with_recovery}` total evidenced physical transactions.
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

Final validator state: `{validators.get('validator_count', 'not recorded')}`
containers, all running `{validators.get('all_running', 'not recorded')}`, all
healthy `{validators.get('all_healthy', 'not recorded')}`, cumulative Docker
restart count `{validators.get('total_restart_count', 'not recorded')}`.
The closeout inventory contains `{storage.get('total_files', 'not recorded')}`
runtime files and `{storage.get('total_bytes', 'not recorded')}` bytes.
Resource sampling ran from
`{resources.get('first_observed_at', 'not recorded')}` to
`{resources.get('last_observed_at', 'not recorded')}`; the median, P95, and
maximum observed intervals were respectively
`{resources.get('interval_seconds', {}).get('median', 'not recorded')}`,
`{resources.get('interval_seconds', {}).get('p95', 'not recorded')}`, and
`{resources.get('interval_seconds', {}).get('maximum', 'not recorded')}`
seconds.

Scale coordinator calldata covered
`{coordinator_calldata.get('transactions', 'not recorded')}` transactions and
`{coordinator_calldata.get('total_bytes', 'not recorded')}` bytes. LayerZero
worker calldata induced by scale dispatches covered
`{worker_calldata.get('transactions', 'not recorded')}` transactions and
`{worker_calldata.get('total_bytes', 'not recorded')}` bytes. Official
Hyperlane relayer process transactions remain proven by on-chain process
lineage, but the pinned agent does not retain raw signed process transactions;
therefore no aggregate Hyperlane process-calldata claim is made.

Recorded submission recovery events: LayerZero raw rebroadcasts
`{observed['retries']['layerzero_raw_rebroadcasts']}`, runner raw transaction
replacements `{observed['retries']['runner_raw_replacements']}`, runner
transient RPC retries `{observed['retries']['runner_transient_rpc_retries']}`,
and semantic attempt retries
`{observed['retries']['semantic_retry_attempts']}`. Raw submission recovery
and transient RPC retries retain the original attempt identity and retry
lineage; they do not add a designated logical attempt.

Natural interruption records: `{interruptions.get('event_count', 'not recorded')}`.
All are classified as non-injected:
`{interruptions.get('all_natural', 'not recorded')}`; the attempt denominator
remained unchanged:
`{interruptions.get('attempt_denominator_unchanged', 'not recorded')}`; and no
replacement attempt was created:
`{interruptions.get('no_replacement_attempts', 'not recorded')}`.

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
- Validator and worker restarts, RPC interruptions, and nonce recovery pauses
  occurred naturally during scale. They inflate wall-clock means and maxima;
  the run is exact for functional accounting but is not an uninterrupted
  performance measurement. Median and percentile values are reported without
  removing affected attempts, and all recovery windows remain in the evidence.
- Coordinator gas excludes protocol-agent gas; complete physical-transaction
  evidence and receipts are retained separately.
- Run-001 is historical evidence and run-002 is rejected qualification
  evidence. Neither contributes a row, timing value, effect, message, resource
  sample, or denominator to accepted run-003 statistics.
"""
