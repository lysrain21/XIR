"""Immutable freeze, offline rebuild, and final handoff for multihop evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any, cast

import rfc8785
from web3 import Web3

from xir_lab.localnet.multihop_volume_bootstrap import (
    validate_validator_volume_provenance_files,
)
from xir_lab.localnet.toolchain_preflight import verify_toolchain_preflight
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_freeze_v2 import secret_scan, sqlite_backup
from xir_lab.native.multihop_analysis import publish_multihop_analysis
from xir_lab.native.multihop_deployer import CHAIN_ROLES
from xir_lab.native.multihop_effects import _expected_effect_lineage, validate_effect_audit
from xir_lab.native.multihop_hyperlane_observer import load_hyperlane_observer_events
from xir_lab.native.multihop_identity import (
    config_identity,
    evidence_namespace,
    phase_attempt_count,
    phase_role,
)
from xir_lab.native.multihop_scalability import (
    MultihopPhase,
    load_multihop_config,
    load_multihop_profile,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise LocalTopologyError(f"freeze source is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _write_public_identity_manifest(source: Path, destination: Path) -> None:
    """Remove private path locators while preserving public chain identities."""

    document = cast(dict[str, Any], json.loads(source.read_text(encoding="utf-8")))
    payload = document.get("payload")
    networks = payload.get("networks") if isinstance(payload, dict) else None
    if not isinstance(networks, list):
        encoded = json.dumps(document, sort_keys=True).lower()
        if "private_key" in encoded or "mnemonic" in encoded:
            raise LocalTopologyError("identity manifest network inventory is invalid")
        _copy(source, destination)
        return
    redacted = 0
    for network in networks:
        validators = network.get("validators") if isinstance(network, dict) else None
        if not isinstance(validators, list):
            raise LocalTopologyError("identity manifest validator inventory is invalid")
        for validator in validators:
            if not isinstance(validator, dict) or "private_key_path" not in validator:
                raise LocalTopologyError("identity manifest private path inventory is invalid")
            del validator["private_key_path"]
            redacted += 1
    if redacted != 20:
        raise LocalTopologyError("identity manifest private path count is not 20")
    document["publication_redaction"] = {
        "schema_version": "xir-lab-public-identity-redaction-v1",
        "source_sha256": _sha(source),
        "removed_private_path_locator_count": redacted,
        "public_addresses_and_enodes_preserved": True,
    }
    _write(destination, document)


def _normalize_frozen_sqlite(path: Path) -> None:
    """Verify one closed backup and remove any runtime sidecars."""

    for suffix in ("-shm", "-wal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30) as connection:
        connection.execute("PRAGMA busy_timeout=30000")
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise LocalTopologyError(f"frozen SQLite quick check failed: {path.name}")


def _canonical_hash(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _verify_resource_segment_evidence(
    *, manifest_path: Path, combined_path: Path, segment_root: Path
) -> tuple[dict[str, Any], list[tuple[Path, Path]]]:
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
    segments = manifest.get("segments")
    if (
        manifest.get("schema_version") != "xir-lab-native-multihop-resource-segments-v1"
        or manifest.get("valid") is not True
        or manifest.get("combined_path") != "resource-samples.jsonl"
        or not isinstance(segments, list)
        or not segments
    ):
        raise LocalTopologyError("resource-monitor segment manifest is invalid")
    expected_sequence = 0
    payload = bytearray()
    verified: list[tuple[Path, Path]] = []
    previous_utc = 0
    for expected_completion in cast(list[dict[str, Any]], segments):
        name = expected_completion.get("path")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.startswith("resource-samples.segment-")
            or not name.endswith(".jsonl")
        ):
            raise LocalTopologyError("resource-monitor segment path is invalid")
        segment_path = segment_root / name
        completion_path = segment_path.with_suffix(".completion.json")
        completion = cast(
            dict[str, Any], json.loads(completion_path.read_text(encoding="utf-8"))
        )
        raw = segment_path.read_bytes()
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        sequences = [int(row.get("sequence", -1)) for row in rows]
        utc_values = [int(row.get("utc_ns", 0)) for row in rows]
        if (
            completion != expected_completion
            or completion.get("schema_version")
            != "xir-lab-native-multihop-resource-segment-completion-v1"
            or completion.get("valid") is not True
            or completion.get("sha256") != hashlib.sha256(raw).hexdigest()
            or int(completion.get("sample_count", -1)) != len(rows)
            or not rows
            or sequences
            != list(range(expected_sequence, expected_sequence + len(rows)))
            or int(completion.get("sequence_start", -1)) != expected_sequence
            or int(completion.get("sequence_end", -1))
            != expected_sequence + len(rows) - 1
            or any(
                row.get("schema_version")
                != "xir-lab-native-multihop-resource-sample-v1"
                for row in rows
            )
            or any(value <= 0 for value in utc_values)
            or utc_values != sorted(utc_values)
            or utc_values[0] < previous_utc
            or int(completion.get("last_utc_ns", -1)) != utc_values[-1]
        ):
            raise LocalTopologyError(f"resource-monitor segment is invalid: {name}")
        expected_sequence += len(rows)
        previous_utc = utc_values[-1]
        payload.extend(raw)
        verified.append((segment_path, completion_path))
    if (
        combined_path.read_bytes() != bytes(payload)
        or manifest.get("combined_sha256") != hashlib.sha256(payload).hexdigest()
        or int(manifest.get("sample_count", -1)) != expected_sequence
    ):
        raise LocalTopologyError("resource-monitor combined evidence is invalid")
    return manifest, verified


def _verify_observer_completion(
    *, ledger_path: Path, completion_path: Path, processes_path: Path
) -> dict[str, Any]:
    completion = cast(
        dict[str, Any], json.loads(completion_path.read_text(encoding="utf-8"))
    )
    processes = cast(dict[str, Any], json.loads(processes_path.read_text(encoding="utf-8")))
    rows = load_hyperlane_observer_events(ledger_path)
    roles = set(CHAIN_ROLES)
    target = completion.get("target_blocks")
    next_blocks = completion.get("next_blocks")
    if (
        completion.get("schema_version")
        != "xir-lab-native-multihop-hyperlane-observer-completion-v1"
        or completion.get("valid") is not True
        or completion.get("ledger_path") != ledger_path.name
        or completion.get("ledger_sha256") != _sha(ledger_path)
        or completion.get("all_targets_scanned") is not True
        or not isinstance(target, dict)
        or not isinstance(next_blocks, dict)
        or set(target) != roles
        or set(next_blocks) != roles
        or any(int(next_blocks[role]) <= int(target[role]) for role in roles)
        or processes.get("end_blocks") != target
        or rows[-1].get("event") != "observer_stopped"
    ):
        raise LocalTopologyError("Hyperlane observer completion is invalid")
    return completion


def _validate_phase_authority(
    *,
    runner_database: Path,
    authority_path: Path,
    phase: str,
    config_path: Path,
    plan_path: Path,
    deployment_path: Path,
    preregistration_path: Path,
    review_closure_path: Path,
    review_gate_path: Path,
    preflight_path: Path,
    validator_volume_attestation_path: Path,
    validator_volume_journal_path: Path,
    toolchain_preflight_path: Path,
    smoke_handoff_path: Path | None,
    publication_smoke_handoff_path: Path | None,
) -> dict[str, Any]:
    """Recompute authority from frozen inputs and require the DB singleton to agree."""

    authority = cast(dict[str, Any], json.loads(authority_path.read_text(encoding="utf-8")))
    semantic = dict(authority)
    expected_semantic = str(semantic.pop("semantic_sha256", ""))
    required_prior = {
        "smoke": set(),
        "publication_smoke": {"smoke"},
        "scale": {"smoke", "publication_smoke"},
    }
    prior = authority.get("prior_phase_handoffs")
    prior_rows_valid = isinstance(prior, dict) and all(
        isinstance(row, dict)
        and set(row) == {"file_sha256", "semantic_sha256"}
        and all(_is_sha256(value) for value in row.values())
        for row in prior.values()
    )
    lease_identity = authority.get("lease_identity")
    review_gate = cast(
        dict[str, Any], json.loads(review_gate_path.read_text(encoding="utf-8"))
    )
    preflight = cast(
        dict[str, Any], json.loads(preflight_path.read_text(encoding="utf-8"))
    )
    attestation, journal = validate_validator_volume_provenance_files(
        attestation_path=validator_volume_attestation_path,
        journal_path=validator_volume_journal_path,
    )
    toolchain = verify_toolchain_preflight(toolchain_preflight_path)
    try:
        config, _ = load_multihop_config(config_path)
        evidence_name = config_identity(config).evidence_namespace
    except LocalTopologyError:
        config = cast(dict[str, Any], json.loads(config_path.read_text(encoding="utf-8")))
        evidence_name = evidence_namespace(config)
    expected_prior = verify_prior_phase_handoffs(
        phase=phase,
        smoke_handoff_path=smoke_handoff_path,
        publication_smoke_handoff_path=publication_smoke_handoff_path,
        expected_namespace=evidence_name,
    )
    expected_bindings = {
        "review_gate_sha256": _sha(review_gate_path),
        "review_closure_sha256": _sha(review_closure_path),
        "preflight_sha256": _sha(preflight_path),
        "preflight_semantic_sha256": preflight.get("semantic_sha256"),
        "validator_volume_attestation_sha256": _sha(
            validator_volume_attestation_path
        ),
        "validator_volume_attestation_semantic_sha256": attestation.get(
            "semantic_sha256"
        ),
        "validator_volume_journal_sha256": _sha(validator_volume_journal_path),
        "validator_volume_journal_semantic_sha256": journal.get("semantic_sha256"),
        "toolchain_preflight_sha256": _sha(toolchain_preflight_path),
        "toolchain_preflight_semantic_sha256": toolchain.get("semantic_sha256"),
        "config_sha256": _sha(config_path),
        "plan_sha256": _sha(plan_path),
        "deployment_sha256": _sha(deployment_path),
        "preregistration_sha256": _sha(preregistration_path),
    }
    valid = (
        authority.get("schema_version") == "xir-lab-native-multihop-phase-authority-v1"
        and authority.get("namespace") == evidence_name
        and authority.get("phase") == phase
        and isinstance(prior, dict)
        and set(prior) == required_prior.get(phase, {"invalid"})
        and prior_rows_valid
        and prior == expected_prior
        and isinstance(lease_identity, dict)
        and authority.get("lease_identity_sha256")
        == hashlib.sha256(rfc8785.dumps(lease_identity)).hexdigest()
        and all(authority.get(key) == value for key, value in expected_bindings.items())
        and all(
            preflight.get(key) == value
            for key, value in expected_bindings.items()
            if key.startswith("validator_volume_") or key.startswith("toolchain_")
        )
        and review_gate.get("closure_sha256") == _sha(review_closure_path)
        and review_gate.get("preregistration_sha256") == _sha(preregistration_path)
        and all(_is_sha256(value) for value in expected_bindings.values())
        and hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() == expected_semantic
    )
    if not valid:
        raise LocalTopologyError("phase authority file is invalid")
    canonical = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    try:
        with sqlite3.connect(f"file:{runner_database}?mode=ro", uri=True) as connection:
            rows = list(
                connection.execute("SELECT authority_json,semantic_sha256 FROM phase_authority")
            )
    except sqlite3.Error as exc:
        raise LocalTopologyError("runner phase authority singleton is unavailable") from exc
    if rows != [(canonical, expected_semantic)]:
        raise LocalTopologyError("runner/file phase authority binding mismatch")
    return authority


def _freeze_private_raw_evidence(
    *,
    runner_database: Path,
    trace_database: Path,
    coordinator_signed_root: Path,
    hyperlane_process_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Freeze raw signed evidence privately and bind it to durable identities."""

    private_root = output_root / "private-evidence"
    frozen_signed_root = private_root / "coordinator-signed-transactions"
    frozen_signed_root.mkdir(parents=True)
    with sqlite3.connect(f"file:{runner_database}?mode=ro", uri=True) as connection:
        coordinator_rows = list(
            connection.execute(
                """
                SELECT transaction_hash,detail_json
                FROM stages
                WHERE transaction_hash IS NOT NULL
                ORDER BY transaction_hash
                """
            )
        )
    if not coordinator_rows:
        raise LocalTopologyError("frozen coordinator signed evidence is empty")
    referenced: dict[str, str] = {}
    for transaction_hash_value, detail_json in coordinator_rows:
        transaction_hash = _canonical_hash(str(transaction_hash_value))
        detail = cast(dict[str, Any], json.loads(str(detail_json)))
        raw_sha256 = str(detail.get("raw_sha256", ""))
        if len(raw_sha256) != 64:
            raise LocalTopologyError("coordinator stage lacks its durable raw digest")
        prior = referenced.setdefault(transaction_hash, raw_sha256)
        if prior != raw_sha256:
            raise LocalTopologyError("coordinator transaction has conflicting raw digests")
    observed_raw_files = {
        path.name: path for path in coordinator_signed_root.glob("*.raw") if path.is_file()
    }
    expected_names = {f"{transaction_hash}.raw" for transaction_hash in referenced}
    if set(observed_raw_files) != expected_names:
        raise LocalTopologyError(
            "coordinator private raw inventory differs from durable stage inventory"
        )
    for transaction_hash, expected_sha256 in sorted(referenced.items()):
        source = observed_raw_files[f"{transaction_hash}.raw"]
        raw = source.read_bytes()
        if (
            hashlib.sha256(raw).hexdigest() != expected_sha256
            or _canonical_hash(Web3.keccak(raw).hex()) != transaction_hash
        ):
            raise LocalTopologyError("coordinator private raw identity mismatch")
        _copy(source, frozen_signed_root / source.name)

    with sqlite3.connect(f"file:{trace_database}?mode=ro", uri=True) as connection:
        trace_rows = list(
            connection.execute(
                """
                SELECT chain_role,transaction_hash,raw_transaction_hex,raw_sha256
                FROM traces ORDER BY chain_role,transaction_hash
                """
            )
        )
    if not trace_rows:
        raise LocalTopologyError("frozen raw trace evidence is empty")
    trace_hashes: set[str] = set()
    for chain_role, transaction_hash_value, raw_hex, raw_sha256 in trace_rows:
        try:
            raw = bytes.fromhex(str(raw_hex).removeprefix("0x"))
        except ValueError as exc:
            raise LocalTopologyError("raw trace evidence is malformed") from exc
        transaction_hash = _canonical_hash(str(transaction_hash_value))
        if (
            str(chain_role) not in {"a", "b", "c", "d", "e"}
            or not raw
            or hashlib.sha256(raw).hexdigest() != str(raw_sha256)
            or _canonical_hash(Web3.keccak(raw).hex()) != transaction_hash
        ):
            raise LocalTopologyError("raw trace transaction identity mismatch")
        trace_hashes.add(transaction_hash)
    hyperlane = cast(dict[str, Any], json.loads(hyperlane_process_path.read_text(encoding="utf-8")))
    hyperlane_hashes = {
        _canonical_hash(str(row["transaction_hash"]))
        for row in cast(dict[str, dict[str, Any]], hyperlane["messages"]).values()
    }
    if not hyperlane_hashes or not hyperlane_hashes.issubset(trace_hashes):
        raise LocalTopologyError("Hyperlane process transactions lack frozen raw trace evidence")
    return {
        "coordinator_signed_transaction_count": len(referenced),
        "raw_trace_transaction_count": len(trace_rows),
        "hyperlane_raw_transaction_count": len(hyperlane_hashes),
        "private_evidence_root": "private-evidence",
    }


def freeze_multihop_sources(
    *,
    phase: MultihopPhase,
    config_path: Path,
    profile_path: Path,
    deployment_path: Path,
    plan_path: Path,
    preflight_path: Path,
    runner_state_path: Path,
    worker_state_path: Path,
    trace_state_path: Path,
    hyperlane_process_path: Path,
    hyperlane_observer_path: Path,
    hyperlane_observer_completion_path: Path,
    root_signer_audit_path: Path,
    incident_path: Path,
    resource_monitor_path: Path,
    resource_segments_path: Path,
    effect_baseline_path: Path,
    effect_audit_path: Path,
    coordinator_signed_root: Path,
    phase_authority_path: Path,
    smoke_handoff_path: Path | None,
    publication_smoke_handoff_path: Path | None,
    preregistration_path: Path,
    review_closure_path: Path,
    review_gate_path: Path,
    topology_path: Path,
    identity_manifest_path: Path,
    validator_volume_attestation_path: Path,
    validator_volume_journal_path: Path,
    toolchain_preflight_path: Path,
    normalized_stage_schema_path: Path,
    stage_template_schema_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise LocalTopologyError("frozen source output already exists")
    validate_validator_volume_provenance_files(
        attestation_path=validator_volume_attestation_path,
        journal_path=validator_volume_journal_path,
    )
    _validate_phase_authority(
        runner_database=runner_state_path,
        authority_path=phase_authority_path,
        phase=phase,
        config_path=config_path,
        plan_path=plan_path,
        deployment_path=deployment_path,
        preregistration_path=preregistration_path,
        review_closure_path=review_closure_path,
        review_gate_path=review_gate_path,
        preflight_path=preflight_path,
        validator_volume_attestation_path=validator_volume_attestation_path,
        validator_volume_journal_path=validator_volume_journal_path,
        toolchain_preflight_path=toolchain_preflight_path,
        smoke_handoff_path=smoke_handoff_path,
        publication_smoke_handoff_path=publication_smoke_handoff_path,
    )
    resource_segments, verified_resource_segments = _verify_resource_segment_evidence(
        manifest_path=resource_segments_path,
        combined_path=resource_monitor_path,
        segment_root=resource_segments_path.parent,
    )
    _verify_observer_completion(
        ledger_path=hyperlane_observer_path,
        completion_path=hyperlane_observer_completion_path,
        processes_path=hyperlane_process_path,
    )
    with sqlite3.connect(f"file:{runner_state_path}?mode=ro", uri=True) as runner:
        maximum_event_utc = int(
            runner.execute("SELECT COALESCE(MAX(utc_ns),0) FROM events").fetchone()[0]
        )
    if int(cast(list[dict[str, Any]], resource_segments["segments"])[-1]["last_utc_ns"]) < maximum_event_utc:
        raise LocalTopologyError("resource-monitor evidence does not cover the final runner event")
    output_root.mkdir(parents=True)
    public_inputs = {
        "config.json": config_path,
        "profile.json": profile_path,
        "deployment.json": deployment_path,
        "plan.json": plan_path,
        "preflight.json": preflight_path,
        "hyperlane-processes.json": hyperlane_process_path,
        "hyperlane-observer.jsonl": hyperlane_observer_path,
        "hyperlane-observer-completion.json": hyperlane_observer_completion_path,
        "root-signer-audit.jsonl": root_signer_audit_path,
        "incidents.json": incident_path,
        "resource-samples.jsonl": resource_monitor_path,
        "resource-segments.json": resource_segments_path,
        "effect-baseline.json": effect_baseline_path,
        "effect-audit.json": effect_audit_path,
        "phase-authority.json": phase_authority_path,
        "preregistration.json": preregistration_path,
        "review-closure.json": review_closure_path,
        "review-gate.json": review_gate_path,
        "topology.json": topology_path,
        "validator-volume-bootstrap.json": validator_volume_attestation_path,
        "validator-volume-transaction.json": validator_volume_journal_path,
        "toolchain-preflight.json": toolchain_preflight_path,
        "normalized-stages.schema.json": normalized_stage_schema_path,
        "stage-template-set.schema.json": stage_template_schema_path,
    }
    for name, source in public_inputs.items():
        _copy(source, output_root / name)
    _write_public_identity_manifest(
        identity_manifest_path, output_root / "identity-manifest.json"
    )
    prior_handoff_sources = {
        "smoke": smoke_handoff_path,
        "publication_smoke": publication_smoke_handoff_path,
    }
    required_prior = {
        "smoke": set(),
        "publication_smoke": {"smoke"},
        "scale": {"smoke", "publication_smoke"},
    }[phase]
    for prior_phase in sorted(required_prior):
        prior_source = prior_handoff_sources[prior_phase]
        if prior_source is None:
            raise LocalTopologyError(f"{prior_phase} predecessor handoff is missing")
        _copy(prior_source, output_root / "prior-phase-handoffs" / f"{prior_phase}.json")
    for segment_path, completion_path in verified_resource_segments:
        _copy(segment_path, output_root / "resource-segments" / segment_path.name)
        _copy(completion_path, output_root / "resource-segments" / completion_path.name)
    preregistration = cast(
        dict[str, Any],
        json.loads((output_root / "preregistration.json").read_text(encoding="utf-8")),
    )
    implementation_manifest: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-implementation-source-manifest-v1",
        "implementation_files": preregistration["implementation_source_sha256"],
        "implementation_source_policy": preregistration["implementation_source_policy"],
        "preregistration_sha256": _sha(output_root / "preregistration.json"),
    }
    implementation_manifest["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(implementation_manifest)
    ).hexdigest()
    _write(output_root / "implementation-source-manifest.json", implementation_manifest)
    for name, source in (
        ("runner.sqlite", runner_state_path),
        ("worker.sqlite", worker_state_path),
        ("traces.sqlite", trace_state_path),
    ):
        destination = output_root / name
        temporary = destination.with_name(f".{name}.{sqlite3.sqlite_version}.tmp")
        if temporary.exists():
            temporary.unlink()
        sqlite_backup(source, temporary)
        _normalize_frozen_sqlite(temporary)
        temporary.replace(destination)
    _validate_phase_authority(
        runner_database=output_root / "runner.sqlite",
        authority_path=output_root / "phase-authority.json",
        phase=phase,
        config_path=output_root / "config.json",
        plan_path=output_root / "plan.json",
        deployment_path=output_root / "deployment.json",
        preregistration_path=output_root / "preregistration.json",
        review_closure_path=output_root / "review-closure.json",
        review_gate_path=output_root / "review-gate.json",
        preflight_path=output_root / "preflight.json",
        validator_volume_attestation_path=output_root
        / "validator-volume-bootstrap.json",
        validator_volume_journal_path=output_root
        / "validator-volume-transaction.json",
        toolchain_preflight_path=output_root / "toolchain-preflight.json",
        smoke_handoff_path=(
            output_root / "prior-phase-handoffs/smoke.json"
            if "smoke" in required_prior
            else None
        ),
        publication_smoke_handoff_path=(
            output_root / "prior-phase-handoffs/publication_smoke.json"
            if "publication_smoke" in required_prior
            else None
        ),
    )
    private_raw = _freeze_private_raw_evidence(
        runner_database=output_root / "runner.sqlite",
        trace_database=output_root / "traces.sqlite",
        coordinator_signed_root=coordinator_signed_root,
        hyperlane_process_path=output_root / "hyperlane-processes.json",
        output_root=output_root,
    )
    config = cast(dict[str, Any], json.loads(config_path.read_text(encoding="utf-8")))
    profile = cast(dict[str, Any], json.loads(profile_path.read_text(encoding="utf-8")))
    repository_root = config_path.resolve().parents[2]
    for relative in sorted(cast(dict[str, str], config["source_sha256"])):
        _copy(repository_root / relative, output_root / "source-locks" / relative)
    component_lock = cast(dict[str, str], profile["component_lock"])
    _copy(
        repository_root / component_lock["relative_path"],
        output_root / "component-lock.json",
    )
    with sqlite3.connect(f"file:{output_root / 'runner.sqlite'}?mode=ro", uri=True) as connection:
        counts = {
            str(status): int(count)
            for status, count in connection.execute(
                "SELECT status,COUNT(*) FROM attempts WHERE phase=? GROUP BY status",
                (phase,),
            )
        }
        event_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
    evidence_name = evidence_namespace(config)
    expected = phase_attempt_count(config, phase)
    expected_effects = _expected_effect_lineage(
        runner_state_path=output_root / "runner.sqlite",
        trace_state_path=output_root / "traces.sqlite",
        phase=phase,
    )
    validate_effect_audit(
        cast(dict[str, Any], json.loads((output_root / "effect-audit.json").read_text())),
        phase=phase,
        expected_effects=expected_effects,
        expected_bindings={
            "baseline_sha256": _sha(output_root / "effect-baseline.json"),
            "config_sha256": _sha(output_root / "config.json"),
            "profile_sha256": _sha(output_root / "profile.json"),
            "deployment_sha256": _sha(output_root / "deployment.json"),
        },
        expected_namespace=evidence_name,
    )
    if counts != {"succeeded": expected}:
        raise LocalTopologyError("frozen runner denominator is not exact")
    root_audit_rows = [
        json.loads(line)
        for line in (output_root / "root-signer-audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if (
        len(root_audit_rows) != expected
        or len({str(row.get("transaction_hash", "")).lower() for row in root_audit_rows})
        != expected
        or any(not str(row.get("transaction_hash", "")) for row in root_audit_rows)
        or any(
            row.get("schema_version") != "xir-lab-finalized-root-signature-audit-v1"
            or row.get("signed") is not True
            or not isinstance(row.get("checks"), dict)
            or not cast(dict[str, bool], row["checks"])
            or not all(cast(dict[str, bool], row["checks"]).values())
            for row in root_audit_rows
        )
    ):
        raise LocalTopologyError("frozen root-signer audit is incomplete")
    with sqlite3.connect(f"file:{output_root / 'traces.sqlite'}?mode=ro", uri=True) as connection:
        trace_count = int(connection.execute("SELECT COUNT(*) FROM traces").fetchone()[0])
    if trace_count <= 0 or event_count <= expected:
        raise LocalTopologyError("frozen trace/event evidence is incomplete")
    findings = secret_scan(output_root)
    expected_private_findings = sorted(
        str(path.relative_to(output_root))
        for path in (output_root / "private-evidence").rglob("*.raw")
    )
    unexpected_findings = sorted(set(findings) - set(expected_private_findings))
    if unexpected_findings:
        raise LocalTopologyError("frozen multihop source contains unexpected sensitive material")
    files = [
        {
            "path": str(path.relative_to(output_root)),
            "bytes": path.stat().st_size,
            "sha256": _sha(path),
        }
        for path in sorted(output_root.rglob("*"))
        if path.is_file()
    ]
    manifest: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-frozen-source-v1",
        "namespace": evidence_name,
        "phase": phase,
        "attempt_counts": counts,
        "event_count": event_count,
        "trace_count": trace_count,
        "root_signer_audit_count": len(root_audit_rows),
        "effect_audit_count": expected,
        "evidence_class": "private_read_only_rebuild_input_not_for_public_sync",
        "public_sync_allowed": False,
        "private_evidence_findings": expected_private_findings,
        "unexpected_sensitive_material_findings": [],
        **private_raw,
        "sqlite_quick_check": {"runner": "ok", "worker": "ok", "traces": "ok"},
        "files": files,
    }
    manifest["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    _write(output_root / "frozen-source-manifest.json", manifest)
    return manifest


def _verify_frozen_source(source_root: Path) -> dict[str, Any]:
    manifest_path = source_root / "frozen-source-manifest.json"
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
    semantic = dict(manifest)
    expected_semantic = str(semantic.pop("semantic_sha256"))
    if hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() != expected_semantic:
        raise LocalTopologyError("frozen source semantic digest drift")
    findings = secret_scan(source_root)
    if sorted(findings) != sorted(cast(list[str], manifest["private_evidence_findings"])):
        raise LocalTopologyError("frozen source private-evidence inventory changed")
    for row in cast(list[dict[str, Any]], manifest["files"]):
        path = source_root / str(row["path"])
        if (
            not path.is_file()
            or path.stat().st_size != int(row["bytes"])
            or _sha(path) != row["sha256"]
        ):
            raise LocalTopologyError(f"frozen source file drift: {row['path']}")
    resource_manifest, _ = _verify_resource_segment_evidence(
        manifest_path=source_root / "resource-segments.json",
        combined_path=source_root / "resource-samples.jsonl",
        segment_root=source_root / "resource-segments",
    )
    _verify_observer_completion(
        ledger_path=source_root / "hyperlane-observer.jsonl",
        completion_path=source_root / "hyperlane-observer-completion.json",
        processes_path=source_root / "hyperlane-processes.json",
    )
    with sqlite3.connect(f"file:{source_root / 'runner.sqlite'}?mode=ro", uri=True) as runner:
        maximum_event_utc = int(
            runner.execute("SELECT COALESCE(MAX(utc_ns),0) FROM events").fetchone()[0]
        )
    if int(cast(list[dict[str, Any]], resource_manifest["segments"])[-1]["last_utc_ns"]) < maximum_event_utc:
        raise LocalTopologyError("frozen resource monitor does not cover runner events")
    for name in ("runner.sqlite", "worker.sqlite", "traces.sqlite"):
        with sqlite3.connect(f"file:{source_root / name}?mode=ro", uri=True) as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise LocalTopologyError(f"frozen SQLite quick check failed: {name}")
    _validate_phase_authority(
        runner_database=source_root / "runner.sqlite",
        authority_path=source_root / "phase-authority.json",
        phase=str(manifest["phase"]),
        config_path=source_root / "config.json",
        plan_path=source_root / "plan.json",
        deployment_path=source_root / "deployment.json",
        preregistration_path=source_root / "preregistration.json",
        review_closure_path=source_root / "review-closure.json",
        review_gate_path=source_root / "review-gate.json",
        preflight_path=source_root / "preflight.json",
        validator_volume_attestation_path=source_root
        / "validator-volume-bootstrap.json",
        validator_volume_journal_path=source_root
        / "validator-volume-transaction.json",
        toolchain_preflight_path=source_root / "toolchain-preflight.json",
        smoke_handoff_path=(
            source_root / "prior-phase-handoffs/smoke.json"
            if str(manifest["phase"]) in {"publication_smoke", "scale"}
            else None
        ),
        publication_smoke_handoff_path=(
            source_root / "prior-phase-handoffs/publication_smoke.json"
            if str(manifest["phase"]) == "scale"
            else None
        ),
    )
    frozen_config = cast(
        dict[str, Any],
        json.loads((source_root / "config.json").read_text(encoding="utf-8")),
    )
    frozen_profile, frozen_profile_sha256 = load_multihop_profile(
        source_root / "profile.json",
        component_lock_path_override=source_root / "component-lock.json",
    )
    if frozen_config.get("payload_schedule") != frozen_profile.get("payload"):
        raise LocalTopologyError("frozen config payload schedule differs from frozen profile")
    manifest_profile = next(
        (
            row
            for row in cast(list[dict[str, Any]], manifest["files"])
            if row["path"] == "profile.json"
        ),
        None,
    )
    if manifest_profile is None or str(manifest_profile["sha256"]) != frozen_profile_sha256:
        raise LocalTopologyError("frozen profile is not bound by the source manifest")
    load_multihop_config(
        source_root / "config.json",
        profile_path_override=source_root / "profile.json",
        component_lock_path_override=source_root / "component-lock.json",
        source_root_override=source_root / "source-locks",
    )
    root_audit_rows = [
        json.loads(line)
        for line in (source_root / "root-signer-audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    expected = phase_attempt_count(frozen_config, str(manifest["phase"]))
    if (
        len(root_audit_rows) != expected
        or len({str(row.get("transaction_hash", "")).lower() for row in root_audit_rows})
        != expected
        or any(
            row.get("schema_version") != "xir-lab-finalized-root-signature-audit-v1"
            or not str(row.get("transaction_hash", ""))
            or row.get("signed") is not True
            or not isinstance(row.get("checks"), dict)
            or not cast(dict[str, bool], row["checks"])
            or not all(cast(dict[str, bool], row["checks"]).values())
            for row in root_audit_rows
        )
    ):
        raise LocalTopologyError("frozen root-signer audit drift")
    return manifest


def rebuild_multihop_publication(*, source_root: Path, output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise LocalTopologyError("offline rebuild output already exists")
    source_manifest = _verify_frozen_source(source_root)
    phase = cast(MultihopPhase, source_manifest["phase"])
    publication_manifest = publish_multihop_analysis(
        config_path=source_root / "config.json",
        profile_path=source_root / "profile.json",
        component_lock_path=source_root / "component-lock.json",
        source_lock_root=source_root / "source-locks",
        phase=phase,
        runner_state_path=source_root / "runner.sqlite",
        worker_state_path=source_root / "worker.sqlite",
        hyperlane_process_path=source_root / "hyperlane-processes.json",
        root_signer_audit_path=source_root / "root-signer-audit.jsonl",
        deployment_path=source_root / "deployment.json",
        trace_state_path=source_root / "traces.sqlite",
        incident_path=source_root / "incidents.json",
        resource_monitor_path=source_root / "resource-samples.jsonl",
        effect_audit_path=source_root / "effect-audit.json",
        provenance_root=source_root,
        output_root=output_root,
    )
    findings = secret_scan(output_root)
    if findings:
        raise LocalTopologyError("offline publication contains sensitive material")
    provenance = {
        "schema_version": "xir-lab-native-multihop-rebuild-provenance-v1",
        "frozen_source_manifest_sha256": _sha(source_root / "frozen-source-manifest.json"),
        "publication_manifest_semantic_sha256": publication_manifest["semantic_sha256"],
        "read_only_inputs": True,
        "network_access_required": False,
    }
    _write(output_root / "rebuild-provenance.json", provenance)
    return publication_manifest


def compare_multihop_rebuilds(
    *, source_publication: Path, rebuild_a: Path, rebuild_b: Path, output_path: Path
) -> dict[str, Any]:
    document = _build_multihop_rebuild_comparison(
        source_publication=source_publication,
        rebuild_a=rebuild_a,
        rebuild_b=rebuild_b,
    )
    _write(output_path, document)
    return document


def _build_multihop_rebuild_comparison(
    *, source_publication: Path, rebuild_a: Path, rebuild_b: Path
) -> dict[str, Any]:
    def inventory(root: Path) -> dict[str, str]:
        return {
            str(path.relative_to(root)): _sha(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.name != "rebuild-provenance.json"
        }

    inventories = [inventory(root) for root in (source_publication, rebuild_a, rebuild_b)]
    valid = inventories[0] == inventories[1] == inventories[2]
    if not valid:
        raise LocalTopologyError("source publication and offline rebuilds differ")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-rebuild-comparison-v1",
        "valid": True,
        "byte_identical_files": inventories[0],
        "source_manifest_sha256": _sha(source_publication / "manifest.json"),
        "rebuild_a_manifest_sha256": _sha(rebuild_a / "manifest.json"),
        "rebuild_b_manifest_sha256": _sha(rebuild_b / "manifest.json"),
    }
    return document


def _build_multihop_handoff_document(
    *,
    frozen_source_root: Path,
    source_publication: Path,
    rebuild_a: Path,
    rebuild_b: Path,
    comparison_path: Path,
    review_closure_path: Path,
) -> dict[str, Any]:
    _verify_frozen_source(frozen_source_root)
    comparison = cast(dict[str, Any], json.loads(comparison_path.read_text(encoding="utf-8")))
    expected_comparison = _build_multihop_rebuild_comparison(
        source_publication=source_publication,
        rebuild_a=rebuild_a,
        rebuild_b=rebuild_b,
    )
    if comparison != expected_comparison:
        raise LocalTopologyError("persisted rebuild comparison differs from recomputed evidence")
    validation = cast(
        dict[str, Any],
        json.loads((source_publication / "validation.json").read_text(encoding="utf-8")),
    )
    frozen_preflight = cast(
        dict[str, Any],
        json.loads((frozen_source_root / "preflight.json").read_text(encoding="utf-8")),
    )
    review_closure = cast(
        dict[str, Any], json.loads(review_closure_path.read_text(encoding="utf-8"))
    )
    review_sha256 = _sha(review_closure_path)
    phase = str(validation.get("phase", ""))
    frozen_config = cast(
        dict[str, Any],
        json.loads((frozen_source_root / "config.json").read_text(encoding="utf-8")),
    )
    evidence_name = evidence_namespace(frozen_config)
    phase_contract = {
        name: (phase_attempt_count(frozen_config, name), phase_role(frozen_config, name))
        for name in ("smoke", "publication_smoke", "scale")
    }
    if phase not in phase_contract:
        raise LocalTopologyError("multihop handoff phase is invalid")
    expected_attempts, role = phase_contract[phase]
    all_gates = (
        comparison.get("valid") is True
        and validation.get("valid") is True
        and int(validation.get("attempt_count", -1)) == expected_attempts
        and frozen_preflight.get("review_closure_sha256") == review_sha256
        and review_closure.get("verdict") == "PASS"
        and int(review_closure.get("blockers", -1)) == 0
        and int(review_closure.get("majors", -1)) == 0
    )
    if not all_gates:
        raise LocalTopologyError("multihop handoff gates are incomplete")
    document: dict[str, Any] = {
        "schema_version": "xir-lab-native-multihop-final-handoff-v1",
        "namespace": evidence_name,
        "phase": phase,
        "role": role,
        "all_gates_pass": True,
        "frozen_source_manifest_sha256": _sha(frozen_source_root / "frozen-source-manifest.json"),
        "source_publication_manifest_sha256": _sha(source_publication / "manifest.json"),
        "rebuild_a_manifest_sha256": _sha(rebuild_a / "manifest.json"),
        "rebuild_b_manifest_sha256": _sha(rebuild_b / "manifest.json"),
        "comparison_sha256": _sha(comparison_path),
        "review_closure_sha256": review_sha256,
        "phase_authority_sha256": _sha(frozen_source_root / "phase-authority.json"),
        "public_provenance_sha256": {
            str(path.relative_to(source_publication / "provenance")): _sha(path)
            for path in sorted((source_publication / "provenance").rglob("*"))
            if path.is_file()
        },
        "prior_phase_handoffs": json.loads(
            (frozen_source_root / "phase-authority.json").read_text(encoding="utf-8")
        )["prior_phase_handoffs"],
        "attempt_count": validation["attempt_count"],
        "physical_transaction_count": validation["physical_transaction_count"],
        "receipt_count": validation["receipt_count"],
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    return document


def build_multihop_handoff(
    *,
    frozen_source_root: Path,
    source_publication: Path,
    rebuild_a: Path,
    rebuild_b: Path,
    comparison_path: Path,
    review_closure_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    document = _build_multihop_handoff_document(
        frozen_source_root=frozen_source_root,
        source_publication=source_publication,
        rebuild_a=rebuild_a,
        rebuild_b=rebuild_b,
        comparison_path=comparison_path,
        review_closure_path=review_closure_path,
    )
    _write(output_path, document)
    return document


def verify_multihop_handoff(
    *,
    frozen_source_root: Path,
    source_publication: Path,
    rebuild_a: Path,
    rebuild_b: Path,
    comparison_path: Path,
    review_closure_path: Path,
    handoff_path: Path,
) -> dict[str, Any]:
    """Recompute every handoff field and require exact persisted equality."""

    expected = _build_multihop_handoff_document(
        frozen_source_root=frozen_source_root,
        source_publication=source_publication,
        rebuild_a=rebuild_a,
        rebuild_b=rebuild_b,
        comparison_path=comparison_path,
        review_closure_path=review_closure_path,
    )
    actual = cast(dict[str, Any], json.loads(handoff_path.read_text(encoding="utf-8")))
    if actual != expected:
        raise LocalTopologyError("persisted multihop handoff differs from recomputed evidence")
    return actual


def verify_prior_phase_handoffs(
    *,
    phase: str,
    smoke_handoff_path: Path | None,
    publication_smoke_handoff_path: Path | None,
    verify_full_trees: bool = False,
    expected_namespace: str = "native-multihop-switching-v1",
) -> dict[str, dict[str, str]]:
    """Bind later phases to exact successful earlier phase handoffs."""

    required: tuple[tuple[str, Path | None, int, str], ...]
    if phase == "smoke":
        required = ()
    elif phase == "publication_smoke":
        required = (("smoke", smoke_handoff_path, 11, "development_gate_only"),)
    elif phase == "scale":
        required = (
            ("smoke", smoke_handoff_path, 11, "development_gate_only"),
            (
                "publication_smoke",
                publication_smoke_handoff_path,
                22,
                "publication_gate_not_formal_estimate",
            ),
        )
    else:
        raise LocalTopologyError("unknown multihop phase")
    digests: dict[str, dict[str, str]] = {}
    for expected_phase, path, expected_count, role in required:
        if path is None or not path.is_file():
            raise LocalTopologyError(f"{expected_phase} handoff is required")
        handoff = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        semantic = dict(handoff)
        expected_semantic = str(semantic.pop("semantic_sha256", ""))
        valid = (
            handoff.get("schema_version") == "xir-lab-native-multihop-final-handoff-v1"
            and handoff.get("namespace") == expected_namespace
            and handoff.get("phase") == expected_phase
            and handoff.get("role") == role
            and handoff.get("all_gates_pass") is True
            and int(handoff.get("attempt_count", -1)) == expected_count
            and hashlib.sha256(rfc8785.dumps(semantic)).hexdigest() == expected_semantic
        )
        if not valid:
            raise LocalTopologyError(f"{expected_phase} handoff is invalid")
        if verify_full_trees:
            phase_root = path.parent
            recomputed = verify_multihop_handoff(
                frozen_source_root=phase_root / "frozen-source",
                source_publication=phase_root / "source-publication",
                rebuild_a=phase_root / "rebuild-a",
                rebuild_b=phase_root / "rebuild-b",
                comparison_path=phase_root / "rebuild-comparison.json",
                review_closure_path=phase_root / "frozen-source/review-closure.json",
                handoff_path=path,
            )
            if recomputed != handoff:
                raise LocalTopologyError(
                    f"{expected_phase} handoff differs from its complete phase tree"
                )
        digests[expected_phase] = {
            "file_sha256": _sha(path),
            "semantic_sha256": expected_semantic,
        }
    return digests
