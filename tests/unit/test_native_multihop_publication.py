from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
import rfc8785
from eth_account import Account

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_deployer import CHAIN_ROLES
from xir_lab.native.multihop_process_identity import process_identity_sha256
from xir_lab.native.multihop_publication import (
    _freeze_private_raw_evidence,
    _validate_phase_authority,
    compare_multihop_rebuilds,
    freeze_multihop_sources,
    verify_prior_phase_handoffs,
)


def _file(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _database(path: Path, statements: str) -> Path:
    with sqlite3.connect(path) as connection:
        connection.executescript(statements)
    return path


def _semantic_file(path: Path, value: dict[str, object]) -> Path:
    value["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    return _file(path, value)


def _toolchain_preflight(tmp_path: Path) -> Path:
    return _semantic_file(
        tmp_path / "toolchain-preflight.json",
        {
            "schema_version": "xir-lab-native-multihop-toolchain-preflight-v1",
            "valid": True,
            "libclang_path": "/lib/libclang-18.so.18",
            "libclang_directory": "/lib",
            "libclang_sha256": "e" * 64,
        },
    )


def _volume_provenance(tmp_path: Path) -> tuple[Path, Path]:
    transaction = "a" * 48
    runtime_digest = "b" * 64
    image = "hyperledger/besu@sha256:" + "c" * 64
    image_id = "sha256:" + "d" * 64
    uid, gid = 1000, 1000
    attestation_rows: list[dict[str, object]] = []
    journal_rows: list[dict[str, object]] = []
    for index in range(20):
        name = f"xir-multihop-volume-{index}"
        labels = {
            "org.xir.environment": "controlled-local-qbft",
            "org.xir.purpose": "validator-data",
            "org.xir.namespace": "native-multihop-switching-v1",
            "org.xir.bootstrap-transaction": transaction,
            "org.xir.runtime-root-sha256": runtime_digest,
            "org.xir.network-id": f"xirlocalchain{index // 4 + 1}",
            "org.xir.validator-id": f"validator-{index % 4 + 1}",
        }
        stager_labels = {
            "org.xir.namespace": "native-multihop-switching-v1",
            "org.xir.bootstrap-transaction": transaction,
            "org.xir.runtime-root-sha256": runtime_digest,
        }
        genesis_sha = f"{index + 1:064x}"
        key_sha = f"{index + 101:064x}"
        attestation_rows.append(
            {
                "network_id": labels["org.xir.network-id"],
                "validator_id": labels["org.xir.validator-id"],
                "service_name": f"service-{index}",
                "image": image,
                "volume_name": name,
                "genesis_path": f"private/genesis-{index}.json",
                "genesis_sha256": genesis_sha,
                "validator_key_path": f"validator-material/key-{index}",
                "validator_key_sha256": key_sha,
                "labels": labels,
                "observed": {
                    "genesis_sha256": genesis_sha,
                    "validator_key_sha256": key_sha,
                    "root_uid": uid,
                    "root_gid": gid,
                    "root_mode": "700",
                    "bootstrap_uid": uid,
                    "bootstrap_gid": gid,
                    "bootstrap_mode": "700",
                    "genesis_uid": uid,
                    "genesis_gid": gid,
                    "genesis_mode": "644",
                    "key_uid": uid,
                    "key_gid": gid,
                    "key_mode": "600",
                    "runtime_uid": uid,
                    "runtime_gid": gid,
                },
            }
        )
        journal_rows.append(
            {
                "volume_name": name,
                "volume_labels": labels,
                "volume_create_intent": True,
                "volume_created": True,
                "volume_remove_intent": False,
                "volume_removed": False,
                "stager_name": f"xir-multihop-stager-{transaction[:16]}-{index}",
                "stager_labels": stager_labels,
                "stager_create_intent": True,
                "stager_created": True,
                "stager_start_intent": True,
                "stager_started": True,
                "stager_remove_intent": True,
                "stager_removed": True,
            }
        )
    attestation = _semantic_file(
        tmp_path / "validator-volume-bootstrap.json",
        {
            "schema_version": "xir-lab-native-multihop-validator-volume-bootstrap-v1",
            "namespace": "native-multihop-switching-v1",
            "valid": True,
            "transaction_id": transaction,
            "runtime_root_sha256": runtime_digest,
            "image": image,
            "image_id": image_id,
            "runtime_uid": uid,
            "runtime_gid": gid,
            "validator_volume_count": 20,
            "volumes": attestation_rows,
        },
    )
    journal = _semantic_file(
        tmp_path / "validator-volume-transaction.json",
        {
            "schema_version": "xir-lab-native-multihop-validator-volume-transaction-v1",
            "namespace": "native-multihop-switching-v1",
            "state": "committed",
            "transaction_id": transaction,
            "runtime_root_sha256": runtime_digest,
            "image": image,
            "image_id": image_id,
            "runtime_uid": uid,
            "runtime_gid": gid,
            "validator_volume_count": 20,
            "resources": journal_rows,
            "probes": [
                {
                    "probe_name": (
                        f"xir-multihop-probe-{transaction[:16]}-image-user"
                        if index == 0
                        else f"xir-multihop-probe-{transaction[:16]}-"
                        f"{'observe' if index % 2 else 'write'}-{(index - 1) // 2}"
                    ),
                    "probe_role": (
                        "image-user"
                        if index == 0
                        else "volume-observe"
                        if index % 2
                        else "volume-write"
                    ),
                    "volume_name": (
                        None if index == 0 else f"xir-multihop-volume-{(index - 1) // 2}"
                    ),
                    "probe_labels": {
                        "org.xir.namespace": "native-multihop-switching-v1",
                        "org.xir.bootstrap-transaction": transaction,
                        "org.xir.runtime-root-sha256": runtime_digest,
                        "org.xir.probe-role": (
                            "image-user"
                            if index == 0
                            else "volume-observe"
                            if index % 2
                            else "volume-write"
                        ),
                    },
                    "create_intent": True,
                    "created": True,
                    "start_intent": True,
                    "started": True,
                    "remove_intent": True,
                    "removed": True,
                }
                for index in range(41)
            ],
            "attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
            "attestation_semantic_sha256": json.loads(attestation.read_text(encoding="utf-8"))[
                "semantic_sha256"
            ],
            "cleanup_errors": [],
        },
    )
    return attestation, journal


def _process_identity(pid: int, label: str) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        "pid": pid,
        "boot_id": "boot",
        "starttime_ticks": pid * 10,
        "runtime_root": "/runtime",
        "executable": "/usr/bin/python3",
        "cmdline_sha256": ("a" if label == "observer" else "b") * 64,
    }
    document["identity_sha256"] = process_identity_sha256(document)
    return document


def test_freeze_uses_sqlite_backups_and_exact_smoke_denominator(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "configs/native").mkdir(parents=True)
    (repository / "locked").mkdir()
    (repository / "toolchain").mkdir()
    locked_source = _file(repository / "locked/source.json", {"frozen": True})
    component_lock = _file(repository / "toolchain/components.json", {"v": 1})
    signed = Account.create().sign_transaction(
        {
            "chainId": 1,
            "nonce": 0,
            "to": "0x1111111111111111111111111111111111111111",
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 1,
            "maxPriorityFeePerGas": 0,
            "data": b"",
            "type": 2,
        }
    )
    raw = bytes(signed.raw_transaction)
    transaction_hash = "0x" + signed.hash.hex().removeprefix("0x")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    runner = _database(
        tmp_path / "runner.sqlite",
        """
        CREATE TABLE attempts(
          attempt_id TEXT, phase TEXT, route TEXT, route_sequence INTEGER, status TEXT
        );
            CREATE TABLE events(
              event_id INTEGER, attempt_id TEXT, stage TEXT, event TEXT,
              chain_role TEXT, detail_json TEXT, utc_ns INTEGER
        );
        CREATE TABLE stages(
          attempt_id TEXT, stage TEXT, state TEXT, transaction_hash TEXT,
          detail_json TEXT, observed_at REAL
        );
        CREATE TABLE phase_authority(
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          authority_json TEXT NOT NULL,
          semantic_sha256 TEXT NOT NULL
        );
        """
        + "\n".join(
            f"INSERT INTO attempts VALUES('a{index}','smoke','H',{index},'succeeded');"
            for index in range(11)
        )
        + "\nINSERT INTO events VALUES(11,'a0','root_create','succeeded','a','{}',100);"
        + "\n"
        + "\n".join(
            (
                "INSERT INTO events VALUES("
                f"{index},'a{index}','destination_effect_observation','observed','b',"
                f'\'{{"mid":"0x{index + 101:064x}",'
                f'"delivery_transaction_hash":"{transaction_hash}"}}\',{101 + index});'
            )
            for index in range(11)
        )
        + "\n"
        + "\n".join(
            (
                f"INSERT INTO stages VALUES('a{index}',"
                "'destination_verify_deliver','succeeded',"
                f"'{transaction_hash}','{{\"raw_sha256\":\"{raw_sha256}\"}}',1.0);"
            )
            for index in range(11)
        ),
    )
    worker = _database(tmp_path / "worker.sqlite", "CREATE TABLE actions(id TEXT);")
    traces = _database(
        tmp_path / "traces.sqlite",
        """
        CREATE TABLE traces(
          chain_role TEXT, transaction_hash TEXT, raw_transaction_hex TEXT,
          raw_sha256 TEXT, trace_json TEXT
        );
        """
        + f"INSERT INTO traces VALUES('b','{transaction_hash}',"
        + f"'0x{raw.hex()}','{raw_sha256}',"
        + '\'{"status":1,"block_number":1,'
        + '"block_hash":"0x'
        + "aa" * 32
        + "\"}');",
    )
    signed_root = tmp_path / "private-signed-transactions"
    signed_root.mkdir()
    (signed_root / f"{transaction_hash}.raw").write_bytes(raw)
    inputs = {
        "config.json": _file(
            repository / "configs/native/config.json",
            {
                "source_sha256": {
                    "locked/source.json": hashlib.sha256(locked_source.read_bytes()).hexdigest()
                }
            },
        ),
        "profile.json": _file(
            tmp_path / "profile.json",
            {
                "component_lock": {
                    "relative_path": "toolchain/components.json",
                    "sha256": hashlib.sha256(component_lock.read_bytes()).hexdigest(),
                }
            },
        ),
        **{
            name: _file(tmp_path / name, {"name": name})
            for name in (
                "deployment.json",
                "plan.json",
                "incidents.json",
            )
        },
    }
    volume_attestation, volume_journal = _volume_provenance(tmp_path)
    toolchain_preflight = _toolchain_preflight(tmp_path)
    inputs["preflight.json"] = _semantic_file(
        tmp_path / "preflight.json",
        {
            "name": "preflight.json",
            "validator_volume_attestation_sha256": hashlib.sha256(
                volume_attestation.read_bytes()
            ).hexdigest(),
            "validator_volume_attestation_semantic_sha256": json.loads(
                volume_attestation.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "validator_volume_journal_sha256": hashlib.sha256(
                volume_journal.read_bytes()
            ).hexdigest(),
            "validator_volume_journal_semantic_sha256": json.loads(
                volume_journal.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "toolchain_preflight_sha256": hashlib.sha256(
                toolchain_preflight.read_bytes()
            ).hexdigest(),
            "toolchain_preflight_semantic_sha256": json.loads(
                toolchain_preflight.read_text(encoding="utf-8")
            )["semantic_sha256"],
        },
    )
    observer_blocks = {role: 10 for role in CHAIN_ROLES}
    inputs["hyperlane.json"] = _file(
        tmp_path / "hyperlane.json",
        {
            "messages": {"0x01": {"transaction_hash": transaction_hash}},
            "end_blocks": observer_blocks,
        },
    )
    hyperlane_observer = tmp_path / "hyperlane-observer.jsonl"
    observer_identity = _process_identity(7, "observer")
    relayer_identity = _process_identity(8, "relayer")
    hyperlane_observer.write_text(
        "".join(
            json.dumps(
                {
                    "schema_version": "xir-lab-native-multihop-hyperlane-observer-event-v1",
                    "event": event,
                    "source": "observer",
                    "chain_role": None,
                    "transaction_hash": None,
                    "block_number": None,
                    "utc_ns": utc,
                    "monotonic_ns": utc,
                    "boot_id": "boot",
                    "observer_process_id": 7,
                    "relayer_process_id": 8,
                    "observer_process_identity": observer_identity,
                    "relayer_process_identity": relayer_identity,
                    "observer_process_identity_sha256": observer_identity["identity_sha256"],
                    "relayer_process_identity_sha256": relayer_identity["identity_sha256"],
                },
                sort_keys=True,
            )
            + "\n"
            for event, utc in (("observer_started", 90), ("observer_stopped", 130))
        ),
        encoding="utf-8",
    )
    preregistration = _file(
        tmp_path / "preregistration.json",
        {
            "implementation_source_sha256": {
                "locked/source.json": hashlib.sha256(locked_source.read_bytes()).hexdigest()
            },
            "implementation_source_policy": {"include": ["locked/source.json"]},
        },
    )
    review_closure = _file(tmp_path / "review-closure.json", {"verdict": "PASS"})
    review_gate = _semantic_file(
        tmp_path / "review-gate.json",
        {
            "closure_sha256": hashlib.sha256(review_closure.read_bytes()).hexdigest(),
            "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        },
    )
    public_provenance = {
        "review-closure.json": review_closure,
        "review-gate.json": review_gate,
        **{
            name: _file(tmp_path / name, {"name": name})
            for name in (
                "topology.json",
                "identity-manifest.json",
                "normalized-stages.schema.json",
                "stage-template-set.schema.json",
            )
        },
    }
    resource_segment = tmp_path / "resource-samples.segment-000.jsonl"
    resource_segment.write_text(
        json.dumps(
            {
                "schema_version": "xir-lab-native-multihop-resource-sample-v1",
                "sequence": 0,
                "utc_ns": 1000,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    resource_monitor = tmp_path / "resource-samples.jsonl"
    resource_monitor.write_bytes(resource_segment.read_bytes())
    resource_completion_document = {
        "schema_version": "xir-lab-native-multihop-resource-segment-completion-v1",
        "valid": True,
        "path": resource_segment.name,
        "sha256": hashlib.sha256(resource_segment.read_bytes()).hexdigest(),
        "sample_count": 1,
        "sequence_start": 0,
        "sequence_end": 0,
        "last_utc_ns": 1000,
    }
    _file(
        resource_segment.with_suffix(".completion.json"),
        resource_completion_document,
    )
    resource_segments = _file(
        tmp_path / "resource-segments.json",
        {
            "schema_version": "xir-lab-native-multihop-resource-segments-v1",
            "valid": True,
            "segments": [resource_completion_document],
            "combined_path": "resource-samples.jsonl",
            "combined_sha256": hashlib.sha256(resource_monitor.read_bytes()).hexdigest(),
            "sample_count": 1,
        },
    )
    observer_completion = _file(
        tmp_path / "hyperlane-observer-completion.json",
        {
            "schema_version": "xir-lab-native-multihop-hyperlane-observer-completion-v1",
            "valid": True,
            "ledger_path": hyperlane_observer.name,
            "all_targets_scanned": True,
            "ledger_sha256": hashlib.sha256(hyperlane_observer.read_bytes()).hexdigest(),
            "target_blocks": observer_blocks,
            "next_blocks": {role: 11 for role in CHAIN_ROLES},
        },
    )
    root_audit = tmp_path / "root-signer-audit.jsonl"
    root_audit.write_text(
        "".join(
            json.dumps(
                {
                    "schema_version": "xir-lab-finalized-root-signature-audit-v1",
                    "transaction_hash": f"0x{index:064x}",
                    "signed": True,
                    "checks": {"finalized": True},
                },
                sort_keys=True,
            )
            + "\n"
            for index in range(11)
        ),
        encoding="utf-8",
    )
    effect_baseline = _semantic_file(
        tmp_path / "effect-baseline.json",
        {
            "schema_version": "xir-lab-native-multihop-effect-baseline-v1",
            "namespace": "native-multihop-switching-v1",
            "receivers": [],
        },
    )
    effects = [
        {
            "attempt_id": f"a{index}",
            "chain_role": "b",
            "route": "H",
            "route_sequence": index,
            "transaction_hash": transaction_hash,
            "message_id": "0x" + f"{index + 101:064x}",
            "block_number": 1,
            "block_hash": "0x" + "aa" * 32,
            "log_index": index,
            "status": 1,
        }
        for index in range(11)
    ]
    receiver_checks = [
        {
            "chain_role": role,
            "start_block_inclusive": 0,
            "end_block_inclusive": 2,
            "start_block_hash": "0x" + "cc" * 32,
            "end_block_hash": "0x" + "dd" * 32,
            "delivery_count_before": 0,
            "delivery_count_after": 11 if role == "b" else 0,
            "counter_delta": 11 if role == "b" else 0,
            "event_count": 11 if role == "b" else 0,
            "expected_delta": 11 if role == "b" else 0,
            "scan_windows": [{"from_block": 1, "to_block": 2}],
        }
        for role in CHAIN_ROLES[1:]
    ]
    effect_audit = _semantic_file(
        tmp_path / "effect-audit.json",
        {
            "schema_version": "xir-lab-native-multihop-effect-reconciliation-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "smoke",
            "baseline_sha256": hashlib.sha256(effect_baseline.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(inputs["config.json"].read_bytes()).hexdigest(),
            "profile_sha256": hashlib.sha256(inputs["profile.json"].read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(inputs["deployment.json"].read_bytes()).hexdigest(),
            "valid": True,
            "expected_effect_count": 11,
            "observed_effect_count": 11,
            "complete_block_range_scanned": True,
            "receiver_counters_reconciled": True,
            "receiver_checks": receiver_checks,
            "effects": effects,
        },
    )
    lease_identity = {"holder": "fixture", "acquired_utc_ns": "1"}
    phase_authority = _semantic_file(
        tmp_path / "phase-authority.json",
        {
            "schema_version": "xir-lab-native-multihop-phase-authority-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "smoke",
            "prior_phase_handoffs": {},
            "review_gate_sha256": hashlib.sha256(review_gate.read_bytes()).hexdigest(),
            "review_closure_sha256": hashlib.sha256(review_closure.read_bytes()).hexdigest(),
            "lease_identity": lease_identity,
            "lease_identity_sha256": hashlib.sha256(rfc8785.dumps(lease_identity)).hexdigest(),
            "preflight_sha256": hashlib.sha256(inputs["preflight.json"].read_bytes()).hexdigest(),
            "preflight_semantic_sha256": json.loads(
                inputs["preflight.json"].read_text(encoding="utf-8")
            )["semantic_sha256"],
            "validator_volume_attestation_sha256": hashlib.sha256(
                volume_attestation.read_bytes()
            ).hexdigest(),
            "validator_volume_attestation_semantic_sha256": json.loads(
                volume_attestation.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "validator_volume_journal_sha256": hashlib.sha256(
                volume_journal.read_bytes()
            ).hexdigest(),
            "validator_volume_journal_semantic_sha256": json.loads(
                volume_journal.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "toolchain_preflight_sha256": hashlib.sha256(
                toolchain_preflight.read_bytes()
            ).hexdigest(),
            "toolchain_preflight_semantic_sha256": json.loads(
                toolchain_preflight.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "config_sha256": hashlib.sha256(inputs["config.json"].read_bytes()).hexdigest(),
            "plan_sha256": hashlib.sha256(inputs["plan.json"].read_bytes()).hexdigest(),
            "deployment_sha256": hashlib.sha256(inputs["deployment.json"].read_bytes()).hexdigest(),
            "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        },
    )
    authority_document = json.loads(phase_authority.read_text(encoding="utf-8"))
    with sqlite3.connect(runner) as connection:
        connection.execute(
            "INSERT INTO phase_authority VALUES(1,?,?)",
            (
                json.dumps(authority_document, sort_keys=True, separators=(",", ":")),
                authority_document["semantic_sha256"],
            ),
        )
    output = tmp_path / "frozen"
    manifest = freeze_multihop_sources(
        phase="smoke",
        config_path=inputs["config.json"],
        profile_path=inputs["profile.json"],
        deployment_path=inputs["deployment.json"],
        plan_path=inputs["plan.json"],
        preflight_path=inputs["preflight.json"],
        runner_state_path=runner,
        worker_state_path=worker,
        trace_state_path=traces,
        hyperlane_process_path=inputs["hyperlane.json"],
        hyperlane_observer_path=hyperlane_observer,
        hyperlane_observer_completion_path=observer_completion,
        root_signer_audit_path=root_audit,
        incident_path=inputs["incidents.json"],
        resource_monitor_path=resource_monitor,
        resource_segments_path=resource_segments,
        effect_baseline_path=effect_baseline,
        effect_audit_path=effect_audit,
        coordinator_signed_root=signed_root,
        phase_authority_path=phase_authority,
        smoke_handoff_path=None,
        publication_smoke_handoff_path=None,
        preregistration_path=preregistration,
        review_closure_path=public_provenance["review-closure.json"],
        review_gate_path=public_provenance["review-gate.json"],
        topology_path=public_provenance["topology.json"],
        identity_manifest_path=public_provenance["identity-manifest.json"],
        validator_volume_attestation_path=volume_attestation,
        validator_volume_journal_path=volume_journal,
        toolchain_preflight_path=toolchain_preflight,
        normalized_stage_schema_path=public_provenance["normalized-stages.schema.json"],
        stage_template_schema_path=public_provenance["stage-template-set.schema.json"],
        output_root=output,
    )
    assert manifest["attempt_counts"] == {"succeeded": 11}
    assert manifest["sqlite_quick_check"] == {
        "runner": "ok",
        "worker": "ok",
        "traces": "ok",
    }
    assert manifest["root_signer_audit_count"] == 11
    assert (output / "component-lock.json").is_file()
    assert (output / "source-locks/locked/source.json").is_file()
    assert (output / "resource-samples.jsonl").is_file()
    assert (output / "resource-segments.json").is_file()
    assert (output / "implementation-source-manifest.json").is_file()
    assert (output / "review-closure.json").is_file()
    assert (output / "normalized-stages.schema.json").is_file()
    assert manifest["public_sync_allowed"] is False
    assert manifest["coordinator_signed_transaction_count"] == 1
    assert manifest["hyperlane_raw_transaction_count"] == 1
    assert (
        output / "private-evidence/coordinator-signed-transactions" / f"{transaction_hash}.raw"
    ).read_bytes() == raw
    assert (output / "validator-volume-transaction.json").is_file()

    replaced_attestation = json.loads(volume_attestation.read_text(encoding="utf-8"))
    replaced_attestation["volumes"][0]["service_name"] = "self-consistent-substitute"
    replaced_attestation.pop("semantic_sha256")
    _semantic_file(volume_attestation, replaced_attestation)
    replaced_journal = json.loads(volume_journal.read_text(encoding="utf-8"))
    replaced_journal["attestation_sha256"] = hashlib.sha256(
        volume_attestation.read_bytes()
    ).hexdigest()
    replaced_journal["attestation_semantic_sha256"] = replaced_attestation["semantic_sha256"]
    replaced_journal.pop("semantic_sha256")
    _semantic_file(volume_journal, replaced_journal)
    with pytest.raises(LocalTopologyError, match="phase authority file is invalid"):
        _validate_phase_authority(
            runner_database=runner,
            authority_path=phase_authority,
            phase="smoke",
            config_path=inputs["config.json"],
            plan_path=inputs["plan.json"],
            deployment_path=inputs["deployment.json"],
            preregistration_path=preregistration,
            review_closure_path=review_closure,
            review_gate_path=review_gate,
            preflight_path=inputs["preflight.json"],
            validator_volume_attestation_path=volume_attestation,
            validator_volume_journal_path=volume_journal,
            toolchain_preflight_path=toolchain_preflight,
            smoke_handoff_path=None,
            publication_smoke_handoff_path=None,
        )


def test_rebuild_comparison_ignores_only_rebuild_provenance(tmp_path: Path) -> None:
    roots = [tmp_path / name for name in ("source", "a", "b")]
    for root in roots:
        root.mkdir()
        (root / "analysis.json").write_text("same\n", encoding="utf-8")
        (root / "manifest.json").write_text("manifest\n", encoding="utf-8")
    for root in roots[1:]:
        (root / "rebuild-provenance.json").write_text("different\n", encoding="utf-8")
    result = compare_multihop_rebuilds(
        source_publication=roots[0],
        rebuild_a=roots[1],
        rebuild_b=roots[2],
        output_path=tmp_path / "comparison.json",
    )
    assert result["valid"] is True


def test_phase_authority_rejects_a_different_self_consistent_runner_singleton(
    tmp_path: Path,
) -> None:
    volume_attestation, volume_journal = _volume_provenance(tmp_path)
    toolchain_preflight = _toolchain_preflight(tmp_path)
    inputs = {
        name: _semantic_file(tmp_path / name, {"name": name})
        for name in ("config.json", "plan.json", "deployment.json", "preflight.json")
    }
    preflight_document = json.loads(inputs["preflight.json"].read_text(encoding="utf-8"))
    preflight_document.update(
        {
            "validator_volume_attestation_sha256": hashlib.sha256(
                volume_attestation.read_bytes()
            ).hexdigest(),
            "validator_volume_attestation_semantic_sha256": json.loads(
                volume_attestation.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "validator_volume_journal_sha256": hashlib.sha256(
                volume_journal.read_bytes()
            ).hexdigest(),
                "validator_volume_journal_semantic_sha256": json.loads(
                    volume_journal.read_text(encoding="utf-8")
                )["semantic_sha256"],
                "toolchain_preflight_sha256": hashlib.sha256(
                    toolchain_preflight.read_bytes()
                ).hexdigest(),
                "toolchain_preflight_semantic_sha256": json.loads(
                    toolchain_preflight.read_text(encoding="utf-8")
                )["semantic_sha256"],
        }
    )
    preflight_document["semantic_sha256"] = hashlib.sha256(
        rfc8785.dumps(
            {key: value for key, value in preflight_document.items() if key != "semantic_sha256"}
        )
    ).hexdigest()
    _file(inputs["preflight.json"], preflight_document)
    preregistration = _file(tmp_path / "preregistration.json", {"status": "closed"})
    review_closure = _file(tmp_path / "review-closure.json", {"verdict": "PASS"})
    review_gate = _semantic_file(
        tmp_path / "review-gate.json",
        {
            "closure_sha256": hashlib.sha256(review_closure.read_bytes()).hexdigest(),
            "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        },
    )
    lease_identity = {"holder": "fixture", "acquired_utc_ns": "1"}
    authority = {
        "schema_version": "xir-lab-native-multihop-phase-authority-v1",
        "namespace": "native-multihop-switching-v1",
        "phase": "smoke",
        "prior_phase_handoffs": {},
        "review_gate_sha256": hashlib.sha256(review_gate.read_bytes()).hexdigest(),
        "review_closure_sha256": hashlib.sha256(review_closure.read_bytes()).hexdigest(),
        "lease_identity": lease_identity,
        "lease_identity_sha256": hashlib.sha256(rfc8785.dumps(lease_identity)).hexdigest(),
        "preflight_sha256": hashlib.sha256(inputs["preflight.json"].read_bytes()).hexdigest(),
        "preflight_semantic_sha256": json.loads(
            inputs["preflight.json"].read_text(encoding="utf-8")
        )["semantic_sha256"],
        "validator_volume_attestation_sha256": preflight_document[
            "validator_volume_attestation_sha256"
        ],
        "validator_volume_attestation_semantic_sha256": preflight_document[
            "validator_volume_attestation_semantic_sha256"
        ],
        "validator_volume_journal_sha256": preflight_document["validator_volume_journal_sha256"],
        "validator_volume_journal_semantic_sha256": preflight_document[
            "validator_volume_journal_semantic_sha256"
        ],
        "toolchain_preflight_sha256": preflight_document["toolchain_preflight_sha256"],
        "toolchain_preflight_semantic_sha256": preflight_document[
            "toolchain_preflight_semantic_sha256"
        ],
        "config_sha256": hashlib.sha256(inputs["config.json"].read_bytes()).hexdigest(),
        "plan_sha256": hashlib.sha256(inputs["plan.json"].read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(inputs["deployment.json"].read_bytes()).hexdigest(),
        "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
    }
    authority["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(authority)).hexdigest()
    authority_path = _file(tmp_path / "authority.json", authority)
    database = _database(
        tmp_path / "runner.sqlite",
        "CREATE TABLE phase_authority(singleton INTEGER,authority_json TEXT,semantic_sha256 TEXT);",
    )
    different = dict(authority)
    different["phase"] = "scale"
    payload = dict(different)
    payload.pop("semantic_sha256")
    different["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO phase_authority VALUES(1,?,?)",
            (
                json.dumps(different, sort_keys=True, separators=(",", ":")),
                different["semantic_sha256"],
            ),
        )
    with pytest.raises(LocalTopologyError, match="runner/file"):
        _validate_phase_authority(
            runner_database=database,
            authority_path=authority_path,
            phase="smoke",
            config_path=inputs["config.json"],
            plan_path=inputs["plan.json"],
            deployment_path=inputs["deployment.json"],
            preregistration_path=preregistration,
            review_closure_path=review_closure,
            review_gate_path=review_gate,
            preflight_path=inputs["preflight.json"],
            validator_volume_attestation_path=volume_attestation,
            validator_volume_journal_path=volume_journal,
            toolchain_preflight_path=toolchain_preflight,
            smoke_handoff_path=None,
            publication_smoke_handoff_path=None,
        )


def test_phase_authority_rejects_self_consistent_wrong_frozen_config(tmp_path: Path) -> None:
    volume_attestation, volume_journal = _volume_provenance(tmp_path)
    toolchain_preflight = _toolchain_preflight(tmp_path)
    config = _file(tmp_path / "config.json", {"actual": True})
    other = _file(tmp_path / "other-config.json", {"actual": False})
    plan = _file(tmp_path / "plan.json", {"plan": True})
    deployment = _file(tmp_path / "deployment.json", {"deployment": True})
    preregistration = _file(tmp_path / "preregistration.json", {"status": "closed"})
    closure = _file(tmp_path / "review-closure.json", {"verdict": "PASS"})
    gate = _file(
        tmp_path / "review-gate.json",
        {
            "closure_sha256": hashlib.sha256(closure.read_bytes()).hexdigest(),
            "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        },
    )
    preflight = _semantic_file(
        tmp_path / "preflight.json",
        {
            "valid": True,
            "validator_volume_attestation_sha256": hashlib.sha256(
                volume_attestation.read_bytes()
            ).hexdigest(),
            "validator_volume_attestation_semantic_sha256": json.loads(
                volume_attestation.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "validator_volume_journal_sha256": hashlib.sha256(
                volume_journal.read_bytes()
            ).hexdigest(),
            "validator_volume_journal_semantic_sha256": json.loads(
                volume_journal.read_text(encoding="utf-8")
            )["semantic_sha256"],
            "toolchain_preflight_sha256": hashlib.sha256(
                toolchain_preflight.read_bytes()
            ).hexdigest(),
            "toolchain_preflight_semantic_sha256": json.loads(
                toolchain_preflight.read_text(encoding="utf-8")
            )["semantic_sha256"],
        },
    )
    lease_identity = {"holder": "fixture", "acquired_utc_ns": "1"}
    authority: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-phase-authority-v1",
        "namespace": "native-multihop-switching-v1",
        "phase": "smoke",
        "prior_phase_handoffs": {},
        "review_gate_sha256": hashlib.sha256(gate.read_bytes()).hexdigest(),
        "review_closure_sha256": hashlib.sha256(closure.read_bytes()).hexdigest(),
        "lease_identity": lease_identity,
        "lease_identity_sha256": hashlib.sha256(rfc8785.dumps(lease_identity)).hexdigest(),
        "preflight_sha256": hashlib.sha256(preflight.read_bytes()).hexdigest(),
        "preflight_semantic_sha256": json.loads(preflight.read_text())["semantic_sha256"],
        "validator_volume_attestation_sha256": json.loads(preflight.read_text(encoding="utf-8"))[
            "validator_volume_attestation_sha256"
        ],
        "validator_volume_attestation_semantic_sha256": json.loads(
            preflight.read_text(encoding="utf-8")
        )["validator_volume_attestation_semantic_sha256"],
        "validator_volume_journal_sha256": json.loads(preflight.read_text(encoding="utf-8"))[
            "validator_volume_journal_sha256"
        ],
        "validator_volume_journal_semantic_sha256": json.loads(
            preflight.read_text(encoding="utf-8")
        )["validator_volume_journal_semantic_sha256"],
        "toolchain_preflight_sha256": json.loads(preflight.read_text(encoding="utf-8"))[
            "toolchain_preflight_sha256"
        ],
        "toolchain_preflight_semantic_sha256": json.loads(
            preflight.read_text(encoding="utf-8")
        )["toolchain_preflight_semantic_sha256"],
        "config_sha256": hashlib.sha256(other.read_bytes()).hexdigest(),
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "deployment_sha256": hashlib.sha256(deployment.read_bytes()).hexdigest(),
        "preregistration_sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
    }
    authority["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(authority)).hexdigest()
    authority_path = _file(tmp_path / "authority.json", authority)
    database = _database(
        tmp_path / "runner.sqlite",
        "CREATE TABLE phase_authority(singleton INTEGER,authority_json TEXT,semantic_sha256 TEXT);",
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO phase_authority VALUES(1,?,?)",
            (
                json.dumps(authority, sort_keys=True, separators=(",", ":")),
                authority["semantic_sha256"],
            ),
        )
    with pytest.raises(LocalTopologyError, match="phase authority file is invalid"):
        _validate_phase_authority(
            runner_database=database,
            authority_path=authority_path,
            phase="smoke",
            config_path=config,
            plan_path=plan,
            deployment_path=deployment,
            preregistration_path=preregistration,
            review_closure_path=closure,
            review_gate_path=gate,
            preflight_path=preflight,
            validator_volume_attestation_path=volume_attestation,
            validator_volume_journal_path=volume_journal,
            toolchain_preflight_path=toolchain_preflight,
            smoke_handoff_path=None,
            publication_smoke_handoff_path=None,
        )


def test_prior_phase_handoff_binds_file_and_semantic_digests(tmp_path: Path) -> None:
    handoff = _semantic_file(
        tmp_path / "smoke-handoff.json",
        {
            "schema_version": "xir-lab-native-multihop-final-handoff-v1",
            "namespace": "native-multihop-switching-v1",
            "phase": "smoke",
            "role": "development_gate_only",
            "all_gates_pass": True,
            "attempt_count": 11,
        },
    )
    result = verify_prior_phase_handoffs(
        phase="publication_smoke",
        smoke_handoff_path=handoff,
        publication_smoke_handoff_path=None,
    )
    document = json.loads(handoff.read_text(encoding="utf-8"))
    assert result == {
        "smoke": {
            "file_sha256": hashlib.sha256(handoff.read_bytes()).hexdigest(),
            "semantic_sha256": document["semantic_sha256"],
        }
    }
    document["attempt_count"] = 12
    _file(handoff, document)
    with pytest.raises(LocalTopologyError, match="handoff is invalid"):
        verify_prior_phase_handoffs(
            phase="publication_smoke",
            smoke_handoff_path=handoff,
            publication_smoke_handoff_path=None,
        )


def test_private_raw_freeze_rejects_unbound_or_drifted_raw(tmp_path: Path) -> None:
    signed = Account.create().sign_transaction(
        {
            "chainId": 1,
            "nonce": 0,
            "to": "0x1111111111111111111111111111111111111111",
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 1,
            "maxPriorityFeePerGas": 0,
            "data": b"",
            "type": 2,
        }
    )
    raw = bytes(signed.raw_transaction)
    transaction_hash = "0x" + signed.hash.hex().removeprefix("0x")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    runner = _database(
        tmp_path / "runner.sqlite",
        "CREATE TABLE stages(transaction_hash TEXT,detail_json TEXT);"
        + f"INSERT INTO stages VALUES('{transaction_hash}',"
        + f'\'{{"raw_sha256":"{raw_sha256}"}}\');',
    )
    traces = _database(
        tmp_path / "traces.sqlite",
        "CREATE TABLE traces(chain_role TEXT,transaction_hash TEXT,"
        "raw_transaction_hex TEXT,raw_sha256 TEXT);"
        + f"INSERT INTO traces VALUES('b','{transaction_hash}',"
        + f"'0x{raw.hex()}','{raw_sha256}');",
    )
    hyperlane = _file(
        tmp_path / "hyperlane.json",
        {"messages": {"m": {"transaction_hash": transaction_hash}}},
    )
    signed_root = tmp_path / "signed"
    signed_root.mkdir()
    (signed_root / f"{transaction_hash}.raw").write_bytes(raw)
    orphan_path = signed_root / ("0x" + "22" * 32 + ".raw")
    orphan_path.write_bytes(b"orphan")
    with pytest.raises(LocalTopologyError, match="inventory differs"):
        _freeze_private_raw_evidence(
            runner_database=runner,
            trace_database=traces,
            coordinator_signed_root=signed_root,
            hyperlane_process_path=hyperlane,
            output_root=tmp_path / "frozen-extra",
        )
    orphan_path.unlink()
    (signed_root / f"{transaction_hash}.raw").write_bytes(b"drift")
    with pytest.raises(LocalTopologyError, match="identity mismatch"):
        _freeze_private_raw_evidence(
            runner_database=runner,
            trace_database=traces,
            coordinator_signed_root=signed_root,
            hyperlane_process_path=hyperlane,
            output_root=tmp_path / "frozen-drift",
        )
