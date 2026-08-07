from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import MethodType

import pytest
from eth_abi import encode
from eth_utils import keccak  # type: ignore[attr-defined]
from web3.exceptions import Web3RPCError

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.ablation_v1 import (
    LAYERS,
    LAYERZERO_BASELINE_WRAPPER_BYTES,
    LAYERZERO_MESSAGE_LIMIT_BYTES,
    MECHANISMS,
    ROUTES,
    NativeAblationRunner,
    _incident_free_latency_analysis,
    _index_layerzero_actions,
    _moving_block_interval,
    _render_waterfall,
    _write_manifest,
    ablation_route_id,
    build_ablation_plan,
    encode_b1_wire_payload,
    load_ablation_config,
    rebuild_ablation_publication,
    validate_ablation_plan,
    validate_publication_tree,
    write_plan,
)
from xir_lab.native.deployer import gateway_typed_id
from xir_lab.native.xir_trace import XIRContext, XIRRecord, message_id, root_id

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "native" / "native-ablation-v1.json"


def test_config_and_smoke_plan_are_valid_and_balanced(tmp_path: Path) -> None:
    config, digest = load_ablation_config(CONFIG)
    assert len(digest) == 64
    plan = build_ablation_plan(config_path=CONFIG, phase="smoke")
    per_cell = int(config["smoke_attempts_per_cell"])
    assert len(plan) == per_cell * len(ROUTES) * len(LAYERS)
    for route in ROUTES:
        for layer in LAYERS:
            assert (
                sum(entry.attempt.route == route and entry.layer == layer for entry in plan)
                == per_cell
            )
    output = tmp_path / "plan.json"
    first = write_plan(output, plan)
    second = write_plan(output, plan)
    assert first == second
    assert json.loads(output.read_text(encoding="utf-8"))["attempt_count"] == 16


def test_ablation_entry_retries_transient_read_only_rpc_failure() -> None:
    entry = build_ablation_plan(config_path=CONFIG, phase="smoke")[0]
    runner = object.__new__(NativeAblationRunner)

    class State:
        @staticmethod
        def begin(_attempt: object) -> bool:
            return True

    runner.state = State()  # type: ignore[assignment]
    runner.timeout_seconds = 2
    calls = 0

    def execute(_self: object, _entry: object, *, started: float) -> None:
        nonlocal calls
        assert started > 0
        calls += 1
        if calls == 1:
            raise Web3RPCError({"code": -32603, "message": "Internal error"})

    runner._execute_entry = MethodType(execute, runner)  # type: ignore[method-assign]
    runner._run_entry(entry)
    assert calls == 2


def test_layerzero_actions_are_indexed_once_by_normalized_guid() -> None:
    worker = sqlite3.connect(":memory:")
    worker.row_factory = sqlite3.Row
    worker.execute(
        """
        CREATE TABLE actions(
          guid TEXT NOT NULL,
          stage TEXT NOT NULL,
          destination_chain_id INTEGER NOT NULL,
          transaction_hash TEXT,
          status TEXT NOT NULL
        )
        """
    )
    worker.executemany(
        "INSERT INTO actions VALUES (?, ?, ?, ?, ?)",
        [
            ("0xAbC", "executor_execute", 3, "0x03", "succeeded"),
            ("0xAbC", "commit_verification", 3, "0x02", "succeeded"),
            ("0xAbC", "dvn_execute", 3, "0x01", "succeeded"),
            ("0xDEF", "dvn_execute", 2, "0x04", "succeeded"),
        ],
    )

    indexed = _index_layerzero_actions(worker)

    assert sorted(indexed) == ["0xabc", "0xdef"]
    assert [str(row["stage"]) for row in indexed["0xabc"]] == [
        "commit_verification",
        "dvn_execute",
        "executor_execute",
    ]


def test_plan_is_deterministic_and_interleaved() -> None:
    first = build_ablation_plan(config_path=CONFIG, phase="smoke")
    second = build_ablation_plan(config_path=CONFIG, phase="smoke")
    assert first == second
    for block in range(2):
        rows = [entry for entry in first if entry.interleave_block == block]
        assert {(row.attempt.route, row.layer) for row in rows} == {
            (route, layer) for route in ROUTES for layer in LAYERS
        }
        assert len({row.attempt.payload_sha256 for row in rows}) == 1
        assert sorted(row.interleave_slot for row in rows) == list(range(8))


def test_mechanisms_are_strictly_nested() -> None:
    prior: set[str] = set()
    for layer in LAYERS:
        current = set(MECHANISMS[layer])
        assert prior < current or layer == "B0"
        assert prior.issubset(current)
        prior = current


def test_every_scale_b1_wire_object_fits_the_native_layerzero_limit() -> None:
    plan = build_ablation_plan(config_path=CONFIG, phase="scale")
    for entry in plan:
        if entry.layer != "B1" or entry.attempt.route != "HL":
            continue
        application = bytes(entry.attempt.payload_bytes)
        payload = encode(
            ["(bytes32,bytes2,uint64,bytes)"],
            [
                (
                    keccak(text=entry.attempt.attempt_id),
                    entry.attempt.route.encode("ascii"),
                    entry.attempt.route_sequence,
                    application,
                )
            ],
        )
        record = XIRRecord(
            source_gateway=gateway_typed_id(910001),
            source_app=(1, bytes.fromhex("11" * 20)),
            destination_app=(1, bytes.fromhex("22" * 20)),
            nonce=entry.logical_nonce,
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
        rid = root_id(record, context, 1)
        wire = encode_b1_wire_payload(
            payload=payload,
            record=record,
            context=context,
            rid=rid,
            mid=message_id(rid, record.destination_app),
        )
        assert len(wire) + LAYERZERO_BASELINE_WRAPPER_BYTES <= LAYERZERO_MESSAGE_LIMIT_BYTES


def test_validator_rejects_a_missing_cell() -> None:
    plan = list(build_ablation_plan(config_path=CONFIG, phase="smoke"))
    with pytest.raises(LocalTopologyError, match="unbalanced"):
        validate_ablation_plan(plan[:-1], expected_per_cell=2)


def test_route_ids_are_cell_specific() -> None:
    ids = {ablation_route_id(route, layer) for route in ROUTES for layer in ("B0", "B1")}
    assert len(ids) == 4
    with pytest.raises(LocalTopologyError):
        ablation_route_id("HL", "B2")  # type: ignore[arg-type]


def test_block_bootstrap_is_deterministic() -> None:
    first = _moving_block_interval(
        [float(value) for value in range(32)],
        repetitions=1000,
        block_length=4,
        confidence=0.95,
        seed=17,
        statistic="mean",
    )
    second = _moving_block_interval(
        [float(value) for value in range(32)],
        repetitions=1000,
        block_length=4,
        confidence=0.95,
        seed=17,
        statistic="mean",
    )
    assert first == second
    assert first[1] <= first[0] <= first[2]


def test_incident_latency_sensitivity_excludes_complete_matched_block() -> None:
    rows = []
    slot = 0
    for sequence in range(3):
        for route in ROUTES:
            for layer_index, layer in enumerate(LAYERS):
                rows.append(
                    {
                        "attempt_id": f"attempt-{sequence}-{route}-{layer}",
                        "route": route,
                        "layer": layer,
                        "pair_id": f"pair-{sequence}",
                        "sequence": sequence,
                        "interleave_block": sequence,
                        "interleave_slot": slot % 8,
                        "latency_seconds": float(sequence + layer_index),
                    }
                )
                slot += 1
    rule = {
        "phase": "scale",
        "rule_id": "test-rule",
        "selection_unit": "deterministic_interleave_block",
        "excluded_route_sequences": [1],
        "exclusion_reason": "test incident",
        "full_matched_blocks": 3,
        "expected_included_blocks": 2,
        "expected_excluded_blocks": 1,
        "expected_included_attempts": 16,
        "expected_excluded_attempts": 8,
        "expected_included_per_cell": 2,
        "ordering": "ascending sequence",
        "interval_method": "paired moving-block bootstrap",
    }
    summary, audit, cells, paired = _incident_free_latency_analysis(
        rows,
        phase="scale",
        incidents=[
            {
                "incident_id": "incident-1",
                "affected_attempt_id": "attempt-1-HL-B1",
                "route": "HL",
                "layer": "B1",
                "route_sequence": 1,
            }
        ],
        rule=rule,
        bootstrap={
            "seed": "test-seed",
            "repetitions": 100,
            "block_length": 2,
            "confidence": 0.95,
        },
    )
    assert summary["valid"]
    assert summary["included_attempts"] == 16
    assert summary["excluded_attempts"] == 8
    assert all(value == 2 for value in summary["included_cell_counts"].values())
    assert sum(not row["included"] for row in audit) == 8
    assert len(cells) == 8
    assert {row["n_pairs"] for row in paired} == {2}


def test_publication_validation_detects_secret_like_files(tmp_path: Path) -> None:
    (tmp_path / "validation.json").write_text('{"valid": true}\n', encoding="utf-8")
    (tmp_path / "table.csv").write_text("metric,value\ngas,1\n", encoding="utf-8")
    _write_manifest(tmp_path)
    assert validate_publication_tree(tmp_path)["valid"]
    (tmp_path / "leak.key").write_text("not-a-real-key\n", encoding="utf-8")
    _write_manifest(tmp_path)
    result = validate_publication_tree(tmp_path)
    assert not result["valid"]
    assert "leak.key" in result["forbidden_publishable_content"]


def test_waterfall_render_is_rebuild_stable(tmp_path: Path) -> None:
    cell_summary = [
        {
            "route": route,
            "layer": layer,
            "complete_gas_mean": 100.0 + 10 * index,
            "complete_calldata_mean": 20.0 + index,
            "latency_seconds_mean": 1.0 + index / 10,
        }
        for route in ROUTES
        for index, layer in enumerate(LAYERS)
    ]
    paired = [
        {
            "route": route,
            "increment": increment,
            "metric": metric,
            "statistic": "mean",
            "estimate": 1.0,
            "ci_low": 0.5,
            "ci_high": 1.5,
        }
        for route in ROUTES
        for increment in ("B0->B1", "B1->B2", "B2->B3")
        for metric in ("complete_gas", "complete_calldata", "latency_seconds")
    ]
    _render_waterfall(tmp_path, cell_summary, paired)
    first = {
        suffix: (tmp_path / f"mechanism-waterfall.{suffix}").read_bytes()
        for suffix in ("pdf", "svg")
    }
    _render_waterfall(tmp_path, cell_summary, paired)
    assert all(
        first[suffix] == (tmp_path / f"mechanism-waterfall.{suffix}").read_bytes()
        for suffix in first
    )


def test_offline_publication_rebuilds_are_identical(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    cell_summary = []
    for route in ROUTES:
        for index, layer in enumerate(LAYERS):
            cell_summary.append(
                {
                    "route": route,
                    "layer": layer,
                    "n": 1000,
                    "complete_gas_mean": 100.0 + index,
                    "complete_calldata_mean": 20.0 + index,
                    "latency_seconds_mean": 1.0 + index / 10,
                    "physical_transactions_mean": 6.0 + index,
                }
            )
    paired = [
        {
            "route": route,
            "increment": increment,
            "metric": metric,
            "statistic": statistic,
            "n_pairs": 1000,
            "estimate": 1.0,
            "ci_low": 0.5,
            "ci_high": 1.5,
            "confidence": 0.95,
            "bootstrap_repetitions": 4000,
            "block_length": 16,
        }
        for route in ROUTES
        for increment in ("B0->B1", "B1->B2", "B2->B3")
        for metric in (
            "latency_seconds",
            "complete_gas",
            "complete_calldata",
            "coordinator_gas",
            "coordinator_calldata",
        )
        for statistic in ("mean", "median")
    ]
    validation = {
        "schema_version": "xir-lab-native-ablation-v1-validation",
        "valid": True,
        "phase": "scale",
        "expected_attempts": 8000,
        "reconciled_attempts": 8000,
        "application_effects": 8000,
        "missing_attempts": [],
        "unexpected_attempts": [],
        "incomplete_attempts": [],
        "missing_effects": [],
        "duplicate_effects": [],
        "reconciliation_errors": [],
        "cell_counts": {f"{route}_{layer}": 1000 for route in ROUTES for layer in LAYERS},
        "mechanism_matrix": {layer: list(MECHANISMS[layer]) for layer in LAYERS},
        "mechanism_deltas": {layer: [] for layer in LAYERS},
        "mechanism_nesting_valid": True,
        "matched_payload_blocks": 1000,
        "paired_increment_counts": {
            f"{route}_{increment}": 1000
            for route in ROUTES
            for increment in ("B0->B1", "B1->B2", "B2->B3")
        },
        "scale_minimum_satisfied": True,
        "physical_lineage_complete": True,
        "complete_physical_transactions": 62000,
        "b1_exact_wire_checks": 2000,
        "b1_exact_wire_rebuild_valid": True,
        "b1_layerzero_size_checks": 2000,
        "b1_layerzero_size_valid": True,
        "coordinator_retry_count": 0,
        "retry_free_complete_lineage": True,
        "analyzer_transaction_read_retry_count": 0,
        "operational_incident_count": 0,
        "operational_incident_logs_valid": True,
        "operational_incident_source_snapshots_valid": True,
        "operational_incidents_recovered": True,
        "incident_latency_sensitivity_required": False,
        "incident_latency_sensitivity_valid": True,
        "incident_latency_sensitivity_included_attempts": 8000,
        "incident_latency_sensitivity_excluded_attempts": 0,
        "incident_latency_sensitivity_included_blocks": 1000,
        "incident_latency_sensitivity_excluded_blocks": 0,
        "incident_latency_sensitivity_cell_counts": {
            f"{route}_{layer}": 1000 for route in ROUTES for layer in LAYERS
        },
        "incident_latency_sensitivity_paired_counts": {
            f"{route}_{increment}": 1000
            for route in ROUTES
            for increment in ("B0->B1", "B1->B2", "B2->B3")
        },
    }
    analysis = {
        "schema_version": "xir-lab-native-ablation-v1-analysis",
        "namespace": "native-ablation-v1",
        "result_role": "revision_evidence_only",
        "phase": "scale",
        "config_sha256": "0" * 64,
        "analysis_source_sha256": "5" * 64,
        "operational_incidents_sha256": "",
        "deployment_sha256": "1" * 64,
        "runner_state_sha256": "2" * 64,
        "layerzero_state_sha256": "3" * 64,
        "attempt_count": 8000,
        "physical_transaction_count": 62000,
        "cell_summary": cell_summary,
        "paired_deltas": paired,
        "stage_costs": [{"stage": "root", "gas_mean": 1}],
        "incident_latency_sensitivity": {
            "required": False,
            "valid": True,
            "included_attempts": 8000,
            "excluded_attempts": 0,
        },
        "incident_free_latency_summary": cell_summary,
        "incident_free_latency_deltas": [
            row for row in paired if row["metric"] == "latency_seconds"
        ],
        "validation": validation,
        "semantic_digest": "4" * 64,
    }
    (source / "analysis.json").write_text(json.dumps(analysis, sort_keys=True), encoding="utf-8")
    (source / "validation.json").write_text(
        json.dumps(validation, sort_keys=True), encoding="utf-8"
    )
    for name in (
        "attempt-metrics.csv",
        "physical-transactions.csv",
        "cell-summary.csv",
        "paired-deltas.csv",
        "stage-costs.csv",
        "latency-sensitivity-attempts.csv",
        "incident-free-latency-summary.csv",
        "incident-free-latency-deltas.csv",
    ):
        (source / name).write_text("field\nvalue\n", encoding="utf-8")
    _write_manifest(source)
    first_root = tmp_path / "rebuild-a"
    second_root = tmp_path / "rebuild-b"
    first_result = rebuild_ablation_publication(source_root=source, output_root=first_root)
    second_result = rebuild_ablation_publication(source_root=source, output_root=second_root)
    assert first_result == second_result
    assert {
        path.relative_to(first_root): path.read_bytes()
        for path in first_root.rglob("*")
        if path.is_file()
    } == {
        path.relative_to(second_root): path.read_bytes()
        for path in second_root.rglob("*")
        if path.is_file()
    }
