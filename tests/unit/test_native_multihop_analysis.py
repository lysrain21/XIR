from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero_worker import LayerZeroWorkerState
from xir_lab.native.multihop_analysis import (
    TAIL_LATENCY_REPORTING,
    _resource_summary,
    _tail_latency_reporting_from_preregistration,
    capture_multihop_incidents,
    linear_model,
    summarize_attempt_metrics,
)
from xir_lab.native.multihop_process_identity import process_identity_sha256
from xir_lab.native.multihop_runner import MultihopRunnerState
from xir_lab.native.multihop_scalability import (
    ROUTE_ORDER,
    build_multihop_attempts,
    expected_coordinator_transactions,
    expected_physical_transactions,
    switch_count,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/native/native-multihop-switching-v1.json"


def _replacement_identity(detail_json: str) -> tuple[str, str]:
    detail = json.loads(detail_json)
    identity = dict(detail["_process_identity"])
    identity["starttime_ticks"] = int(identity["starttime_ticks"]) + 1
    identity["identity_sha256"] = process_identity_sha256(identity)
    detail["_process_identity"] = identity
    return str(identity["identity_sha256"]), json.dumps(detail, sort_keys=True)


def _replace_sqlite_identity(
    connection: sqlite3.Connection, *, table: str, identifier: str, value: int
) -> None:
    row = connection.execute(
        f"SELECT detail_json FROM {table} WHERE {identifier}=?", (value,)
    ).fetchone()
    assert row is not None
    digest, detail_json = _replacement_identity(str(row[0]))
    connection.execute(
        f"""
        UPDATE {table}
        SET process_id=process_id+1,process_identity_sha256=?,detail_json=?
        WHERE {identifier}=?
        """,
        (digest, detail_json, value),
    )


def _fake_process_identity(pid: int, label: str) -> dict[str, object]:
    identity: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        "pid": pid,
        "boot_id": "boot-a",
        "starttime_ticks": pid * 10,
        "runtime_root": "/runtime",
        "executable": "/usr/bin/python3",
        "cmdline_sha256": ("a" if label == "observer" else "b") * 64,
    }
    identity["identity_sha256"] = process_identity_sha256(identity)
    return identity


def _rows(n: int = 12) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for sequence in range(n):
        for route in ROUTE_ORDER:
            hops = len(route)
            switches = switch_count(route)
            direction = int(route.startswith("L"))
            result.append(
                {
                    "route": route,
                    "sequence": sequence,
                    "hop_count": hops,
                    "switch_count": switches,
                    "starts_with_l": direction,
                    "coordinator_transactions": expected_coordinator_transactions(route),
                    "physical_transactions": expected_physical_transactions(route),
                    "gas": 100_000 + 20_000 * hops + 7_000 * switches + 500 * direction,
                    "calldata_bytes": 100 + 50 * hops + 8 * switches + direction,
                    "latency_seconds": 1.0 + 0.2 * hops + 0.05 * switches + 0.01 * direction,
                    "switch_stage_gas": 40_000 + 100 * max(hops - 2, 0),
                    "switch_stage_calldata_bytes": 400 + max(hops - 2, 0),
                    "switch_stage_latency_seconds": 0.4 + 0.01 * max(hops - 2, 0),
                    "core_switch_gas": 35_000 + 100 * max(hops - 2, 0),
                    "core_switch_calldata_bytes": 320 + max(hops - 2, 0),
                    "core_switch_latency_seconds": 0.3 + 0.01 * max(hops - 2, 0),
                    "prefix_receipt_count": hops - 1,
                    "encoded_envelope_bytes": 1_000 + 256 * hops,
                    "final_delivery_calldata_bytes": 2_000 + 256 * hops,
                    "theoretical_last_receipt_envelope_byte_increment": 256,
                    "final_gateway_exclusive_residual_gas": 20_000 + 50 * hops,
                    "final_registry_and_verifier_subcall_gas": 10_000 + 25 * hops,
                    "final_receiver_subcall_gas": 5_000,
                    "final_other_direct_subcall_gas": 1_000,
                    "final_trace_execution_gas": 50_000 + 100 * hops,
                }
            )
    return result


def test_linear_model_recovers_switch_slope() -> None:
    rows = _rows()
    model = linear_model(
        rows, response="gas", predictors=("hop_count", "switch_count", "starts_with_l")
    )
    assert model["coefficients"]["switch_count"] == pytest.approx(7000)
    assert model["r_squared"] == pytest.approx(1)


def test_summary_requires_exact_cells_and_reports_equivalence(tmp_path: Path) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["attempts_per_route"]["scale"] = 12
    config["bootstrap"]["repetitions"] = 80
    summary = summarize_attempt_metrics(_rows(), config=config)
    assert len(summary["cell_summary"]) == 44
    assert len(summary["models"]) == 4
    assert len(summary["equivalence"]) == 4
    assert all(row["equivalent"] for row in summary["equivalence"])
    assert len(summary["paired_switch_marginals"]) == 12
    assert len(summary["carrier_calibrated_switch_marginals"]) == 12
    assert len(summary["receipt_growth_models"]) == 6
    assert all(
        set(model["coefficient_intervals"])
        == {"intercept", "hop_count", "switch_count", "starts_with_l"}
        for model in summary["models"]
    )
    assert len(summary["transaction_summary"]) == len(ROUTE_ORDER)
    assert summary["latency_sensitivity"]["excluded_attempts"] == 0
    latency_cells = [row for row in summary["cell_summary"] if row["metric"] == "latency_seconds"]
    assert latency_cells
    assert all(
        row["tail_point_estimates_role"] == "descriptive"
        and row["tail_scope"] == "shared_host_alpha_system"
        and row["tail_inferential"] is False
        and row["tail_release_gate"] is False
        and "p95_ci_low" not in row
        and "p99_ci_low" not in row
        for row in latency_cells
    )
    with pytest.raises(LocalTopologyError, match="11 routes"):
        summarize_attempt_metrics(_rows()[:-1], config=config)


def test_tail_latency_reporting_is_bound_to_frozen_preregistration(tmp_path: Path) -> None:
    preregistration = json.loads(
        (
            ROOT.parent
            / "openspec/changes/measure-multihop-switching-scalability/artifacts/preregistration-v1.json"
        ).read_text(encoding="utf-8")
    )
    path = tmp_path / "preregistration.json"
    path.write_text(json.dumps(preregistration) + "\n", encoding="utf-8")
    assert _tail_latency_reporting_from_preregistration(path) == TAIL_LATENCY_REPORTING
    preregistration["estimands"]["tail_latency_reporting"]["release_gate"] = True
    path.write_text(json.dumps(preregistration) + "\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="tail-latency reporting boundary drift"):
        _tail_latency_reporting_from_preregistration(path)


def test_latency_excludes_only_complete_matched_blocks() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["attempts_per_route"]["scale"] = 12
    config["bootstrap"]["repetitions"] = 80
    rows = _rows()
    next(row for row in rows if row["sequence"] == 4 and row["route"] == "HLHL")[
        "latency_seconds"
    ] = float("nan")
    summary = summarize_attempt_metrics(rows, config=config)
    latency_sensitivity = summary["latency_sensitivity"]
    assert {
        key: latency_sensitivity[key]
        for key in (
            "selection_unit",
            "primary_attempts",
            "included_attempts",
            "excluded_attempts",
            "excluded_sequences",
            "included_per_route",
        )
    } == {
        "selection_unit": "complete_11_route_sequence_block",
        "primary_attempts": 132,
        "included_attempts": 121,
        "excluded_attempts": 11,
        "excluded_sequences": [4],
        "included_per_route": 11,
    }
    assert "share one host" in latency_sensitivity["mandatory_limitation"]
    latency_cells = [row for row in summary["cell_summary"] if row["metric"] == "latency_seconds"]
    assert {row["n"] for row in latency_cells} == {11, 12}


def test_full_latency_estimands_keep_finite_same_boot_restart_rows() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["attempts_per_route"]["scale"] = 12
    config["bootstrap"]["repetitions"] = 80
    rows = _rows()
    restarted = next(row for row in rows if row["sequence"] == 4 and row["route"] == "HL")
    restarted["latency_clock_valid"] = False
    summary = summarize_attempt_metrics(rows, config=config)
    full_model = next(
        row
        for row in summary["models"]
        if row["metric"] == "latency_seconds"
        and row["sample_role"] == "primary_all_finite_clock_attempts_including_incidents"
    )
    sensitivity_model = next(
        row
        for row in summary["models"]
        if row["metric"] == "latency_seconds"
        and row["sample_role"] == "interruption_free_complete_blocks_sensitivity"
    )
    assert full_model["linear"]["n"] == 8 * 12
    assert sensitivity_model["linear"]["n"] == 8 * 11
    primary_tost = next(
        row
        for row in summary["equivalence"]
        if row["metric"] == "latency_seconds"
        and row["sample_role"] == "primary_all_finite_clock_blocks_including_incidents"
    )
    sensitivity_tost = next(
        row
        for row in summary["equivalence"]
        if row["metric"] == "latency_seconds"
        and row["sample_role"] == "interruption_free_complete_blocks_sensitivity"
    )
    assert primary_tost["n"] == 3 * 12
    assert sensitivity_tost["n"] == 3 * 11
    for key in ("cell_summary", "paired_switch_marginals", "carrier_calibrated_switch_marginals"):
        latency = [row for row in summary[key] if row["metric"] == "latency_seconds"]
        assert {row["sample_role"] for row in latency} == {
            "primary_all_finite_clock_attempts_including_incidents"
            if key == "cell_summary"
            else "primary_all_finite_clock_blocks_including_incidents",
            "interruption_free_complete_blocks_sensitivity",
        }
        assert {row["n"] if key == "cell_summary" else row["n_pairs"] for row in latency} == {
            11,
            12,
        }


def test_resource_summary_covers_campaign_without_changing_exclusion_policy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resources.jsonl"
    rows = []
    for sequence, utc in enumerate((100, 300)):
        rows.append(
            {
                "schema_version": "xir-lab-native-multihop-resource-sample-v1",
                "sequence": sequence,
                "utc_ns": utc,
                "monotonic_ns": utc + 10,
                "boot_id": "boot",
                "load_average": [1.0 + sequence, 0.0, 0.0],
                "memory": {"available_bytes": 1_000 - sequence},
                "runtime_disk": {"available_bytes": 2_000 - sequence},
                "processes": [
                    {"name": "runner", "healthy": True, "pid": 7},
                    {"name": "layerzero-worker", "healthy": True, "pid": 8},
                ],
                "gaps": [],
            }
        )
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary = _resource_summary(
        path,
        [
            {"utc_ns": 150},
            {"utc_ns": 250},
        ],
    )
    assert summary["campaign_event_coverage"] is True
    assert summary["sample_count"] == 2
    assert summary["monitor_gap_count"] == 0
    assert summary["runner_process_ids"] == [7]


def test_incident_inventory_selects_process_restart_as_complete_block(
    tmp_path: Path,
) -> None:
    runner_path = tmp_path / "runner.sqlite"
    state = MultihopRunnerState(runner_path)
    attempt = build_multihop_attempts(config_path=CONFIG, phase="smoke")[0]
    assert state.begin(attempt)  # type: ignore[arg-type]
    state.record_event(
        attempt_id=attempt.attempt_id,
        stage="root_create",
        event="intended",
        source="coordinator",
        detail={},
    )
    event_id = int(
        state.connection.execute(
            "SELECT event_id FROM events WHERE attempt_id=?", (attempt.attempt_id,)
        ).fetchone()[0]
    )
    _replace_sqlite_identity(
        state.connection, table="events", identifier="event_id", value=event_id
    )
    state.record_event(
        attempt_id=attempt.attempt_id,
        stage="root_create",
        event="succeeded",
        source="coordinator",
        detail={},
    )
    state.connection.commit()
    state.connection.close()
    output = tmp_path / "incidents.json"
    document = capture_multihop_incidents(
        runner_state_path=runner_path, phase="smoke", output_path=output
    )
    assert document["excluded_sequences"] == [0]
    assert document["records"][0]["reason"] == "host_process_interruption"


def test_incident_inventory_detects_restart_between_routes_in_same_sequence(
    tmp_path: Path,
) -> None:
    runner_path = tmp_path / "runner.sqlite"
    state = MultihopRunnerState(runner_path)
    attempts = build_multihop_attempts(config_path=CONFIG, phase="smoke")[:2]
    assert {attempt.route_sequence for attempt in attempts} == {0}
    for attempt in attempts:
        assert state.begin(attempt)  # type: ignore[arg-type]
        state.record_event(
            attempt_id=attempt.attempt_id,
            stage="root_create",
            event="intended",
            source="coordinator",
            detail={},
        )
    event_id = int(
        state.connection.execute(
            "SELECT event_id FROM events WHERE attempt_id=?", (attempts[1].attempt_id,)
        ).fetchone()[0]
    )
    _replace_sqlite_identity(
        state.connection, table="events", identifier="event_id", value=event_id
    )
    state.connection.commit()
    state.connection.close()
    document = capture_multihop_incidents(
        runner_state_path=runner_path,
        phase="smoke",
        output_path=tmp_path / "incidents.json",
    )
    assert document["excluded_sequences"] == [0]
    assert {row["attempt_id"] for row in document["records"]} == {
        attempt.attempt_id for attempt in attempts
    }
    assert {row["reason"] for row in document["records"]} == {"host_process_interruption"}


def test_incident_inventory_selects_layerzero_worker_restart_block(
    tmp_path: Path,
) -> None:
    runner_path = tmp_path / "runner.sqlite"
    state = MultihopRunnerState(runner_path)
    attempt = next(
        attempt
        for attempt in build_multihop_attempts(config_path=CONFIG, phase="smoke")
        if attempt.route == "L"
    )
    assert state.begin(attempt)  # type: ignore[arg-type]
    guid = "0x" + "ab" * 32
    state.record_stage(
        attempt.attempt_id,
        "hop_1_l_dispatch",
        "succeeded",
        {"role": "a", "hop_index": 1, "native_message_id": guid},
        "0x" + "11" * 32,
    )
    state.connection.close()

    worker_path = tmp_path / "worker.sqlite"
    worker = LayerZeroWorkerState(worker_path)
    worker.connection.execute(
        """
        INSERT INTO packets(
          guid,source_eid,destination_eid,source_block,source_transaction_hash,
          source_log_index,encoded_packet_hex,packet_sha256,status,observed_at,updated_at
        ) VALUES (?,1,2,1,'0x1',0,'0x00','sha','observed','now','now')
        """,
        (guid,),
    )
    action = worker.intend_action(
        guid=guid,
        stage="dvn_execute",
        destination_chain_id=2,
        nonce=1,
        target="0x" + "22" * 20,
        call_data=b"call",
    )
    worker.observe_action(str(action["action_id"]), "submitted", {})
    worker.observe_action(str(action["action_id"]), "succeeded", {})
    observation_id = int(
        worker.connection.execute(
            """
            SELECT observation_id FROM observations
            WHERE action_id=? AND state='succeeded'
            """,
            (action["action_id"],),
        ).fetchone()[0]
    )
    _replace_sqlite_identity(
        worker.connection,
        table="observations",
        identifier="observation_id",
        value=observation_id,
    )
    worker.connection.commit()
    worker.connection.close()

    document = capture_multihop_incidents(
        runner_state_path=runner_path,
        worker_state_path=worker_path,
        phase="smoke",
        output_path=tmp_path / "incidents.json",
    )
    assert document["excluded_sequences"] == [0]
    assert document["records"][0]["reason"] == ("layerzero_worker_process_or_boot_change")


@pytest.mark.parametrize("changed_identity", ["observer", "relayer"])
def test_hyperlane_boundary_restart_excludes_entire_route_sequence(
    tmp_path: Path, changed_identity: str
) -> None:
    runner_path = tmp_path / "runner.sqlite"
    state = MultihopRunnerState(runner_path)
    attempts = build_multihop_attempts(config_path=CONFIG, phase="smoke")[:11]
    assert {attempt.route_sequence for attempt in attempts} == {0}
    for attempt in attempts:
        assert state.begin(attempt)  # type: ignore[arg-type]
        state.record_event(
            attempt_id=attempt.attempt_id,
            stage="root_create",
            event="intended",
            source="coordinator",
            detail={},
        )
    attempt = next(item for item in attempts if "H" in item.route)
    message_id = "0x" + "ab" * 32
    state.record_stage(
        attempt.attempt_id,
        "hop_1_h_dispatch",
        "succeeded",
        {"role": "a", "hop_index": 1, "native_message_id": message_id},
        "0x" + "11" * 32,
    )
    state.connection.close()
    submitted_observer = 101
    mined_observer = 102 if changed_identity == "observer" else 101
    submitted_relayer = 201
    mined_relayer = 202 if changed_identity == "relayer" else 201
    submitted_observer_identity = _fake_process_identity(submitted_observer, "observer")
    mined_observer_identity = _fake_process_identity(mined_observer, "observer")
    submitted_relayer_identity = _fake_process_identity(submitted_relayer, "relayer")
    mined_relayer_identity = _fake_process_identity(mined_relayer, "relayer")
    process_path = tmp_path / "hyperlane-processes.json"
    process_path.write_text(
        json.dumps(
            {
                "messages": {
                    message_id: {
                        "observer_boot_id": "boot-a",
                        "observer_boundary_valid": True,
                        "submitted_observer_process_id": submitted_observer,
                        "submitted_observer_process_identity": submitted_observer_identity,
                        "submitted_observer_process_identity_sha256": (
                            submitted_observer_identity["identity_sha256"]
                        ),
                        "mined_observer_process_id": mined_observer,
                        "mined_observer_process_identity": mined_observer_identity,
                        "mined_observer_process_identity_sha256": (
                            mined_observer_identity["identity_sha256"]
                        ),
                        "submitted_relayer_process_id": submitted_relayer,
                        "submitted_relayer_process_identity": submitted_relayer_identity,
                        "submitted_relayer_process_identity_sha256": (
                            submitted_relayer_identity["identity_sha256"]
                        ),
                        "mined_relayer_process_id": mined_relayer,
                        "mined_relayer_process_identity": mined_relayer_identity,
                        "mined_relayer_process_identity_sha256": (
                            mined_relayer_identity["identity_sha256"]
                        ),
                        "restart_crossing": True,
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    document = capture_multihop_incidents(
        runner_state_path=runner_path,
        phase="smoke",
        hyperlane_process_path=process_path,
        output_path=tmp_path / "incidents.json",
    )
    assert document["excluded_sequences"] == [0]
    assert len(document["records"]) == 11
    assert {row["reason"] for row in document["records"]} == {
        "hyperlane_relayer_process_or_boot_change"
    }
