import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hexbytes import HexBytes
from requests import ConnectionError

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.runner import NativeExperimentRunner, RunnerState


def test_runner_state_resumes_stages_without_repeating_completed_attempt(
    tmp_path: Path,
) -> None:
    attempt = NativeAttempt(
        attempt_id="native_test",
        phase="smoke",
        route="HL",
        route_sequence=0,
        first_protocol="hyperlane",
        second_protocol="layerzero-v2",
        execution_class="heterogeneous-xir",
        xir=True,
        payload_bytes=32,
        payload_sha256="11" * 32,
    )
    state = RunnerState(tmp_path / "runner.sqlite")
    assert state.begin(attempt)
    state.record_stage(
        attempt.attempt_id,
        "xir_root_record",
        "succeeded",
        {"record_nonce": 7},
        "0xabc",
    )
    resumed = RunnerState(tmp_path / "runner.sqlite")
    assert resumed.begin(attempt)
    stage = resumed.stage(attempt.attempt_id, "xir_root_record")
    assert stage is not None
    assert stage["state"] == "succeeded"
    resumed.finish(attempt.attempt_id)
    assert not resumed.begin(attempt)


def test_runner_state_preserves_append_only_stage_history(tmp_path: Path) -> None:
    attempt = NativeAttempt(
        attempt_id="native_retry",
        phase="scale",
        route="LL",
        route_sequence=0,
        first_protocol="layerzero-v2",
        second_protocol="layerzero-v2",
        execution_class="homogeneous-native",
        xir=False,
        payload_bytes=32,
        payload_sha256="22" * 32,
    )
    path = tmp_path / "runner.sqlite"
    state = RunnerState(path)
    assert state.begin(attempt)
    state.record_stage(
        attempt.attempt_id,
        "source_dispatch",
        "signed",
        {"transaction_nonce": 7},
        "old-hash",
    )
    state.record_stage(
        attempt.attempt_id,
        "source_dispatch",
        "superseded",
        {
            "retry_count": 1,
            "retry_lineage": [
                {
                    "prior_transaction_hash": "old-hash",
                    "prior_transaction_nonce": 7,
                    "resolution": "superseded_by_mined_nonce",
                }
            ],
        },
        "old-hash",
    )
    state.record_stage(
        attempt.attempt_id,
        "source_dispatch",
        "succeeded",
        {"transaction_nonce": 8, "retry_count": 1},
        "new-hash",
    )

    connection = sqlite3.connect(path)
    rows = connection.execute(
        """
        SELECT state, transaction_hash, detail_json
        FROM stage_history
        WHERE attempt_id=? AND stage=?
        ORDER BY history_id
        """,
        (attempt.attempt_id, "source_dispatch"),
    ).fetchall()
    assert [row[0] for row in rows] == ["signed", "superseded", "succeeded"]
    assert [row[1] for row in rows] == ["old-hash", "old-hash", "new-hash"]
    assert json.loads(rows[1][2])["retry_lineage"][0][
        "prior_transaction_nonce"
    ] == 7


def test_runner_state_records_transient_errors_without_failing_stage(
    tmp_path: Path,
) -> None:
    attempt = NativeAttempt(
        attempt_id="native_rpc_retry",
        phase="scale",
        route="HH",
        route_sequence=0,
        first_protocol="hyperlane",
        second_protocol="hyperlane",
        execution_class="homogeneous-native",
        xir=False,
        payload_bytes=32,
        payload_sha256="33" * 32,
    )
    path = tmp_path / "runner.sqlite"
    state = RunnerState(path)
    assert state.begin(attempt)
    state.record_transient_error(
        attempt.attempt_id,
        ConnectionError("temporary RPC disconnect"),
        1,
    )

    connection = sqlite3.connect(path)
    row = connection.execute(
        """
        SELECT error_class, error_message, retry_index
        FROM attempt_errors WHERE attempt_id=?
        """,
        (attempt.attempt_id,),
    ).fetchone()
    assert row == ("ConnectionError", "temporary RPC disconnect", 1)
    assert state.stage(attempt.attempt_id, "runtime_rpc_retry") is None


def test_runner_persists_recovered_receipt_with_complete_detail(
    tmp_path: Path,
) -> None:
    runner = object.__new__(NativeExperimentRunner)
    runner.raw_root = tmp_path
    transaction_hash = "0x" + "44" * 32
    result = runner._persist_receipt(
        transaction_hash=transaction_hash,
        receipt={
            "status": 1,
            "gasUsed": 123,
            "blockNumber": 456,
            "transactionHash": HexBytes(transaction_hash),
            "logs": [],
        },
        detail={"native_fee": 7},
    )

    receipt_path = Path(result["receipt"])
    assert receipt_path == tmp_path / f"{transaction_hash}.json"
    assert result["gas_used"] == 123
    assert result["block_number"] == 456
    assert result["native_fee"] == 7
    assert result["receipt_sha256"]
    assert json.loads(receipt_path.read_text(encoding="utf-8"))["status"] == 1


def test_runner_recovers_receipt_for_legacy_succeeded_stage(
    tmp_path: Path,
) -> None:
    transaction_hash = "0x" + "55" * 32
    state = MagicMock()
    state.stage.return_value = {
        "state": "succeeded",
        "transaction_hash": transaction_hash,
        "detail_json": json.dumps({"native_fee": 9}),
    }
    client = MagicMock()
    client.eth.get_transaction_receipt.return_value = {
        "status": 1,
        "gasUsed": 321,
        "blockNumber": 654,
        "transactionHash": HexBytes(transaction_hash),
        "logs": [],
    }
    runner = object.__new__(NativeExperimentRunner)
    runner.state = state
    runner.clients = {"intermediate": client}
    runner.raw_root = tmp_path

    result = runner._transact(
        attempt_id="native_legacy_stage",
        stage="second_protocol_dispatch",
        role="intermediate",
        function=MagicMock(),
    )

    assert result["native_fee"] == 9
    assert result["gas_used"] == 321
    assert result["block_number"] == 654
    assert Path(result["receipt"]).is_file()
    state.record_stage.assert_called_once_with(
        "native_legacy_stage",
        "second_protocol_dispatch",
        "succeeded",
        result,
        transaction_hash,
    )


def test_runner_refuses_a_new_batch_after_monitor_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = object.__new__(NativeExperimentRunner)
    runner.profile_path = tmp_path / "profile.json"
    runner.batch_attempts = 1
    runner.submission_stop_file = tmp_path / "submissions.stop"
    runner.submission_stop_file.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        "xir_lab.native.runner.build_native_attempts",
        lambda **_: (MagicMock(),),
    )

    with pytest.raises(LocalTopologyError, match="resource monitor"):
        runner.run_phase("scale")
