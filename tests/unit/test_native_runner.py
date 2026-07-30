from pathlib import Path

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.native.runner import RunnerState


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
