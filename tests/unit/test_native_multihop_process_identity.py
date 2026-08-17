from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_process_identity import (
    record_process_identity,
    signal_verified_process,
    verify_process_identity,
)


def test_identity_rejects_pid_reuse_without_signalling_unrelated_process(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    token = str(runtime)
    first = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", token])
    identity = tmp_path / "process.json"
    try:
        record_process_identity(
            pid=first.pid,
            identity_path=identity,
            runtime_root=runtime,
            expected_token=token,
        )
    finally:
        first.terminate()
        first.wait(timeout=5)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", token])
    try:
        document = __import__("json").loads(identity.read_text(encoding="utf-8"))
        document["pid"] = unrelated.pid
        document["starttime_ticks"] = int(document["starttime_ticks"]) - 1
        identity.write_text(__import__("json").dumps(document), encoding="utf-8")
        with pytest.raises(LocalTopologyError, match="starttime"):
            signal_verified_process(identity, "SIGTERM")
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_identity_verifies_original_process_and_signals_it(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    token = str(runtime)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", token])
    identity = tmp_path / "process.json"
    record_process_identity(
        pid=process.pid,
        identity_path=identity,
        runtime_root=runtime,
        expected_token=token,
    )
    assert verify_process_identity(identity)["pid"] == process.pid
    signal_verified_process(identity, "SIGTERM")
    process.wait(timeout=5)


def test_pidfd_path_refuses_when_target_exits_after_initial_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    token = str(runtime)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", token])
    identity = tmp_path / "process.json"
    record_process_identity(
        pid=process.pid,
        identity_path=identity,
        runtime_root=runtime,
        expected_token=token,
    )
    from xir_lab.native import multihop_process_identity as process_identity

    real_pidfd_open = process_identity._pidfd_open

    def exit_then_open(pid: int) -> int:
        process.terminate()
        process.wait(timeout=5)
        return real_pidfd_open(pid)

    monkeypatch.setattr(process_identity, "_pidfd_open", exit_then_open)
    with pytest.raises(LocalTopologyError, match="disappeared before pidfd"):
        signal_verified_process(identity, "SIGTERM")
