from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_analysis import capture_hyperlane_processes
from xir_lab.native.multihop_hyperlane_observer import (
    SCHEMA,
    _pending_transactions,
    _rpc,
    load_hyperlane_observer_events,
    observe_hyperlane_relayer,
)
from xir_lab.native.multihop_process_identity import process_identity_sha256


def _identity(pid: int, label: str) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-process-identity-v1",
        "pid": pid,
        "boot_id": "boot-a",
        "starttime_ticks": pid * 10,
        "runtime_root": "/runtime",
        "executable": "/usr/bin/python3",
        "cmdline_sha256": ("a" if label == "observer" else "b") * 64,
    }
    document["identity_sha256"] = process_identity_sha256(document)
    return document


def _current_identity(pid: int, label: str) -> dict[str, object]:
    document = _identity(pid, label)
    document["boot_id"] = (
        Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    )
    document["identity_sha256"] = process_identity_sha256(document)
    return document


def _event(
    event: str,
    *,
    transaction_hash: str | None = None,
    chain_role: str | None = None,
    relayer_process_id: int = 7,
) -> dict[str, object]:
    observer_identity = _identity(9, "observer")
    relayer_identity = _identity(relayer_process_id, "relayer")
    return {
        "schema_version": SCHEMA,
        "event": event,
        "source": "test",
        "chain_role": chain_role,
        "transaction_hash": transaction_hash,
        "block_number": 1 if transaction_hash else None,
        # Match real nanosecond clocks, which exceed the RFC 8785 safe integer
        # domain and therefore exercise canonical string publication.
        "utc_ns": 1_786_621_043_488_854_263,
        "monotonic_ns": 11_872_066_575_108_387,
        "boot_id": "boot-a",
        "observer_process_id": 9,
        "relayer_process_id": relayer_process_id,
        "observer_process_identity_sha256": observer_identity["identity_sha256"],
        "relayer_process_identity_sha256": relayer_identity["identity_sha256"],
        "observer_process_identity": observer_identity,
        "relayer_process_identity": relayer_identity,
    }


def test_pending_transactions_treats_exhausted_rpc_disconnect_as_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "xir_lab.native.multihop_hyperlane_observer._rpc",
        lambda *_args: (_ for _ in ()).throw(LocalTopologyError("disconnect")),
    )
    assert _pending_transactions("http://rpc") == []


def test_rpc_retries_transient_disconnect_before_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def urlopen(_request: object, timeout: int) -> object:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ConnectionResetError("transient disconnect")

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"jsonrpc":"2.0","id":1,"result":[]}'

        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    assert _rpc("http://rpc", "eth_getBlockByNumber", ["pending", True]) == []
    assert calls == 3


def test_process_capture_requires_stable_observer_and_relayer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_hash = "0x" + "11" * 32
    message_id = "0x" + "22" * 32
    observer = tmp_path / "observer.jsonl"
    rows = [
        _event("observer_started"),
        _event(
            "submitted_observed",
            transaction_hash=transaction_hash,
            chain_role="b",
        ),
        _event(
            "mined_observed",
            transaction_hash=transaction_hash,
            chain_role="b",
        ),
        _event("observer_stopped"),
    ]
    observer.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "chains": [
                    {"rpc_url": f"http://chain-{role}", "chain_id": index}
                    for index, role in enumerate("abcde", start=1)
                ]
            }
        ),
        encoding="utf-8",
    )
    for role in "bcde":
        address = tmp_path / f"hyperlane/registry/chains/xirlocalchain{role}/addresses.yaml"
        address.parent.mkdir(parents=True)
        address.write_text(
            "mailbox: '0x"
            + "33" * 20
            + "'\ndefaultIsm: '0x"
            + "55" * 20
            + "'\n",
            encoding="utf-8",
        )

    transaction_target = "0x" + "33" * 20

    def rpc(_url: str, method: str, _params: list[object]) -> object:
        if method == "eth_getLogs":
            if "chain-b" not in _url:
                return []
            return [
                {
                    "topics": ["0x" + "44" * 32, message_id],
                    "transactionHash": transaction_hash,
                }
            ]
        if method == "eth_getTransactionByHash":
            return {"input": "0x1234", "to": transaction_target}
        if method == "eth_getTransactionReceipt":
            return {
                "blockNumber": "0x1",
                "transactionIndex": "0x0",
                "status": "0x1",
                "gasUsed": "0x5208",
            }
        raise AssertionError(method)

    monkeypatch.setattr("xir_lab.native.multihop_analysis._rpc", rpc)
    result = capture_hyperlane_processes(
        profile_path=profile,
        runtime_root=tmp_path,
        start_blocks={"b": 1, "c": 1, "d": 1, "e": 1},
        end_blocks={"b": 1, "c": 0, "d": 0, "e": 0},
        observer_path=observer,
        output_path=tmp_path / "processes.json",
    )
    assert result["messages"][message_id]["observer_boundary_valid"] is True
    published = result["messages"][message_id]
    assert published["mailbox"] == "0x" + "33" * 20
    assert published["default_ism"] == "0x" + "55" * 20
    assert published["submitted_utc_ns"] == "1786621043488854263"
    assert published["submitted_monotonic_ns"] == "11872066575108387"
    assert published["mined_utc_ns"] == "1786621043488854263"
    assert published["mined_monotonic_ns"] == "11872066575108387"
    transaction_target = "0x" + "99" * 20
    with pytest.raises(LocalTopologyError, match="frozen Mailbox"):
        capture_hyperlane_processes(
            profile_path=profile,
            runtime_root=tmp_path,
            start_blocks={"b": 1, "c": 1, "d": 1, "e": 1},
            end_blocks={"b": 1, "c": 0, "d": 0, "e": 0},
            observer_path=observer,
            output_path=tmp_path / "processes-wrong-target.json",
        )
    transaction_target = "0x" + "33" * 20
    rows[2]["relayer_process_id"] = 8
    rows[2]["observer_process_id"] = 10
    relayer_identity = _identity(8, "relayer")
    observer_identity = _identity(10, "observer")
    rows[2]["relayer_process_identity"] = relayer_identity
    rows[2]["observer_process_identity"] = observer_identity
    rows[2]["relayer_process_identity_sha256"] = relayer_identity["identity_sha256"]
    rows[2]["observer_process_identity_sha256"] = observer_identity["identity_sha256"]
    observer.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    restarted = capture_hyperlane_processes(
        profile_path=profile,
        runtime_root=tmp_path,
        start_blocks={"b": 1, "c": 1, "d": 1, "e": 1},
        end_blocks={"b": 1, "c": 0, "d": 0, "e": 0},
        observer_path=observer,
        output_path=tmp_path / "processes-drift.json",
    )
    assert restarted["messages"][message_id]["restart_crossing"] is True


def test_observer_rejects_mined_before_submitted_dual_clock(tmp_path: Path) -> None:
    transaction_hash = "0x" + "55" * 32
    rows = [
        _event("observer_started"),
        _event("submitted_observed", transaction_hash=transaction_hash, chain_role="b"),
        _event("mined_observed", transaction_hash=transaction_hash, chain_role="b"),
        _event("observer_stopped"),
    ]
    rows[1]["utc_ns"] = 301
    rows[1]["monotonic_ns"] = 401
    rows[2]["utc_ns"] = 300
    rows[2]["monotonic_ns"] = 400
    observer = tmp_path / "observer.jsonl"
    observer.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="unordered"):
        load_hyperlane_observer_events(observer)


def test_observer_append_accepts_only_an_incomplete_final_segment(tmp_path: Path) -> None:
    observer = tmp_path / "observer.jsonl"
    observer.write_text(
        json.dumps(_event("observer_started")) + "\n",
        encoding="utf-8",
    )
    rows = load_hyperlane_observer_events(observer, allow_incomplete_tail=True)
    assert [row["event"] for row in rows] == ["observer_started"]
    with pytest.raises(LocalTopologyError, match="ledger is invalid"):
        load_hyperlane_observer_events(observer)


def test_observer_append_recovers_submitted_only_then_accepts_unique_mined(
    tmp_path: Path,
) -> None:
    transaction_hash = "0x" + "77" * 32
    rows = [
        _event("observer_started"),
        _event("submitted_observed", transaction_hash=transaction_hash, chain_role="b"),
    ]
    observer = tmp_path / "observer.jsonl"
    observer.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    loaded = load_hyperlane_observer_events(observer, allow_incomplete_tail=True)
    assert [row["event"] for row in loaded] == ["observer_started", "submitted_observed"]
    rows.extend(
        [
            _event("mined_observed", transaction_hash=transaction_hash, chain_role="b"),
            _event("observer_stopped"),
        ]
    )
    observer.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert len(load_hyperlane_observer_events(observer)) == 4


def test_observer_append_quarantines_and_fsync_truncates_torn_final_json(
    tmp_path: Path,
) -> None:
    observer = tmp_path / "observer.jsonl"
    complete = (json.dumps(_event("observer_started")) + "\n").encode()
    fragment = b'{"schema_version":"partial"'
    observer.write_bytes(complete + fragment)
    rows = load_hyperlane_observer_events(observer, allow_incomplete_tail=True)
    assert [row["event"] for row in rows] == ["observer_started"]
    assert observer.read_bytes() == complete
    quarantines = list(tmp_path.glob("observer.jsonl.torn-tail-*.fragment"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == fragment
    with pytest.raises(LocalTopologyError, match="torn tail"):
        observer.write_bytes(complete + fragment)
        load_hyperlane_observer_events(observer)


def test_observer_persists_ready_before_polling_or_runner_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"chains": [{"rpc_url": f"http://{role}"} for role in "abcde"]}),
        encoding="utf-8",
    )
    pid_path = tmp_path / "runtime/hyperlane/agents/pids/relayer.pid"
    pid_path.parent.mkdir(parents=True)
    pid_path.write_text(f"{os.getpid()}\n", encoding="ascii")
    stop = tmp_path / "stop"
    stop.touch()
    monkeypatch.setattr(
        "xir_lab.native.multihop_hyperlane_observer._rpc",
        lambda _url, method, params: (
            {"transactions": []}
            if method == "eth_getBlockByNumber" and params == ["pending", True]
            else "0x0"
        ),
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_hyperlane_observer.verify_process_identity",
        lambda _path: _current_identity(os.getpid(), "relayer"),
    )
    monkeypatch.setattr(
        "xir_lab.native.multihop_hyperlane_observer.current_process_identity",
        lambda **_kwargs: _current_identity(os.getpid(), "observer"),
    )
    output = tmp_path / "observer.jsonl"
    ready = tmp_path / "observer-ready.json"
    observe_hyperlane_relayer(
        profile_path=profile,
        runtime_root=tmp_path / "runtime",
        relayer_address="0x" + "11" * 20,
        start_blocks={role: 1 for role in "abcde"},
        output_path=output,
        stop_file=stop,
        poll_seconds=0.01,
        ready_path=ready,
    )
    document = json.loads(ready.read_text(encoding="utf-8"))
    rows = load_hyperlane_observer_events(output)
    assert document["valid"] is True
    assert document["observer_process_id"] == os.getpid()
    assert document["started_utc_ns"] == rows[0]["utc_ns"]
    assert rows[0]["event"] == "observer_started"


def test_pending_transactions_use_besu_standard_pending_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, list[object]]] = []

    def rpc(_url: str, method: str, params: list[object]) -> object:
        calls.append((method, params))
        return {"transactions": [{"hash": "0x" + "44" * 32}]}

    monkeypatch.setattr("xir_lab.native.multihop_hyperlane_observer._rpc", rpc)
    assert _pending_transactions("http://besu") == [{"hash": "0x" + "44" * 32}]
    assert calls == [("eth_getBlockByNumber", ["pending", True])]


@pytest.mark.parametrize(
    "result",
    [None, [], {}, {"transactions": None}, {"transactions": ["0x01"]}],
)
def test_pending_transactions_treat_malformed_besu_block_as_empty_poll(
    result: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "xir_lab.native.multihop_hyperlane_observer._rpc",
        lambda _url, _method, _params: result,
    )
    assert _pending_transactions("http://besu") == []
