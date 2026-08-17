from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

import xir_lab.native.multihop_effects as effects_module
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_effects import (
    EFFECT_DESTINATION_ROLES,
    EFFECT_LOG_BLOCK_WINDOW,
    _block_windows,
    _build_effect_hash_index,
    _expected_effect_lineage,
    _fetch_effect_logs,
    capture_effect_baseline,
    validate_effect_audit,
)


def test_effect_lineage_canonicalizes_runner_transaction_hash_prefix(
    tmp_path: Path,
) -> None:
    runner_path = tmp_path / "runner.sqlite"
    trace_path = tmp_path / "traces.sqlite"
    transaction_hash = "11" * 32
    attempt_id = "attempt-prefix-regression"
    with sqlite3.connect(runner_path) as runner:
        runner.executescript(
            """
            CREATE TABLE attempts(
              attempt_id TEXT, route TEXT, route_sequence INTEGER,
              phase TEXT, status TEXT
            );
            CREATE TABLE stages(
              attempt_id TEXT, stage TEXT, state TEXT, transaction_hash TEXT
            );
            CREATE TABLE events(
              attempt_id TEXT, stage TEXT, event TEXT,
              chain_role TEXT, detail_json TEXT
            );
            """
        )
        runner.execute(
            "INSERT INTO attempts VALUES(?,?,?,?,?)",
            (attempt_id, "HL", 1, "smoke", "succeeded"),
        )
        runner.execute(
            "INSERT INTO stages VALUES(?,?,?,?)",
            (attempt_id, "destination_verify_deliver", "succeeded", transaction_hash),
        )
        runner.execute(
            "INSERT INTO events VALUES(?,?,?,?,?)",
            (
                attempt_id,
                "destination_effect_observation",
                "observed",
                "c",
                json.dumps(
                    {
                        "delivery_transaction_hash": transaction_hash,
                        "mid": "0x" + "22" * 32,
                    }
                ),
            ),
        )
    with sqlite3.connect(trace_path) as traces:
        traces.execute(
            "CREATE TABLE traces(chain_role TEXT, transaction_hash TEXT, trace_json TEXT)"
        )
        traces.execute(
            "INSERT INTO traces VALUES(?,?,?)",
            (
                "c",
                "0x" + transaction_hash,
                json.dumps(
                    {
                        "status": 1,
                        "block_number": 17,
                        "block_hash": "0x" + "33" * 32,
                    }
                ),
            ),
        )

    lineage = _expected_effect_lineage(
        runner_state_path=runner_path,
        trace_state_path=trace_path,
        phase="smoke",
    )
    assert lineage[attempt_id]["transaction_hash"] == "0x" + transaction_hash


def _audit() -> dict[str, object]:
    effects = [
        {
            "attempt_id": "attempt-a",
            "route": "H",
            "route_sequence": 1,
            "chain_role": "b",
            "transaction_hash": "0x" + "11" * 32,
            "message_id": "0x" + "22" * 32,
            "block_number": 11,
            "block_hash": "0x" + "aa" * 32,
            "log_index": 0,
            "status": 1,
        },
        {
            "attempt_id": "attempt-b",
            "route": "HL",
            "route_sequence": 2,
            "chain_role": "c",
            "transaction_hash": "0x" + "33" * 32,
            "message_id": "0x" + "44" * 32,
            "block_number": 21,
            "block_hash": "0x" + "bb" * 32,
            "log_index": 0,
            "status": 1,
        },
    ]
    checks = []
    for role in EFFECT_DESTINATION_ROLES:
        count = sum(row["chain_role"] == role for row in effects)
        start = 10 if role == "b" else 20 if role == "c" else 30
        checks.append(
            {
                "chain_role": role,
                "start_block_inclusive": start,
                "end_block_inclusive": start + 10,
                "start_block_hash": "0x" + "cc" * 32,
                "end_block_hash": "0x" + "dd" * 32,
                "delivery_count_before": 100,
                "delivery_count_after": 100 + count,
                "counter_delta": count,
                "event_count": count,
                "expected_delta": count,
                "scan_windows": [
                    {"from_block": start + 1, "to_block": start + 10},
                ],
            }
        )
    document: dict[str, object] = {
        "schema_version": "xir-lab-native-multihop-effect-reconciliation-v1",
        "namespace": "native-multihop-switching-v1",
        "phase": "smoke",
        "baseline_sha256": "55" * 32,
        "config_sha256": "66" * 32,
        "profile_sha256": "77" * 32,
        "deployment_sha256": "88" * 32,
        "valid": True,
        "expected_effect_count": 2,
        "observed_effect_count": 2,
        "receiver_checks": checks,
        "effects": effects,
        "complete_block_range_scanned": True,
        "receiver_counters_reconciled": True,
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    return document


def test_effect_baseline_uses_profile_labels_and_never_accesses_source_receiver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roles = ("e", "c", "a", "d", "b")
    profile = {
        "chains": [
            {
                "label": role.upper(),
                "chain_id": 31_337_000 + index,
                "rpc_url": f"rpc://{role}",
            }
            for index, role in enumerate(roles, start=1)
        ]
    }
    deployment = {
        "chains": {
            "a": {"gateway": "0x" + "a0" * 20},
            **{
                role: {"receiver": "0x" + role * 40}
                for role in EFFECT_DESTINATION_ROLES
            },
        }
    }
    profile_path = tmp_path / "profile.json"
    deployment_path = tmp_path / "deployment.json"
    config_path = tmp_path / "config.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    deployment_path.write_text(json.dumps(deployment), encoding="utf-8")
    config_path.write_text("{}", encoding="utf-8")

    class Call:
        def call(self) -> int:
            return 17

    class Functions:
        def deliveryCount(self) -> Call:  # noqa: N802
            return Call()

    class Contract:
        functions = Functions()

    class Eth:
        block_number = 23

        def __init__(self, role: str) -> None:
            self.role = role

        def contract(self, *, address: str, abi: object) -> Contract:
            assert self.role != "a"
            assert address.lower() == deployment["chains"][self.role]["receiver"]
            assert abi == []
            return Contract()

        def get_block(self, number: int) -> dict[str, object]:
            assert number == self.block_number
            return {"hash": bytes.fromhex("11" * 32)}

    monkeypatch.setattr(effects_module, "_artifact", lambda _root: {"abi": []})
    monkeypatch.setattr(
        effects_module,
        "qbft_web3",
        lambda url: SimpleNamespace(eth=Eth(str(url).removeprefix("rpc://"))),
    )
    document = capture_effect_baseline(
        repository_root=tmp_path,
        profile_path=profile_path,
        deployment_path=deployment_path,
        config_path=config_path,
        phase="smoke",
        output_path=tmp_path / "baseline.json",
    )
    rows = document["receivers"]
    assert isinstance(rows, list)
    assert [row["chain_role"] for row in rows] == list(EFFECT_DESTINATION_ROLES)


def _expected(audit: dict[str, object]) -> dict[str, dict[str, object]]:
    keys = (
        "attempt_id",
        "route",
        "route_sequence",
        "chain_role",
        "transaction_hash",
        "message_id",
        "block_number",
        "block_hash",
    )
    return {
        str(row["attempt_id"]): {key: row[key] for key in keys}
        for row in audit["effects"]  # type: ignore[union-attr]
    }


def _bindings() -> dict[str, str]:
    return {
        "baseline_sha256": "55" * 32,
        "config_sha256": "66" * 32,
        "profile_sha256": "77" * 32,
        "deployment_sha256": "88" * 32,
    }


def test_effect_audit_requires_complete_ranges_counters_and_unique_attempts() -> None:
    audit = _audit()
    validate_effect_audit(
        audit,
        phase="smoke",
        expected_effects=_expected(audit),
        expected_bindings=_bindings(),
    )
    drift = _audit()
    drift["complete_block_range_scanned"] = False
    semantic = dict(drift)
    semantic.pop("semantic_sha256")
    drift["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(semantic)).hexdigest()
    with pytest.raises(LocalTopologyError, match="exact-one effect audit"):
        validate_effect_audit(
            drift,
            phase="smoke",
            expected_effects=_expected(_audit()),
            expected_bindings=_bindings(),
        )


def test_effect_audit_rejects_counter_or_block_range_drift() -> None:
    audit = _audit()
    checks = audit["receiver_checks"]
    assert isinstance(checks, list)
    checks[1]["end_block_inclusive"] = 10
    semantic = dict(audit)
    semantic.pop("semantic_sha256")
    audit["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(semantic)).hexdigest()
    with pytest.raises(LocalTopologyError, match="exact-one effect audit"):
        validate_effect_audit(
            audit,
            phase="smoke",
            expected_effects=_expected(_audit()),
            expected_bindings=_bindings(),
        )


def test_effect_audit_rejects_cross_runtime_lineage_and_binding_drift() -> None:
    audit = _audit()
    expected = _expected(audit)
    expected["attempt-a"]["transaction_hash"] = "0x" + "99" * 32
    with pytest.raises(LocalTopologyError, match="exact-one effect audit"):
        validate_effect_audit(
            audit,
            phase="smoke",
            expected_effects=expected,
            expected_bindings=_bindings(),
        )
    with pytest.raises(LocalTopologyError, match="exact-one effect audit"):
        validate_effect_audit(
            audit,
            phase="smoke",
            expected_effects=_expected(audit),
            expected_bindings={**_bindings(), "config_sha256": "00" * 32},
        )


def test_effect_hash_index_is_linear_at_formal_cardinality() -> None:
    expected = {
        f"formal-attempt-{index:06d}": SimpleNamespace(index=index)
        for index in range(110_000)
    }
    index = _build_effect_hash_index(expected)
    assert len(index) == 110_000
    assert {attempt_id for attempt_id, _attempt in index.values()} == set(expected)


def test_effect_block_windows_are_bounded_contiguous_and_complete() -> None:
    start = 91
    end = start + EFFECT_LOG_BLOCK_WINDOW * 3 + 17
    windows = _block_windows(start, end)
    assert windows[0]["from_block"] == start + 1
    assert windows[-1]["to_block"] == end
    assert all(
        windows[index]["to_block"] + 1 == windows[index + 1]["from_block"]
        for index in range(len(windows) - 1)
    )
    assert all(
        window["to_block"] - window["from_block"] + 1 <= EFFECT_LOG_BLOCK_WINDOW
        for window in windows
    )


def test_effect_audit_rejects_a_scan_window_gap() -> None:
    audit = _audit()
    checks = audit["receiver_checks"]
    assert isinstance(checks, list)
    checks[1]["scan_windows"] = [{"from_block": 22, "to_block": 30}]
    semantic = dict(audit)
    semantic.pop("semantic_sha256")
    audit["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(semantic)).hexdigest()
    with pytest.raises(LocalTopologyError, match="exact-one effect audit"):
        validate_effect_audit(
            audit,
            phase="smoke",
            expected_effects=_expected(_audit()),
            expected_bindings=_bindings(),
        )


def test_effect_log_fetch_uses_every_window_and_stable_chain_order() -> None:
    class Source:
        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def get_logs(self, *, from_block: int, to_block: int) -> list[dict[str, int]]:
            self.calls.append((from_block, to_block))
            return [
                {
                    "blockNumber": to_block,
                    "transactionIndex": 1,
                    "logIndex": 0,
                },
                {
                    "blockNumber": from_block,
                    "transactionIndex": 0,
                    "logIndex": 1,
                },
            ]

    windows = _block_windows(0, EFFECT_LOG_BLOCK_WINDOW * 2 + 1)
    source = Source()
    logs = _fetch_effect_logs(source, windows)
    assert source.calls == [
        (window["from_block"], window["to_block"]) for window in windows
    ]
    assert [
        (row["blockNumber"], row["transactionIndex"], row["logIndex"]) for row in logs
    ] == sorted(
        (row["blockNumber"], row["transactionIndex"], row["logIndex"]) for row in logs
    )
