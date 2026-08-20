from __future__ import annotations

import json
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.layerzero import decode_packet
from xir_lab.native.layerzero_worker import LayerZeroWorkerState, load_worker_chains


def _packet() -> bytes:
    return (
        b"\x01"
        + (9).to_bytes(8, "big")
        + (49001).to_bytes(4, "big")
        + bytes.fromhex("00" * 12 + "11" * 20)
        + (49002).to_bytes(4, "big")
        + bytes.fromhex("00" * 12 + "22" * 20)
        + bytes.fromhex("33" * 32)
        + b"payload"
    )


@pytest.mark.parametrize("schema_version", (None, "wrong-schema-v1"))
def test_worker_config_loader_rejects_missing_or_wrong_schema(
    tmp_path: Path, schema_version: str | None
) -> None:
    document: dict[str, object] = {"chains": [{} for _ in range(5)]}
    if schema_version is not None:
        document["schema_version"] = schema_version
    path = tmp_path / "worker-config.json"
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="config schema is missing or invalid"):
        load_worker_chains(path)


def test_worker_state_is_resumable_and_intent_precedes_signature(tmp_path: Path) -> None:
    state = LayerZeroWorkerState(tmp_path / "worker.sqlite")
    packet = decode_packet(_packet())
    state.observe_packet(
        packet=packet,
        source_block=100,
        source_transaction_hash="0xabc",
        source_log_index=2,
    )
    assert state.ready_packets({49001: 100}, 1) == []
    ready = state.ready_packets({49001: 101}, 1)
    assert len(ready) == 1
    action = state.intend_action(
        guid="0x" + packet.guid.hex(),
        stage="dvn_execute",
        destination_chain_id=3133702,
        nonce=7,
        target="0x" + "44" * 20,
        call_data=b"call",
    )
    assert action["calldata_bytes"] == 4
    assert action["nonce"] == 7
    resumed_action = state.intend_action(
        guid="0x" + packet.guid.hex(),
        stage="commit_verification",
        destination_chain_id=3133702,
        nonce=7,
        target="0x" + "55" * 20,
        call_data=b"resumed",
    )
    assert resumed_action["nonce"] == 8
    state.record_signed(str(action["action_id"]), b"signed", "0xdead")
    observations = state.connection.execute(
        "SELECT state FROM observations ORDER BY observation_id"
    ).fetchall()
    assert [row["state"] for row in observations] == ["intended", "intended", "signed"]
    assert state.cursor(49001, 12) == 12
    state.advance_cursor(49001, 200)
    assert state.cursor(49001, 12) == 200
