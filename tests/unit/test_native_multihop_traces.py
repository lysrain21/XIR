from __future__ import annotations

import pytest
from eth_account import Account

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.multihop_traces import (
    _hyperlane_process_bindings,
    normalize_raw_transaction,
    normalize_transaction_trace,
)


def test_normalize_transaction_trace_preserves_non_additive_call_gas() -> None:
    transaction_hash = "0x" + "12" * 32
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash=transaction_hash,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox=None,
        expected_hyperlane_default_ism=None,
        labels={("b", "0x" + "34" * 20): "gateway"},
        trace_result=[
            {
                "action": {
                    "callType": "call",
                    "from": "0x" + "11" * 20,
                    "to": "0x" + "22" * 20,
                    "input": "0x1234",
                    "gas": "0x100000",
                },
                "result": {"gasUsed": "0x9c40", "output": "0x"},
                "subtraces": 1,
                "traceAddress": [],
                "type": "call",
            },
            {
                "action": {
                    "callType": "call",
                    "from": "0x" + "22" * 20,
                    "to": "0x" + "34" * 20,
                    "input": "0x",
                    "gas": "0x1000",
                },
                "result": {"gasUsed": "0x800", "output": "0x"},
                "subtraces": 0,
                "traceAddress": [0],
                "type": "call",
            },
        ],
    )
    assert result["top_level_execution_gas"] == 40_000
    assert result["receipt_minus_trace_gas"] == 10_000
    assert result["internal_call_count"] == 1
    assert result["internal_gas_is_inclusive_non_additive"] is True
    assert result["traces"][1]["component"] == "gateway"


def test_normalize_transaction_trace_rejects_errored_root() -> None:
    with pytest.raises(LocalTopologyError, match="unexpected errored trace"):
        normalize_transaction_trace(
            chain_role="a",
            transaction_hash="0x" + "12" * 32,
            receipt_gas=50_000,
            receipt_status=1,
            expected_root_target="0x" + "22" * 20,
            expected_hyperlane_mailbox=None,
            expected_hyperlane_default_ism=None,
            labels={},
            trace_result=[
                {
                    "action": {
                        "callType": "call",
                        "from": "0x" + "11" * 20,
                        "to": "0x" + "22" * 20,
                        "gas": "0x100",
                    },
                    "result": {"gasUsed": "0x80"},
                    "traceAddress": [],
                    "type": "call",
                    "error": "Reverted",
                }
            ],
        )


def test_normalize_transaction_trace_preserves_expected_optional_ism_probe_error() -> None:
    adapter = "0x" + "34" * 20
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox=None,
        expected_hyperlane_default_ism=None,
        labels={("b", adapter): "route_h_hop_1_in"},
        trace_result=[
            {
                "action": {
                    "callType": "call",
                    "from": "0x" + "11" * 20,
                    "to": "0x" + "22" * 20,
                    "input": "0x1234",
                    "gas": "0x100000",
                },
                "result": {"gasUsed": "0x9c40", "output": "0x"},
                "traceAddress": [],
                "type": "call",
            },
            {
                "action": {
                    "callType": "staticcall",
                    "from": "0x" + "22" * 20,
                    "to": adapter,
                    "input": "0xde523cf3",
                    "gas": "0x1000",
                },
                "traceAddress": [0],
                "type": "call",
                "error": "Reverted",
            },
        ],
    )
    probe = result["traces"][1]
    assert probe["error"] == "Reverted"
    assert probe["error_classification"] == "expected_optional_recipient_ism_probe"
    assert probe["gas_used"] is None


@pytest.mark.parametrize(
    ("call_type", "selector", "label"),
    [
        ("call", "0xde523cf3", "route_h_hop_1_in"),
        ("staticcall", "0x12345678", "route_h_hop_1_in"),
        ("staticcall", "0xde523cf3", "gateway"),
    ],
)
def test_normalize_transaction_trace_rejects_other_errored_subcalls(
    call_type: str, selector: str, label: str
) -> None:
    destination = "0x" + "34" * 20
    with pytest.raises(LocalTopologyError, match="unexpected errored trace"):
        normalize_transaction_trace(
            chain_role="b",
            transaction_hash="0x" + "12" * 32,
            receipt_gas=50_000,
            receipt_status=1,
            expected_root_target="0x" + "22" * 20,
            expected_hyperlane_mailbox=None,
            expected_hyperlane_default_ism=None,
            labels={("b", destination): label},
            trace_result=[
                {
                    "action": {
                        "callType": "call",
                        "from": "0x" + "11" * 20,
                        "to": "0x" + "22" * 20,
                        "input": "0x",
                        "gas": "0x100000",
                    },
                    "result": {"gasUsed": "0x9c40", "output": "0x"},
                    "traceAddress": [],
                    "type": "call",
                },
                {
                    "action": {
                        "callType": call_type,
                        "from": "0x" + "22" * 20,
                        "to": destination,
                        "input": selector,
                        "gas": "0x1000",
                    },
                    "traceAddress": [0],
                    "type": "call",
                    "error": "Reverted",
                },
            ],
        )


def _successful_hyperlane_process_trace() -> list[dict[str, object]]:
    mailbox = "0x" + "22" * 20
    recipient = "0x" + "34" * 20
    ism = "0x" + "56" * 20
    return [
        {
            "action": {
                "callType": "call",
                "from": "0x" + "11" * 20,
                "to": mailbox,
                "input": "0x7c39d130",
                "gas": "0x100000",
            },
            "result": {"gasUsed": "0x9c40", "output": "0x"},
            "traceAddress": [],
            "type": "call",
        },
        {
            "action": {
                "callType": "staticcall",
                "from": mailbox,
                "to": recipient,
                "input": "0xde523cf3",
                "gas": "0x1000",
            },
            "traceAddress": [0],
            "type": "call",
            "error": "Reverted",
        },
        {
            "action": {
                # Hyperlane's interface does not declare verify as view, so
                # the real Mailbox boundary is CALL rather than STATICCALL.
                "callType": "call",
                "from": mailbox,
                "to": ism,
                "input": "0xf7e83aee",
                "gas": "0x2000",
            },
            "traceAddress": [1],
            "type": "call",
            "error": "Reverted",
        },
        {
            "action": {
                "callType": "call",
                "from": mailbox,
                "to": recipient,
                "input": "0x56d5d475",
                "gas": "0x3000",
            },
            "result": {"gasUsed": "0x1800", "output": "0x"},
            "traceAddress": [2],
            "type": "call",
        },
    ]


def test_normalize_transaction_trace_preserves_exact_successful_hyperlane_ism_boundary() -> None:
    recipient = "0x" + "34" * 20
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", recipient): "route_h_hop_1_in"},
        trace_result=_successful_hyperlane_process_trace(),
    )
    assert result["traces"][1]["error_classification"] == (
        "expected_optional_recipient_ism_probe"
    )
    assert result["traces"][2]["error_classification"] == (
        "successful_hyperlane_ism_verification_trace_boundary"
    )


def test_normalize_transaction_trace_preserves_bound_besu_reverted_delivery() -> None:
    trace = _successful_hyperlane_process_trace()
    trace[3].pop("result")
    trace[3]["error"] = "Reverted"
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
        trace_result=trace,
    )
    assert result["traces"][3]["error_classification"] == (
        "successful_hyperlane_delivery_trace_boundary"
    )
    assert result["traces"][3]["gas_used"] is None


@pytest.mark.parametrize(
    ("probe_result", "verify_result"),
    [
        (None, None),
        ({"gasUsed": "0x1", "output": "0x"}, None),
        (None, {"gasUsed": "0x1", "output": "0x" + "00" * 31 + "01"}),
        ({"gasUsed": "0x1", "output": "0x"}, {}),
    ],
)
def test_normalize_transaction_trace_accepts_besu_success_boundary_representations(
    probe_result: dict[str, str] | None,
    verify_result: dict[str, str] | None,
) -> None:
    trace = _successful_hyperlane_process_trace()
    if probe_result is not None:
        trace[1].pop("error")
        trace[1]["result"] = probe_result
    if verify_result is not None:
        trace[2]["result"] = verify_result
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
        trace_result=trace,
    )
    assert result["traces"][2]["error_classification"] == (
        "successful_hyperlane_ism_verification_trace_boundary"
    )
    assert all("_result_output" not in row for row in result["traces"])
    assert all("_result_output_present" not in row for row in result["traces"])


def test_normalize_transaction_trace_accepts_bound_besu_null_results() -> None:
    trace = _successful_hyperlane_process_trace()
    trace[1]["result"] = None
    trace[2]["result"] = None
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
        trace_result=trace,
    )
    assert result["traces"][1]["result_is_null"] is True
    assert result["traces"][2]["result_is_null"] is True
    assert result["traces"][2]["error_classification"] == (
        "successful_hyperlane_ism_verification_trace_boundary"
    )


@pytest.mark.parametrize("malformed_result", ["0x", [], 1])
def test_normalize_transaction_trace_ignores_verify_result_representation(
    malformed_result: object,
) -> None:
    trace = _successful_hyperlane_process_trace()
    trace[2]["result"] = malformed_result
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
        trace_result=trace,
    )
    assert result["traces"][2]["error_classification"] == (
        "successful_hyperlane_ism_verification_trace_boundary"
    )


@pytest.mark.parametrize("diagnostic_result", ["0x", [], 1])
def test_normalize_transaction_trace_ignores_caught_probe_result_representation(
    diagnostic_result: object,
) -> None:
    trace = _successful_hyperlane_process_trace()
    trace[1]["result"] = diagnostic_result
    result = normalize_transaction_trace(
        chain_role="b",
        transaction_hash="0x" + "12" * 32,
        receipt_gas=50_000,
        receipt_status=1,
        expected_root_target="0x" + "22" * 20,
        expected_hyperlane_mailbox="0x" + "22" * 20,
        expected_hyperlane_default_ism="0x" + "56" * 20,
        labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
        trace_result=trace,
    )
    assert result["traces"][1]["error_classification"] == (
        "expected_optional_recipient_ism_probe"
    )


@pytest.mark.parametrize(
    ("mutation", "receipt_status"),
    [
        ("root_selector", 1),
        ("root_call_type", 1),
        ("verify_call_type", 1),
        ("verify_selector", 1),
        ("verify_error", 1),
        ("verify_parent", 1),
        ("verify_position", 1),
        ("missing_verify", 1),
        ("missing_probe_and_verify", 1),
        ("successful_arbitrary_verify", 1),
        ("coupled_probe_substitution", 1),
        ("missing_probe", 1),
        ("missing_delivery", 1),
        ("delivery_selector", 1),
        ("delivery_target", 1),
        ("delivery_parent", 1),
        ("delivery_no_gas_result", 1),
        ("duplicate_child", 1),
        ("extra_child", 1),
        ("probe_wrong_error", 1),
        ("probe_nonempty_result", 1),
        ("probe_missing_output", 1),
        ("delivery_error", 1),
        ("delivery_call_type", 1),
        ("root_target", 1),
        ("mailbox_binding", 1),
        ("missing_mailbox_binding", 1),
        ("default_ism_binding", 1),
        ("missing_default_ism_binding", 1),
        ("failed_receipt", 0),
    ],
)
def test_normalize_transaction_trace_rejects_incomplete_hyperlane_ism_boundary(
    mutation: str, receipt_status: int
) -> None:
    trace = _successful_hyperlane_process_trace()
    if mutation == "root_selector":
        trace[0]["action"]["input"] = "0x12345678"  # type: ignore[index]
    elif mutation == "root_call_type":
        trace[0]["action"]["callType"] = "staticcall"  # type: ignore[index]
    elif mutation == "verify_call_type":
        trace[2]["action"]["callType"] = "staticcall"  # type: ignore[index]
    elif mutation == "verify_selector":
        trace[2]["action"]["input"] = "0x12345678"  # type: ignore[index]
    elif mutation == "verify_error":
        trace[2]["error"] = "Out of gas"
    elif mutation == "verify_parent":
        trace[2]["action"]["from"] = "0x" + "99" * 20  # type: ignore[index]
    elif mutation == "verify_position":
        trace[2]["traceAddress"] = [3]
    elif mutation == "missing_verify":
        trace.pop(2)
    elif mutation == "missing_probe_and_verify":
        trace.pop(2)
        trace.pop(1)
    elif mutation == "successful_arbitrary_verify":
        trace[2].pop("error")
        trace[2]["result"] = {"gasUsed": "0x1", "output": "0x"}
        trace[2]["action"] = {
            "callType": "delegatecall",
            "from": "0x" + "98" * 20,
            "to": "0x" + "99" * 20,
            "input": "0x12345678",
            "gas": "0x2000",
        }
    elif mutation == "coupled_probe_substitution":
        trace[2]["action"] = dict(trace[1]["action"])  # type: ignore[arg-type]
    elif mutation == "missing_probe":
        trace.pop(1)
    elif mutation == "missing_delivery":
        trace.pop()
    elif mutation == "delivery_selector":
        trace[3]["action"]["input"] = "0x12345678"  # type: ignore[index]
    elif mutation == "delivery_target":
        trace[3]["action"]["to"] = "0x" + "99" * 20  # type: ignore[index]
    elif mutation == "delivery_parent":
        trace[3]["action"]["from"] = "0x" + "99" * 20  # type: ignore[index]
    elif mutation == "delivery_no_gas_result":
        trace[3]["result"] = {"output": "0x"}
    elif mutation == "duplicate_child":
        trace.append(dict(trace[3]))
    elif mutation == "extra_child":
        extra = dict(trace[3])
        extra["traceAddress"] = [3]
        trace.append(extra)
    elif mutation == "probe_wrong_error":
        trace[1]["error"] = "Out of gas"
    elif mutation == "probe_nonempty_result":
        trace[1].pop("error")
        trace[1]["result"] = {"gasUsed": "0x1", "output": "0x" + "00" * 12 + "99" * 20}
    elif mutation == "probe_missing_output":
        trace[1].pop("error")
        trace[1]["result"] = {"gasUsed": "0x1"}
    elif mutation == "delivery_error":
        trace[3].pop("result")
        trace[3]["error"] = "Out of gas"
    elif mutation == "delivery_call_type":
        trace[3]["action"]["callType"] = "staticcall"  # type: ignore[index]
    elif mutation == "root_target":
        trace[0]["action"]["to"] = "0x" + "99" * 20  # type: ignore[index]
    expected_mailbox: str | None = "0x" + "22" * 20
    expected_default_ism: str | None = "0x" + "56" * 20
    if mutation == "mailbox_binding":
        expected_mailbox = "0x" + "99" * 20
    elif mutation == "missing_mailbox_binding":
        expected_mailbox = None
    elif mutation == "default_ism_binding":
        expected_default_ism = "0x" + "99" * 20
    elif mutation == "missing_default_ism_binding":
        expected_default_ism = None
    with pytest.raises(LocalTopologyError):
        normalize_transaction_trace(
            chain_role="b",
            transaction_hash="0x" + "12" * 32,
            receipt_gas=50_000,
            receipt_status=receipt_status,
            expected_root_target="0x" + "22" * 20,
            expected_hyperlane_mailbox=expected_mailbox,
            expected_hyperlane_default_ism=expected_default_ism,
            labels={("b", "0x" + "34" * 20): "route_h_hop_1_in"},
            trace_result=trace,
        )


def test_hyperlane_process_mailboxes_requires_semantic_binding(tmp_path) -> None:
    import hashlib
    import json

    import rfc8785

    transaction_hash = "0x" + "12" * 32
    mailbox = "0x" + "22" * 20
    document = {
        "schema_version": "xir-lab-native-multihop-hyperlane-processes-v1",
        "messages": {
            "0x" + "34" * 32: {
                "chain_role": "b",
                "transaction_hash": transaction_hash,
                "mailbox": mailbox,
                "default_ism": "0x" + "56" * 20,
                "status": 1,
            }
        },
    }
    document["semantic_sha256"] = hashlib.sha256(rfc8785.dumps(document)).hexdigest()
    path = tmp_path / "hyperlane-processes.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert _hyperlane_process_bindings(path) == {
        ("b", transaction_hash): (mailbox, "0x" + "56" * 20)
    }
    document["messages"]["0x" + "34" * 32]["mailbox"] = "0x" + "99" * 20
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LocalTopologyError, match="semantic hash"):
        _hyperlane_process_bindings(path)


def test_normalize_raw_transaction_binds_hash_chain_and_signer() -> None:
    account = Account.create("multihop-trace-test")
    signed = account.sign_transaction(
        {
            "chainId": 3133701,
            "nonce": 7,
            "to": "0x" + "12" * 20,
            "data": b"\x12\x34",
            "value": 0,
            "gas": 100_000,
            "maxFeePerGas": 2,
            "maxPriorityFeePerGas": 0,
            "type": 2,
        }
    )
    row = normalize_raw_transaction(
        raw_hex=signed.raw_transaction.hex(),
        transaction_hash=signed.hash.hex(),
        expected_chain_id=3133701,
    )
    assert row["sender"] == account.address.lower()
    assert row["nonce"] == 7
    with pytest.raises(LocalTopologyError, match="hash/chain"):
        normalize_raw_transaction(
            raw_hex=signed.raw_transaction.hex(),
            transaction_hash=signed.hash.hex(),
            expected_chain_id=3133702,
        )


def test_normalize_raw_transaction_accepts_eip155_legacy_hyperlane_shape() -> None:
    account = Account.create("multihop-trace-legacy-test")
    signed = account.sign_transaction(
        {
            "chainId": 3133702,
            "nonce": 5,
            "to": "0x" + "34" * 20,
            "data": bytes.fromhex("7c39d130") + (b"\x56" * 768),
            "value": 0,
            "gas": 206_564,
            "gasPrice": 1,
        }
    )
    assert signed.raw_transaction[0] >= 0xC0
    row = normalize_raw_transaction(
        raw_hex=signed.raw_transaction.hex(),
        transaction_hash=signed.hash.hex(),
        expected_chain_id=3133702,
    )
    assert row["sender"] == account.address.lower()
    assert row["nonce"] == 5
    assert row["target"] == "0x" + "34" * 20
    assert row["chain_id"] == 3133702


def test_normalize_raw_transaction_rejects_unprotected_legacy_transaction() -> None:
    account = Account.create("multihop-trace-unprotected-legacy-test")
    signed = account.sign_transaction(
        {
            "nonce": 1,
            "to": "0x" + "45" * 20,
            "data": b"",
            "value": 0,
            "gas": 21_000,
            "gasPrice": 1,
        }
    )
    with pytest.raises(LocalTopologyError, match="undecodable"):
        normalize_raw_transaction(
            raw_hex=signed.raw_transaction.hex(),
            transaction_hash=signed.hash.hex(),
            expected_chain_id=3133702,
        )
