import pytest
from requests import ConnectionError
from web3.exceptions import Web3RPCError
from web3.middleware import ExtraDataToPOAMiddleware

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.rpc import (
    BESU_RAW_TRANSACTION_RPC_METHOD,
    decode_besu_raw_transaction_result,
    is_transient_rpc_error,
    qbft_web3,
)


def test_besu_raw_transaction_rpc_uses_supported_debug_method() -> None:
    assert BESU_RAW_TRANSACTION_RPC_METHOD == "debug_getRawTransaction"
    assert decode_besu_raw_transaction_result("0x02c0") == b"\x02\xc0"


def test_besu_raw_transaction_decoder_unwraps_264_block_body_encoding() -> None:
    # Besu 26.4's DebugGetRawTransaction calls Transaction.writeTo.  That
    # introduces exactly one RLP byte-string wrapper for EIP-2718 transactions.
    assert decode_besu_raw_transaction_result("0x8202c0") == b"\x02\xc0"

    typed = b"\x02\xf8\x37" + (b"\x00" * 55)
    wrapped = b"\xb8" + bytes([len(typed)]) + typed
    assert decode_besu_raw_transaction_result("0x" + wrapped.hex()) == typed


@pytest.mark.parametrize("value", ["0x8202", "0xb80102", "0x8280c0", "0x81c0"])
def test_besu_raw_transaction_decoder_rejects_invalid_rlp_wrapper(value: str) -> None:
    with pytest.raises(LocalTopologyError, match="raw transaction RLP"):
        decode_besu_raw_transaction_result(value)


@pytest.mark.parametrize(
    "value", [None, "", "0x", "0x0", "0xzz", "0x01 02", "0x01\n02", "0x01\t02"]
)
def test_besu_raw_transaction_result_rejects_missing_or_invalid_hex(value: object) -> None:
    with pytest.raises(LocalTopologyError, match="raw transaction result"):
        decode_besu_raw_transaction_result(value)


def test_qbft_web3_injects_extra_data_middleware_at_outer_layer() -> None:
    client = qbft_web3("http://127.0.0.1:1", timeout=7)

    assert client.middleware_onion.get(ExtraDataToPOAMiddleware) is not None
    assert client.provider._request_kwargs["timeout"] == 7


def test_transient_rpc_error_accepts_transport_and_besu_sync_window() -> None:
    assert is_transient_rpc_error(ConnectionError("RPC reset"))
    assert is_transient_rpc_error(
        Web3RPCError(
            "Transaction pool not enabled. "
            "(Either txpool explicitly disabled, or node not yet in sync)."
        )
    )


def test_transient_rpc_error_rejects_semantic_web3_failures() -> None:
    assert not is_transient_rpc_error(Web3RPCError("execution reverted"))
    assert not is_transient_rpc_error(ValueError("invalid transaction"))
