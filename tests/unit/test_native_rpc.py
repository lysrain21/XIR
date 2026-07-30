from requests import ConnectionError
from web3.exceptions import Web3RPCError
from web3.middleware import ExtraDataToPOAMiddleware

from xir_lab.native.rpc import is_transient_rpc_error, qbft_web3


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
