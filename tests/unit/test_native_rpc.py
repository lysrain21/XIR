from web3.middleware import ExtraDataToPOAMiddleware

from xir_lab.native.rpc import qbft_web3


def test_qbft_web3_injects_extra_data_middleware_at_outer_layer() -> None:
    client = qbft_web3("http://127.0.0.1:1", timeout=7)

    assert client.middleware_onion.get(ExtraDataToPOAMiddleware) is not None
    assert client.provider._request_kwargs["timeout"] == 7
