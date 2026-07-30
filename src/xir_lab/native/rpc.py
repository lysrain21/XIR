"""Web3 client construction for the retained Besu QBFT chains."""

from __future__ import annotations

from web3 import HTTPProvider, Web3
from web3.middleware import ExtraDataToPOAMiddleware


def qbft_web3(rpc_url: str, *, timeout: int = 60) -> Web3:
    """Return a client that accepts QBFT consensus data in block headers."""

    client = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
    client.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return client
