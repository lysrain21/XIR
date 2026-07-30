"""Web3 client construction for the retained Besu QBFT chains."""

from __future__ import annotations

from requests import RequestException
from web3 import HTTPProvider, Web3
from web3.exceptions import Web3RPCError
from web3.middleware import ExtraDataToPOAMiddleware


def is_transient_rpc_error(error: BaseException) -> bool:
    """Return whether a transport/RPC failure is safe to retry unchanged."""

    if isinstance(error, RequestException):
        return True
    if not isinstance(error, Web3RPCError):
        return False
    message = str(error).lower()
    return (
        "transaction pool not enabled" in message
        and "node not yet in sync" in message
    )


def qbft_web3(rpc_url: str, *, timeout: int = 60) -> Web3:
    """Return a client that accepts QBFT consensus data in block headers."""

    client = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
    client.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return client
