from __future__ import annotations

import hashlib
from typing import Any

from eth_abi import decode, encode  # type: ignore[attr-defined]
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.preflight.carriers import RegistryCandidate, UnsignedSimulationRequest
from xir_lab.preflight.evm_carriers import (
    EvmCarrierStateProvider,
    EvmUnsignedSimulationProvider,
    LayerZeroProbe,
)


def _selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def _result(types: list[str], values: list[Any]) -> str:
    return "0x" + encode(types, values).hex()


PEER = "0x" + "ab" * 20
APP = "0x" + "cd" * 20
ENDPOINT = "0x" + "ef" * 20
ISM = "0x" + "11" * 20
HOOK = "0x" + "12" * 20
REQUIRED_HOOK = "0x" + "13" * 20
SEND_LIB = "0x" + "21" * 20
RECEIVE_LIB = "0x" + "22" * 20
DVN = "0x" + "23" * 20
EXECUTOR = "0x" + "24" * 20
OPTIONS = b"frozen-options"


class AbiFixtureClient:
    def __init__(self, protocol: str) -> None:
        self.protocol = protocol
        self.calls: list[str] = []

    def call(self, method: str, params: list[Any]) -> Any:
        self.calls.append(method)
        if method == "eth_getCode":
            return "0x60016000"
        if method != "eth_call":
            raise AssertionError(method)
        data = bytes.fromhex(params[0]["data"][2:])
        selector = data[:4]
        if self.protocol == "hyperlane":
            responses = {
                _selector("localDomain()"): _result(["uint32"], [11_155_420]),
                _selector("recipientIsm(address)"): _result(["address"], [ISM]),
                _selector("defaultHook()"): _result(["address"], [HOOK]),
                _selector("requiredHook()"): _result(["address"], [REQUIRED_HOOK]),
                _selector("remoteAdapter()"): _result(
                    ["bytes32"], [bytes(12) + bytes.fromhex(PEER[2:])]
                ),
                _selector("quoteBaseline(bytes32,bytes,bytes)"): _result(
                    ["uint256"], [77]
                ),
            }
            return responses[selector]
        if selector == _selector("eid()"):
            return _result(["uint32"], [40_232])
        if selector == _selector("isSupportedEid(uint32)"):
            return _result(["bool"], [True])
        if selector == _selector("getSendLibrary(address,uint32)"):
            return _result(["address"], [SEND_LIB])
        if selector == _selector("getReceiveLibrary(address,uint32)"):
            return _result(["address", "bool"], [RECEIVE_LIB, True])
        if selector == _selector("getConfig(address,address,uint32,uint32)"):
            _, _, _, config_type = decode(
                ["address", "address", "uint32", "uint32"], data[4:]
            )
            if config_type == 1:
                config = encode(["uint32", "address"], [10_000, EXECUTOR])
            else:
                config = encode(
                    ["uint64", "uint8", "uint8", "uint8", "address[]", "address[]"],
                    [5, 1, 0, 0, [DVN], []],
                )
            return _result(["bytes"], [config])
        if selector == _selector("remotePeer()"):
            return _result(["bytes32"], [bytes(12) + bytes.fromhex(PEER[2:])])
        if selector == _selector("enforcedOptionsHash()"):
            return _result(["bytes32"], [keccak(OPTIONS)])
        if selector == _selector("quoteBaseline(bytes32,bytes,bytes)"):
            return _result(["uint256"], [88])
        raise AssertionError(selector.hex())


def _candidate(protocol: str) -> RegistryCandidate:
    return RegistryCandidate(
        protocol=protocol,  # type: ignore[arg-type]
        local_network="op-sepolia",
        remote_network="arbitrum-sepolia",
        endpoint_address=ENDPOINT,
        remote_selector=421_614 if protocol == "hyperlane" else 40_231,
        peer_address=PEER,
        local_adapter_address=APP,
        source_url=(
            "https://raw.githubusercontent.com/hyperlane-xyz/"
            "hyperlane-registry/main/chains/optimismsepolia/addresses.yaml"
            if protocol == "hyperlane"
            else "https://metadata.layerzero-api.com/v1/metadata/deployments"
        ),
        source_sha256="11" * 32,
    )


def test_hyperlane_provider_recollects_endpoint_security_peer_and_quote() -> None:
    client = AbiFixtureClient("hyperlane")
    provider = EvmCarrierStateProvider(clients={"op-sepolia": client}, layerzero_probes={})
    state = provider.hyperlane_state(_candidate("hyperlane"))
    assert state.local_domain == 11_155_420
    assert state.ism_address == ISM
    assert state.hook_address == HOOK
    assert state.enrolled_remote_peer == PEER
    assert state.quoted_payment_wei == 77
    assert len(state.runtime_code_sha256) == 64
    assert set(client.calls) == {"eth_call", "eth_getCode"}


def test_layerzero_provider_recollects_libraries_dvns_executor_options_peer_quote() -> None:
    client = AbiFixtureClient("layerzero-v2")
    route_id = bytes.fromhex("31" * 32)
    provider = EvmCarrierStateProvider(
        clients={"op-sepolia": client},
        layerzero_probes={
            "layerzero-v2:op-sepolia:arbitrum-sepolia": LayerZeroProbe(
                options=OPTIONS,
                route_id=route_id,
            )
        },
    )
    state = provider.layerzero_state(_candidate("layerzero-v2"))
    assert state.local_eid == 40_232
    assert state.supported_remote_eid
    assert state.send_library == SEND_LIB
    assert state.receive_library == RECEIVE_LIB
    assert state.dvns == (DVN,)
    assert state.executor == EXECUTOR
    assert state.configured_peer == PEER
    assert state.quoted_payment_wei == 88
    assert len(state.enforced_options_sha256) == 64


class SimulationClient:
    def __init__(self) -> None:
        self.methods: list[str] = []

    def call(self, method: str, params: list[Any]) -> Any:
        self.methods.append(method)
        if method == "eth_call":
            return "0x"
        if method == "eth_estimateGas":
            return "0x5208"
        raise AssertionError(method)


def test_unsigned_simulation_provider_uses_only_call_and_estimate() -> None:
    client = SimulationClient()
    calldata = bytes.fromhex("60016000")
    request = UnsignedSimulationRequest(
        simulation_id="deployment-op-sepolia",
        category="deployment",
        network_id="op-sepolia",
        condition=None,
        arm=None,
        destination=None,
        value_wei=0,
        calldata_sha256=hashlib.sha256(calldata).hexdigest(),
        gas_limit=100_000,
        sender=APP,
        calldata_hex="0x" + calldata.hex(),
    )
    result = EvmUnsignedSimulationProvider({"op-sepolia": client}).simulate(request)
    assert result.success
    assert client.methods == ["eth_call", "eth_estimateGas"]
