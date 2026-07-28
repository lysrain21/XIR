"""Concrete read-only EVM carrier state and unsigned simulation providers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, cast

import rfc8785
from eth_abi import decode, encode  # type: ignore[attr-defined]
from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.preflight.carriers import (
    CarrierPreflightError,
    CarrierStateProvider,
    HyperlaneState,
    LayerZeroState,
    RegistryCandidate,
    SimulationResult,
    UnsignedSimulationRequest,
)
from xir_lab.preflight.rpc import RpcClient


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise CarrierPreflightError(f"{label} is not hexadecimal RPC data")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise CarrierPreflightError(f"{label} is not hexadecimal RPC data") from exc


def _abi_call(
    client: RpcClient,
    *,
    to: str,
    signature: str,
    input_types: tuple[str, ...] = (),
    values: tuple[Any, ...] = (),
    output_types: tuple[str, ...],
) -> tuple[Any, ...]:
    if len(input_types) != len(values):
        raise CarrierPreflightError("ABI input arity mismatch")
    calldata = keccak(text=signature)[:4] + encode(list(input_types), list(values))
    result = client.call(
        "eth_call",
        [{"to": to, "data": "0x" + calldata.hex()}, "latest"],
    )
    raw = _hex_bytes(result, f"{signature} result")
    try:
        return decode(list(output_types), raw)
    except Exception as exc:
        raise CarrierPreflightError(f"{signature} ABI result is invalid") from exc


def _address(value: Any, label: str) -> str:
    if isinstance(value, bytes) and len(value) == 20:
        result = "0x" + value.hex()
    elif isinstance(value, str):
        result = value
    else:
        raise CarrierPreflightError(f"{label} is not an address")
    try:
        valid = len(result) == 42 and result.startswith("0x") and int(result, 16) != 0
    except ValueError:
        valid = False
    if not valid:
        raise CarrierPreflightError(f"{label} is not a nonzero address")
    return result


def _peer_address(value: Any, label: str) -> str:
    if not isinstance(value, bytes) or len(value) != 32 or value[:12] != bytes(12):
        raise CarrierPreflightError(f"{label} is not a canonical EVM bytes32 peer")
    return _address(value[12:], label)


def _runtime_sha256(client: RpcClient, address: str) -> str:
    raw = _hex_bytes(
        client.call("eth_getCode", [address, "latest"]),
        "runtime bytecode",
    )
    if not raw:
        return "0" * 64
    return hashlib.sha256(raw).hexdigest()


def _security_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(rfc8785.dumps(document)).hexdigest()


def _route_id(candidate: RegistryCandidate) -> str:
    return f"{candidate.protocol}:{candidate.local_network}:{candidate.remote_network}"


@dataclass(frozen=True)
class LayerZeroProbe:
    options: bytes
    route_id: bytes
    payload: bytes = b"xir-carrier-preflight-v1"


class EvmCarrierStateProvider(CarrierStateProvider):
    """Recollect every carrier fact from public contracts with eth_call only."""

    def __init__(
        self,
        *,
        clients: dict[str, RpcClient],
        layerzero_probes: dict[str, LayerZeroProbe],
    ) -> None:
        self.clients = clients
        self.layerzero_probes = layerzero_probes

    def _client(self, candidate: RegistryCandidate) -> RpcClient:
        try:
            return self.clients[candidate.local_network]
        except KeyError as exc:
            raise CarrierPreflightError("carrier RPC client is unavailable") from exc

    def hyperlane_state(self, candidate: RegistryCandidate) -> HyperlaneState:
        if candidate.protocol != "hyperlane":
            raise CarrierPreflightError("Hyperlane provider received another protocol")
        client = self._client(candidate)
        endpoint = candidate.endpoint_address
        (domain,) = _abi_call(
            client,
            to=endpoint,
            signature="localDomain()",
            output_types=("uint32",),
        )
        (recipient_ism_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="recipientIsm(address)",
            input_types=("address",),
            values=(candidate.local_adapter_address,),
            output_types=("address",),
        )
        (default_hook_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="defaultHook()",
            output_types=("address",),
        )
        (required_hook_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="requiredHook()",
            output_types=("address",),
        )
        (peer_raw,) = _abi_call(
            client,
            to=candidate.local_adapter_address,
            signature="remoteAdapter()",
            output_types=("bytes32",),
        )
        (quote,) = _abi_call(
            client,
            to=candidate.local_adapter_address,
            signature="quoteBaseline(bytes32,bytes,bytes)",
            input_types=("bytes32", "bytes", "bytes"),
            values=(keccak(text=_route_id(candidate)), b"xir-carrier-preflight-v1", b""),
            output_types=("uint256",),
        )
        ism = _address(recipient_ism_raw, "Hyperlane recipient ISM")
        default_hook = _address(default_hook_raw, "Hyperlane default hook")
        required_hook = _address(required_hook_raw, "Hyperlane required hook")
        peer = _peer_address(peer_raw, "Hyperlane remote adapter")
        security = {
            "local_domain": cast(int, domain),
            "recipient_ism": ism.lower(),
            "default_hook": default_hook.lower(),
            "required_hook": required_hook.lower(),
            "remote_adapter": peer.lower(),
        }
        return HyperlaneState(
            runtime_code_sha256=_runtime_sha256(client, endpoint),
            local_domain=cast(int, domain),
            ism_address=ism,
            hook_address=default_hook,
            payment_required_wei=cast(int, quote),
            enrolled_remote_peer=peer,
            security_config_sha256=_security_digest(security),
            quoted_payment_wei=cast(int, quote),
        )

    def layerzero_state(self, candidate: RegistryCandidate) -> LayerZeroState:
        if candidate.protocol != "layerzero-v2":
            raise CarrierPreflightError("LayerZero provider received another protocol")
        client = self._client(candidate)
        endpoint = candidate.endpoint_address
        try:
            probe = self.layerzero_probes[_route_id(candidate)]
        except KeyError as exc:
            raise CarrierPreflightError("LayerZero route probe is unavailable") from exc
        if len(probe.route_id) != 32:
            raise CarrierPreflightError("LayerZero route ID must be bytes32")
        (eid,) = _abi_call(
            client,
            to=endpoint,
            signature="eid()",
            output_types=("uint32",),
        )
        (supported,) = _abi_call(
            client,
            to=endpoint,
            signature="isSupportedEid(uint32)",
            input_types=("uint32",),
            values=(candidate.remote_selector,),
            output_types=("bool",),
        )
        (send_library_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="getSendLibrary(address,uint32)",
            input_types=("address", "uint32"),
            values=(candidate.local_adapter_address, candidate.remote_selector),
            output_types=("address",),
        )
        receive_library_raw, receive_is_default = _abi_call(
            client,
            to=endpoint,
            signature="getReceiveLibrary(address,uint32)",
            input_types=("address", "uint32"),
            values=(candidate.local_adapter_address, candidate.remote_selector),
            output_types=("address", "bool"),
        )
        send_library = _address(send_library_raw, "LayerZero send library")
        receive_library = _address(receive_library_raw, "LayerZero receive library")
        (send_uln_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="getConfig(address,address,uint32,uint32)",
            input_types=("address", "address", "uint32", "uint32"),
            values=(
                candidate.local_adapter_address,
                send_library,
                candidate.remote_selector,
                2,
            ),
            output_types=("bytes",),
        )
        (receive_uln_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="getConfig(address,address,uint32,uint32)",
            input_types=("address", "address", "uint32", "uint32"),
            values=(
                candidate.local_adapter_address,
                receive_library,
                candidate.remote_selector,
                2,
            ),
            output_types=("bytes",),
        )
        (executor_raw,) = _abi_call(
            client,
            to=endpoint,
            signature="getConfig(address,address,uint32,uint32)",
            input_types=("address", "address", "uint32", "uint32"),
            values=(
                candidate.local_adapter_address,
                send_library,
                candidate.remote_selector,
                1,
            ),
            output_types=("bytes",),
        )
        try:
            send_uln = decode(
                ["uint64", "uint8", "uint8", "uint8", "address[]", "address[]"],
                cast(bytes, send_uln_raw),
            )
            receive_uln = decode(
                ["uint64", "uint8", "uint8", "uint8", "address[]", "address[]"],
                cast(bytes, receive_uln_raw),
            )
            _, executor_raw_address = decode(
                ["uint32", "address"], cast(bytes, executor_raw)
            )
        except Exception as exc:
            raise CarrierPreflightError("LayerZero security config is not ULN302") from exc
        dvn_values = {
            _address(item, "LayerZero DVN")
            for config in (send_uln, receive_uln)
            for item in (*cast(tuple[Any, ...], config[4]), *cast(tuple[Any, ...], config[5]))
        }
        executor = _address(executor_raw_address, "LayerZero executor")
        (peer_raw,) = _abi_call(
            client,
            to=candidate.local_adapter_address,
            signature="remotePeer()",
            output_types=("bytes32",),
        )
        (options_hash_raw,) = _abi_call(
            client,
            to=candidate.local_adapter_address,
            signature="enforcedOptionsHash()",
            output_types=("bytes32",),
        )
        if (
            not isinstance(options_hash_raw, bytes)
            or options_hash_raw == bytes(32)
            or options_hash_raw != keccak(probe.options)
        ):
            raise CarrierPreflightError("LayerZero enforced options are absent or changed")
        (quote,) = _abi_call(
            client,
            to=candidate.local_adapter_address,
            signature="quoteBaseline(bytes32,bytes,bytes)",
            input_types=("bytes32", "bytes", "bytes"),
            values=(probe.route_id, probe.payload, probe.options),
            output_types=("uint256",),
        )
        peer = _peer_address(peer_raw, "LayerZero remote peer")
        security = {
            "local_eid": cast(int, eid),
            "remote_eid": candidate.remote_selector,
            "send_library": send_library.lower(),
            "receive_library": receive_library.lower(),
            "receive_is_default": cast(bool, receive_is_default),
            "send_uln": cast(bytes, send_uln_raw).hex(),
            "receive_uln": cast(bytes, receive_uln_raw).hex(),
            "executor": executor.lower(),
            "enforced_options_hash": options_hash_raw.hex(),
            "remote_peer": peer.lower(),
        }
        return LayerZeroState(
            runtime_code_sha256=_runtime_sha256(client, endpoint),
            local_eid=cast(int, eid),
            supported_remote_eid=cast(bool, supported),
            send_library=send_library,
            receive_library=receive_library,
            dvns=tuple(sorted(dvn_values)),
            executor=executor,
            enforced_options_sha256=hashlib.sha256(options_hash_raw).hexdigest(),
            configured_peer=peer,
            security_config_sha256=_security_digest(security),
            quoted_payment_wei=cast(int, quote),
        )


class EvmUnsignedSimulationProvider:
    """Execute eth_call and eth_estimateGas without signing or broadcasting."""

    def __init__(self, clients: dict[str, RpcClient]) -> None:
        self.clients = clients

    def simulate(self, request: UnsignedSimulationRequest) -> SimulationResult:
        success = False
        reason = "simulation_unavailable"
        try:
            client = self.clients[request.network_id]
            if request.calldata_hex is None:
                raise CarrierPreflightError("simulation calldata is unavailable")
            calldata = _hex_bytes(request.calldata_hex, "simulation calldata")
            if hashlib.sha256(calldata).hexdigest() != request.calldata_sha256:
                raise CarrierPreflightError("simulation calldata digest mismatch")
            transaction: dict[str, str] = {
                "data": request.calldata_hex,
                "value": hex(request.value_wei),
                "gas": hex(request.gas_limit),
            }
            if request.destination is not None:
                transaction["to"] = request.destination
            if request.sender is not None:
                transaction["from"] = request.sender
            client.call("eth_call", [transaction, "latest"])
            estimated = client.call("eth_estimateGas", [transaction, "latest"])
            if not isinstance(estimated, str) or int(estimated, 16) > request.gas_limit:
                raise CarrierPreflightError("simulation gas estimate exceeds limit")
            success = True
            reason = "simulation_pass"
        except Exception:
            reason = "simulation_revert"
        raw = hashlib.sha256(
            rfc8785.dumps(
                {
                    "simulation_id": request.simulation_id,
                    "success": success,
                    "reason_code": reason,
                }
            )
        ).hexdigest()
        return SimulationResult(request.simulation_id, success, raw, reason)
