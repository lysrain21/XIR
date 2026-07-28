"""Read-only Hyperlane/LayerZero quote and gas-estimate adapters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

import rfc8785

CarrierProtocol = Literal["hyperlane", "layerzero-v2"]
Arm = Literal["baseline", "xir"]

FIXED_LEGS = (
    ("op-sepolia", "arbitrum-sepolia"),
    ("arbitrum-sepolia", "base-sepolia"),
)
CONDITION_PROTOCOLS: dict[str, tuple[CarrierProtocol, CarrierProtocol]] = {
    "HH": ("hyperlane", "hyperlane"),
    "HL": ("hyperlane", "layerzero-v2"),
    "LH": ("layerzero-v2", "hyperlane"),
    "LL": ("layerzero-v2", "layerzero-v2"),
}


class QuoteError(RuntimeError):
    """Raised when read-only quote evidence is stale, changed, or excessive."""


@dataclass(frozen=True)
class LegQuoteRequest:
    condition: str
    arm: Arm
    leg_index: int
    protocol: CarrierProtocol
    source_network: str
    destination_network: str
    sender: str
    receiver: str
    payload_sha256: str
    payload_length: int
    security_config_sha256: str
    fee_options_sha256: str


@dataclass(frozen=True)
class ProviderEstimate:
    carrier_payment_wei: int
    gas_limit: int
    max_fee_per_gas_wei: int
    quoted_at: datetime
    raw_sha256: str


@dataclass(frozen=True)
class LegQuote:
    request_sha256: str
    request: LegQuoteRequest
    carrier_payment_wei: int
    gas_limit: int
    max_fee_per_gas_wei: int
    quoted_at: datetime
    raw_sha256: str

    @property
    def gas_worst_case_wei(self) -> int:
        return self.gas_limit * self.max_fee_per_gas_wei


@dataclass(frozen=True)
class PathQuoteInput:
    condition: str
    arm: Arm
    legs: tuple[LegQuoteRequest, LegQuoteRequest]


@dataclass(frozen=True)
class PathQuote:
    condition: str
    arm: Arm
    legs: tuple[LegQuote, LegQuote]


@dataclass(frozen=True)
class EightPathQuoteBundle:
    paths: tuple[PathQuote, ...]


class ReadOnlyCarrierProvider(Protocol):
    def quote_and_estimate(self, request: LegQuoteRequest) -> ProviderEstimate:
        """Perform only quote/simulation/gas-estimate reads."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise QuoteError("quote timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _request_sha256(request: LegQuoteRequest) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "condition": request.condition,
                "arm": request.arm,
                "leg_index": request.leg_index,
                "protocol": request.protocol,
                "source_network": request.source_network,
                "destination_network": request.destination_network,
                "sender": request.sender.lower(),
                "receiver": request.receiver.lower(),
                "payload_sha256": request.payload_sha256,
                "payload_length": request.payload_length,
                "security_config_sha256": request.security_config_sha256,
                "fee_options_sha256": request.fee_options_sha256,
            }
        )
    ).hexdigest()


class CarrierQuoteAdapter:
    def __init__(
        self,
        *,
        protocol: CarrierProtocol,
        provider: ReadOnlyCarrierProvider,
    ) -> None:
        self.protocol = protocol
        self.provider = provider

    def quote(self, request: LegQuoteRequest) -> LegQuote:
        if request.protocol != self.protocol:
            raise QuoteError("carrier adapter protocol does not match request")
        _validate_request(request)
        estimate = self.provider.quote_and_estimate(request)
        if min(
            estimate.carrier_payment_wei,
            estimate.gas_limit,
            estimate.max_fee_per_gas_wei,
        ) < 0:
            raise QuoteError("provider estimate values cannot be negative")
        if len(estimate.raw_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in estimate.raw_sha256
        ):
            raise QuoteError("provider raw quote digest is invalid")
        return LegQuote(
            request_sha256=_request_sha256(request),
            request=request,
            carrier_payment_wei=estimate.carrier_payment_wei,
            gas_limit=estimate.gas_limit,
            max_fee_per_gas_wei=estimate.max_fee_per_gas_wei,
            quoted_at=_utc(estimate.quoted_at),
            raw_sha256=estimate.raw_sha256,
        )


class QuotePlanner:
    def __init__(
        self,
        *,
        hyperlane: CarrierQuoteAdapter,
        layerzero: CarrierQuoteAdapter,
    ) -> None:
        if hyperlane.protocol != "hyperlane":
            raise QuoteError("Hyperlane adapter is mislabeled")
        if layerzero.protocol != "layerzero-v2":
            raise QuoteError("LayerZero adapter is mislabeled")
        self.adapters = {
            "hyperlane": hyperlane,
            "layerzero-v2": layerzero,
        }

    def quote_eight_paths(
        self, inputs: tuple[PathQuoteInput, ...]
    ) -> EightPathQuoteBundle:
        cells = {(item.condition, item.arm) for item in inputs}
        expected_cells = {
            (condition, arm)
            for condition in CONDITION_PROTOCOLS
            for arm in ("baseline", "xir")
        }
        if len(inputs) != 8 or cells != expected_cells:
            raise QuoteError("quote inputs must cover exactly all eight condition/arm paths")
        quoted: list[PathQuote] = []
        for path in sorted(inputs, key=lambda item: (item.condition, item.arm)):
            expected_protocols = CONDITION_PROTOCOLS[path.condition]
            legs: list[LegQuote] = []
            for index, request in enumerate(path.legs):
                if (
                    request.condition != path.condition
                    or request.arm != path.arm
                    or request.leg_index != index
                    or request.protocol != expected_protocols[index]
                    or (
                        request.source_network,
                        request.destination_network,
                    )
                    != FIXED_LEGS[index]
                ):
                    raise QuoteError("path request changed carrier order or fixed route")
                legs.append(self.adapters[request.protocol].quote(request))
            quoted.append(
                PathQuote(
                    condition=path.condition,
                    arm=path.arm,
                    legs=(legs[0], legs[1]),
                )
            )
        return EightPathQuoteBundle(tuple(quoted))


def validate_payment(
    quote: LegQuote,
    *,
    required_payment_wei: int,
    checked_at: datetime,
    max_quote_age_seconds: int,
    payment_margin_bps: int,
) -> None:
    if min(required_payment_wei, max_quote_age_seconds, payment_margin_bps) < 0:
        raise QuoteError("payment and quote policy values cannot be negative")
    checked = _utc(checked_at)
    age = (checked - quote.quoted_at).total_seconds()
    if age < 0:
        raise QuoteError("quote timestamp is in the future")
    if age > max_quote_age_seconds:
        raise QuoteError("quote is stale")
    maximum = (
        quote.carrier_payment_wei * (10_000 + payment_margin_bps) + 9_999
    ) // 10_000
    if required_payment_wei > maximum:
        raise QuoteError("required carrier payment exceeds approved quote margin")


def _validate_request(request: LegQuoteRequest) -> None:
    if request.leg_index not in {0, 1}:
        raise QuoteError("quote leg index must be zero or one")
    if request.payload_length < 0:
        raise QuoteError("payload length cannot be negative")
    for value in (
        request.payload_sha256,
        request.security_config_sha256,
        request.fee_options_sha256,
    ):
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise QuoteError("quote-bound digests must be lowercase SHA-256 values")
    for address in (request.sender, request.receiver):
        if (
            len(address) != 42
            or not address.startswith("0x")
            or int(address, 16) == 0
        ):
            raise QuoteError("quote sender and receiver must be nonzero EVM addresses")
