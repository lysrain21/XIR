from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from xir_lab.preflight.quotes import (
    CONDITION_PROTOCOLS,
    FIXED_LEGS,
    CarrierQuoteAdapter,
    LegQuoteRequest,
    PathQuoteInput,
    ProviderEstimate,
    QuoteError,
    QuotePlanner,
    validate_payment,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)
SENDER = "0x" + "11" * 20
RECEIVER = "0x" + "22" * 20


class MockReadOnlyCarrier:
    def __init__(self, protocol: str) -> None:
        self.protocol = protocol
        self.read_calls: list[LegQuoteRequest] = []
        self.broadcast_calls = 0

    def quote_and_estimate(self, request: LegQuoteRequest) -> ProviderEstimate:
        self.read_calls.append(request)
        protocol_offset = 10 if self.protocol == "hyperlane" else 20
        return ProviderEstimate(
            carrier_payment_wei=100 + protocol_offset + request.leg_index,
            gas_limit=21_000 + request.payload_length,
            max_fee_per_gas_wei=2,
            quoted_at=NOW,
            raw_sha256=(
                "aa" * 32 if self.protocol == "hyperlane" else "bb" * 32
            ),
        )

    def broadcast(self, payload: bytes) -> None:  # pragma: no cover - must stay unused
        del payload
        self.broadcast_calls += 1


def _inputs() -> tuple[PathQuoteInput, ...]:
    paths = []
    for condition, protocols in CONDITION_PROTOCOLS.items():
        for arm in ("baseline", "xir"):
            legs = []
            for index, protocol in enumerate(protocols):
                source, destination = FIXED_LEGS[index]
                legs.append(
                    LegQuoteRequest(
                        condition=condition,
                        arm=arm,  # type: ignore[arg-type]
                        leg_index=index,
                        protocol=protocol,
                        source_network=source,
                        destination_network=destination,
                        sender=SENDER,
                        receiver=RECEIVER,
                        payload_sha256=(
                            "33" * 32 if arm == "baseline" else "44" * 32
                        ),
                        payload_length=32 if arm == "baseline" else 96,
                        security_config_sha256="55" * 32,
                        fee_options_sha256="66" * 32,
                    )
                )
            paths.append(
                PathQuoteInput(
                    condition=condition,
                    arm=arm,  # type: ignore[arg-type]
                    legs=(legs[0], legs[1]),
                )
            )
    return tuple(paths)


def _planner() -> tuple[QuotePlanner, MockReadOnlyCarrier, MockReadOnlyCarrier]:
    hyperlane = MockReadOnlyCarrier("hyperlane")
    layerzero = MockReadOnlyCarrier("layerzero-v2")
    planner = QuotePlanner(
        hyperlane=CarrierQuoteAdapter(
            protocol="hyperlane",
            provider=hyperlane,
        ),
        layerzero=CarrierQuoteAdapter(
            protocol="layerzero-v2",
            provider=layerzero,
        ),
    )
    return planner, hyperlane, layerzero


def test_all_eight_paths_quote_both_legs_with_zero_broadcasts() -> None:
    planner, hyperlane, layerzero = _planner()
    bundle = planner.quote_eight_paths(_inputs())
    assert len(bundle.paths) == 8
    assert len(hyperlane.read_calls) == 8
    assert len(layerzero.read_calls) == 8
    assert hyperlane.broadcast_calls == layerzero.broadcast_calls == 0
    assert all(len(path.legs) == 2 for path in bundle.paths)
    assert all(leg.gas_worst_case_wei > 0 for path in bundle.paths for leg in path.legs)
    assert len(
        {leg.request_sha256 for path in bundle.paths for leg in path.legs}
    ) == 16


def test_quote_age_and_payment_margin_are_enforced_at_submission_boundary() -> None:
    planner, _, _ = _planner()
    quote = planner.quote_eight_paths(_inputs()).paths[0].legs[0]
    validate_payment(
        quote,
        required_payment_wei=(quote.carrier_payment_wei * 11_000 + 9_999) // 10_000,
        checked_at=NOW + timedelta(seconds=60),
        max_quote_age_seconds=60,
        payment_margin_bps=1_000,
    )
    with pytest.raises(QuoteError, match="stale"):
        validate_payment(
            quote,
            required_payment_wei=quote.carrier_payment_wei,
            checked_at=NOW + timedelta(seconds=61),
            max_quote_age_seconds=60,
            payment_margin_bps=1_000,
        )
    with pytest.raises(QuoteError, match="margin"):
        validate_payment(
            quote,
            required_payment_wei=quote.carrier_payment_wei * 2,
            checked_at=NOW,
            max_quote_age_seconds=60,
            payment_margin_bps=1_000,
        )


def test_changed_route_or_carrier_order_fails_before_any_read() -> None:
    planner, hyperlane, layerzero = _planner()
    inputs = list(_inputs())
    first = inputs[0]
    changed_leg = replace(
        first.legs[0],
        destination_network="base-sepolia",
    )
    inputs[0] = replace(first, legs=(changed_leg, first.legs[1]))
    with pytest.raises(QuoteError, match="carrier order or fixed route"):
        planner.quote_eight_paths(tuple(inputs))
    assert hyperlane.read_calls == layerzero.read_calls == []


def test_missing_path_or_changed_bound_input_is_not_silently_substituted() -> None:
    planner, _, _ = _planner()
    with pytest.raises(QuoteError, match="exactly all eight"):
        planner.quote_eight_paths(_inputs()[:-1])
    first = _inputs()[0].legs[0]
    changed = replace(first, payload_sha256="77" * 32)
    adapter = planner.adapters[first.protocol]
    original = adapter.quote(first)
    updated = adapter.quote(changed)
    assert original.request_sha256 != updated.request_sha256
