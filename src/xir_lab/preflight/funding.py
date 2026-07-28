"""Public-only manual funding request generation and receipt verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

import jsonschema
import rfc8785

from xir_lab.preflight.estimator import CHAIN_NAMES, EstimateReport


class FundingHandoffError(ValueError):
    """Raised when manual funding evidence does not match the frozen request."""


@dataclass(frozen=True)
class PublicFundingTransaction:
    transaction_hash: str
    chain_id: int
    recipient: str
    amount_wei: int
    block_number: int
    block_hash: str
    canonical: bool


class FundingObservationProvider(Protocol):
    def transaction(self, transaction_hash: str) -> PublicFundingTransaction:
        """Return canonical public transaction facts."""

    def balance_at(self, address: str, block_number: int) -> int:
        """Return public balance at the receipt observation block."""

    def block_hash(self, block_number: int) -> str | None:
        """Return the current canonical block hash."""


def _schema(name: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[3] / "schemas" / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _validate(document: dict[str, Any], schema_name: str) -> None:
    validator = jsonschema.Draft202012Validator(
        _schema(schema_name),
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        raise FundingHandoffError(
            f"{schema_name} violation at {location}: {first.message}"
        )


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FundingHandoffError("funding timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise FundingHandoffError("funding timestamp must include an offset")
    return parsed.astimezone(UTC)


def build_funding_request(
    *,
    estimate: EstimateReport,
    config_sha256: str,
    generated_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Freeze only public recipients and bounded manual test-ETH instructions."""

    generated = generated_at.astimezone(UTC)
    expires = expires_at.astimezone(UTC)
    if expires <= generated:
        raise FundingHandoffError("funding request expiry must follow generation")
    if not estimate.passed:
        raise FundingHandoffError("funding request requires a passing estimate")
    targets = [
        {
            "chain_id": item.chain_id,
            "network_name": item.network_name,
            "native_test_token": item.native_test_token,
            "role": item.role,
            "recipient": item.recipient_address,
            "observed_balance_wei": item.observed_balance_wei,
            "estimated_spend_wei": item.estimated_spend_wei,
            "balance_floor_wei": item.balance_floor_wei,
            "required_manual_deposit_wei": item.required_manual_deposit_wei,
            "maximum_manual_deposit_wei": item.maximum_deposit_wei,
            "approved_budget_wei": item.estimated_spend_wei + item.margin_wei,
        }
        for item in sorted(
            estimate.funding_instructions,
            key=lambda instruction: (instruction.chain_id, instruction.role),
        )
    ]
    payload: dict[str, Any] = {
        "domain": "xir-lab-funding-request-v1",
        "config_sha256": config_sha256,
        "generated_at": generated.isoformat(),
        "expires_at": expires.isoformat(),
        "targets": targets,
        "prohibited_actions": [
            "automatic_faucet_claim",
            "automatic_bridge",
            "mainnet_transfer",
            "asset_purchase",
        ],
    }
    request_digest = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    document = {
        "schema_version": "xir-lab-funding-request-v1",
        "request_id": f"funding_{request_digest[:24]}",
        "request_sha256": request_digest,
        "payload": payload,
        "effects": {
            "wallets_created": 0,
            "funding_operations": 0,
            "signing_operations": 0,
            "broadcasts": 0,
        },
    }
    _validate(document, "funding-request-v1.schema.json")
    return document


def verify_funding_handoff(
    *,
    request: dict[str, Any],
    handoff: dict[str, Any],
    providers: dict[int, FundingObservationProvider],
) -> dict[str, Any]:
    """Verify public funding receipts without acquiring faucet/session credentials."""

    _validate(request, "funding-request-v1.schema.json")
    _validate(handoff, "funding-handoff-v1.schema.json")
    request_payload = cast(dict[str, Any], request["payload"])
    if hashlib.sha256(rfc8785.dumps(request_payload)).hexdigest() != request["request_sha256"]:
        raise FundingHandoffError("funding request digest mismatch")
    handoff_payload = cast(dict[str, Any], handoff["payload"])
    if hashlib.sha256(rfc8785.dumps(handoff_payload)).hexdigest() != handoff["payload_sha256"]:
        raise FundingHandoffError("funding handoff attested digest mismatch")
    if (
        handoff_payload["request_id"] != request["request_id"]
        or handoff_payload["request_sha256"] != request["request_sha256"]
    ):
        raise FundingHandoffError("handoff references a different funding request")
    if set(providers) != set(CHAIN_NAMES):
        raise FundingHandoffError("funding providers must cover exactly three testnets")

    expires = _parse_time(cast(str, request_payload["expires_at"]))
    targets = {
        (cast(int, item["chain_id"]), cast(str, item["role"])): item
        for item in cast(list[dict[str, Any]], request_payload["targets"])
        if cast(int, item["required_manual_deposit_wei"]) > 0
    }
    receipts = cast(list[dict[str, Any]], handoff_payload["receipts"])
    cells = [(cast(int, item["chain_id"]), cast(str, item["role"])) for item in receipts]
    if len(cells) != len(set(cells)):
        raise FundingHandoffError("duplicate funding receipt target")
    if set(cells) != set(targets):
        raise FundingHandoffError("funding receipts do not exactly cover requested deposits")

    verified: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for receipt in receipts:
        chain_id = cast(int, receipt["chain_id"])
        role = cast(str, receipt["role"])
        target = targets[(chain_id, role)]
        if cast(str, receipt["recipient"]).lower() != cast(str, target["recipient"]).lower():
            raise FundingHandoffError("funding receipt recipient differs from request")
        transaction_hash = cast(str, receipt["transaction_hash"]).lower()
        if transaction_hash in seen_hashes:
            raise FundingHandoffError("duplicate funding transaction hash")
        seen_hashes.add(transaction_hash)
        observed_at = _parse_time(cast(str, receipt["observed_at"]))
        if observed_at > expires:
            raise FundingHandoffError("funding receipt was observed after request expiry")
        public = providers[chain_id].transaction(transaction_hash)
        expected = (
            chain_id,
            cast(str, target["recipient"]).lower(),
            cast(int, receipt["amount_wei"]),
            cast(int, receipt["observation_block"]),
            cast(str, receipt["observation_block_hash"]).lower(),
        )
        observed = (
            public.chain_id,
            public.recipient.lower(),
            public.amount_wei,
            public.block_number,
            public.block_hash.lower(),
        )
        if observed != expected or not public.canonical:
            raise FundingHandoffError("public funding transaction facts mismatch or reorg")
        current_hash = providers[chain_id].block_hash(public.block_number)
        if current_hash is None or current_hash.lower() != public.block_hash.lower():
            raise FundingHandoffError("funding observation block is no longer canonical")
        amount = public.amount_wei
        if not (
            cast(int, target["required_manual_deposit_wei"])
            <= amount
            <= cast(int, target["maximum_manual_deposit_wei"])
        ):
            raise FundingHandoffError("funding amount is outside frozen request bounds")
        balance = providers[chain_id].balance_at(public.recipient, public.block_number)
        if balance != receipt["resulting_balance_wei"]:
            raise FundingHandoffError("resulting public balance mismatch")
        required_balance = (
            cast(int, target["approved_budget_wei"])
            + cast(int, target["balance_floor_wei"])
        )
        if balance < required_balance:
            raise FundingHandoffError("resulting public balance remains below floor")
        verified.append(
            {
                "chain_id": chain_id,
                "role": role,
                "recipient": public.recipient,
                "transaction_hash": transaction_hash,
                "amount_wei": amount,
                "observation_block": public.block_number,
                "resulting_balance_wei": balance,
                "approved_budget_wei": target["approved_budget_wei"],
            }
        )
    return {
        "schema_version": "xir-lab-funding-verification-v1",
        "outcome": "pass",
        "request_id": request["request_id"],
        "receipts": sorted(verified, key=lambda item: (item["chain_id"], item["role"])),
        "effects": {
            "funding_operations": 0,
            "signing_operations": 0,
            "broadcasts": 0,
        },
    }
