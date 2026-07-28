from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import rfc8785

from xir_lab.preflight.estimator import (
    CHAIN_NAMES,
    EstimateCheck,
    EstimateReport,
    FundingInstruction,
)
from xir_lab.preflight.funding import (
    FundingHandoffError,
    PublicFundingTransaction,
    build_funding_request,
    verify_funding_handoff,
)

NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)


def _estimate() -> EstimateReport:
    instructions = tuple(
        FundingInstruction(
            chain_id=chain_id,
            network_name=network,
            native_test_token=f"{network} native test ETH",
            role=role,  # type: ignore[arg-type]
            recipient_address=f"0x{index * 2 + role_index + 1:040x}",
            estimated_spend_wei=100,
            margin_wei=10,
            balance_floor_wei=20,
            observed_balance_wei=0,
            required_manual_deposit_wei=130,
            maximum_deposit_wei=200,
        )
        for index, (chain_id, network) in enumerate(CHAIN_NAMES.items())
        for role_index, role in enumerate(("deployer", "runner"))
    )
    return EstimateReport(
        checks=(EstimateCheck("all", "pass", "within_limit", True, True),),
        funding_instructions=instructions,
        projected_nonces={},
        estimated_physical_transactions=40,
        estimated_duration_seconds=3600,
        estimated_storage_bytes=1000,
        estimated_rpc_requests=500,
        effects={
            "wallets_created": 0,
            "funding_operations": 0,
            "signing_operations": 0,
            "broadcasts": 0,
        },
    )


class FixtureFundingProvider:
    def __init__(self) -> None:
        self.transactions: dict[str, PublicFundingTransaction] = {}
        self.balances: dict[tuple[str, int], int] = {}
        self.canonical_hashes: dict[int, str] = {}

    def transaction(self, transaction_hash: str) -> PublicFundingTransaction:
        return self.transactions[transaction_hash]

    def balance_at(self, address: str, block_number: int) -> int:
        return self.balances[(address.lower(), block_number)]

    def block_hash(self, block_number: int) -> str | None:
        return self.canonical_hashes.get(block_number)


def _request() -> dict[str, Any]:
    return build_funding_request(
        estimate=_estimate(),
        config_sha256="11" * 32,
        generated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _handoff(
    request: dict[str, Any],
) -> tuple[dict[str, Any], dict[int, FixtureFundingProvider]]:
    providers = {chain_id: FixtureFundingProvider() for chain_id in CHAIN_NAMES}
    receipts = []
    targets = request["payload"]["targets"]
    for index, target in enumerate(targets):
        transaction_hash = f"0x{index + 1:064x}"
        block_number = 1000 + index
        block_hash = f"0x{index + 101:064x}"
        balance = target["approved_budget_wei"] + target["balance_floor_wei"]
        public = PublicFundingTransaction(
            transaction_hash=transaction_hash,
            chain_id=target["chain_id"],
            recipient=target["recipient"],
            amount_wei=target["required_manual_deposit_wei"],
            block_number=block_number,
            block_hash=block_hash,
            canonical=True,
        )
        provider = providers[target["chain_id"]]
        provider.transactions[transaction_hash] = public
        provider.balances[(target["recipient"].lower(), block_number)] = balance
        provider.canonical_hashes[block_number] = block_hash
        receipts.append(
            {
                "chain_id": target["chain_id"],
                "role": target["role"],
                "recipient": target["recipient"],
                "transaction_hash": transaction_hash,
                "amount_wei": target["required_manual_deposit_wei"],
                "observation_block": block_number,
                "observation_block_hash": block_hash,
                "resulting_balance_wei": balance,
                "observed_at": (NOW + timedelta(minutes=5)).isoformat(),
            }
        )
    payload = {
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "receipts": receipts,
    }
    return (
        {
            "schema_version": "xir-lab-funding-handoff-v1",
            "payload": payload,
            "payload_sha256": hashlib.sha256(rfc8785.dumps(payload)).hexdigest(),
        },
        providers,
    )


def _resign(document: dict[str, Any]) -> None:
    document["payload_sha256"] = hashlib.sha256(
        rfc8785.dumps(document["payload"])
    ).hexdigest()


def test_public_funding_request_is_expiring_bounded_and_zero_write() -> None:
    request = _request()
    assert len(request["payload"]["targets"]) == 6
    assert request["payload"]["prohibited_actions"] == [
        "automatic_faucet_claim",
        "automatic_bridge",
        "mainnet_transfer",
        "asset_purchase",
    ]
    assert set(request["effects"].values()) == {0}


def test_public_receipts_balances_and_canonical_blocks_verify() -> None:
    request = _request()
    handoff, providers = _handoff(request)
    result = verify_funding_handoff(
        request=request,
        handoff=handoff,
        providers=providers,
    )
    assert result["outcome"] == "pass"
    assert len(result["receipts"]) == 6
    assert all(item["approved_budget_wei"] == 110 for item in result["receipts"])
    assert set(result["effects"].values()) == {0}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("missing", "exactly cover"),
        ("duplicate", "duplicate"),
        ("recipient", "recipient"),
        ("amount", "bounds"),
        ("balance", "balance"),
        ("expired", "expiry"),
    ),
)
def test_missing_duplicate_wrong_recipient_amount_balance_and_expiry_fail(
    mutation: str,
    reason: str,
) -> None:
    request = _request()
    handoff, providers = _handoff(request)
    receipts = handoff["payload"]["receipts"]
    if mutation == "missing":
        receipts.pop()
    elif mutation == "duplicate":
        receipts[1]["chain_id"] = receipts[0]["chain_id"]
        receipts[1]["role"] = receipts[0]["role"]
    elif mutation == "recipient":
        receipts[0]["recipient"] = "0x" + "ff" * 20
    elif mutation == "amount":
        receipts[0]["amount_wei"] = 201
        tx_hash = receipts[0]["transaction_hash"]
        provider = providers[receipts[0]["chain_id"]]
        providers[receipts[0]["chain_id"]].transactions[tx_hash] = (
            PublicFundingTransaction(
                **{
                    **provider.transactions[tx_hash].__dict__,
                    "amount_wei": 201,
                }
            )
        )
    elif mutation == "balance":
        receipts[0]["resulting_balance_wei"] = 1
    else:
        receipts[0]["observed_at"] = (NOW + timedelta(hours=2)).isoformat()
    _resign(handoff)
    with pytest.raises(FundingHandoffError, match=reason):
        verify_funding_handoff(
            request=request,
            handoff=handoff,
            providers=providers,
        )


def test_reorganization_and_mainnet_chain_are_rejected() -> None:
    request = _request()
    handoff, providers = _handoff(request)
    first = handoff["payload"]["receipts"][0]
    providers[first["chain_id"]].canonical_hashes[first["observation_block"]] = (
        "0x" + "ff" * 32
    )
    with pytest.raises(FundingHandoffError, match="canonical"):
        verify_funding_handoff(
            request=request,
            handoff=handoff,
            providers=providers,
        )

    mainnet = copy.deepcopy(handoff)
    mainnet["payload"]["receipts"][0]["chain_id"] = 1
    _resign(mainnet)
    with pytest.raises(FundingHandoffError, match="schema"):
        verify_funding_handoff(
            request=request,
            handoff=mainnet,
            providers=providers,
        )
