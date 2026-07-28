from __future__ import annotations

from pathlib import Path

import pytest

from xir_lab.config.loaders import load_lab_config
from xir_lab.execute.signer import (
    PrivateSpool,
    PublicSignerIdentity,
    SignedTransaction,
    SignerCoordinator,
    SignerRequest,
)
from xir_lab.preflight.network_identity import (
    NetworkIdentityVerifier,
    PreflightBoundaryError,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tests" / "fixtures" / "config" / "lab-config.json"
SCHEMA = ROOT / "schemas" / "lab-config-v1.schema.json"


class FixtureProvider:
    def __init__(
        self,
        chain_id: int,
        block_hash: str | None,
        *,
        fail: bool = False,
    ) -> None:
        self.expected_chain_id = chain_id
        self.expected_block_hash = block_hash
        self.fail = fail
        self.chain_calls = 0
        self.block_calls = 0

    def chain_id(self) -> int:
        self.chain_calls += 1
        if self.fail:
            raise ConnectionError("fixture RPC unavailable")
        return self.expected_chain_id

    def block_hash(self, block_number: int) -> str | None:
        assert block_number >= 0
        self.block_calls += 1
        return self.expected_block_hash


class CountingSigner:
    def __init__(self) -> None:
        self.identity_calls = 0
        self.sign_calls = 0

    def public_identity(self, network_id: str) -> PublicSignerIdentity:
        self.identity_calls += 1
        return PublicSignerIdentity(
            "runner",
            network_id,
            "0x" + "11" * 20,
            "22" * 32,
        )

    def sign_transaction(
        self, operation_id: str, request: SignerRequest
    ) -> SignedTransaction:
        self.sign_calls += 1
        return SignedTransaction(operation_id, "0x" + "33" * 32, b"never-called")


def _providers() -> dict[str, FixtureProvider]:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    return {
        network.network_id: FixtureProvider(
            network.chain_id,
            network.checkpoint.block_hash,
        )
        for network in config.networks
    }


def test_all_three_checkpoint_identities_gate_public_identity_only(
    tmp_path: Path,
) -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    providers = _providers()
    verifier = NetworkIdentityVerifier(
        networks=config.networks,
        providers=providers,
    )
    signer = CountingSigner()
    coordinator = SignerCoordinator(signer, PrivateSpool(tmp_path / "spool"))
    with pytest.raises(PreflightBoundaryError, match="gated"):
        verifier.query_public_signer_identity(
            signer=coordinator,
            network_id="op-sepolia",
        )

    suite = verifier.verify()
    assert suite.passed
    assert [result.network_id for result in suite.results] == [
        "op-sepolia",
        "arbitrum-sepolia",
        "base-sepolia",
    ]
    identity = verifier.query_public_signer_identity(
        signer=coordinator,
        network_id="op-sepolia",
    )
    assert identity.signer_id == "runner"
    assert signer.identity_calls == 1
    assert signer.sign_calls == 0
    assert all(provider.chain_calls == 1 for provider in providers.values())
    assert all(provider.block_calls == 1 for provider in providers.values())


def test_wrong_chain_id_fails_before_checkpoint_and_blocks_signer_access(
    tmp_path: Path,
) -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    providers = _providers()
    providers["op-sepolia"].expected_chain_id = 1
    verifier = NetworkIdentityVerifier(networks=config.networks, providers=providers)
    suite = verifier.verify()
    result = suite.results[0]
    assert (result.status, result.reason_code) == ("fail", "chain_id_mismatch")
    assert providers["op-sepolia"].block_calls == 0
    signer = CountingSigner()
    with pytest.raises(PreflightBoundaryError, match="gated"):
        verifier.query_public_signer_identity(
            signer=SignerCoordinator(signer, PrivateSpool(tmp_path / "spool")),
            network_id="op-sepolia",
        )
    assert signer.identity_calls == signer.sign_calls == 0


def test_checkpoint_mismatch_and_rpc_error_are_fail_closed() -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    providers = _providers()
    providers["arbitrum-sepolia"].expected_block_hash = "0x" + "ff" * 32
    providers["base-sepolia"].fail = True
    suite = NetworkIdentityVerifier(
        networks=config.networks,
        providers=providers,
    ).verify()
    assert [(item.status, item.reason_code) for item in suite.results] == [
        ("pass", "identity_verified"),
        ("fail", "checkpoint_hash_mismatch"),
        ("unknown", "read_rpc_error"),
    ]
    assert not suite.passed


def test_provider_set_must_match_fixed_route_exactly() -> None:
    config = load_lab_config(CONFIG, schema_path=SCHEMA)
    providers = _providers()
    del providers["base-sepolia"]
    with pytest.raises(PreflightBoundaryError, match="each fixed-route"):
        NetworkIdentityVerifier(
            networks=config.networks,
            providers=providers,
        ).verify()
