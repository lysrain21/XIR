from __future__ import annotations

from eth_utils import keccak  # type: ignore[attr-defined]

from xir_lab.native.deployer import (
    PROFILE_HASHES,
    ROUTE_IDS,
    gateway_typed_id,
    typed_id_hash,
)


def test_gateway_identifier_hash_matches_solidity_abi_encoding() -> None:
    identifier = gateway_typed_id(3133701)
    assert typed_id_hash(identifier) == keccak(
        bytes([identifier[0], len(identifier[1])]) + identifier[1]
    )
    assert len(identifier[1]) == 20


def test_route_and_profile_coordinates_are_distinct() -> None:
    assert len(set(ROUTE_IDS.values())) == 4
    assert len(set(PROFILE_HASHES.values())) == 4
