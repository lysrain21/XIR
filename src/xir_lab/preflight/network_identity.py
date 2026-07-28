"""Read-only chain/checkpoint verification before any signer access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from xir_lab.config.loaders import EXPECTED_NETWORKS, Network
from xir_lab.execute.signer import PublicSignerIdentity, SignerCoordinator


class PreflightBoundaryError(RuntimeError):
    """Raised when identity ordering or fixed-network invariants fail."""


class ReadOnlyChainProvider(Protocol):
    def chain_id(self) -> int:
        """Return eth_chainId without modifying public state."""

    def block_hash(self, block_number: int) -> str | None:
        """Return one public block hash without modifying public state."""


@dataclass(frozen=True)
class ChainIdentityResult:
    network_id: str
    expected_chain_id: int
    observed_chain_id: int | None
    checkpoint_block_number: int
    expected_checkpoint_hash: str
    observed_checkpoint_hash: str | None
    status: str
    reason_code: str


@dataclass(frozen=True)
class ChainIdentitySuite:
    results: tuple[ChainIdentityResult, ...]

    @property
    def passed(self) -> bool:
        return len(self.results) == 3 and all(
            result.status == "pass" for result in self.results
        )


class NetworkIdentityVerifier:
    """Verify the exact fixed route and gate the public-identity-only signer call."""

    def __init__(
        self,
        *,
        networks: tuple[Network, ...],
        providers: dict[str, ReadOnlyChainProvider],
    ) -> None:
        self.networks = networks
        self.providers = providers
        self._suite: ChainIdentitySuite | None = None

    def verify(self) -> ChainIdentitySuite:
        network_map = {network.network_id: network for network in self.networks}
        if set(network_map) != set(EXPECTED_NETWORKS):
            raise PreflightBoundaryError(
                "preflight networks must be exactly OP, Arbitrum, and Base Sepolia"
            )
        if set(self.providers) != set(EXPECTED_NETWORKS):
            raise PreflightBoundaryError(
                "one read-only provider is required for each fixed-route network"
            )
        results: list[ChainIdentityResult] = []
        for network_id in ("op-sepolia", "arbitrum-sepolia", "base-sepolia"):
            network = network_map[network_id]
            expected_chain_id, expected_role = EXPECTED_NETWORKS[network.network_id]
            if (
                network.chain_id != expected_chain_id
                or network.route_role != expected_role
            ):
                raise PreflightBoundaryError(
                    f"configured network identity changed: {network.network_id}"
                )
            provider = self.providers[network_id]
            observed_chain_id: int | None = None
            observed_hash: str | None = None
            try:
                observed_chain_id = provider.chain_id()
                if observed_chain_id == expected_chain_id:
                    observed_hash = provider.block_hash(
                        network.checkpoint.block_number
                    )
            except Exception:
                status = "unknown"
                reason = "read_rpc_error"
            else:
                if observed_chain_id != expected_chain_id:
                    status = "fail"
                    reason = "chain_id_mismatch"
                elif observed_hash is None:
                    status = "unknown"
                    reason = "checkpoint_unavailable"
                elif observed_hash.lower() != network.checkpoint.block_hash.lower():
                    status = "fail"
                    reason = "checkpoint_hash_mismatch"
                else:
                    status = "pass"
                    reason = "identity_verified"
            results.append(
                ChainIdentityResult(
                    network_id=network_id,
                    expected_chain_id=expected_chain_id,
                    observed_chain_id=observed_chain_id,
                    checkpoint_block_number=network.checkpoint.block_number,
                    expected_checkpoint_hash=network.checkpoint.block_hash,
                    observed_checkpoint_hash=observed_hash,
                    status=status,
                    reason_code=reason,
                )
            )
        self._suite = ChainIdentitySuite(tuple(results))
        return self._suite

    def query_public_signer_identity(
        self,
        *,
        signer: SignerCoordinator,
        network_id: str,
    ) -> PublicSignerIdentity:
        if self._suite is None or not self._suite.passed:
            raise PreflightBoundaryError(
                "public signer identity is gated by full network verification"
            )
        if network_id not in EXPECTED_NETWORKS:
            raise PreflightBoundaryError("signer identity network is outside fixed route")
        return signer.public_identity(network_id)
