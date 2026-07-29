# Claim boundaries

This project may report observations only for the named testnets, ordered
route, protocol sequence, deployment versions, application payload, security
configuration, observation period, finality policy, and eligible sample count
recorded in a frozen release.

The strongest intended primary claim is a measured paired resource difference
between an XIR arm and its matched carrier-only baseline for a specific
condition and run.

The project must not claim:

- production readiness or mainnet safety;
- a production bridge or general interoperability system;
- arbitrary-chain, arbitrary-hop, or four-leg execution support;
- production throughput, reliability, latency, or capacity;
- equivalence of Hyperlane and LayerZero security;
- formal correctness of XIR or carrier implementations;
- private relayer, DVN, or executor cost or internal behavior;
- real-currency cost inferred from testnet-native assets;
- an XIR overhead value when eligible matched evidence is absent.

Runner budgets describe only experiment-controlled accounts. Externally funded
carrier activity must be labeled separately. Chain-specific gas, fees,
carrier payments, and L1 data fees remain separate measures unless a released
method explicitly and validly defines a conversion.

Failures, timeouts, incomplete evidence, retries, and not-submitted attempts
remain in their planned denominators. A retry does not replace a failed
designated primary attempt in headline matched-overhead statistics.

The optional 10,000-attempt profile evaluates the bounded runner, collector,
recovery, storage, and reconciliation pipeline. It is not a carrier throughput
benchmark or a production reliability estimate.

Controlled-local evidence has a separate identity: three private Besu QBFT
chains, twelve validators, controlled carrier labels, repository-external
development accounts, and a frozen topology digest. It may support claims
about deterministic planning, local execution, restart recovery, evidence
storage, reconciliation, and resource use on the recorded host.

Controlled-local results cannot establish public Hyperlane or LayerZero
capacity, public carrier latency or fees, testnet reliability, production
security, or real cross-chain message delivery. A report must label the
environment `controlled-local-qbft` and carry these exclusions.
