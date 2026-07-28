# XIR Testnet Lab

XIR Testnet Lab is a reproducible cross-protocol testnet research prototype.
It is designed to compare a minimal carrier-only baseline with the
Cross-chain Intermediate Representation (XIR) over one fixed route:

```text
OP Sepolia -> Arbitrum Sepolia -> Base Sepolia
```

The four experiment conditions are `HH`, `HL`, `LH`, and `LL`, where `H`
means Hyperlane and `L` means LayerZero V2. Each condition contains an
isolated baseline arm and an XIR arm with matched application inputs.

This repository is not a production bridge, wallet, relayer, token-transfer
product, or general interoperability system. It does not authorize mainnet
use or any public-testnet write operation.

## Current status

The repository is being built as the zero-write implementation for the
`build-xir-testnet-lab` OpenSpec change. Planning, fixture replay, validation,
and offline analysis must work without a signer. Public-testnet deployment,
configuration, pilot execution, primary execution, scale execution, funding,
and publication require separately scoped approvals and follow-up operations.

## Planned workflow

The command surface is organized into independently restartable phases:

```text
xir-lab plan
xir-lab preflight
xir-lab deploy
xir-lab run
xir-lab collect
xir-lab reconcile
xir-lab analyze
xir-lab publish
```

Live-capable commands must remain fail-closed unless their operation-specific
approval, identity, signer, deployment, budget, and preflight gates all pass.
No command creates a wallet, obtains test tokens, or funds an account.

## Architecture

First-party components are:

- Solidity contracts and carrier adapters;
- a bounded runner and external-signer interface;
- a read-only collector;
- a SQLite evidence ledger and content-addressed raw store;
- reconciliation and invariant validators;
- deterministic offline analysis and publication packaging.

External dependencies include OP Sepolia, Arbitrum Sepolia, Base Sepolia,
RPC providers, Hyperlane services, LayerZero services, faucets, block
production, and signer custody. Their availability and behavior are not
controlled by this repository.

## Repository layout

```text
contracts/       Solidity sources, scripts, and Foundry tests
src/xir_lab/     Python orchestration, evidence, validation, and analysis
configs/         Versioned network, condition, profile, and deployment inputs
schemas/         JSON Schemas for durable configuration and evidence
tests/           Unit, integration, replay, and fixture tests
data/examples/   Sanitized small examples only
docs/            Architecture, operations, and data documentation
```

## Safety and claims

Read [SECURITY.md](SECURITY.md) before configuring any signer or RPC endpoint.
Scientific and public-description limits are recorded in
[CLAIM_BOUNDARIES.md](CLAIM_BOUNDARIES.md). Contribution requirements are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Code is licensed under the [MIT License](LICENSE). Repository data and
documentation artifacts covered by [DATA_LICENSE.md](DATA_LICENSE.md) are
licensed under CC BY 4.0 unless a file states another license.
