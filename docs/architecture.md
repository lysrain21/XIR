# Architecture and experiment boundaries

XIR composes configured cross-chain protocol connections while carrying a
stable application record and ordered verification evidence. The EVM prototype
integrates Hyperlane and LayerZero V2 through Solidity contracts and a Python
runtime. In protocol paths, `H` denotes Hyperlane and `L` denotes LayerZero.

The repository contains several experiment families. The original public-testnet
design uses OP Sepolia, Arbitrum Sepolia, and Base Sepolia, with isolated
baseline and XIR arms where configured. The paper also reports native
protocol-stack experiments on three local chains and multi-hop paths across
five local chains. Each profile and frozen campaign defines its own execution
and comparison units; see [claim boundaries](../CLAIM_BOUNDARIES.md).

The repository has five trust zones:

1. Solidity route, adapter, registry, replay-control, and destination-effect
   contracts.
2. A bounded runner that records intent before asking an external signer and
   never stores a private key.
3. A private signed-transaction recovery spool outside all publication roots.
4. A read-only collector backed by public RPC and auxiliary carrier APIs.
5. A SQLite evidence ledger, content-addressed raw store, reconciliation gates,
   and network-disabled analysis build.

The external approval authority is separate from deployer and runner keys.
RPC providers, public testnets, block producers, Hyperlane, LayerZero, faucets,
and research-data hosts are external dependencies. Their availability,
ordering, private queues, internal costs, security, and correctness are not
controlled by this project.

The public-testnet design separates deployer/admin and runner identities.
Custody and funding occur outside the repository; state-changing operations
require the documented approvals, signer configuration, and network preflight.
The controlled local lab separately generates disposable development keys
under its repository-external runtime root.

The original matched design specifies four protocol conditions and two arms.
Its legacy 10,000-attempt scale profile measures runner and evidence-pipeline
behavior. The preserved public-testnet observations have no eligible matched
pairs, so they cannot establish a paired overhead estimate. Native four-route
and five-chain campaigns use their separately documented workloads and
denominators.

Resources remain in their native units by chain. Gas, calldata bytes, execution
fees, rollup L1 data fees, carrier quotes, carrier payments, transaction value,
balance change, and transaction count are distinct. External carrier-funded
transactions are observable but excluded from runner spending.

Observable evidence includes public transactions, receipts, block headers and
logs; experiment-side UTC and monotonic clocks; public block timestamps; and
explicit auxiliary API responses. Unobservable fields include private relayer
or DVN queues, internal cost/profit, routing decisions, exact first mempool
arrival, and packet latency. They remain unavailable rather than inferred.

Stops are persistent: drain prevents new source work while allowing bounded
in-flight completion; halt blocks signing and all broadcasts, including
persisted bytes; revocation additionally blocks approval reuse. Reservations
remain locked through ambiguous submission and approved finality.

## Controlled local scale plane

The local scale plane is independent from the public-testnet plane. A frozen
topology renders three Besu QBFT chains with four validators per chain.
Chain IDs 3133701, 3133702, and 3133703 represent source, intermediate, and
destination roles. Exactly one RPC endpoint per chain is exposed on loopback;
validator-to-validator RPC and P2P traffic remain on three isolated Docker
networks.

`local-init` generates disposable secp256k1 deployer, runner, and validator
keys in a repository-external runtime root. The checked-in topology and public
identity manifest deterministically render Compose; validator databases and
private signed recovery bytes stay outside publishable roots.

The progression is 40-attempt smoke, 1,000-attempt rehearsal, and
10,000-attempt scale. Scale execution requires frozen smoke, rehearsal, and
measured-limit digests plus a matching eligible twelve-node preflight. Each
designated attempt creates three physical transactions. A durable SQLite
ledger and exact-byte private spool support restart recovery and terminal
reconciliation.

Controlled carriers exercise ordering, replay rejection, outage, and recovery
inside the local environment. They do not emulate the private infrastructure
or public behavior of Hyperlane and LayerZero.

## Native protocol stacks and multi-hop experiments

The [native-stack runbook](native-stack-runbook.md) describes the controlled
three-chain environment with official Hyperlane and LayerZero EVM contracts.
Hyperlane uses upstream Rust validator and relayer binaries. LayerZero's
chain-external roles are provided by a self-hosted Python research worker.
The paper's four-route campaign records 10,000 requests for each of HH, LL, HL,
and LH, for 40,000 requests in total. Each result retains the exact protocol
and verification configuration used for execution.

The [five-chain profile](../configs/profiles/native-multihop-five-chain-v1.json)
extends the local topology to five Besu QBFT chains with four validators per
chain. Its multi-hop campaign supplies the paper's 22,000-execution cost
analysis. These local campaigns have different component and physical
transaction accounting from the earlier controlled-carrier workload above.

The [Kaggle event dataset](https://www.kaggle.com/datasets/yushenlee/xir-cross-chain-events-2025)
contains historical observations from six protocol feeds. It is a separate
input to the paper's graph analysis and does not contain those local execution
campaigns. The [paper](https://arxiv.org/abs/2609.20010) explains how the graph,
provisioning model, conditional analysis, and prototype measurements relate.
