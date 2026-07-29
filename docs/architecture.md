# Architecture and experiment boundaries

XIR Testnet Lab compares a carrier-only baseline with XIR on one fixed
three-chain route: OP Sepolia to Arbitrum Sepolia to Base Sepolia. `HH`, `HL`,
`LH`, and `LL` select Hyperlane or LayerZero V2 independently for the two
carrier legs. A condition contains isolated baseline and XIR arms; a primary
pair is the scientific unit.

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

Experiment-controlled funds use two public addresses: a deployer/admin address
for deployment and configuration, and a runner address for bounded experiment
transactions. Custody and funding occur outside this repository at explicit
human checkpoints. The code creates no wallet, requests no faucet funds, and
performs no transfer.

The primary experiment contains four conditions and two arms. Pilot, warm-up,
primary, retry, and scale attempts remain separate. The 10,000-attempt scale
profile measures only the named runner, collector, recovery, storage, and
reconciliation pipeline; it is not carrier capacity or production reliability.

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
