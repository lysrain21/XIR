# Native Hyperlane–LayerZero–XIR Experiment Report

## Result

The controlled local experiment reconciled `40000`
designated two-hop attempts for phase `scale`. Reconciliation
status is `true`. HH and LL are homogeneous
native-protocol routes without XIR; HL and LH use exactly one XIR transition.

| Route | Attempts | Success rate | Mean latency (s) | P95 latency (s) | Coordinator gas | XIR |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| HH | 10000 | 1.000 | 156.459 | 12.195 | 942555397 | False |
| LL | 10000 | 1.000 | 157.570 | 6.153 | 1919916016 | False |
| HL | 10000 | 1.000 | 169.267 | 14.863 | 7219208191 | True |
| LH | 10000 | 1.000 | 169.292 | 14.045 | 7287099433 | True |

Total application effects: `41040`. Total XIR
transitions: `20520`. Observed protocol
messages: Hyperlane `41040`, LayerZero
V2 `41040`. Observed unique physical
transactions: `287280`.
The phase wall time was `54549.482` seconds and the
logical-attempt throughput was
`0.733279 attempts/s`.

## Deployment and provenance

The topology is three retained Besu QBFT chains, four validators per chain,
with chain IDs `3133701`,
`3133702`, and
`3133703`. Component source identities:

- hyperlane: `5857ead81a8783d168d48d370be72de88d5fb230`
- layerzero-v2: `9c741e7f9790639537b1710a203bcdfd73b0b9ac`
- layerzero-devtools: `4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8`

Hyperlane uses official Mailbox, MerkleTreeHook, one-of-one message-ID
multisig ISM, validator agents, and relayer. LayerZero uses official
EndpointV2, ULN302, DVN, Executor, price/fee, treasury, and proxy contracts.
LayerZero's private-chain off-chain roles are performed by the auditable
self-hosted XIR research worker; this is not a LayerZero Labs managed service.
Deployment manifest schema: `xir-lab-native-application-deployment-v1`.

## Resource and reliability evidence

Resource samples: `2486`; explicit sampling gaps:
`8`; observed dedicated-process restarts:
`4`. Minimum available host memory:
`96981946368` bytes; minimum GPFS free space:
`61516172754944` bytes; minimum Docker filesystem free
space: `81920` bytes.

Recorded submission recovery events: LayerZero raw rebroadcasts
`42`, runner raw transaction
replacements `3`, runner
transient RPC retries `595`,
and semantic attempt retries
`0`. Raw submission recovery
and transient RPC retries retain the original attempt identity and retry
lineage; they do not add a designated logical attempt.

## Evidence and reproducibility

Raw receipts, protocol databases, checkpoint files, logs, signed-action
lineage, runner databases, resource samples, build outputs, and deployment
evidence are retained at `/vePFS-Mindverse/user/intern/lucian/xir/runtime/native-stack-run-001`. The SHA-256 evidence-manifest
digest is `621cd3655fc73383603ab9b2d7a46fa4fea140abae91b8d1b8c396a3a7d8016a`. Analysis is generated only after exact
reconciliation and is rebuilt twice offline with equal semantic digests.

## Interpretation limits

- These are controlled single-host local-chain measurements, not public-network
  throughput, fee, decentralization, security, or reliability measurements.
- The Hyperlane and LayerZero off-chain service boundaries differ; results do
  not measure vendor-operated service performance.
- Hyperlane's pinned agent schema requires an `interchainGasPaymaster` address
  even with gas enforcement disabled. The pinned IGP implementation requires
  Cancun opcodes unavailable on the retained London chains, so the unused
  config field transparently aliases the deployed official ProtocolFee hook;
  no IGP is claimed, invoked, or included in protocol-cost results.
- Protocol family, direction, and XIR presence are partly confounded by the
  four-route design. Route-level results are primary; pooled results are
  descriptive.
- Coordinator gas excludes protocol-agent gas; complete physical-transaction
  evidence and receipts are retained separately.
