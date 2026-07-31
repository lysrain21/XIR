# Native Hyperlane–LayerZero–XIR Experiment Report

## Result

The controlled local experiment reconciled `40000`
designated two-hop attempts for phase `scale`. Reconciliation
status is `true`. HH and LL are homogeneous
native-protocol routes without XIR; HL and LH use exactly one XIR transition.

| Route | Attempts | Success rate | Mean (s) | Median (s) | P95 (s) | P99 (s) | Min (s) | Max (s) | Coordinator gas | XIR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| HH | 10000 | 1.000 | 8.587 | 7.103 | 12.157 | 17.240 | 2.699 | 1036.217 | 941999905 | False |
| LL | 10000 | 1.000 | 7.154 | 5.159 | 6.154 | 7.180 | 4.532 | 1037.070 | 1919916016 | False |
| HL | 10000 | 1.000 | 13.232 | 10.955 | 14.893 | 19.985 | 7.568 | 1048.980 | 7219771195 | True |
| LH | 10000 | 1.000 | 12.846 | 10.918 | 14.011 | 19.079 | 7.245 | 1047.960 | 7287656584 | True |

The accepted scale denominator contains 40,000 effects and 20,000 XIR
transitions. The cumulative run-003 counters, which also include accepted smoke
and rehearsal qualification phases, are effects
`41040`, XIR transitions
`20520`, Hyperlane messages
`41040`, and LayerZero V2 messages
`41040`. Reconciled workload
transactions are `287280`; `78`
additional recovery-only transactions make
`287358` total evidenced physical transactions.
The phase wall time was `25278.518` seconds and the
logical-attempt throughput was
`1.582371 attempts/s`.

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

Resource samples: `2580`; explicit sampling gaps:
`10`; observed dedicated-process restarts:
`2`. Minimum available host memory:
`96824201216` bytes; minimum GPFS free space:
`61227107614720` bytes; minimum Docker filesystem free
space: `23524364288` bytes.

Final validator state: `12`
containers, all running `True`, all
healthy `True`, cumulative Docker
restart count `24`.
The closeout inventory contains `504108`
runtime files and `14329564729` bytes.
Resource sampling ran from
`2026-07-31T01:30:31.858074+00:00` to
`2026-07-31T08:31:41.037467+00:00`; the median, P95, and
maximum observed intervals were respectively
`9.465768098831177`,
`12.041474771499635`, and
`333.1556360721588`
seconds.

Scale coordinator calldata covered
`120000` transactions and
`119840000` bytes. LayerZero
worker calldata induced by scale dispatches covered
`120000` transactions and
`67040000` bytes. Official
Hyperlane relayer process transactions remain proven by on-chain process
lineage, but the pinned agent does not retain raw signed process transactions;
therefore no aggregate Hyperlane process-calldata claim is made.

Recorded submission recovery events: LayerZero raw rebroadcasts
`47`, runner raw transaction
replacements `23`, runner
transient RPC retries `1742`,
and semantic attempt retries
`0`. Raw submission recovery
and transient RPC retries retain the original attempt identity and retry
lineage; they do not add a designated logical attempt.

Natural interruption records: `11`.
All are classified as non-injected:
`True`; the attempt denominator
remained unchanged:
`True`; and no
replacement attempt was created:
`True`.

## Evidence and reproducibility

Raw receipts, protocol databases, checkpoint files, logs, signed-action
lineage, runner databases, resource samples, build outputs, and deployment
evidence are retained at `/vePFS-Mindverse/user/intern/lucian/xir/runtime/native-stack-run-003`. The SHA-256 evidence-manifest
digest is `95aced6a135f9ccace974af1311102a5c9c9c1384ba4f1f2210bd092e6b6d119`. Analysis is generated only after exact
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
- Validator and worker restarts, RPC interruptions, and nonce recovery pauses
  occurred naturally during scale. They inflate wall-clock means and maxima;
  the run is exact for functional accounting but is not an uninterrupted
  performance measurement. Median and percentile values are reported without
  removing affected attempts, and all recovery windows remain in the evidence.
- Coordinator gas excludes protocol-agent gas; complete physical-transaction
  evidence and receipts are retained separately.
- Run-001 is historical evidence and run-002 is rejected qualification
  evidence. Neither contributes a row, timing value, effect, message, resource
  sample, or denominator to accepted run-003 statistics.
