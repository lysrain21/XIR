# Native B0--B3 mechanism ablation v1

## Question

The experiment measures the incremental cost of preserving verification context when a message changes carrier. Hyperlane-to-LayerZero (`HL`) and LayerZero-to-Hyperlane (`LH`) are reported separately.

## Nested configurations

| Layer | Retained mechanisms | Added at this layer |
|---|---|---|
| B0 | Two authenticated native carrier hops, destination-visible final-hop authentication, application-level replay protection, one destination effect | Bare cross-carrier payload forwarding |
| B1 | B0 plus the exact executable `Record`, `rid`, and `mid` encodings | Logical record and route-independent identifier |
| B2 | B1 plus two prefix-linked hop receipts, adapter evidence membership, and ordered final-bundle lineage | Destination-verifiable prior-profile/history continuity |
| B3 | B2 plus current-state registry lookup, `securityLevel >= requiredSecurity`, and Gateway-level atomic `mid` consumption and delivery | Full implemented XIR policy and delivery path |

B0 and B1 use the baseline message kind on both native carriers. The first inbound adapter calls `NativeAblationIngressV1`; the runner starts the second native hop only after that contract records the first authenticated delivery. The final inbound adapter calls the shared `NativeAblationReceiverV1`. The first hop is therefore natively authenticated at the intermediate network, while its identity and verification context are not carried to or bound by the destination. The destination sees only the final-hop native authentication.

B1 represents the three EVM typed identifiers as fixed-width addresses on the wire. The receiver reconstructs the exact typed `Record` and context, then recomputes and checks `rid` and `mid`. Across the full 1,000-payload schedule, the resulting LayerZero message ranges from 800 to 896 bytes, below the configured 1,000-byte native limit. The offline analyzer independently rebuilds this wire object from the frozen plan and checks its hash and length against both native dispatch stages.

B2 uses the lineage-bound XIR message kind on both carriers. `NativeAblationTransitionV1` statically verifies the first receipt and emits the intermediate carrier-change record. The shared receiver statically verifies both receipt tuples and the ordered bundle commitment. It performs no registry or policy lookup.

B3 uses `XIRGateway`, `XIRRegistry`, `NativeXIRTransitionRecorder`, the independent finalized-event root signer, and the same shared receiver.

## Matching and interleaving

The frozen configuration contains 1,000 attempts per route and layer: eight cells and 8,000 scale attempts in total. Each sequence supplies one application payload to all eight cells. A deterministic rotation changes the layer order for each sequence, and the route order alternates between `HL,LH` and `LH,HL`. Two complete sequence blocks form one submission batch. The frozen concurrency is 16.

Attempt IDs, pair IDs, cell assignments, logical nonces, payload hashes, slots, and mechanism sets are materialized in `plan.json` before submission. The plan validator requires all eight cells in every sequence block and checks strict mechanism nesting.

## Metrics and physical lineage

Complete-route gas and calldata include:

1. every runner/coordinator transaction;
2. the Hyperlane `ProcessId` transaction for each Hyperlane hop; and
3. all three successful LayerZero worker actions (`dvn_execute`, `commit_verification`, and `executor_execute`) for each LayerZero hop.

Every physical transaction is linked to one logical attempt. Coordinator totals and directly measured stages are also reported separately. Attempt latency begins when the durable attempt row is created and ends after the reconciled destination effect.

For each route, the analyzer pairs B0/B1/B2/B3 by sequence and computes B0→B1, B1→B2, and B2→B3 deltas. Mean and median deltas use a route-specific circular moving-block bootstrap with 4,000 repetitions, block length 16, and 95% intervals. The seed is derived from the frozen seed, route, increment, metric, and statistic.

The primary latency analysis retains all 8,000 attempts. Two read-only RPC
polling incidents interrupted the runner after on-chain progress. A separately
frozen sensitivity analysis removes each incident's complete eight-cell
interleave block, retains the remaining blocks in sequence order, and applies
the same paired moving-block interval method. The publication records all
7,984 included attempts, all 16 exclusions, and the resulting 998 observations
per route-layer cell. Gas and calldata always use the complete 8,000-attempt
denominator.

## Gates

The smoke phase contains two attempts per cell. Scale begins after smoke verifies the exact stage set, one destination effect per attempt, complete native lineage, balanced cells, and absence of secret-bearing publishable files. The accepted run-003 directory and the paper's frozen Figure 1 are outside every ablation output path.

Two diagnostic smokes precede the official smoke and remain outside every published denominator. The first exposed the LayerZero message-size limit in an initial dynamic-identifier encoding. The second reused deterministic identifiers already committed by that partial run, and the B3 transition rejected the duplicates. The official configuration freezes a new campaign seed and records both exclusions in the generated report and machine-readable handoff.
