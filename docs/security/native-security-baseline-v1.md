# Native payload-only baseline capability v1

> **Status: frozen; 300 dynamic case-runs and two identical offline rebuilds passed.**

This campaign supplies the capability-aligned B0 comparison used by the security
evaluation. It executed on the administrator-bound final revision and reused
only the isolated `native-ablation-v2` B0 contracts. Its runner database, raw
receipts, attempt IDs, publication tree, and manifest use the independent
`native-security-baseline-v1` namespace. Preflight checks bind the campaign to
the final source hashes, fresh deployment digest, and the on-chain H_AB/L_AB
prior-verifier mappings. B0 is a custom two-hop relay, not a Hyperlane or
LayerZero product baseline.

## Static capability table

`baseline-capability.csv` describes the B0 ABI and destination entrypoint. The B0 carrier payload is `(uint8 layer=0, bytes routePayload)`. Both native hops execute and authenticate: the intermediate ingress records the first native callback before the runner submits hop 2. That first-hop authentication terminates at the intermediate network and is not bound into the final payload. The destination entrypoint `baselineCarrierReceive(bytes32 nativeMessageId, bytes encoded)` therefore sees only final-hop authentication. Verifier profile/version, registry version/status, prior-hop native message ID, and ordered receipt history are absent. The application route payload also carries a stable `attemptId`, which the receiver uses for application-level idempotency; the receiver separately records final native message IDs. These rows are static capability facts and do not contribute to the 300-attempt denominator.

## Dynamic cases

Each route (`HL`, `LH`) executed 30 deterministic repetitions of five cases:

1. `history_absent_delivery` sends a normal B0 payload whose envelope has no history field.
2. `between_hop_payload_substitution` authenticates one application payload on hop 1 and places different application bytes in the second-hop native envelope. The corresponding XIR conformance probe changes the destination-supplied payload after a valid trace forms, so the comparison aligns the destination-visible capability rather than the injection point.
3. `route_label_substitution` uses one physical carrier order and the reverse two-byte route label at the destination.
4. `inactive_profile_unchecked` uses the registry owner to disable the same real first-hop profile as the corresponding XIR case (`H_AB` for `HL`, `L_AB` for `LH`). B0 defines no profile-admission policy, so this case probes whether profile state is represented rather than violating a B0 rule. It sends B0 while that profile is disabled and restores the complete original snapshot in a `finally` step. Disable and restore transactions are part of the raw lineage.
5. `new_native_envelope_replay` submits a new final-carrier envelope for the same application attempt. The final native message ID changes and the native adapter authenticates it. The receiver then observes the already-consumed stable `attemptId`, emits `AblationReplayRejected`, and returns without a second application effect; the carrier transaction has status one.

The first four cases produced one application effect each. Each replay case
produced one initial effect and one `AblationReplayRejected` event with no
second effect. Non-registry cases completed before each inactive-profile case;
the two registry-mutating cells then executed serially. `baseline-results.csv`
contains exactly these 300 executions.

## Evidence and gates

Every row includes source, intermediate, and destination entrypoints;
coordinator calldata digests; enforcement stage; effect counts; and complete
coordinator/Hyperlane/LayerZero transaction lineage. All ten route-by-case
cells contain 30 runs, all 300 attempts produced one initial effect, and the
replay cells produced exactly 60 rejection events. The source publication,
manifest validation, and secret scan pass. Two clean offline rebuilds have the
same semantic digest and identical publication files. The local frozen entry
point is
`experiment-results/native-followups-final/native-security-baseline-v1/`.
