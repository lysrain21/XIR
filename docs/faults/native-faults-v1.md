# Native controlled-recovery campaign v1

> **Status: preregistered; full 60-case results and publication are pending.**

## Purpose

`native-faults-v1` is designed to test recovery at durable process boundaries
on an isolated three-network deployment. Each logical case must use one
deterministic attempt ID. The injector must fire once, store the hit in SQLite
with `synchronous=FULL`, and emit the configured process-exit or transient-retry
signal. Recovery must reopen the same runner or LayerZero worker database.

The campaign is separate from the natural interruptions observed during the
40,000-attempt run. Its case count, database, receipts, report, and manifest
use a new namespace.

## Frozen matrix

Both `HL` and `LH` must execute three repetitions of each boundary:

1. before durable intent;
2. after intent and before signing;
3. after signing and before broadcast;
4. after broadcast and before local acknowledgement handling;
5. after acknowledgement and before receipt observation;
6. after mining and before receipt persistence;
7. after receipt persistence and before the succeeded-stage commit;
8. after a LayerZero worker action is durably submitted;
9. a deterministic transient failure after broadcast;
10. two concurrent recovery processes for one signed destination transaction.

Coordinator failures target `destination_deliver`. Both native carrier hops
therefore finish before the controlled stop, and the recovery check can count
the destination effect directly. The worker case targets the LayerZero
`executor_execute` action and verifies all three actions for the same packet
GUID after restart.

## Reconciliation

Every case must satisfy all checks below:

- the planned and stored logical attempt IDs match;
- exactly one planned fault fires;
- the recovered attempt and destination stage succeed;
- all destination-stage records name one nonce and one transaction hash;
- `NativeEffectApplied` occurs exactly once for the attempt ID;
- the receiver and Gateway consumption mappings are set;
- the transient case records a retry, and both concurrent recovery children
  join successfully;
- the worker case preserves its packet GUID and completes all worker actions.

Private keys, raw signed transactions, process logs, SQLite databases, and raw
worker receipts must remain below the remote private runtime. The publication
tree must contain case JSON, aggregates, a CSV recovery table, a report,
environment metadata, an invariant validation document, a secret scan, and a
verified SHA-256 manifest.

## Commands

After the final prior-verifier-binding deployment is idle, stop its LayerZero
worker and create a no-overwrite overlay. The overlay gate verifies that both
outbound adapters bind `H_AB` and `L_AB` to the deployed inbound adapters. The
script copies the public deployment inputs, makes a SQLite backup, and retains
the three required keys only inside the remote private directory:

```bash
.venv/bin/python scripts/prepare_native_faults_v1_overlay.py \
  --source-runtime "$security_runtime" \
  --source-deployment "$security_deployment" \
  --target-runtime "$fault_runtime"
```

Run the frozen campaign on a dedicated runtime:

```bash
.venv/bin/python scripts/run_native_faults_v1.py campaign \
  --runtime-root "$fault_runtime" \
  --profile "$fault_runtime/profile.json" \
  --deployment "$fault_runtime/native-application/deployment.json" \
  --config configs/native/native-faults-v1.json \
  --runner-key-file "$fault_runtime/private/accounts/runner.key" \
  --root-signer-key-file "$fault_runtime/private/accounts/root-signer.key" \
  --fault-ledger "$fault_results/private/fault-ledger.sqlite" \
  --runner-state "$fault_results/private/runner.sqlite" \
  --output-root "$fault_results" \
  --deployment-scope prior-verifier-final-revision-shared-idle
```

Rebuild the publication from the frozen ledger:

```bash
.venv/bin/python scripts/analyze_native_faults_v1.py \
  --fault-ledger "$fault_results/private/fault-ledger.sqlite" \
  --config configs/native/native-faults-v1.json \
  --deployment "$fault_runtime/native-application/deployment.json" \
  --environment-source "$fault_results/publish/environment.json" \
  --output-root "$rebuild_root"
```

Render the paper-ready recovery overview twice and compare both formats before
publishing the real matrix:

```bash
.venv/bin/python scripts/render_native_faults_v1.py \
  --summary "$fault_results/publish/summary.json" \
  --schema-root schemas \
  --output-dir "$fault_figure"
```

The renderer emits `recovery-overview.pdf`, `recovery-overview.svg`, the exact
20-row source table `recovery-overview.csv`, and
`recovery-overview-source.json` with their input and output digests.

After two offline rebuilds and two byte-identical figure renders, generate the
machine-readable handoff:

```bash
.venv/bin/python scripts/build_native_faults_v1_handoff.py \
  --frozen-publish "$fault_results/publish" \
  --rebuild-a-publish "$rebuild_a/publish" \
  --rebuild-b-publish "$rebuild_b/publish" \
  --figure-dir "$fault_figure" \
  --schema-root schemas \
  --output "$artifact_root/handoff.json"
```
