# Native Protocol-Stack Experiment Runbook

## Scope

This runbook is only for `native-protocol-stack-four-route-v1`. It starts three
retained Besu QBFT networks with four validators each, deploys the pinned
official Hyperlane and LayerZero V2 on-chain stacks, and executes HH, LL, HL,
and LH. HL and LH each contain exactly one verified XIR transition. The earlier
adapter-emulation experiment is a separate result and is never merged into this
run.

Hyperlane uses the official Rust validator and relayer binaries. LayerZero V2
uses official EndpointV2, ULN302, DVN, Executor, fee, treasury, and proxy
contracts. Because LayerZero does not provide a managed service for these
private EIDs, `scripts/layerzero_worker.py` is explicitly a self-hosted research
worker performing the off-chain observation, signing, commit, and execution
roles. It is not a LayerZero Labs managed DVN or Executor.

## Fixed paths and safety rules

- Remote workspace: `/vePFS-Mindverse/user/intern/lucian/xir`
- Formal runtime: `runtime/native-stack-run-001`
- Source snapshot: `repo/xir-testnet-lab`
- Validator state remains in the twelve named Docker volumes.
- Never run Docker prune, Compose down with volumes, or recursive deletion.
- Protocol sources, builds, logs, keys, raw receipts, and SQLite databases live
  under the formal runtime on GPFS.
- Only aggregate secret-free results and evidence digests are copied into Git.

## Qualification and deployment

1. Confirm the component-lock digest in the frozen profile.
2. Start the retained validators with `scripts/docker_volume_engine.py up` and
   require all twelve health checks, the three chain IDs, peer agreement, host
   memory, GPFS space, and Docker space.
3. Run `scripts/bootstrap_native_protocols.sh all`. It checks the official
   repository URL, exact commit, clean tree, licenses, build output, and
   SHA-256 provenance.
4. Render and deploy Hyperlane core contracts; capture the official CLI logs,
   registry addresses, deployment blocks, transactions, receipts, runtime
   bytecode, and Mailbox domains. The deployment project compiles only its
   explicit London-compatible deployment script and marker dependency graph;
   unrelated upstream Cancun-only token/IGP helpers are outside this
   experiment's admitted contract set.
5. Prepare and deploy the import-only LayerZero project. Capture every Forge
   transaction and receipt and run the effective configuration verifier.
6. The formal gate fails if any forbidden test/mock component is present.
7. Deploy the XIR registries/gateways, directional adapters, homogeneous
   forwarder, transition recorder, and receiver. Persist intent before every
   transaction and retain every receipt.
8. Configure directional peers, route receivers, LayerZero Type-3 options,
   adapter runners, XIR roots, and four protocol profiles.

## Processes

Start the official Hyperlane agents, then the LayerZero worker, then a phase
resource monitor. The monitor records the twelve validators, all agent PIDs,
worker/coordinator PIDs, queues, restarts, sampling gaps, RPC heights/peers,
host memory/load, Docker space, GPFS space, and evidence growth.

All process-control commands are scoped. `native_stack_processes.sh stop`
stops only the dedicated agents/workers/monitor and retains validators,
volumes, protocol state, raw receipts, and evidence.

## Phase progression

The workload order is deterministic and balanced:

| Phase | Per route | Total attempts |
| --- | ---: | ---: |
| smoke | 10 | 40 |
| rehearsal | 250 | 1,000 |
| scale | 10,000 | 40,000 |

The scale phase is forbidden until smoke and rehearsal reconcile exactly and
the measured concurrency/batch/resource limits are frozen. Retries are not
part of the designated denominator. A retry must preserve the same semantic
coordinates and is reported separately.

The coordinator uses bounded batches and concurrency. The LayerZero worker
uses bounded packet batches and pipelines signed transactions while preserving
per-account nonce order. A transaction is successful only when its receipt
succeeds and the expected official PayloadVerified, PacketVerified, or
PacketDelivered event is present.

## Recovery

For a controlled recovery test, stop one dedicated worker between persisted
intent/signature and final completion, record the old PID, restart it, and
require the same action/packet coordinates to complete. Signed raw
transactions remain under the private runtime directory. Do not create a new
logical attempt. Record all process gaps and restarts.

## Reconciliation and closeout

Each phase must reconcile:

- exact logical attempts and route balance;
- exactly two protocol messages per attempt;
- zero XIR transitions for HH/LL and one for HL/LH;
- exactly one destination effect per attempt;
- official Hyperlane dispatch/process evidence;
- official LayerZero packet/DVN/ULN/Executor evidence;
- unique chain/account nonces and all raw rebroadcasts;
- cumulative physical transactions derived from observed receipts;
- no failed worker stage or missing sampling interval.

After scale, stop dedicated processes, retain validators and all state, freeze
the evidence manifest, secret-scan the publication set, rebuild analysis twice,
validate the report, and record all exclusions and confounds.

## Clean replication (`native-stack-run-002`)

The second formal run is independent. Preserve `native-stack-run-001` and its
closeout digests unchanged. Before creating run 002, capture the complete
Docker inventory and require the cleanup target to equal exactly the twelve
validator containers and twelve volumes with Compose project label
`xir-local-scale`. Stop and remove those explicit objects, capture the after
inventory and reclaimed bytes, and do not run a global prune or remove any
anonymous/unrelated volume.

Create `runtime/native-stack-run-002` only after the scoped cleanup. Run
`scripts/preflight_native_replication.py fresh` while the directory is empty.
Render new validator volumes and create new random protocol-role accounts,
protocol deployments, application deployment receipts, worker databases,
runner databases, and attempt namespaces. Deterministic contract deployment
addresses can repeat on a fresh chain; isolation is established by fresh
labelled volumes, role identities, databases, receipt paths, and block
evidence. Before smoke, run the `qualified` preflight and retain its JSON
output. When the remote Compose engine renders GPFS bind-backed validator data,
`local_scale.sh up` grants write access only to the twelve dedicated data
leaves while keeping validator keys and the rest of the private runtime
restricted.

Scale admission requires at least 28 GiB free on the Docker filesystem and
40 GiB free on GPFS. The phase monitor writes `submissions.stop` atomically if
Docker space falls below 8 GiB or GPFS falls below 40 GiB. The runner checks
that marker before every new batch; in-flight work is reconciled and the cause
must be resolved before resumption. The monitor, agents, worker, and runner
must remain stable through a multi-sample soak before scale.

Do not inject a recovery event during the measured replication. If a natural
interruption occurs, retain its append-only lineage and original attempt
identity, then classify its timing impact in the report. All phase commands,
analysis, manifests, and report generation must receive only the run-002
runtime. The publication directory must be run-specific and contain only
secret-free aggregates, validation records, digests, and the remote evidence
pointer.
