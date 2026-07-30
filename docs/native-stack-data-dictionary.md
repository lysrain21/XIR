# Native Protocol-Stack Evidence Dictionary

## Identifiers and denominators

| Field | Meaning |
| --- | --- |
| `attempt_id` | Stable logical two-hop attempt; retries retain this value. |
| `route` | `HH`, `LL`, `HL`, or `LH`; order is first hop then second hop. |
| `route_sequence` | Matched sequence shared by all four routes. |
| `guid` | Official LayerZero PacketV1 GUID. |
| `message_id` | Official Hyperlane message ID or adapter-authenticated evidence ID. |
| `rid` / `mid` | Independently recomputable XIR root and message identifiers. |
| designated denominator | Planned logical attempts; retry broadcasts are excluded. |
| physical transaction | Unique `(chain, transaction hash)` with a retained receipt. |

## SQLite evidence

`runner.sqlite` records one row per planned attempt and one durable stage row
per coordinator action. Stage details include public chain role, nonce, target,
calldata SHA-256, transaction hash, receipt SHA-256, gas used, block number,
protocol evidence identity, and XIR coordinates.

`layerzero/worker.sqlite` records PacketSent observations, PacketV1 bytes and
SHA-256, source/destination EIDs, source block/transaction/log index, action
intent, nonce, target, calldata SHA-256, signed raw transaction digest,
broadcast observations, receipt location, and terminal state. Signed raw bytes
are private runtime material and are excluded from publication.

The main evidence ledger migration adds native component/configuration,
protocol-message, checkpoint, packet, DVN instruction, XIR transition,
application effect, lineage, process/host sample, restart, and reconciliation
tables. Observation and sampling tables are append-only.

## Raw protocol evidence

Hyperlane evidence includes Mailbox Dispatch/DispatchId, MerkleTreeHook
insertion, local checkpoint content and signature digests, relayer decisions,
Mailbox Process/ProcessId, agent logs, transaction receipts, and deployment
bytecode/configuration.

LayerZero evidence includes encoded PacketV1 bytes, header, payload hash, GUID,
nonce, EIDs, PacketSent, signed DVN instruction/hash, PayloadVerified,
PacketVerified, Executor submission, PacketDelivered, all receipts, effective
send/receive library configuration, ULN302 DVN sets, Executor, options, and
deployment bytecode/configuration.

XIR evidence includes root certificate/version, record/context hashes, both
receipt transitions and prefixes, the single heterogeneous boundary
transition, recomputed transition digest, destination delivery, and the
absence of such a transition on homogeneous routes.

## Timing, resource, and failure fields

Timestamps are UTC ISO-8601 or Unix seconds and are always labeled. Latency is
seconds per logical two-hop attempt. Gas is receipt `gasUsed`; fee and balance
quantities are wei. Memory, disk, IO, and evidence size use bytes. CPU process
samples retain scheduler ticks; raw Docker stats retain their original unit
strings.

Every sample contains an explicit `gaps` array. Missing PID, RPC, Docker,
filesystem, queue, or database measurements are recorded as gaps rather than
silently omitted. Restart records contain old/new PID and observation time.
Failures retain error class, raw receipt, stage, and whether the same signed
transaction was rebroadcast.

## Analysis boundaries

Per-route CSV/JSON reports success, end-to-end latency, coordinator
transactions/gas, protocol message counts, XIR counts, physical transaction
counts, retries, resource samples/gaps, and process restarts. Raw evidence is
the authority; aggregates are rebuildable derivatives.

The report must state that Hyperlane off-chain work uses official agents while
LayerZero private-chain work uses a self-hosted research worker. It must not
attribute that worker's performance to LayerZero Labs managed infrastructure,
generalize local-host results to public networks, or combine this dataset with
the earlier adapter-only experiment.
