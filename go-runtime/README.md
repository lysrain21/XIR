# XIR Go runtime

`xirlab-go` is an independent implementation of the XIR execution layer. It
creates XIR roots, dispatches every hop through the Hyperlane or LayerZero
carrier adapters, confirms the evidence each adapter recorded, records carrier
switches, delivers the envelope to the destination gateway, and survives a
mid-flight process restart without duplicating a transaction.

The Python runtime in `src/xir_lab/` remains the authority for frozen plans,
preflight gates, analysis, and publication. The Go runtime consumes those frozen
inputs (a deployment document and a list of attempts) and writes the same
durable rows, so the Python analysis tooling can still read a Go-produced run.

## Layout

| Package | Contents |
| --- | --- |
| `internal/xir` | Wire encoding: typed ids, record/context/receipt hashing, `rid`/`mid`/prefix chain, bundle commitments, profile hashes, application payloads, ABI tuple shapes |
| `internal/abiutil` | ABI document parsing, calldata packing, log decoding |
| `internal/state` | Durable SQLite ledger: actions, attempts, stages, stage history, events, errors |
| `internal/evm` | JSON-RPC client, signer, transactor with intent→signed→submitted→receipt durability, finality rule |
| `internal/artifacts` | Forge artifact loading (`out/<Name>.sol/<Name>.json`) |
| `internal/deploy` | Protocol-stack and XIR application deployment, registry and adapter configuration |
| `internal/layerzero` | PacketV1Codec, DVN instruction, DVN/ReceiveUln302/Executor submission plan |
| `internal/hyperlane` | Message format, checkpoint digest, ISM metadata, validator signing, mailbox `process` plan |
| `internal/runner` | Multihop orchestration, carriers, delivery, destination effect checks |
| `internal/lab` | Disposable anvil chains for integration tests |
| `cmd/xirlab-go` | Command line entry point |

## Parity

Every derivation is byte exact with the Solidity contracts and with the Python
runtime. The parity suite is generated from the Python modules:

```console
$ uv run python scripts/generate_go_parity_vectors.py --output go-runtime/testdata/vectors.json
$ cd go-runtime && go test ./...
```

`go-runtime/testdata/vectors.json` pins typed-id encodings, record/context/root
hashes, message ids, prefix chains, bundle commitments, profile hashes, gateway
ids, adapter keys, application payloads, the full envelope ABI encoding, the
EIP-191 root signature, the LayerZero packet and DVN instruction, and the
Hyperlane evidence hash. `internal/xir` and `internal/layerzero` compare against
those bytes; a mismatch is a defect, never an approximation.

## Running

The runtime reads one JSON configuration document
(`schemas/xir-go-runtime-config-v1.schema.json`). Private keys never appear in
the document: each entry of `key_environment` names an environment variable that
holds one signing key.

```console
$ export XIR_RUNNER_KEY=0x...        # runner: createRecord, recorder.record, deliver
$ export XIR_ROOT_SIGNER_KEY=0x...   # XIR root certificate signer
$ export XIR_LZ_WORKER_KEY=0x...     # LayerZero DVN signer and Executor submitter
$ export XIR_HL_VALIDATOR_KEY=0x...  # Hyperlane validator
$ export XIR_HL_RELAYER_KEY=0x...    # Hyperlane process() submitter
$ cd go-runtime && go run ./cmd/xirlab-go run --config ../configs/go-runtime/local-hl.json
```

`--config` names the chains, the deployment document, the attempts, and the
private state paths. `state_path` and `raw_root` must live outside the
repository: they hold the durable ledger and the raw signed transactions.

Set `embedded_agents` to `false` when an external LayerZero DVN/Executor or
Hyperlane validator/relayer should perform the delivery; the runtime then only
dispatches and waits for the destination adapter to report the evidence.

`finality.mode` decides when a created root may be signed. `rpc-finalized` (the
default) requires the creation block to reach the finalized height the node
reports, and falls back to the private-QBFT rule when the node does not
implement the tag, which is what the frozen Besu lab does. `confirmations`
requires N successor blocks and a canonical creation block; it exists because
development chains such as anvil pin the finalized tag at genesis. `none`
accepts the mined receipt and is recorded in the ledger as test-only.

## What this runtime is not

- It is not a production bridge, wallet, or relayer service.
- It does not reproduce the campaign governance gates (review gate, phase
  authority, validator-volume attestation, resource monitor, preflight digests);
  those remain Python-side and a Go run is not a campaign result.
- It has no mainnet path and no public-testnet write path.
- Its integration tests run on disposable anvil chains with the same chain ids
  and one-second block period as the frozen five-chain Besu topology, because
  that topology needs more CPU and memory than a development host provides. The
  frozen lab remains the environment of record for published measurements.
