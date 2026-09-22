# Go runtime

`go-runtime/` holds an independent implementation of the XIR execution layer.
It was added so the delivery, confirmation, and recovery paths can be reviewed,
tested, and operated without the Python runtime's analysis and publication
machinery, while staying byte compatible with the Solidity contracts and with
the frozen campaign artefacts.

## What was ported

| Python reference | Go implementation |
| --- | --- |
| `src/xir_lab/native/xir_trace.py` | `internal/xir` (typed ids, record/context/receipt hashing, `rid`/`mid`, prefix chain, bundle commitment, tuples) |
| `src/xir_lab/native/multihop_deployer.py` identity helpers | `internal/xir` (`ProfileHash`, `GatewayTypedID`, `AdapterKey`) |
| `src/xir_lab/native/multihop_runner.py` coordinator | `internal/runner` (attempt loop, carriers, transitions, delivery, effect check) |
| `src/xir_lab/native/layerzero.py` | `internal/layerzero` (packet codec, options, DVN instruction, stage encoders) |
| `src/xir_lab/native/layerzero_worker.py` | `internal/layerzero` `Plan` + `internal/runner` LayerZero carrier |
| `src/xir_lab/native/runner.py` and `multihop_runner.py` state | `internal/state` (SQLite ledger with the same tables) |
| `src/xir_lab/native/root_signer.py` | `internal/runner` root signing (`verifyRootCreation`) and `internal/evm` signer |
| `src/xir_lab/native/multihop_deployer.py` deployment | `internal/deploy` |

The Hyperlane delivery role has no Python counterpart: the native campaign used
the upstream Rust validator and relayer binaries, so `internal/hyperlane` and the
embedded relayer in `internal/runner` are new code. They follow the pinned
Hyperlane sources (`toolchain/native-protocol-stack.lock.json` commit
`5857ead81a8783d168d48d370be72de88d5fb230`) and are accepted by the real
`StaticMessageIdMultisigIsm` deployed in the integration test, which is the
binding check for the checkpoint digest, the metadata layout, and the validator
signature.

## What was deliberately not ported

The campaign governance chain stays Python-side: the review gate, phase
authority, validator-volume attestation, resource monitor, preflight digests,
plan materialisation, analysis, and publication. A Go run therefore produces
execution evidence, never a campaign result.

## Parity

`go-runtime/testdata/vectors.json` is generated from the Python modules by
`scripts/generate_go_parity_vectors.py` and pins:

- typed-id encodings and hashes;
- record, context, root id, message id, root prefix, transition hashes;
- receipt hashes, prefix chains, bundle start/step commitments;
- multihop profile hashes, gateway typed ids, adapter keys;
- application payloads and the `NativeMultihopPayload` encoding;
- the full `XIRTypes.Envelope` ABI encoding and the EIP-191 root signature;
- the LayerZero packet fields, DVN instruction (call data, hash, signature) and
  the three stage calldatas;
- the Hyperlane evidence hash.

`internal/xir`, `internal/layerzero`, and `internal/hyperlane` assert those bytes
directly, and the runner's on-chain calls are accepted by the same contracts the
Python runner used, which checks the encoding a second time from the other side.

## Verification

```console
$ cd go-runtime
$ go vet ./...
$ go test ./...
```

Unit and parity tests run anywhere. Integration tests deploy the pinned real
Hyperlane and LayerZero contracts onto disposable local Anvil chains. Build the
fixtures from the protocol lock (Git, jq, Foundry, Node 22 and Corepack required):

```console
$ scripts/prepare_go_e2e.sh /tmp/xir-go-e2e-protocols
$ scripts/run_go_e2e.sh /tmp/xir-go-e2e-results.json
```

The preparation script fetches the two locked protocol commits, installs their
Soldeer/Yarn dependencies and builds Solidity artifacts. It does not build Rust
validators or send transactions to remote networks. The test script forces
`XIR_REQUIRE_E2E=1`, disables test caching, retains Go JSON output and rejects any
skip, failure, or missing required recovery test. CI runs both scripts; a skipped
integration test cannot count as success. Plain `go test ./...` still permits
missing-fixture skips for developers; use the script for release verification.

The integration tests assert the destination `NativeMultihopEffectApplied`
event, the receiver's `deliveryCount`, and that each carrier dispatched exactly
once. `TestAnvilRestartResumesWithoutDuplicateDispatch` interrupts an attempt
after its first dispatch with an injected fault, restarts the runtime over the
same ledger, and asserts that the attempt completes while the dispatch count
stays at one.

## Environment boundary

The published measurements come from the frozen five-chain Besu QBFT topology,
which requires at least eight logical CPUs and 20 GB of memory
(`configs/local/topology-multihop-remote-v1.json`). The integration tests use
anvil with the same chain ids and the same contracts because that topology does
not fit on a development host. Anvil chains are test fixtures: they produce no
campaign evidence, and a Go run is never a substitute for a frozen campaign
result.
