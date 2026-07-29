# Final verification

- Change: `build-xir-testnet-lab`
- Verification date: 2026-07-26 UTC
- Release state: local zero-write research prototype
- Public-testnet state: deferred; no wallet was created or funded, no test
  tokens were obtained, and no public deployment, signing operation, broadcast,
  or remote publication occurred.

## Capability traceability

| OpenSpec capability | Implementation and evidence |
| --- | --- |
| `testnet-lab-workspace` | Standalone repository metadata and locks; `src/xir_lab/cli.py`; `.github/workflows/ci.yml`; `provenance/manifest.json`; local-only tests and sanitized release inputs. |
| `testnet-account-safety` | `schemas/approval-*-v1.schema.json`; `templates/approvals/`; `src/xir_lab/preflight/`; `src/xir_lab/execute/approvals.py`, `controls.py`, `signer.py`, and `submission.py`; fail-closed live command boundary. |
| `paired-protocol-execution` | `contracts/src/`; `contracts/test/`; versioned route, stage, pilot, primary, and scale configurations; `src/xir_lab/config/`; bounded scheduler and executor tests. |
| `durable-experiment-evidence` | `src/xir_lab/evidence/`; collectors, finality, bounded backfill, protocol/XIR linkers, deadline/eventual outcomes, recovery spool, append-only journal, reconciliation, and crash/reorganization/storage tests. |
| `reproducible-overhead-reporting` | `src/xir_lab/analysis/`; normalized schemas; pair-first resource accounting; deterministic offline double rebuild; primary and separate 10,000-attempt scale reports; local publication and claim gates. |

Required architecture, operations, data-dictionary, live-run, claim-review, and
follow-up OpenSpec documents exist under `docs/`. Sanitized examples and their
manifest exist under `data/examples/`. Code, data, citation, security, claim,
and contribution metadata exist at the repository root.

## Commands and results

Run from the standalone repository unless noted otherwise:

```text
uv run pytest -q
246 passed in 40.27s

uv run ruff check .
All checks passed!

uv run mypy src/xir_lab
Success: no issues found in 43 source files

forge test --root contracts
24 passed; 0 failed; 0 skipped

uv run python -c '<validate every schemas/*.json as JSON Schema Draft 2020-12>'
schemas: ok

uv run pytest tests/integration tests/unit/test_submission.py \
  tests/unit/test_finality_manager.py tests/unit/test_evidence_store.py \
  tests/unit/test_reports.py tests/unit/test_publication.py -q
66 passed in 16.36s

npx --yes @fission-ai/openspec@1.4.1 \
  validate build-xir-testnet-lab --strict
Change 'build-xir-testnet-lab' is valid
```

The full Python suite includes all eight local condition/arm paths, every
defined submission and collection crash boundary, corrupt/missing spool
objects, disk-full and corrupt-backup handling, reorganization behavior,
10,000-attempt scheduling/report fixtures, schema and publication gates, and
two byte-equivalent offline rebuilds with socket creation disabled.

For each of `plan`, `preflight`, `deploy`, `run`, `collect`, `reconcile`,
`analyze`, and `publish`, this check was also run:

```text
uv run python -m xir_lab <command> --live
```

Every command returned exit status 2 with
`reason_code=live_execution_not_authorized_in_zero_write_build` and reported
zero wallets created, funding operations, signing operations, deployments, and
broadcasts. A tracked-path scan found no `private-spool` or `keystore`
directory. Publication tests reject private spool objects, credential-shaped
values, and authenticated endpoints without unrestricted free-text keyword
matching.

## Tool versions

```text
Python 3.12.3
uv 0.11.21
forge 1.5.1-stable (b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2)
OpenSpec 1.4.1
```

## External limitations and next authorization boundary

No current public-testnet route availability, carrier configuration, RPC
quota, faucet balance, funded address, deployment identity, quote, or fee
budget is asserted by this local verification. Fresh address custody and
chain-specific test-token funding remain explicit manual checkpoints outside
this change.

Actual deployment/configuration and the 20-pair pilot require separately
signed, operation-scoped approvals in a follow-up OpenSpec change. Only a
reconciled pilot freeze may inform a separately approved 120-pair primary run.
The optional 10,000-attempt public-testnet scale run requires its own later
approval/change and is not required for the primary research result.

No GitHub release, DOI upload, or other remote publication was performed.

## Controlled local three-chain scale extension

- OpenSpec change: `add-local-three-chain-scale-lab`
- Verification date: 2026-07-29 UTC
- Implementation state: complete
- Full-scale execution state: correctly blocked on this host by capacity
  preflight; no twelve-node launch was attempted

The extension adds a pinned Besu 26.4.0 topology for three independent QBFT
chains and exactly four validators per chain, repository-external development
identity initialization, deterministic Compose rendering, strict host and
twelve-node health gates, a resumable three-stage workload, exact
smoke/rehearsal/scale progression, and controlled-local claim exclusions.

The scale plan is fixed at 5,000 matched pairs, 10,000 designated attempts,
1,250 attempts per condition/arm cell, and 30,000 physical transactions.
Scale execution verifies the content digests of reconciled smoke and rehearsal
SQLite evidence plus `measured-limits.json`; it also requires an eligible
identity-bound twelve-node preflight.

Verification results:

```text
ruff check .
All checks passed!

mypy src/xir_lab
Success: no issues found in 65 source files

pytest -q
360 passed, 1 warning

forge test --root contracts
32 passed; 0 failed; 0 skipped

docker compose ... config --quiet
compose config: ok

validate all schemas/*.json as JSON Schema Draft 2020-12
schemas: ok

openspec validate add-local-three-chain-scale-lab --strict
Change 'add-local-three-chain-scale-lab' is valid
```

A bounded live infrastructure check started one complete four-validator
`local-source` network. All nodes reported chain ID 3133701 and three peers,
all advanced their heads, and all returned the same hash at checkpoint block
18. The temporary containers, network, volumes, and disposable keys were
removed after verification. See
`docs/verification/local-source-four-validator-20260729.json`.

The current host reported 2 logical CPUs, 8,320,823,296 bytes of memory, and
107,331,014,656 bytes of available disk. Smoke requires 4 CPUs and 12 GiB;
scale requires 8 CPUs and 16 GiB. Both modes are ineligible because CPU and
memory are below threshold. See
`docs/verification/local-scale-host-capacity-20260729.json`.

No public-network RPC, signature, broadcast, faucet request, token transfer,
deployment, or carrier operation occurred during this extension.
