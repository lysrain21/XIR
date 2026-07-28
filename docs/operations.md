# Reproduction and future operations

## Local zero-write reproduction

Use Python 3.13, the pinned `uv.lock`, and the pinned Foundry toolchain recorded
in `toolchain.lock.json`.

```bash
./scripts/bootstrap.sh
uv run pytest -q
uv run ruff check .
uv run mypy src/xir_lab
cd contracts && forge test
```

All fixture replay, reconciliation, normalized export, figures, and package
validation run without a signer or network. `xir-lab ... --live` is blocked in
this OpenSpec change.

## External signer and approval authority

The runner refers to an external transaction signer by public identity and
operation ID. Private keys, passwords, authenticated URLs, decrypted
keystores, and reusable signed bytes must stay outside the repository and
release roots. The signer must return identical bytes for a repeated operation
ID or fail explicitly.

The offline Ed25519 approval authority signs canonical approval envelopes. Its
private key is never loaded by the runner. Rotate by pinning a new public key,
issuing a higher authority sequence, recording revocation for affected
approvals, and retaining the signed revocation digest in evidence.

## Dry run and interruption recovery

Deployment dry run verifies network identity, bytecode/constructor digests,
deployer nonce, predicted addresses, and operation budget without signing.
Pilot and later phases require separate approvals. On interruption:

1. stop new work and inspect persistent run control;
2. recover/quarantine the private spool;
3. resolve every `broadcast_unknown` lineage by precomputed hash and nonce;
4. recheck approval, signer/network identity, quote, nonce, reservation, and
   stop state before any exact-byte repeat;
5. resume collector overlap scans from the latest versioned checkpoint;
6. reconcile finality, budgets, deadline outcomes, and pending backfill.

## Offline rebuild

A formal rebuild begins from one immutable freeze, verifies SQLite and raw
digests, runs reconciliation and cross-table invariants, exports normalized
JSON plus analysis-only CSV, decides designated-primary eligibility, and
builds tables/figures twice with sockets disabled. Equal semantic digests are
required.

The future live-run sequence and manual funding checkpoints are specified in
`docs/live-run-runbook.md`. This repository does not execute those steps.
