# Future separately authorized live-run runbook

This is a handoff, not authorization. Do not execute it under
`build-xir-testnet-lab`.

1. A human custodian creates fresh external deployer/administrator and runner
   addresses. Record only public addresses and signer identity digests.
2. Freeze network checkpoints, code, schemas, configuration, route, peers,
   application payload/effect, budgets, stop policy, and observation windows.
3. At a separately authorized manual checkpoint, fund each public address on
   each required chain with a chain-specific amount. Record public funding
   transaction hashes and balances. Never automate faucet access or transfers
   in this repository.
4. Issue and consume a `deployment` approval. Dry-run creation bytecode,
   constructor digests, nonce, factory and predicted addresses before signing.
5. Recollect deployed runtime bytecode and issue a separate `configuration`
   approval for administrator, runner, pause state, endpoints, peers,
   domains/EIDs, XIR route/profile, and expected transitions.
6. Freeze a concrete pilot profile and issue a `pilot` approval. Execute
   exactly five pair slots in each of HH, HL, LH and LL: 20 pair slots and
   40 designated attempts total. Reconcile every pilot attempt, deadline,
   finality, budget, raw object, invariant, and rollback gate.
7. Use frozen pilot observations to estimate primary time, quote movement,
   physical transactions, storage, RPC quota and test-token budget. Do not
   extrapolate production price or capacity.
8. Freeze a concrete primary profile and issue a distinct `primary` approval.
   Execute exactly 30 pair slots per condition: 120 primary pair slots and
   240 designated primary attempts, plus exactly eight separately reported
   warm-ups. Retries remain separate and never replace designated attempts.
9. Drain, collect overlap/backfill, reconcile all scoped pilot/warm-up/primary/
   retry attempts, recheck canonical finality, and create an immutable evidence
   freeze. Two socket-disabled rebuilds must match.
10. Issue a separate `closeout` approval for pause, runner revocation, or
    profile disable. Verify the expected current state immediately before each
    signature. Preserve public closeout receipts.
11. If rollback is needed, use only the predeclared pause/revoke/disable
    transitions and their own approval. Do not attempt arbitrary recovery
    calls.
12. Record an authority-signed post-run revocation for approvals that should no
    longer be usable. Destroy signed spool bytes only after canonical
    reconciliation or separately authorized proof of a dead lineage.

An optional scale run occurs only after the primary freeze and under its own
`scale` approval/change. It is not required for the primary paper result.
