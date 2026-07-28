# Change: authorize-xir-testnet-scale

## Preconditions

- [ ] Primary evidence is frozen and its digest is referenced.
- [ ] Frozen pilot/primary measurements feed the scale estimator.
- [ ] Exactly 10,000 primary attempts are planned as 1,250 per condition/arm.
- [ ] Time, quote, physical-transaction, storage, RPC-quota and test-token
      bounds pass.

## Authorization

Use a separate `scale` approval binding the deployment, profile, counts,
concurrency, batches, retries, networks, signer, budgets, observation window,
stop policy and partial-condition rule. Reconcile all 10,000 planned items plus
separate retries. Report only bounded runner/evidence-pipeline behavior, never
carrier capacity or production reliability.
