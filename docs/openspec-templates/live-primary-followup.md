# Change: authorize-xir-testnet-live-primary

## Preconditions

- [ ] External custody confirms fresh deployer/admin and runner public addresses.
- [ ] A human records separately authorized, chain-specific manual funding.
- [ ] Code/config/schema/network/deployment/profile/stop-policy digests are frozen.

## Separately approved operations

- [ ] Deployment approval and receipts
- [ ] Configuration approval and receipts
- [ ] Pilot approval for exactly 5 pair slots per condition, 20 total
- [ ] Pilot reconciliation and measured primary estimate
- [ ] Primary approval for exactly 30 pair slots per condition, 120 total
- [ ] Evidence freeze and deterministic rebuild
- [ ] Closeout approval, rollback if required, and revocation record

No approval type substitutes for another. Include operation IDs, issuer/key
identity and sequence, validity window, expected pre-state/transition, public
addresses, ordered networks, deployment IDs, exact counts, per-chain budgets,
stop policy and `allow_partial_conditions`.
