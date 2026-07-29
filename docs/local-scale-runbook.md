# Controlled local three-chain scale lab

## Scope

This lab runs three independent Besu 26.4.0 QBFT networks with four validators
per network. The route roles are `local-source`, `local-intermediate`, and
`local-destination`. Only each network's first validator exposes RPC, bound to
loopback on ports 18545, 28545, and 38545.

The scale profile contains exactly 5,000 matched pairs and 10,000 designated
attempts. Each attempt records one source, one intermediate, and one destination
transaction, for 30,000 physical transactions. Every `HH`, `HL`, `LH`, and
`LL` condition/arm cell contains 1,250 attempts.

The carriers are controlled local protocol labels and fault controls. Results
describe the local runner, recovery spool, QBFT nodes, evidence database, and
reconciliation pipeline. Public Hyperlane or LayerZero capacity, latency,
fees, and reliability remain outside this evidence.

## Host and tool requirements

Use a dedicated host with at least:

- smoke: 4 logical CPUs, 12 GiB memory, and 20 GiB free disk;
- full scale: 8 logical CPUs, 16 GiB memory, and 40 GiB free disk.

Required tools are Docker Engine, Docker Compose v2, Python 3.13 with the
repository environment installed, and Foundry. The topology pins the Besu
image by digest. Development keys are created under a dedicated runtime root
outside the repository.

## Initialize and start

```bash
export XIR_LOCAL_RUNTIME_ROOT=/var/tmp/xir-local-scale-run-001
scripts/local_scale.sh init
scripts/local_scale.sh render
scripts/local_scale.sh up
scripts/local_scale.sh health
```

`up` checks host capacity before starting containers. `health` requires all 12
validators to report the expected chain ID, three peers, advancing
blocks, and the same checkpoint hash within each four-validator network.

## Deploy and run the progression

```bash
scripts/local_scale.sh deploy
scripts/local_scale.sh run-smoke
sha256sum "$XIR_LOCAL_RUNTIME_ROOT/evidence/smoke.sqlite"

scripts/local_scale.sh run-rehearsal
sha256sum "$XIR_LOCAL_RUNTIME_ROOT/evidence/rehearsal.sqlite"
```

Capture resource observations and operational limits in
`$XIR_LOCAL_RUNTIME_ROOT/measured-limits.json`. The plan command hashes this
file and both reconciled evidence databases, then freezes the three digests
into the exact scale plan:

```bash
scripts/local_scale.sh plan

scripts/local_scale.sh scale-preflight
scripts/local_scale.sh run-scale
```

`run-scale` requires both `$XIR_LOCAL_RUNTIME_ROOT/scale-plan.json` and
`$XIR_LOCAL_RUNTIME_ROOT/scale-preflight.json`. Their topology, identity,
profile, progression, resource, and twelve-node health fields must match and
be eligible.

The default batch size is 25. Set `XIR_LOCAL_BATCH_SIZE` to a value from 1 to
250 after the rehearsal has measured a safe limit. The runner writes intent
and exact signed recovery bytes before submission, reconciles receipts, and
deletes each private spool item after finalization. Re-running a phase resumes
from its SQLite evidence ledger.

## Fault and recovery exercise

After smoke succeeds, stop one non-bootnode validator:

```bash
docker compose \
  --project-name xir-local-scale \
  -f "$XIR_LOCAL_RUNTIME_ROOT/compose.yaml" \
  stop local-intermediate-v4
```

Run the health check and preserve its failed result. Restart the validator,
wait for catch-up, and require a passing health check before continuing:

```bash
docker compose \
  --project-name xir-local-scale \
  -f "$XIR_LOCAL_RUNTIME_ROOT/compose.yaml" \
  start local-intermediate-v4
scripts/local_scale.sh health
```

If Docker access uses passwordless `sudo`, prefix these two direct Compose
commands with `sudo --preserve-env=XIR_LOCAL_RUNTIME_ROOT`.

## Stop and cleanup

```bash
scripts/local_scale.sh stop
scripts/local_scale.sh cleanup --confirm-remove-local-volumes
```

`stop` retains validator data. `cleanup` removes only this Compose project's
containers and three networks. Runtime-bound validator databases, identity
files, evidence databases, plans, and reports remain in the external runtime
root for audit or explicit later disposal.

Never publish `private/`, signed spool bytes, account keys, or validator keys.
Only validated redacted reports and public identity metadata are suitable for
release.
