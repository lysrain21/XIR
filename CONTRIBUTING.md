# Contributing

Contributions must preserve the repository's zero-write default, evidence
provenance, deterministic rebuilds, and bounded scientific claims.

## Development rules

- Work only with local networks, mocks, or sanitized read-only fixtures unless
  a separate live operation explicitly authorizes otherwise.
- Never add a private key, seed, keystore, password, authenticated RPC URL, or
  reusable signed transaction.
- Add or update JSON Schemas for durable formats.
- Record source path, exact source digest, license, extraction date, source
  revision or unavailable reason, and modifications for imported files.
- Preserve append-only evidence history; do not overwrite observations,
  attempts, retries, or transaction lineages.
- Add tests for failure and recovery behavior, not only successful paths.
- Keep baseline and XIR inputs matched and receiver state isolated.
- Do not manually copy numerical claims into reports or figures.

## Validation

Before submitting a change, run the documented locked-environment checks for:

- Python formatting, linting, typing, and tests;
- Foundry build, unit, fuzz, and invariant tests;
- all eight local condition/arm paths;
- schema and fixture validation;
- recovery and deterministic offline rebuilds;
- secret and publication-hygiene scans.

No pull request workflow may use a live signer, public write RPC, faucet,
test-token funding, deployment broadcast, or experiment broadcast.
