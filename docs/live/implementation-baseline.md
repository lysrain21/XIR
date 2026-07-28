# Live implementation baseline

- Recorded: 2026-07-28 UTC
- Baseline branch: `main`
- Baseline commit:
  `9f9553dee7b796f2553e7e252a762b9bf6fc26d3`
- Purpose: immutable zero-write reference before implementing
  `enable-xir-testnet-live-pilot`

## Toolchain and input digests

| Input | SHA-256 |
| --- | --- |
| `uv.lock` | `33b2b30bc07955062252cb0b72ace90f879f33ca547a0a3c80fb1d546ba273df` |
| `toolchain.lock.json` | `6329421763d0a66d4d6d85b679a6ef7df977277a99abe6ceca14dce8630b3d9e` |
| `.python-version` | `f8faecf2505680716c6279bf2cdec3d5a5ba2ba852f0d7df45d51ac1ce8d9ade` |
| sorted `schemas/*` file/digest stream | `9927c4f48e8f16cb9232a6e471ba122e9feda4f645d5c910a21f0f906a0c9005` |

Observed tools:

```text
Python 3.12.3
uv 0.11.21
forge 1.5.1-stable
forge commit b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2
```

## Local verification

Executed from the baseline checkout on 2026-07-28:

```text
uv run ruff check .
All checks passed

uv run mypy src/xir_lab
Success: no issues found in 43 source files

uv run pytest -q
246 passed in 40.84s

forge test --root contracts
24 passed; 0 failed; 0 skipped
```

## Zero-write command effects

Each baseline command was invoked with `--live`. Every invocation exited `2`
with `reason_code=live_execution_not_authorized_in_zero_write_build`:

| Command | Wallets | Funding | Signatures | Deployments | Broadcasts |
| --- | ---: | ---: | ---: | ---: | ---: |
| `plan` | 0 | 0 | 0 | 0 | 0 |
| `preflight` | 0 | 0 | 0 | 0 | 0 |
| `deploy` | 0 | 0 | 0 | 0 | 0 |
| `run` | 0 | 0 | 0 | 0 | 0 |
| `collect` | 0 | 0 | 0 | 0 | 0 |
| `reconcile` | 0 | 0 | 0 | 0 | 0 |
| `analyze` | 0 | 0 | 0 | 0 | 0 |
| `publish` | 0 | 0 | 0 | 0 | 0 |

The live implementation MUST preserve these effects whenever live mode is
absent, hard-disabled, incompletely approved, or unconfirmed.
