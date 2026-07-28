# Data dictionary

| Class | Examples | Provenance |
|---|---|---|
| Public chain observation | transaction, receipt, header, log, balance | Exact public RPC bytes plus normalized fields |
| Experiment-side observation | intent, lease, approval, UTC/monotonic phase clock | Local append-only ledger |
| Auxiliary observation | carrier explorer delivery status | Public API; never sufficient for final delivery |
| Derived value | execution fee, pair difference, median, IQR | Named normalized input rows and deterministic code |
| Unavailable private value | relayer queue time, DVN cost, routing decision | `null` plus machine-readable reason; never inferred |

`included` and `finalized` are distinct. Each included observation records
block number and hash; its finality row names confirmations, L2 safe/finalized,
or L1 settlement. Orphans are retained and superseded.

`outcome_at_deadline` is immutable. A later delivery appends
`eventual_outcome = delivered_after_timeout`. Observer failure and incomplete
evidence are not carrier/XIR/destination failures.

Observer elapsed time uses a single monotonic-clock session. UTC wall time and
per-chain block timestamps are separate. Cross-chain block intervals state
that independent chain clocks are not a precise common clock; negative or
implausible values are unavailable.

SQLite is the source of truth. JSON exports are versioned normalized records;
CSV is analysis convenience only. Each raw object is gzip-compressed under its
SHA-256 and verified before freeze.
