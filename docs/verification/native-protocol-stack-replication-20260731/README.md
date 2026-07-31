# Native protocol-stack replication run-003

Accepted scale result: 40,000/40,000 logical attempts succeeded and exact
reconciliation passed. The Chinese experiment report is
[`experiment-report-zh.md`](experiment-report-zh.md).

Machine-readable publication files:

- `analysis.json` and `per-route.csv`: scale latency, throughput, gas, resource,
  and retry aggregates.
- `reconciliation.json`: independent denominator, lineage, transaction, nonce,
  stage, message, effect, and XIR invariants.
- `final-run-summary.json`: validator restarts, natural interruptions,
  calldata, storage, monitoring coverage, and process generations.
- `offline-rebuild-verification.json`: equal semantic digests from two offline
  reconstructions.
- `manifest-verification.json` and `evidence-manifest.json.sha256`: frozen
  remote-evidence verification and manifest digest.
- `publication-validation.json`: machine checks binding the report claims to
  the reconciliation, analysis, closeout summary, rebuild, and manifest.
- `component-provenance.json`, `deployment.json`, `profile.json`, and
  `measured-limits.json`: pinned stack and admitted topology parameters.

The complete evidence remains on the experiment host at:

`/vePFS-Mindverse/user/intern/lucian/xir/runtime/native-stack-run-003`

Private keys, runtime-private files, and raw signed transactions are retained
there and are deliberately not published in Git.
