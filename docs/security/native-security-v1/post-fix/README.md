# native-security-v1 post-fix evidence

This directory freezes the lineage-bound security campaign. The final carrier
adapter authenticates the exact ordered tuple sequence transported in one
native bundle. The Gateway then checks each hop receipt, its prefix, Gateway
identity, and current registry profile.

The official campaign executed 11 cases over HL and LH with 30 repetitions per
route and case. All 660 case runs validated. Every rejected transaction
produced zero application effects. Sequential and concurrent replay cases each
produced one initial effect and zero duplicate effects. The strong
cross-execution splice reached an application effect in the preserved pre-fix
test and was rejected in all 60 post-fix native-stack repetitions.

`publication/` is one canonical offline rebuild. Its `SHA256SUMS` validates all
published files. `rebuild-comparison-final.json` records that two independent
offline rebuilds were byte-identical and matched the online core results.

The profile-inactivity result does not rely only on an error selector.
`profile-inactive-lineage.json` links every one of the 60 cases to the decoded
`setProfile` calldata and `ProfileSet` log that disabled the exact first-hop
profile, the rejected delivery transaction, and the successful transaction
that restored the same snapshot with `enabled=true`.

The run-003 audit checked 504,113 manifest entries. Exactly one byte mismatch
was observed: `layerzero/worker.sqlite-shm`, the non-durable SQLite shared-memory
WAL index and locking file. All durable evidence entries matched. The preflight
therefore records `strict_byte_identity=false` and
`durable_evidence_identity=true`; run-003 was not modified to mask the mismatch.

Paper-facing sources are:

- `publication/paper-security-results.csv`: 22 route-by-case rows with expected
  and actual rejection stages and application effects.
- `publication/paper-profile-inactive-lineage.csv`: 60 exact registry-state
  transition sequences.
- `publication/paper-classification-table.csv`: A1--A4 and guarantee mapping.
- `publication/profile-inactive-lineage.json`: raw-evidence hashes and decoded
  state observations for every profile-inactivity case.

The remote raw receipts, public profile transaction inputs, durable runner
database, and signer audit remain under the isolated `security-full-v1`
runtime. No private key or signed-transaction spool is included here.
