# Native mechanism ablation v2

> **Status: frozen; 8,000 primary attempts, two identical offline rebuilds,
> and the real-figure visual audit passed.**

`native-ablation-v2` is the final mechanism-cost result for the
administrator-bound verifier revision.  Version 1 remains immutable revision
evidence and is not used for final cost claims.

## Frozen design and result

- Routes: `HL`, `LH`.
- Treatments: `B0`, `B1`, `B2`, `B3`.
- Primary denominator: 1,000 attempts per route/treatment cell, 8,000 total.
- Schedule: every deterministic payload block interleaves the same eight cells.
- Physical boundary: every coordinator transaction, Hyperlane process
  transaction, and LayerZero DVN, commit, and executor action.
- Reconciliation: 62,000 complete physical transactions, 8,000 destination
  effects, and no missing or duplicate attempt.
- Intervals: paired moving-block bootstrap intervals for `B0->B1`, `B1->B2`,
  and `B2->B3`, with `HL` and `LH` reported separately.  An interval belongs
  to one adjacent increment and is not additive across layers.

One read-only receipt-poll interruption occurred after the destination effect
had committed.  The primary analysis retains the complete 8,000-attempt
denominator.  The matched-block latency sensitivity excludes route sequence
564 from all eight cells and retains 7,992 attempts, or 999 per cell and paired
increment.

## Frozen authority and source gate

Both outbound XIR adapters bind `H_AB` to `h_in` and `L_AB` to `l_in` under
the administrator-selected mappings.  The final campaign froze these source
identities:

```text
HyperlaneAdapter.sol  1ca91fb1cb8137d7b1cfb2ef5dc21ac95f45b22defea729f1535c73d33773f18
LayerZeroAdapter.sol  042fbeeb00d93ce4ec077bbeeb944daed752c16f649460c5ee2df88218c53941
deployer.py            788bf7f9d929a265da3a6e00dacca9b9b97913541b0cad9f49550addc6178653
runner.py              02c43d51d3604c86ac9f4059684c443a03d98878f0ccb03a7be58b18238c4c1d
```

## Frozen evidence

The secret-free source publication, two byte-identical rebuilds, physical
lineage, incident audit, real 131.6 x 62.0 mm figure, and final handoff live at
`experiment-results/native-followups-final/native-ablation-v2/`.  The semantic
digest is
`48c4f31a3bb1acd5d7b0359c6d6a18279e138967098aaca30e79aa45d2a9f0a9`;
the source manifest digest is
`9c18c6dad7c5e5b77f594a974ae16001df5e519862cac8fe512f9001882fa9a5`.
