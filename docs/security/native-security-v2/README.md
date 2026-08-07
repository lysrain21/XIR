# native-security-v2

This directory freezes the secret-free publication for the administrator-bound
XIR security campaign.  The campaign executed 13 cases on both heterogeneous
routes (`HL` and `LH`) with 30 repetitions per cell: 780/780 case runs were
validated and none failed.

The two authority cases contributed 120 status-0 transactions.  Every
`fake_verifier` and `wrong_endpoint` transaction failed at
`second_protocol_dispatch` with `UnapprovedPriorVerifier` (selector
`0x819d4ecb`), left the message identifier unconsumed, and produced no
application effect.

- `official/` is the online campaign publication.
- `rebuild/` is one independently rebuilt publication.  Its manifest and
  secret scan are valid.
- `metadata/` contains the deployment and smoke validations, remote preflight,
  public profile-transaction capture, byte-for-byte rebuild comparison, and
  final handoff.

The second independent rebuild is represented by
`metadata/rebuild-comparison-final.json`; all core and derived publication files
matched byte for byte.  The final handoff SHA-256 is
`392aaead9aaaac2f72c844aa6938cd4d502f7ce2ea2577cc8d637c98b0e7c491`.
Raw receipts and private transaction spools remain in the immutable remote run
tree and are not copied into this source repository.
