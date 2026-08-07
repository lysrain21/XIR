# Pre-fix splice regression source

This directory preserves the exact untracked regression source used to produce
`../pre-fix-splice-regression.json`. The source was recovered byte-for-byte
from the local append-only agent tool-call log. Its SHA-256 digest is
`f84f5034075ea1ff38abc9602acf71b03f9c0f3f21c38fd66b53a8ea1697afc8`,
which matches the digest frozen in the original evidence JSON.

The production sources come from repository revision `86f844d`. Their three
digests also match the original evidence JSON. The test can be reproduced in
an isolated checkout as follows:

```text
git worktree add --detach /tmp/xir-prefx-repro 86f844d
cp docs/security/native-security-v1/pre-fix/SecuritySpliceRegression.t.sol \
  /tmp/xir-prefx-repro/contracts/test/SecuritySpliceRegression.t.sol
forge clean --root /tmp/xir-prefx-repro/contracts
forge test --root /tmp/xir-prefx-repro/contracts \
  --match-contract SecuritySpliceRegressionTest -vvv
```

The clean rebuild on 2026-08-07 compiled 19 Solidity files and passed the
single pre-fix case with gas `238337`. The destination application effect count
was one, reproducing the result recorded before ordered final-bundle binding.
