# Security policy

## Scope

XIR Testnet Lab is a research prototype for named public testnets. It is not
approved for mainnet, production assets, custody, or arbitrary contract calls.

## Never place secrets in this repository

Do not commit, log, attach to an issue, or include in a release:

- private keys, seed phrases, signer passwords, or decrypted keystores;
- authenticated RPC URLs, bearer tokens, cookies, or provider credentials;
- reusable signed transactions or private recovery-spool contents;
- environment dumps or command lines containing sensitive values.

The runtime may refer to an external signer or encrypted keystore by a
non-secret identifier. Signer material and private spools must remain outside
the repository, run-result roots, CI workspace, and publication roots.

The controlled local lab is the sole exception to the general wallet-creation
boundary: `local-init` creates disposable development keys under the
user-selected `XIR_LOCAL_RUNTIME_ROOT`, which must resolve outside the
repository. These keys are operationally designated only for private chain IDs
3133701–3133703, must never receive public-network funds, and remain excluded
from publication.
The public identity manifest contains addresses and enode identities only.

## Public-network writes

All commands default to offline or read-only behavior. Wallet creation,
funding, token transfers, deployments, configuration transactions, experiment
transactions, and closeout transactions require separate authorization. CI
must never load a live signer or send a public-network write request.

If a secret or reusable signed payload is exposed, stop execution, revoke or
rotate the affected credential, preserve only redacted audit metadata, and
invalidate any release containing it.

## Reporting vulnerabilities

Do not disclose a credential or exploitable live configuration in a public
issue. Use the private security-reporting channel configured by the repository
host or contact the maintainers privately. Include affected versions,
reproduction steps using sanitized fixtures, and expected impact.

## Supported versions

Only the latest tagged research release is supported. Experimental branches
and unreleased live configurations receive no security or availability
guarantee.
