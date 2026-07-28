# Current carrier discovery record

This is a public, read-only discovery record captured on 2026-07-28 UTC. It is
not deployment or pilot authority. Every value must be fetched again, queried
on-chain, simulated, and placed in an unexpired operation preflight before a
public write.

| Network | Chain ID | Hyperlane domain / Mailbox | LayerZero V2 EID / Endpoint |
| --- | ---: | --- | --- |
| OP Sepolia | 11155420 | 11155420 / `0x6966b0E55883d49BFB24539356a2f8A673E02039` | 40232 / `0x6EDCE65403992e310A62460808c4b910D972f10f` |
| Arbitrum Sepolia | 421614 | 421614 / `0x598facE78a4302f11E3de0bee1894Da0b2Cb71F8` | 40231 / `0x6EDCE65403992e310A62460808c4b910D972f10f` |
| Base Sepolia | 84532 | 84532 / `0x6966b0E55883d49BFB24539356a2f8A673E02039` | 40245 / `0x6EDCE65403992e310A62460808c4b910D972f10f` |

The official Hyperlane registry was read at commit
`fe308be1c196abee3b1b064c6cf0b0c4be1729b1`. The official LayerZero metadata
response SHA-256 was
`9cfe124c272fa02c47a5a5e1d56cf1da5ad41ddcb4275d04fd1853f56e8fabf0`.
The live parser's six-deployment discovery digest was
`6f257eb0242f237c03cf1622d6ea1118ba62c6d060704cc18bfc2e8439bf45a3`.

Sources:

- Hyperlane:
  `https://github.com/hyperlane-xyz/hyperlane-registry/tree/main/chains`
- LayerZero:
  `https://metadata.layerzero-api.com/v1/metadata/deployments`

Application adapter addresses and remote peers are deliberately absent. They
must come from the separately frozen deterministic deployment plan. The
registry discovery module rejects incomplete adapter mappings so protocol
registry values cannot be mistaken for XIR peers.
