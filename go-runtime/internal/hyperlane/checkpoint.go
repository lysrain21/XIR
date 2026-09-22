package hyperlane

import (
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// domainSeparator is the literal every Hyperlane signing domain is bound to.
//
// solidity/contracts/libs/CheckpointLib.sol:90 — `abi.encodePacked(_origin,
// _merkleTreeHook, "HYPERLANE")`. A string literal in `abi.encodePacked` is
// appended as its 8 raw ASCII bytes, with no length word and no padding.
const domainSeparator = "HYPERLANE"

// Checkpoint is the origin MerkleTreeHook checkpoint validators sign: which tree
// (Domain), which root (Root) and which leaf index (Index).
//
// The signing struct is larger
// (`Checkpoint{origin, merkleTree, root, index, messageId}`,
// solidity/contracts/libs/CheckpointLib.sol:7-13); the merkle tree address and
// the message id are supplied separately here because the tree address is ISM
// metadata field 0 and the message id is derived from the message itself.
type Checkpoint struct {
	Domain uint32
	Root   [32]byte
	Index  uint32
}

// DomainHash returns the signing domain of one origin tree.
//
// solidity/contracts/libs/CheckpointLib.sol:80-91:
//
//	keccak256(abi.encodePacked(uint32 origin, bytes32 merkleTreeHook, "HYPERLANE"))
//
// so the digest preimage is exactly 45 bytes: 4 big-endian bytes of origin, the
// 32-byte left-padded hook address, then the 9 ASCII bytes "HYPERLANE". The
// comment at CheckpointLib.sol:84-88 records why the tree address is inside the
// domain hash: without it a signature for tree A would be indistinguishable from
// one for tree B, and a slashing protocol could not attribute it.
//
// The Rust agent computes the same bytes with the arguments in the opposite
// order (`domain_hash(merkle_tree_hook_address, domain)`,
// rust/main/hyperlane-core/src/utils.rs:47-57); the hashed field order is
// unchanged: domain first, then address.
func DomainHash(domain uint32, merkleTreeHook common.Address) [32]byte {
	hook := AddressToBytes32(merkleTreeHook)
	preimage := make([]byte, 0, 4+32+len(domainSeparator))
	preimage = binary.BigEndian.AppendUint32(preimage, domain)
	preimage = append(preimage, hook[:]...)
	preimage = append(preimage, domainSeparator...)
	return xir.Keccak256(preimage)
}

// Hash returns the 32-byte hash a validator signs with `eth_sign` for one
// message: the checkpoint's own hash, before EIP-191 prefixing.
//
// solidity/contracts/libs/CheckpointLib.sol:28-45 hashes a 100-byte preimage:
//
//	keccak256(
//	    abi.encodePacked(domainHash, root, uint32 index, messageId)
//	)
//
// with `messageId` = `keccak256(message)` (see MessageID). Feed this value to a
// personal-message signer (internal/evm's `Signer.SignPersonalDigest`), which
// applies the prefixing itself; use Digest when a digest has to be verified
// without a signer.
func (c Checkpoint) Hash(merkleTreeHook common.Address, messageID [32]byte) [32]byte {
	domainHash := DomainHash(c.Domain, merkleTreeHook)
	preimage := make([]byte, 0, 32+32+4+32)
	preimage = append(preimage, domainHash[:]...)
	preimage = append(preimage, c.Root[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, c.Index)
	preimage = append(preimage, messageID[:]...)
	return xir.Keccak256(preimage)
}

// Digest returns the value the deployed ISM recovers a validator from, i.e. the
// checkpoint hash with the EIP-191 personal-sign prefix already applied.
//
// Which bytes are hashed and which are prefixed, exactly:
//
//   - hashed (100 bytes, CheckpointLib.sol:39-44): domainHash [32] || root [32]
//     || uint32 index [4, big-endian] || messageId [32];
//   - prefixed (CheckpointLib.sol:35-38): that keccak256 output is wrapped by
//     `ECDSA.toEthSignedMessageHash`, i.e. keccak256 of
//     "\x19Ethereum Signed Message:\n32" (28 bytes) || the 32-byte hash
//     (openzeppelin-contracts v4.9.3 ECDSA.sol:165-174);
//   - recovered (solidity/contracts/isms/multisig/AbstractMultisigIsm.sol:110):
//     `ECDSA.recover(_digest, signatureAt(_metadata, i))` — OZ `recover` applies
//     no further prefix, so this Digest value is what `ecrecover` sees.
//
// Equivalently (AbstractMessageIdMultisigIsm.sol:29-41), the ISM builds it from
// `_message.origin()`, metadata fields [0:32] and [32:64] as the tree and root,
// metadata field [64:68] as the index, and `_message.id()`.
//
// A validator therefore signs Hash (via personal signing) and the chain verifies
// Digest: one signature, two representations of the same statement.
func (c Checkpoint) Digest(merkleTreeHook common.Address, messageID [32]byte) [32]byte {
	return personalDigest(c.Hash(merkleTreeHook, messageID))
}

// CheckpointDigest returns the 32-byte signing hash of one
// (origin domain, origin tree hook, root, index, messageID) tuple.
//
// It is exactly `Checkpoint.Hash` for the same tuple: the 100-byte preimage
// above, hashed and *not* yet EIP-191 prefixed. Pass it to a personal-message
// signer — `SignPersonalDigest(CheckpointDigest(...))` yields the signature that
// goes into the metadata and that the deployed ISM recovers from
// `Checkpoint.Digest`, which is the prefixed form of this value. The distinction
// matters: signing this hash with a raw (non-personal) signer would recover a
// different address on chain and `process` would revert with "ISM verification
// failed" (solidity/contracts/Mailbox.sol:235-238).
//
// originMerkleTreeHook is the origin MerkleTreeHook, i.e. the emitter of the
// `InsertedIntoTree` log and the contract `MerkleTreeHook.latestCheckpoint()` is
// read from, not the origin Mailbox: the tree address is the second component of
// the domain hash (CheckpointLib.sol:80-91) and metadata field [0:32]
// (MessageIdMultisigIsmMetadata.sol:5-9), and the ISM never sees a mailbox
// address. Substituting the Mailbox silently produces a digest no validator ever
// signed.
func CheckpointDigest(
	originDomain uint32,
	originMerkleTreeHook common.Address,
	root [32]byte,
	index uint32,
	messageID [32]byte,
) ([32]byte, error) {
	if originMerkleTreeHook == (common.Address{}) {
		return [32]byte{}, errors.New(
			"hyperlane: origin merkle tree hook is the zero address, not a MerkleTreeHook",
		)
	}
	checkpoint := Checkpoint{Domain: originDomain, Root: root, Index: index}
	return checkpoint.Hash(originMerkleTreeHook, messageID), nil
}
