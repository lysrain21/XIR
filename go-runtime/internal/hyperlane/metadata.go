package hyperlane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// MessageIdMultisigIsm metadata layout, in bytes from the start of the metadata.
//
// solidity/contracts/isms/libs/MessageIdMultisigIsmMetadata.sol:5-16:
//
//	[   0:  32] Origin merkle tree address
//	[  32:  64] Signed checkpoint root
//	[  64:  68] Signed checkpoint index
//	[  68:????] Validator signatures (length := threshold * 65)
//
// There is no merkle proof in this module: the ISM only re-hashes the signed
// checkpoint, so the root and index fields are copied verbatim from what the
// validators signed and any tampering changes the recovered signer.
const (
	MetadataOriginMerkleTreeHookOffset = 0
	MetadataRootOffset                 = 32
	MetadataIndexOffset                = 64
	MetadataSignaturesOffset           = 68

	// SignatureLength is the length of one validator signature: r || s || v, as
	// MessageIdMultisigIsmMetadata.sol:16 and the Solidity test's
	// `abi.encodePacked(metadata, r, s, v)` (solidity/test/isms/MultisigIsm.t.sol:119-124).
	SignatureLength = 65
)

// secp256k1HalfOrder is the largest `s` OpenZeppelin's ECDSA accepts; a higher
// value reverts with "ECDSA: invalid signature 's' value"
// (openzeppelin-contracts v4.9.3 utils/cryptography/ECDSA.sol:23-33, enforced in
// `tryRecover` at :124-136).
var secp256k1HalfOrder = [32]byte{
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
	0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
}

// MetadataLength returns the size of MessageIdMultisigIsm metadata for a
// threshold of `threshold` validators: 68 + 65*threshold.
//
// MessageIdMultisigIsmMetadata.sol:15-16; the Rust relayer emits exactly these
// four tokens in this order
// (rust/main/agents/relayer/src/msg/metadata/multisig/message_id_multisig.rs:25-31).
// A negative threshold describes no signature list, so it is clamped to the
// 68-byte header instead of shrinking the result.
func MetadataLength(threshold int) int {
	if threshold < 0 {
		return MetadataSignaturesOffset
	}
	return MetadataSignaturesOffset + SignatureLength*threshold
}

// SignatureCount returns how many signatures a signature blob carries.
//
// This is the rule of
// solidity/contracts/isms/libs/MessageIdMultisigIsmMetadata.sol:77-83
// (`(metadata.length - 68) / 65`, reverting with "Invalid signatures length" when
// the remainder is non-zero) applied to the signature blob alone, i.e. to
// metadata without its 68-byte header.
func SignatureCount(signatures []byte) (int, error) {
	if remainder := len(signatures) % SignatureLength; remainder != 0 {
		return 0, fmt.Errorf(
			"hyperlane: signatures length %d is %d bytes past a signature boundary",
			len(signatures), remainder,
		)
	}
	return len(signatures) / SignatureLength, nil
}

// Metadata builds the metadata for one signed checkpoint.
//
// The bytes are exactly `hook[32] || root[32] || uint32 index[4] || signatures`,
// each signature `r || s || v` with `v` in {27,28} in the order of the ISM's
// validator array: `verify` walks the validator array and the signature list with
// two pointers and fails on an out-of-order or duplicate signature
// (solidity/contracts/isms/multisig/AbstractMultisigIsm.sol:106-121).
//
// The validator set and threshold are not inputs here: for the static ISM they
// live in the ISM's own MetaProxy code
// (solidity/contracts/isms/multisig/StaticMultisigIsm.sol:17-25), and the ISM
// reads exactly `threshold` signatures, so trailing signatures are ignored
// (`verify` never calls `signatureCount`).
//
// signatures must be a whole number of 65-byte, low-`s`, `v`-normalized
// signatures; anything else is rejected here rather than at `process`, where the
// only feedback would be a reverted destination transaction.
func Metadata(
	originMerkleTreeHook common.Address,
	root [32]byte,
	index uint32,
	signatures []byte,
) ([]byte, error) {
	count, err := SignatureCount(signatures)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New(
			"hyperlane: metadata needs at least one validator signature " +
				"(the ISM requires threshold > 0)",
		)
	}
	if err := validateSignatures(signatures, count); err != nil {
		return nil, err
	}
	hook := AddressToBytes32(originMerkleTreeHook)
	metadata := make([]byte, 0, MetadataLength(count))
	metadata = append(metadata, hook[:]...)
	metadata = append(metadata, root[:]...)
	metadata = binary.BigEndian.AppendUint32(metadata, index)
	return append(metadata, signatures...), nil
}

// Metadata builds the metadata of one checkpoint, taking the tree address and
// the root and index from the checkpoint itself.
func (c Checkpoint) Metadata(
	originMerkleTreeHook common.Address,
	signatures []byte,
) ([]byte, error) {
	return Metadata(originMerkleTreeHook, c.Root, c.Index, signatures)
}

// MetadataOriginMerkleTreeHook returns metadata field [0:32] as bytes32.
//
// MessageIdMultisigIsmMetadata.sol:23-27. This is the origin MerkleTreeHook
// address the validators signed for; it is left-padded, so it round-trips
// through Bytes32ToAddress whenever the upper 96 bits are zero.
func MetadataOriginMerkleTreeHook(metadata []byte) ([32]byte, error) {
	var hook [32]byte
	if err := requireLength(metadata, MetadataRootOffset, "origin merkle tree hook"); err != nil {
		return hook, err
	}
	copy(hook[:], metadata[MetadataOriginMerkleTreeHookOffset:MetadataRootOffset])
	return hook, nil
}

// MetadataRoot returns metadata field [32:64], the signed checkpoint root
// (MessageIdMultisigIsmMetadata.sol:38-40).
func MetadataRoot(metadata []byte) ([32]byte, error) {
	var root [32]byte
	if err := requireLength(metadata, MetadataIndexOffset, "merkle root"); err != nil {
		return root, err
	}
	copy(root[:], metadata[MetadataRootOffset:MetadataIndexOffset])
	return root, nil
}

// MetadataIndex returns metadata field [64:68], the signed checkpoint leaf index
// (MessageIdMultisigIsmMetadata.sol:47-51).
func MetadataIndex(metadata []byte) (uint32, error) {
	if err := requireLength(metadata, MetadataSignaturesOffset, "merkle index"); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(metadata[MetadataIndexOffset:MetadataSignaturesOffset]), nil
}

// MetadataSignatureAt returns the 65-byte signature at index, the view
// `AbstractMultisigIsm.verify` recovers a validator from
// (MessageIdMultisigIsmMetadata.sol:63-70).
func MetadataSignatureAt(metadata []byte, index int) ([]byte, error) {
	if index < 0 {
		return nil, fmt.Errorf("hyperlane: signature index %d is negative", index)
	}
	start := MetadataSignaturesOffset + index*SignatureLength
	if err := requireLength(metadata, start+SignatureLength, "signature"); err != nil {
		return nil, err
	}
	return metadata[start : start+SignatureLength], nil
}

// requireLength reports a metadata payload that is too short for one field,
// mirroring the calldata slice bounds `MessageIdMultisigIsmMetadata` relies on.
func requireLength(metadata []byte, length int, field string) error {
	if len(metadata) < length {
		return fmt.Errorf(
			"hyperlane: metadata length %d cannot hold the %s field (%d bytes)",
			len(metadata), field, length,
		)
	}
	return nil
}

// validateSignatures rejects anything the on-chain recovery would reject, so a
// malformed relayer action fails before it is broadcast.
func validateSignatures(signatures []byte, count int) error {
	for index := 0; index < count; index++ {
		signature := signatures[index*SignatureLength : (index+1)*SignatureLength]
		var r, s [32]byte
		copy(r[:], signature[:32])
		copy(s[:], signature[32:64])
		if r == ([32]byte{}) || s == ([32]byte{}) {
			return fmt.Errorf("hyperlane: signature %d has a zero r or s value", index)
		}
		if bytes.Compare(s[:], secp256k1HalfOrder[:]) > 0 {
			return fmt.Errorf(
				"hyperlane: signature %d has a high s value (not low-s canonical)", index,
			)
		}
		if v := signature[64]; v != 27 && v != 28 {
			return fmt.Errorf("hyperlane: signature %d has v %d, want 27 or 28", index, v)
		}
	}
	return nil
}

// normalizeSignature converts a raw secp256k1 signature into the r || s || v form
// the ISM recovers: it shifts `v` from the {0,1} convention go-ethereum's
// `crypto.Sign` uses to the {27,28} convention OZ `ECDSA.recover` requires
// (openzeppelin-contracts v4.9.3 ECDSA.sol:88-92 rejects any other value), and
// refuses a signature that would not recover on chain.
func normalizeSignature(signature []byte) ([]byte, error) {
	if len(signature) != SignatureLength {
		return nil, fmt.Errorf(
			"hyperlane: signature length %d, want %d", len(signature), SignatureLength,
		)
	}
	normalized := append([]byte(nil), signature...)
	if normalized[64] < 27 {
		normalized[64] += 27
	}
	if err := validateSignatures(normalized, 1); err != nil {
		return nil, err
	}
	return normalized, nil
}
