// Package hyperlane implements the Hyperlane v3 wire and verification layer the
// XIR runtime needs to deliver a hop that was dispatched through
// contracts/src/HyperlaneAdapter.sol.
//
// Every layout, digest and constant is byte exact with the pinned upstream
// commit hyperlane-xyz/hyperlane-monorepo@5857ead81a8783d168d48d370be72de88d5fb230
// (cited below as `solidity/...:<line>`), which is the contract stack the lab
// deploys on the origin and destination chains.
//
// The relayer path this package reproduces is short:
//
//  1. the origin Mailbox packs a message (message.go) and a MerkleTreeHook
//     inserts its id as a leaf of the origin tree (OriginMerkleTreeHook);
//  2. validators sign the checkpoint of that leaf (checkpoint.go, validator.go);
//  3. the relayer pairs the signed checkpoint with the validator signatures into
//     ISM metadata (metadata.go) and submits one call,
//     Mailbox.process(metadata, message), on the destination chain (relayer.go);
//  4. Mailbox computes the digest again, recovers the validators from the
//     metadata signatures and hands the body to the recipient adapter.
//
// This package performs no I/O: it derives payloads, digests and calldata, and
// decodes dispatch receipts. Broadcasting the planned call is the caller's job.
//
// Every event topic in this package is keccak256 of its canonical Solidity
// signature (DispatchTopic, DispatchIDTopic, InsertedIntoTreeTopic,
// ProcessTopic, ProcessIDTopic), never a hand-copied hex literal, and the tests
// pin each derived value against a keccak computed outside Go.
package hyperlane

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// Version is the Hyperlane message version this runtime speaks.
//
// solidity/contracts/upgrade/Versioned.sol:9 — `uint8 public constant VERSION = 3`.
// Mailbox inherits it and uses it both when building a message
// (solidity/contracts/Mailbox.sol:441) and when validating one
// (solidity/contracts/Mailbox.sol:209).
const Version uint8 = 3

// personalDigestPrefix is the EIP-191 personal-sign prefix for a 32-byte payload,
// i.e. the bytes OpenZeppelin's `ECDSA.toEthSignedMessageHash` prepends
// (openzeppelin-contracts v4.9.3 utils/cryptography/ECDSA.sol:165-174, which
// keccak256s a 60-byte preimage built from this 28-byte prefix and the hash).
var personalDigestPrefix = []byte("\x19Ethereum Signed Message:\n32")

// personalDigest applies the EIP-191 personal-sign prefixing to one 32-byte hash.
// It is the exact transformation `eth_account.messages.encode_defunct` performs,
// which is why a validator signed digest and an ISM recovered digest agree.
func personalDigest(hash [32]byte) [32]byte {
	return xir.Keccak256(personalDigestPrefix, hash[:])
}

// AddressToBytes32 left-pads an address with 12 zero bytes.
//
// solidity/contracts/libs/TypeCasts.sol:6-8 — `addressToBytes32` shifts the
// address left by 96 bits.
func AddressToBytes32(address common.Address) [32]byte {
	var value [32]byte
	copy(value[12:], address[:])
	return value
}

// Bytes32ToAddress returns the address encoded in the low 20 bytes of value and
// rejects a value whose upper 96 bits are non-zero.
//
// solidity/contracts/libs/TypeCasts.sol:11-17 — `bytes32ToAddress` reverts with
// "TypeCasts: bytes32ToAddress overflow" instead of truncating.
func Bytes32ToAddress(value [32]byte) (common.Address, error) {
	for _, digit := range value[:12] {
		if digit != 0 {
			return common.Address{}, errBytes32Overflow
		}
	}
	return common.BytesToAddress(value[12:]), nil
}

// Event topics, derived from the canonical signatures the contracts declare.
// Each value is keccak256 of the signature text, so it can never drift from a
// re-derived value; the tests pin every one of them against an independent
// keccak computed outside Go.
var (
	// DispatchTopic is `Dispatch(address,uint32,bytes32,bytes)`
	// (solidity/contracts/interfaces/IMailbox.sol:16-21). The log carries the
	// raw message in its data and sender/destination/recipient in its topics.
	DispatchTopic = topic("Dispatch(address,uint32,bytes32,bytes)")

	// DispatchIDTopic is `DispatchId(bytes32)` (IMailbox.sol:27).
	DispatchIDTopic = topic("DispatchId(bytes32)")

	// InsertedIntoTreeTopic is `InsertedIntoTree(bytes32,uint32)`, emitted by the
	// origin MerkleTreeHook with the pre-insertion leaf index
	// (solidity/contracts/hooks/MerkleTreeHook.sol:32, emitted at :76). The log
	// comes from the hook address, not from the Mailbox, so it must be filtered
	// by emitter.
	InsertedIntoTreeTopic = topic("InsertedIntoTree(bytes32,uint32)")

	// ProcessTopic is `Process(uint32,bytes32,address)` (IMailbox.sol:41-45),
	// emitted by the destination Mailbox once the message is delivered.
	ProcessTopic = topic("Process(uint32,bytes32,address)")

	// ProcessIDTopic is `ProcessId(bytes32)` (IMailbox.sol:33).
	ProcessIDTopic = topic("ProcessId(bytes32)")
)

func topic(signature string) common.Hash {
	return common.Hash(xir.Keccak256([]byte(signature)))
}

// errBytes32Overflow mirrors the revert of TypeCasts.bytes32ToAddress: a bytes32
// that does not fit an address is not silently truncated.
var errBytes32Overflow = errors.New("hyperlane: bytes32 value does not fit an address")
