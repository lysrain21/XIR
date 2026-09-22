package hyperlane

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// PersonalSigner is the signing surface a Hyperlane validator needs: an address
// and EIP-191 personal-message signing of a 32-byte digest.
//
// internal/evm's `*Signer` implements this (`SignPersonalDigest` is documented as
// identical to `eth_account.messages.encode_defunct`), which is exactly the
// transform `CheckpointLib.digest` bakes into the ISM digest: the validators in
// the lab are ordinary EOA keys signing the checkpoint hash with `eth_sign`.
type PersonalSigner interface {
	Address() common.Address
	SignPersonalDigest(digest [32]byte) ([]byte, error)
}

// Validator signs origin checkpoints for one key.
type Validator struct {
	signer PersonalSigner
}

// NewValidator wraps a signer. The key material stays with the signer; this
// package never sees or records it.
func NewValidator(signer PersonalSigner) (*Validator, error) {
	if signer == nil {
		return nil, errors.New("hyperlane: validator needs a signer")
	}
	return &Validator{signer: signer}, nil
}

// Address returns the validator address the ISM must list in its validator set.
func (v *Validator) Address() common.Address {
	return v.signer.Address()
}

// SignCheckpoint signs the checkpoint of one message id and returns the 65-byte
// `r || s || v` signature the ISM metadata carries.
//
// The signed hash is `Checkpoint.Hash(originMerkleTreeHook, messageID)`, so the
// signature recovers from `Checkpoint.Digest` on chain
// (AbstractMessageIdMultisigIsm.sol:29-41, AbstractMultisigIsm.sol:110).
func (v *Validator) SignCheckpoint(
	originMerkleTreeHook common.Address,
	checkpoint Checkpoint,
	messageID [32]byte,
) ([]byte, error) {
	signature, err := v.signer.SignPersonalDigest(
		checkpoint.Hash(originMerkleTreeHook, messageID),
	)
	if err != nil {
		return nil, fmt.Errorf("hyperlane: sign checkpoint: %w", err)
	}
	normalized, err := normalizeSignature(signature)
	if err != nil {
		return nil, fmt.Errorf("hyperlane: sign checkpoint: %w", err)
	}
	return normalized, nil
}

// SignMessage signs the checkpoint of one dispatched message and returns the
// 65-byte `r || s || v` signature the ISM metadata carries.
//
// The checkpoint's Domain must be the message's origin domain: the ISM takes the
// domain half of the digest from the message itself
// (AbstractMessageIdMultisigIsm.sol:35, `_message.origin()`) while the relayer
// takes the tree half from the metadata, so a checkpoint signed for a different
// origin could never verify. The leaf index is not checked against the origin
// tree; the caller reads that from the MerkleTreeHook (`latestCheckpoint`) or
// from its `InsertedIntoTree` log.
func (v *Validator) SignMessage(
	originMerkleTreeHook common.Address,
	checkpoint Checkpoint,
	message []byte,
) ([]byte, error) {
	decoded := Message(message)
	if err := decoded.Validate(); err != nil {
		return nil, err
	}
	if origin := decoded.Origin(); origin != checkpoint.Domain {
		return nil, fmt.Errorf(
			"hyperlane: checkpoint domain %d does not match message origin %d",
			checkpoint.Domain, origin,
		)
	}
	return v.SignCheckpoint(originMerkleTreeHook, checkpoint, MessageID(message))
}
