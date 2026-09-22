package evm

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// personalPrefix is the EIP-191 version 0x45 prefix eth_account uses in
// encode_defunct for a 32 byte primitive.
const personalPrefix = "\x19Ethereum Signed Message:\n32"

// recoveryOffset converts a raw recovery id into the 27/28 encoding that
// eth_account returns from sign_message and Account.signHash.
const recoveryOffset = 27

// Signer signs XIR transactions and digests with one frozen key.
type Signer struct {
	key     *ecdsa.PrivateKey
	address common.Address
	chainID *big.Int
}

// NewSigner parses a private key and binds it to one chain id. The key is never
// echoed in an error, so a failed load cannot leak it into a log.
func NewSigner(privateKeyHex string, chainID *big.Int) (*Signer, error) {
	if strings.TrimSpace(privateKeyHex) == "" {
		return nil, errors.New("xir evm: empty private key")
	}
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, errors.New("xir evm: a signer needs a positive chain id")
	}
	raw, err := hex.DecodeString(
		strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(privateKeyHex), "0x"), "0X"),
	)
	if err != nil {
		return nil, errors.New("xir evm: the private key is not hexadecimal")
	}
	key, err := crypto.ToECDSA(raw)
	if err != nil {
		return nil, errors.New("xir evm: the private key is not a valid secp256k1 scalar")
	}
	return &Signer{key: key, address: crypto.PubkeyToAddress(key.PublicKey), chainID: new(big.Int).Set(chainID)}, nil
}

// Address returns the signer's public address.
func (s *Signer) Address() common.Address { return s.address }

// ChainID returns the chain the signer is bound to.
func (s *Signer) ChainID() *big.Int { return new(big.Int).Set(s.chainID) }

// SignDynamicFee signs an EIP-1559 transaction with the signer's chain id. The
// transaction's chain id must be unset or equal to the signer's.
func (s *Signer) SignDynamicFee(transaction *types.DynamicFeeTx) (*types.Transaction, error) {
	if transaction == nil {
		return nil, errors.New("xir evm: no transaction to sign")
	}
	if transaction.ChainID != nil && transaction.ChainID.Cmp(s.chainID) != 0 {
		return nil, fmt.Errorf(
			"xir evm: transaction chain id %s differs from the signer chain id %s",
			transaction.ChainID, s.chainID,
		)
	}
	frozen := *transaction
	frozen.ChainID = new(big.Int).Set(s.chainID)
	signed, err := types.SignTx(types.NewTx(&frozen), types.LatestSignerForChainID(s.chainID), s.key)
	if err != nil {
		return nil, fmt.Errorf("xir evm: cannot sign the transaction: %w", err)
	}
	return signed, nil
}

// SignPersonalDigest signs the EIP-191 personal digest of a 32 byte value, which
// is byte-identical to
// eth_account.messages.encode_defunct(primitive=digest) followed by
// Account.sign_message. Every XIR signature in the Python runtime (XIR roots,
// LayerZero DVN instructions) uses this scheme.
func (s *Signer) SignPersonalDigest(digest [32]byte) ([]byte, error) {
	prefixed := personalDigestHash(digest)
	return s.signHash(prefixed)
}

// SignRawDigest signs the digest itself, with no EIP-191 prefix. Hyperlane
// checkpoint signatures use this form.
func (s *Signer) SignRawDigest(digest [32]byte) ([]byte, error) {
	return s.signHash(digest)
}

func (s *Signer) signHash(digest [32]byte) ([]byte, error) {
	signature, err := crypto.Sign(digest[:], s.key)
	if err != nil {
		return nil, fmt.Errorf("xir evm: cannot sign the digest: %w", err)
	}
	signature[64] += recoveryOffset
	return signature, nil
}

// RecoverPersonalDigest recovers the address that signed the EIP-191 personal
// digest of a 32 byte value.
func RecoverPersonalDigest(digest [32]byte, signature []byte) (common.Address, error) {
	prefixed := personalDigestHash(digest)
	return recoverHash(prefixed, signature)
}

func personalDigestHash(digest [32]byte) [32]byte {
	payload := make([]byte, 0, len(personalPrefix)+len(digest))
	payload = append(payload, personalPrefix...)
	payload = append(payload, digest[:]...)
	var prefixed [32]byte
	copy(prefixed[:], crypto.Keccak256(payload))
	return prefixed
}

func recoverHash(digest [32]byte, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf(
			"xir evm: signature is %d bytes, want %d", len(signature), crypto.SignatureLength,
		)
	}
	normalized := make([]byte, crypto.SignatureLength)
	copy(normalized, signature)
	switch normalized[64] {
	case 0, 1:
		normalized[64] += recoveryOffset
	case 27, 28:
	default:
		return common.Address{}, fmt.Errorf("xir evm: signature recovery id is %d", signature[64])
	}
	normalized[64] -= recoveryOffset
	publicKey, err := crypto.SigToPub(digest[:], normalized)
	if err != nil {
		return common.Address{}, fmt.Errorf("xir evm: cannot recover the signer: %w", err)
	}
	return crypto.PubkeyToAddress(*publicKey), nil
}
