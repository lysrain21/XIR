package layerzero

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// DigestSigner signs a 32-byte digest with the EIP-191 personal signing rule
// that eth_account.encode_defunct implements. internal/evm.Signer satisfies it
// through SignPersonalDigest, which frames the digest as
// "\x19Ethereum Signed Message:\n32" || digest.
type DigestSigner interface {
	SignPersonalDigest(digest [32]byte) ([]byte, error)
}

// DVNInstruction is one signed official DVN verification instruction.
type DVNInstruction struct {
	// VID is the destination endpoint id the instruction verifies for.
	VID uint32
	// Target is the destination ReceiveUln302 the instruction calls.
	Target common.Address
	// CallData is verify(header, payloadHash, confirmations) on the target.
	CallData []byte
	// Expiration is the unix second after which the DVN refuses the instruction.
	Expiration *big.Int
	// Signature is the personal signature over Hash.
	Signature []byte
	// Hash is keccak(vid || target || expiration || callData).
	Hash [32]byte
}

// DVNRequest describes one verification instruction to build and sign.
type DVNRequest struct {
	// VID is the destination endpoint id, which must be non-zero.
	VID uint32
	// ReceiveULN is the destination ReceiveUln302, which must be non-zero.
	ReceiveULN common.Address
	// Packet is the decoded source packet to verify.
	Packet Packet
	// Confirmations is the source confirmation count the instruction attests.
	Confirmations uint64
	// Expiration is the unix second the instruction stays valid until.
	Expiration *big.Int
	// Signer signs the packed instruction hash.
	Signer DigestSigner
}

// BuildDVNInstruction builds and signs the official DVN.execute verification
// instruction: the target call is verify(bytes,bytes32,uint64), the signed hash
// is keccak(vid || target || expiration || callData) with vid as a 4-byte and
// expiration as a 32-byte big-endian integer, and the signature is the
// EIP-191 personal signature over that hash.
func BuildDVNInstruction(request DVNRequest) (DVNInstruction, error) {
	if request.VID == 0 {
		return DVNInstruction{}, errors.New("layerzero: DVN vid is out of range")
	}
	if !fitsUint256(request.Expiration) || request.Expiration.Sign() <= 0 {
		return DVNInstruction{}, fmt.Errorf("layerzero: DVN expiration %v is invalid", request.Expiration)
	}
	if request.ReceiveULN == (common.Address{}) {
		return DVNInstruction{}, errors.New("layerzero: receive ULN address is invalid")
	}
	if len(request.Packet.Header) != PacketHeaderBytes {
		return DVNInstruction{}, fmt.Errorf("layerzero: packet header is %d bytes, want %d", len(request.Packet.Header), PacketHeaderBytes)
	}
	if request.Signer == nil {
		return DVNInstruction{}, errors.New("layerzero: DVN instruction requires a signer")
	}
	callData, err := receiveULNContract.PackCall("verify", request.Packet.Header, request.Packet.PayloadHash, request.Confirmations)
	if err != nil {
		return DVNInstruction{}, err
	}
	packed := make([]byte, 0, 4+common.AddressLength+32+len(callData))
	packed = binary.BigEndian.AppendUint32(packed, request.VID)
	packed = append(packed, request.ReceiveULN[:]...)
	var expiration [32]byte
	request.Expiration.FillBytes(expiration[:])
	packed = append(packed, expiration[:]...)
	packed = append(packed, callData...)
	hash := xir.Keccak256(packed)
	signature, err := request.Signer.SignPersonalDigest(hash)
	if err != nil {
		return DVNInstruction{}, fmt.Errorf("layerzero: sign DVN instruction: %w", err)
	}
	return DVNInstruction{
		VID:        request.VID,
		Target:     request.ReceiveULN,
		CallData:   callData,
		Expiration: new(big.Int).Set(request.Expiration),
		Signature:  signature,
		Hash:       hash,
	}, nil
}

// EncodeDVNExecute encodes DVN.execute((uint32,address,bytes,uint256,bytes)[])
// with exactly one instruction.
func EncodeDVNExecute(instruction DVNInstruction) ([]byte, error) {
	if !fitsUint256(instruction.Expiration) {
		return nil, fmt.Errorf("layerzero: DVN expiration %v is invalid", instruction.Expiration)
	}
	params := []dvnExecuteParam{{
		VID:        instruction.VID,
		Target:     instruction.Target,
		CallData:   instruction.CallData,
		Expiration: instruction.Expiration,
		Signatures: instruction.Signature,
	}}
	return dvnContract.PackCall("execute", params)
}

// EncodeCommitVerification encodes
// ReceiveUln302.commitVerification(bytes,bytes32) for the packet header and its
// payload hash.
func EncodeCommitVerification(packet Packet) ([]byte, error) {
	return receiveULNContract.PackCall("commitVerification", packet.Header, packet.PayloadHash)
}

// EncodeExecutorSubmission encodes Executor.execute302 with the packet receiver,
// the packet origin, the GUID, the message, empty extra data, and the executor
// gas limit. The receiver must be an EVM address.
func EncodeExecutorSubmission(packet Packet, gasLimit uint64) ([]byte, error) {
	receiver, err := packet.ReceiverAddress()
	if err != nil {
		return nil, err
	}
	params := executionParams{
		Receiver: receiver,
		Origin: originParam{
			SourceEID: packet.SourceEID,
			Sender:    packet.Sender,
			Nonce:     packet.Nonce,
		},
		GUID:      packet.GUID,
		Message:   packet.Message,
		ExtraData: []byte{},
		GasLimit:  new(big.Int).SetUint64(gasLimit),
	}
	return executorContract.PackCall("execute302", params)
}

// fitsUint256 reports whether the value can be encoded as an ABI uint256.
func fitsUint256(value *big.Int) bool {
	return value != nil && value.Sign() >= 0 && value.BitLen() <= maxUint256Bits
}
