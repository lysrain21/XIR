// Package layerzero implements the LayerZero V2 wire format and the DVN,
// ReceiveUln302, and Executor submissions the XIR runtime performs.
//
// It is a port of src/xir_lab/native/layerzero.py and of the submission
// semantics of src/xir_lab/native/layerzero_worker.py. Durability and
// broadcasting stay outside this package: Plan returns the three ordered
// actions the worker submits, ExtractPacket performs the PacketSent decode the
// worker's collection loop performs, and Action.ExpectedTopic records the
// official event each stage receipt must carry.
package layerzero

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// PacketV1Codec layout constants (official LayerZero V2 offsets).
const (
	// PacketHeaderBytes is the length of the packed packet header.
	PacketHeaderBytes = 81
	// PacketGUIDOffset is the offset of the 32-byte GUID in an encoded packet.
	PacketGUIDOffset = 81
	// PacketMessageOffset is the offset of the message in an encoded packet.
	PacketMessageOffset = 113
	// PacketVersion is the only packet version this codec accepts.
	PacketVersion = 1
	// maxUint256Bits bounds every uint256 the package encodes.
	maxUint256Bits = 256
)

// Stage names of the LayerZero worker sequence, equal to
// layerzero_worker.STAGES. The runner prefixes them with the hop it is
// delivering ("hop_1_layerzero_dvn_execute").
const (
	// StageDVNExecute calls DVN.execute, which verifies the packet payload.
	StageDVNExecute = "dvn_execute"
	// StageCommitVerification calls ReceiveUln302.commitVerification.
	StageCommitVerification = "commit_verification"
	// StageExecutorExecute calls Executor.execute302, which delivers the message.
	StageExecutorExecute = "executor_execute"
)

// Stages is the submission order of one LayerZero delivery.
var Stages = [3]string{StageDVNExecute, StageCommitVerification, StageExecutorExecute}

// Canonical signatures of the official V2 events the worker watches.
const (
	PacketSentSignature      = "PacketSent(bytes,bytes,address)"
	PayloadVerifiedSignature = "PayloadVerified(address,bytes,uint256,bytes32)"
	PacketVerifiedSignature  = "PacketVerified((uint32,bytes32,uint64),address,bytes32)"
	PacketDeliveredSignature = "PacketDelivered((uint32,bytes32,uint64),address)"
)

// Topic0 of the official V2 events: keccak of the canonical signature.
// TestEventTopicsMatchOfficialABI re-derives each value from PacketSentSignature
// and friends and from the ABI fragments in abi.go.
const (
	PacketSentTopic      = "0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f"
	PayloadVerifiedTopic = "0x2cb0eed7538baeae4c6fde038c0fd0384d27de0dd55a228c65847bda6aa1ab56"
	PacketVerifiedTopic  = "0x0d87345f3d1c929caba93e1c3821b54ff3512e12b66aa3cfe54b6bcbc17e59b4"
	PacketDeliveredTopic = "0x3cd5e48f9730b129dc7550f0fcea9c767b7be37837cd10e55eb35f734f4bca04"
)

// Packet is one decoded PacketV1Codec payload.
//
// Encoded, Header, and Message alias the buffer handed to DecodePacket; the
// decoder copies nothing.
type Packet struct {
	Encoded        []byte
	Header         []byte
	Version        uint8
	Nonce          uint64
	SourceEID      uint32
	Sender         [32]byte
	DestinationEID uint32
	Receiver       [32]byte
	GUID           [32]byte
	Message        []byte
	PayloadHash    [32]byte
}

// DecodePacket decodes the official PacketV1Codec packed wire format:
// version || nonce || srcEid || sender || dstEid || receiver || guid || message,
// with payload_hash = keccak(guid || message).
//
// A packet shorter than the message offset, a packet whose version is not V1,
// and a packet whose receiver is not a left-padded EVM address are rejected.
func DecodePacket(encoded []byte) (Packet, error) {
	if len(encoded) < PacketMessageOffset {
		return Packet{}, fmt.Errorf("layerzero: packet is %d bytes, shorter than the PacketV1Codec header of %d", len(encoded), PacketMessageOffset)
	}
	if encoded[0] != PacketVersion {
		return Packet{}, fmt.Errorf("layerzero: packet version %d is not V1", encoded[0])
	}
	packet := Packet{
		Encoded:        encoded,
		Header:         encoded[:PacketHeaderBytes],
		Version:        encoded[0],
		Nonce:          binary.BigEndian.Uint64(encoded[1:9]),
		SourceEID:      binary.BigEndian.Uint32(encoded[9:13]),
		Sender:         [32]byte(encoded[13:45]),
		DestinationEID: binary.BigEndian.Uint32(encoded[45:49]),
		Receiver:       [32]byte(encoded[49:81]),
		GUID:           [32]byte(encoded[PacketGUIDOffset:PacketMessageOffset]),
		Message:        encoded[PacketMessageOffset:],
		PayloadHash:    xir.Keccak256(encoded[PacketGUIDOffset:]),
	}
	if _, err := packet.ReceiverAddress(); err != nil {
		return Packet{}, err
	}
	return packet, nil
}

// ReceiverAddress returns the 20-byte EVM receiver carried in the packet.
// A receiver whose leading twelve bytes are not zero is not an EVM address.
func (p Packet) ReceiverAddress() (common.Address, error) {
	var reserved [12]byte
	if !bytes.Equal(p.Receiver[:len(reserved)], reserved[:]) {
		return common.Address{}, errors.New("layerzero: packet receiver is not an EVM bytes32 address")
	}
	return common.BytesToAddress(p.Receiver[len(reserved):]), nil
}

// ReceiveOptions builds the official Type-3 Executor LZ_RECEIVE options for one
// gas limit with zero native value: type 3, worker id 1, option type 17, the
// option marker 1, then the limit as a 16-byte big-endian uint128.
//
// The official encoding carries the limit as a uint128, so a uint64 caller can
// never exceed that ceiling; the limit must still be positive.
func ReceiveOptions(gasLimit uint64) ([]byte, error) {
	if gasLimit == 0 {
		return nil, errors.New("layerzero: executor gas limit is out of uint128 range")
	}
	options := make([]byte, 0, 6+16)
	options = append(options, 0x00, 0x03, 0x01, 0x00, 0x11, 0x01)
	var encoded [16]byte
	binary.BigEndian.PutUint64(encoded[8:], gasLimit)
	return append(options, encoded[:]...), nil
}

// topicHash parses one topic constant into the hash form log topics carry.
func topicHash(topic string) common.Hash { return common.HexToHash(topic) }
