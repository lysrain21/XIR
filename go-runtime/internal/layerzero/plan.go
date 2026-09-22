package layerzero

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// DefaultTransactionGas is the submission gas of every LayerZero stage
// transaction, as the Python worker pins it.
const DefaultTransactionGas uint64 = 5_000_000

// PlanConfig is the destination-side LayerZero configuration of one chain, as
// the worker config document carries it.
type PlanConfig struct {
	// DVN is the destination DVN that executes the verification instruction.
	DVN common.Address
	// ReceiveULN is the destination ReceiveUln302 that commits the payload hash.
	ReceiveULN common.Address
	// Executor is the destination Executor that delivers the message.
	Executor common.Address
	// Confirmations is the source confirmation count the DVN instruction attests.
	Confirmations uint64
	// Expiration is the unix second the DVN instruction stays valid until.
	Expiration *big.Int
	// GasLimit is the gas limit of the executor delivery call.
	GasLimit uint64
	// TransactionGas is the submission gas of each stage transaction; zero uses
	// DefaultTransactionGas.
	TransactionGas uint64
}

// Action is one destination submission of the LayerZero delivery sequence.
type Action struct {
	// Stage is one of StageDVNExecute, StageCommitVerification, or
	// StageExecutorExecute.
	Stage string
	// Target is the contract the submission calls.
	Target common.Address
	// CallData is the full calldata including the selector.
	CallData []byte
	// ExpectedTopic is the official event topic0 the stage receipt must carry.
	ExpectedTopic common.Hash
	// Gas is the transaction gas limit of the submission.
	Gas uint64
}

// Plan returns the ordered destination submissions of one LayerZero delivery:
// DVN.execute, ReceiveUln302.commitVerification, then Executor.execute302.
//
// The DVN verification instruction uses the packet's destination EID as its
// VID, exactly as the Python worker builds it from the destination chain it
// selected for the packet.
func Plan(packet Packet, config PlanConfig, signer DigestSigner) ([]Action, error) {
	if config.GasLimit == 0 {
		return nil, errors.New("layerzero: executor gas limit is out of uint128 range")
	}
	instruction, err := BuildDVNInstruction(DVNRequest{
		VID:           packet.DestinationEID,
		ReceiveULN:    config.ReceiveULN,
		Packet:        packet,
		Confirmations: config.Confirmations,
		Expiration:    config.Expiration,
		Signer:        signer,
	})
	if err != nil {
		return nil, err
	}
	dvnExecute, err := EncodeDVNExecute(instruction)
	if err != nil {
		return nil, err
	}
	commitVerification, err := EncodeCommitVerification(packet)
	if err != nil {
		return nil, err
	}
	executorExecute, err := EncodeExecutorSubmission(packet, config.GasLimit)
	if err != nil {
		return nil, err
	}
	transactionGas := config.TransactionGas
	if transactionGas == 0 {
		transactionGas = DefaultTransactionGas
	}
	return []Action{
		{
			Stage:         StageDVNExecute,
			Target:        config.DVN,
			CallData:      dvnExecute,
			ExpectedTopic: topicHash(PayloadVerifiedTopic),
			Gas:           transactionGas,
		},
		{
			Stage:         StageCommitVerification,
			Target:        config.ReceiveULN,
			CallData:      commitVerification,
			ExpectedTopic: topicHash(PacketVerifiedTopic),
			Gas:           transactionGas,
		},
		{
			Stage:         StageExecutorExecute,
			Target:        config.Executor,
			CallData:      executorExecute,
			ExpectedTopic: topicHash(PacketDeliveredTopic),
			Gas:           transactionGas,
		},
	}, nil
}

// ExtractPacket returns the packet a receipt's PacketSent log carries and
// checks that the log was emitted for the expected source EID.
func ExtractPacket(receipt *types.Receipt, sourceEID uint32) (Packet, error) {
	if receipt == nil {
		return Packet{}, errors.New("layerzero: receipt is missing")
	}
	sentTopic := topicHash(PacketSentTopic)
	var packet Packet
	found := false
	for index := range receipt.Logs {
		log := receipt.Logs[index]
		if log == nil || len(log.Topics) == 0 || log.Topics[0] != sentTopic {
			continue
		}
		values, err := endpointV2Contract.UnpackLog("PacketSent", log)
		if err != nil {
			return Packet{}, err
		}
		encoded, ok := values["encodedPayload"].([]byte)
		if !ok {
			return Packet{}, fmt.Errorf("layerzero: PacketSent log carries %T, want bytes", values["encodedPayload"])
		}
		decoded, err := DecodePacket(encoded)
		if err != nil {
			return Packet{}, err
		}
		if decoded.SourceEID != sourceEID {
			return Packet{}, fmt.Errorf("layerzero: PacketSent source EID %d does not match %d", decoded.SourceEID, sourceEID)
		}
		if found {
			if bytes.Equal(packet.Encoded, decoded.Encoded) {
				continue
			}
			return Packet{}, errors.New("layerzero: receipt carries more than one PacketSent packet")
		}
		packet, found = decoded, true
	}
	if !found {
		return Packet{}, fmt.Errorf("layerzero: receipt carries no PacketSent log for EID %d", sourceEID)
	}
	return packet, nil
}
