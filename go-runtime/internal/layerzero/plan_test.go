package layerzero

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestPlanMatchesWorkerSubmissionSequence checks the three ordered submissions
// against the packet vectors: the stage names, the targets, the calldata (byte
// identical to the Python worker's), and the official event each stage must
// produce.
func TestPlanMatchesWorkerSubmissionSequence(t *testing.T) {
	document := loadVectors(t)
	signer := newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"])
	for _, vector := range document.LayerZeroPackets {
		packet, err := DecodePacket(mustHex(t, vector.EncodedPacket))
		if err != nil {
			t.Fatalf("DecodePacket: %v", err)
		}
		destination := PlanConfig{
			ReceiveULN:    common.HexToAddress(vector.DVNInstruction.Target),
			DVN:           common.HexToAddress("0x" + strings.Repeat("dd", 20)),
			Executor:      common.HexToAddress("0x" + strings.Repeat("ee", 20)),
			Confirmations: vectorConfirmations,
			Expiration:    big.NewInt(vectorExpiration),
			GasLimit:      vectorGasLimit,
		}
		actions, err := Plan(packet, destination, signer)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		wantStages := []string{"dvn_execute", "commit_verification", "executor_execute"}
		if len(actions) != len(wantStages) {
			t.Fatalf("Plan returned %d actions, want %d", len(actions), len(wantStages))
		}
		wantTargets := []common.Address{destination.DVN, destination.ReceiveULN, destination.Executor}
		wantCalldata := []string{
			vector.DVNExecuteCalldata,
			vector.CommitVerificationCalldata,
			vector.ExecutorCalldata,
		}
		wantTopics := []common.Hash{
			topicHash(PayloadVerifiedTopic),
			topicHash(PacketVerifiedTopic),
			topicHash(PacketDeliveredTopic),
		}
		wantSelectors := []string{
			"execute((uint32,address,bytes,uint256,bytes)[])",
			"commitVerification(bytes,bytes32)",
			"execute302((address,(uint32,bytes32,uint64),bytes32,bytes,bytes,uint256))",
		}
		for index, action := range actions {
			if action.Stage != wantStages[index] || action.Stage != Stages[index] {
				t.Errorf("action %d stage = %q, want %q", index, action.Stage, wantStages[index])
			}
			if action.Target != wantTargets[index] {
				t.Errorf("%s target = %s, want %s", action.Stage, action.Target, wantTargets[index])
			}
			checkHex(t, action.Stage+" calldata", action.CallData, wantCalldata[index])
			if action.ExpectedTopic != wantTopics[index] {
				t.Errorf("%s expected topic = %s, want %s", action.Stage, action.ExpectedTopic, wantTopics[index])
			}
			checkHex(t, action.Stage+" selector", action.CallData[:4], hexOf(selector(wantSelectors[index])))
			if action.Gas != DefaultTransactionGas {
				t.Errorf("%s transaction gas = %d, want %d", action.Stage, action.Gas, DefaultTransactionGas)
			}
		}
	}
}

// TestPlanHonoursTransactionGasOverride checks the caller's submission gas on
// every stage of the sequence.
func TestPlanHonoursTransactionGasOverride(t *testing.T) {
	document := loadVectors(t)
	vector := document.LayerZeroPackets[0]
	packet, err := DecodePacket(mustHex(t, vector.EncodedPacket))
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	const override = 250_000
	actions, err := Plan(packet, PlanConfig{
		ReceiveULN:     common.HexToAddress(vector.DVNInstruction.Target),
		DVN:            common.HexToAddress("0x" + strings.Repeat("dd", 20)),
		Executor:       common.HexToAddress("0x" + strings.Repeat("ee", 20)),
		Confirmations:  vectorConfirmations,
		Expiration:     big.NewInt(vectorExpiration),
		GasLimit:       vectorGasLimit,
		TransactionGas: override,
	}, newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"]))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, action := range actions {
		if action.Gas != override {
			t.Errorf("%s transaction gas = %d, want %d", action.Stage, action.Gas, override)
		}
	}
}

func TestPlanRejectsInconsistentDestinations(t *testing.T) {
	document := loadVectors(t)
	vector := document.LayerZeroPackets[0]
	packet, err := DecodePacket(mustHex(t, vector.EncodedPacket))
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	signer := newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"])
	base := func() PlanConfig {
		return PlanConfig{
			ReceiveULN:    common.HexToAddress(vector.DVNInstruction.Target),
			DVN:           common.HexToAddress("0x" + strings.Repeat("dd", 20)),
			Executor:      common.HexToAddress("0x" + strings.Repeat("ee", 20)),
			Confirmations: vectorConfirmations,
			Expiration:    big.NewInt(vectorExpiration),
			GasLimit:      vectorGasLimit,
		}
	}
	if _, err := Plan(packet, base(), signer); err != nil {
		t.Fatalf("Plan rejected the consistent destination: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*PlanConfig)
		signer DigestSigner
	}{
		{"zero gas limit", func(config *PlanConfig) { config.GasLimit = 0 }, signer},
		{"missing signer", func(*PlanConfig) {}, nil},
		{"expired instruction", func(config *PlanConfig) { config.Expiration = big.NewInt(0) }, signer},
		{"zero receive ULN", func(config *PlanConfig) { config.ReceiveULN = common.Address{} }, signer},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := base()
			test.mutate(&destination)
			if _, err := Plan(packet, destination, test.signer); err == nil {
				t.Fatal("Plan accepted an inconsistent destination")
			}
		})
	}
}

func TestExtractPacketReadsPacketSentLog(t *testing.T) {
	document := loadVectors(t)
	vector := document.LayerZeroPackets[0]
	encoded := mustHex(t, vector.EncodedPacket)
	endpoint := common.HexToAddress("0x" + strings.Repeat("ab", 20))
	receipt := &types.Receipt{Logs: []*types.Log{
		{
			Address: endpoint,
			Topics:  []common.Hash{common.HexToHash("0x" + strings.Repeat("00", 32))},
			Data:    []byte{0x01},
		},
		packetSentLog(t, endpoint, encoded),
	}}
	packet, err := ExtractPacket(receipt, vector.SourceEID)
	if err != nil {
		t.Fatalf("ExtractPacket: %v", err)
	}
	checkHex(t, "encoded", packet.Encoded, vector.EncodedPacket)
	checkHex(t, "guid", packet.GUID[:], vector.GUID)
	checkHex(t, "payload_hash", packet.PayloadHash[:], vector.PayloadHash)
}

func TestExtractPacketRejectsUnusableReceipts(t *testing.T) {
	document := loadVectors(t)
	vector := document.LayerZeroPackets[0]
	encoded := mustHex(t, vector.EncodedPacket)
	endpoint := common.HexToAddress("0x" + strings.Repeat("ab", 20))
	second := bytes.Clone(encoded)
	second[PacketGUIDOffset] ^= 0xff
	broken := bytes.Clone(encoded)
	broken[49] = 1
	for _, test := range []struct {
		name    string
		receipt *types.Receipt
		source  uint32
	}{
		{"missing receipt", nil, vector.SourceEID},
		{"no PacketSent log", &types.Receipt{}, vector.SourceEID},
		{"wrong source EID", &types.Receipt{Logs: []*types.Log{packetSentLog(t, endpoint, encoded)}}, vector.SourceEID + 1},
		{"non-EVM receiver", &types.Receipt{Logs: []*types.Log{packetSentLog(t, endpoint, broken)}}, vector.SourceEID},
		{"two distinct packets", &types.Receipt{Logs: []*types.Log{
			packetSentLog(t, endpoint, encoded),
			packetSentLog(t, endpoint, second),
		}}, vector.SourceEID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ExtractPacket(test.receipt, test.source); err == nil {
				t.Fatal("ExtractPacket accepted an unusable receipt")
			}
		})
	}
}

func packetSentLog(t *testing.T, endpoint common.Address, encodedPacket []byte) *types.Log {
	t.Helper()
	data, err := endpointV2Contract.ABI().Events["PacketSent"].Inputs.Pack(encodedPacket, []byte{}, endpoint)
	if err != nil {
		t.Fatalf("pack PacketSent log: %v", err)
	}
	return &types.Log{
		Address: endpoint,
		Topics:  []common.Hash{topicHash(PacketSentTopic)},
		Data:    data,
	}
}
