package layerzero

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// The vector generator pins these three values for every packet vector
// (scripts/generate_go_parity_vectors.py::_packet_vectors).
const (
	vectorConfirmations = 1
	vectorExpiration    = 1_900_000_000
	vectorGasLimit      = 1_500_000
)

type layerZeroVector struct {
	Nonce          uint64 `json:"nonce"`
	EncodedPacket  string `json:"encoded_packet"`
	SourceEID      uint32 `json:"source_eid"`
	DestinationEID uint32 `json:"destination_eid"`
	Sender         string `json:"sender"`
	Receiver       string `json:"receiver"`
	GUID           string `json:"guid"`
	Message        string `json:"message"`
	PayloadHash    string `json:"payload_hash"`
	DVNInstruction struct {
		VID             uint32 `json:"vid"`
		Target          string `json:"target"`
		CallData        string `json:"call_data"`
		Expiration      int64  `json:"expiration"`
		InstructionHash string `json:"instruction_hash"`
		Signature       string `json:"signature"`
	} `json:"dvn_instruction"`
	DVNExecuteCalldata         string `json:"dvn_execute_calldata"`
	CommitVerificationCalldata string `json:"commit_verification_calldata"`
	ExecutorCalldata           string `json:"executor_calldata"`
	ExecutorOptions            string `json:"executor_options"`
}

type vectorDocument struct {
	Constants struct {
		FixtureKeys map[string]string `json:"fixture_keys"`
	} `json:"constants"`
	LayerZeroPackets []layerZeroVector `json:"layerzero_packets"`
}

func loadVectors(t *testing.T) vectorDocument {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read parity vectors: %v", err)
	}
	var document vectorDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("parse parity vectors: %v", err)
	}
	if len(document.LayerZeroPackets) == 0 {
		t.Fatal("parity vectors carry no layerzero_packets")
	}
	return document
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

func hexOf(value []byte) string { return "0x" + hex.EncodeToString(value) }

func checkHex(t *testing.T, name string, value []byte, want string) {
	t.Helper()
	if got := hexOf(value); got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}
}

// checkKeccak compares the keccak256 of parts with the expected hex value.
func checkKeccak(t *testing.T, name string, want string, parts ...[]byte) {
	t.Helper()
	digest := xir.Keccak256(parts...)
	if got := hexOf(digest[:]); got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}
}

// selector derives the 4-byte selector of a canonical ABI signature.
func selector(signature string) []byte {
	digest := xir.Keccak256([]byte(signature))
	return digest[:4]
}

// testSigner signs digests exactly as eth_account's encode_defunct does, which
// is what internal/evm.Signer.SignPersonalDigest implements.
type testSigner struct {
	key *ecdsa.PrivateKey
}

func newTestSigner(t *testing.T, privateKey string) testSigner {
	t.Helper()
	if privateKey == "" {
		t.Fatal("parity vectors carry no dvn_signer fixture key")
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}
	return testSigner{key: key}
}

func (s testSigner) SignPersonalDigest(digest [32]byte) ([]byte, error) {
	signature, err := crypto.Sign(personalDigest(digest), s.key)
	if err != nil {
		return nil, err
	}
	signature[64] += 27
	return signature, nil
}

func (s testSigner) address() common.Address { return crypto.PubkeyToAddress(s.key.PublicKey) }

// personalDigest frames a digest the way EIP-191 personal signing does.
func personalDigest(digest [32]byte) []byte {
	return crypto.Keccak256(append([]byte("\x19Ethereum Signed Message:\n32"), digest[:]...))
}

func recoverAddress(t *testing.T, hash, signature []byte) common.Address {
	t.Helper()
	if len(signature) != 65 {
		t.Fatalf("signature is %d bytes, want 65", len(signature))
	}
	normalized := append([]byte(nil), signature...)
	normalized[64] -= 27
	publicKey, err := crypto.Ecrecover(hash, normalized)
	if err != nil {
		t.Fatalf("recover signer: %v", err)
	}
	return common.BytesToAddress(crypto.Keccak256(publicKey[1:])[12:])
}

// TestLayerZeroVectorsMatchPythonReference compares every field the generator
// writes for layerzero_packets against this package.
func TestLayerZeroVectorsMatchPythonReference(t *testing.T) {
	document := loadVectors(t)
	signer := newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"])
	for _, vector := range document.LayerZeroPackets {
		t.Run(strconv.FormatUint(vector.Nonce, 10), func(t *testing.T) {
			encoded := mustHex(t, vector.EncodedPacket)
			packet, err := DecodePacket(encoded)
			if err != nil {
				t.Fatalf("DecodePacket: %v", err)
			}
			if packet.Version != PacketVersion {
				t.Errorf("version = %d, want %d", packet.Version, PacketVersion)
			}
			if packet.Nonce != vector.Nonce {
				t.Errorf("nonce = %d, want %d", packet.Nonce, vector.Nonce)
			}
			if packet.SourceEID != vector.SourceEID {
				t.Errorf("source_eid = %d, want %d", packet.SourceEID, vector.SourceEID)
			}
			if packet.DestinationEID != vector.DestinationEID {
				t.Errorf("destination_eid = %d, want %d", packet.DestinationEID, vector.DestinationEID)
			}
			checkHex(t, "encoded", packet.Encoded, vector.EncodedPacket)
			checkHex(t, "header", packet.Header, vector.EncodedPacket[:2+2*PacketHeaderBytes])
			checkHex(t, "sender", packet.Sender[:], vector.Sender)
			checkHex(t, "receiver", packet.Receiver[:], vector.Receiver)
			checkHex(t, "guid", packet.GUID[:], vector.GUID)
			checkHex(t, "message", packet.Message, vector.Message)
			checkHex(t, "payload_hash", packet.PayloadHash[:], vector.PayloadHash)
			checkKeccak(t, "keccak(guid||message)", vector.PayloadHash, packet.GUID[:], packet.Message)

			receiver, err := packet.ReceiverAddress()
			if err != nil {
				t.Fatalf("ReceiverAddress: %v", err)
			}
			checkHex(t, "receiver_address", receiver[:], "0x"+strings.TrimPrefix(vector.Receiver, "0x")[24:])

			instruction, err := BuildDVNInstruction(DVNRequest{
				VID:           vector.DestinationEID,
				ReceiveULN:    common.HexToAddress(vector.DVNInstruction.Target),
				Packet:        packet,
				Confirmations: vectorConfirmations,
				Expiration:    big.NewInt(vectorExpiration),
				Signer:        signer,
			})
			if err != nil {
				t.Fatalf("BuildDVNInstruction: %v", err)
			}
			if instruction.VID != vector.DVNInstruction.VID {
				t.Errorf("dvn vid = %d, want %d", instruction.VID, vector.DVNInstruction.VID)
			}
			checkHex(t, "dvn target", instruction.Target[:], vector.DVNInstruction.Target)
			checkHex(t, "dvn call_data", instruction.CallData, vector.DVNInstruction.CallData)
			checkHex(t, "dvn instruction_hash", instruction.Hash[:], vector.DVNInstruction.InstructionHash)
			checkHex(t, "dvn signature", instruction.Signature, vector.DVNInstruction.Signature)
			if instruction.Expiration.Cmp(big.NewInt(vector.DVNInstruction.Expiration)) != 0 {
				t.Errorf("dvn expiration = %s, want %d", instruction.Expiration, vector.DVNInstruction.Expiration)
			}
			var expiration [32]byte
			big.NewInt(vector.DVNInstruction.Expiration).FillBytes(expiration[:])
			packed := binary.BigEndian.AppendUint32(nil, vector.DVNInstruction.VID)
			packed = append(packed, instruction.Target[:]...)
			packed = append(packed, expiration[:]...)
			packed = append(packed, instruction.CallData...)
			checkKeccak(t, "keccak(vid||target||expiration||call_data)", vector.DVNInstruction.InstructionHash, packed)

			dvnExecute, err := EncodeDVNExecute(instruction)
			if err != nil {
				t.Fatalf("EncodeDVNExecute: %v", err)
			}
			checkHex(t, "dvn_execute_calldata", dvnExecute, vector.DVNExecuteCalldata)

			commitVerification, err := EncodeCommitVerification(packet)
			if err != nil {
				t.Fatalf("EncodeCommitVerification: %v", err)
			}
			checkHex(t, "commit_verification_calldata", commitVerification, vector.CommitVerificationCalldata)

			executor, err := EncodeExecutorSubmission(packet, vectorGasLimit)
			if err != nil {
				t.Fatalf("EncodeExecutorSubmission: %v", err)
			}
			checkHex(t, "executor_calldata", executor, vector.ExecutorCalldata)

			options, err := ReceiveOptions(vectorGasLimit)
			if err != nil {
				t.Fatalf("ReceiveOptions: %v", err)
			}
			checkHex(t, "executor_options", options, vector.ExecutorOptions)
		})
	}
}

// TestSelectorsMatchCanonicalSignatures derives every selector this package
// prepends from its canonical signature.
func TestSelectorsMatchCanonicalSignatures(t *testing.T) {
	for _, test := range []struct {
		signature string
		selector  string
	}{
		{"verify(bytes,bytes32,uint64)", "0x0223536e"},
		{"execute((uint32,address,bytes,uint256,bytes)[])", "0xb143044b"},
		{"commitVerification(bytes,bytes32)", "0x0894edf1"},
		{"execute302((address,(uint32,bytes32,uint64),bytes32,bytes,bytes,uint256))", "0xcfc32570"},
	} {
		checkHex(t, test.signature, selector(test.signature), test.selector)
	}
}

// TestEventTopicsMatchOfficialABI re-derives the four topic constants from
// their canonical signatures and from the committed ABI fragments.
func TestEventTopicsMatchOfficialABI(t *testing.T) {
	for _, test := range []struct {
		name      string
		signature string
		topic     string
		hash      common.Hash
	}{
		{"PacketSent", PacketSentSignature, PacketSentTopic, eventTopic(t, endpointV2Contract, "PacketSent")},
		{"PayloadVerified", PayloadVerifiedSignature, PayloadVerifiedTopic, eventTopic(t, receiveULNContract, "PayloadVerified")},
		{"PacketVerified", PacketVerifiedSignature, PacketVerifiedTopic, eventTopic(t, endpointV2Contract, "PacketVerified")},
		{"PacketDelivered", PacketDeliveredSignature, PacketDeliveredTopic, eventTopic(t, endpointV2Contract, "PacketDelivered")},
	} {
		checkKeccak(t, test.name+" topic", test.topic, []byte(test.signature))
		if topicHash(test.topic) != test.hash {
			t.Errorf("%s topic = %s, want ABI topic %s", test.name, test.topic, test.hash)
		}
	}
}

// TestDVNSignatureUsesPersonalSigningDomain pins the signing domain: the Python
// reference signs the instruction hash with eth_account's encode_defunct, so the
// fixture signature recovers the DVN key only under the EIP-191 framing.
func TestDVNSignatureUsesPersonalSigningDomain(t *testing.T) {
	document := loadVectors(t)
	signer := newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"])
	instruction := document.LayerZeroPackets[0].DVNInstruction
	var digest [32]byte
	copy(digest[:], mustHex(t, instruction.InstructionHash))
	signature := mustHex(t, instruction.Signature)

	if got := recoverAddress(t, personalDigest(digest), signature); got != signer.address() {
		t.Errorf("personal digest recovers %s, want the DVN signer %s", got, signer.address())
	}
	if got := recoverAddress(t, digest[:], signature); got == signer.address() {
		t.Error("raw digest recovers the DVN signer: the vector is not EIP-191 framed")
	}
	if !bytes.Equal(signature[64:], []byte{0x1b}) && !bytes.Equal(signature[64:], []byte{0x1c}) {
		t.Errorf("signature recovery byte = %d, want the personal-signing range 27..28", signature[64])
	}
}

func TestDecodePacketRejectsMalformedPackets(t *testing.T) {
	document := loadVectors(t)
	encoded := mustHex(t, document.LayerZeroPackets[0].EncodedPacket)
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"empty", func([]byte) []byte { return []byte{} }},
		{"truncated", func(value []byte) []byte { return value[:PacketMessageOffset-1] }},
		{"header only", func(value []byte) []byte { return value[:PacketHeaderBytes] }},
		{"wrong version", func(value []byte) []byte { mutated := bytes.Clone(value); mutated[0] = 2; return mutated }},
		{"non-EVM receiver", func(value []byte) []byte { mutated := bytes.Clone(value); mutated[49] = 1; return mutated }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodePacket(test.mutate(encoded)); err == nil {
				t.Fatal("DecodePacket accepted a malformed packet")
			}
		})
	}
}

// TestDecodePacketAcceptsEmptyMessage checks the shortest legal packet: a full
// header and GUID with no message bytes.
func TestDecodePacketAcceptsEmptyMessage(t *testing.T) {
	encoded := make([]byte, PacketMessageOffset)
	encoded[0] = PacketVersion
	packet, err := DecodePacket(encoded)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if len(packet.Message) != 0 {
		t.Errorf("message = %s, want empty", hexOf(packet.Message))
	}
	if want := xir.Keccak256(encoded[PacketGUIDOffset:]); packet.PayloadHash != want {
		t.Errorf("payload_hash = %s, want %s", hexOf(packet.PayloadHash[:]), hexOf(want[:]))
	}
}

// TestReceiveOptionsRejectsOutOfRangeGasLimit covers the official uint128 rule.
// A uint64 caller cannot reach the upper bound, so the lower bound is the one
// bound this type can violate.
func TestReceiveOptionsRejectsOutOfRangeGasLimit(t *testing.T) {
	if _, err := ReceiveOptions(0); err == nil {
		t.Fatal("ReceiveOptions accepted a zero gas limit")
	}
	options, err := ReceiveOptions(math.MaxUint64)
	if err != nil {
		t.Fatalf("ReceiveOptions: %v", err)
	}
	checkHex(t, "max gas options", options, "0x000301001101"+"0000000000000000ffffffffffffffff")
}

func TestBuildDVNInstructionRejectsInvalidRequests(t *testing.T) {
	document := loadVectors(t)
	packet, err := DecodePacket(mustHex(t, document.LayerZeroPackets[0].EncodedPacket))
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	signer := newTestSigner(t, document.Constants.FixtureKeys["dvn_signer"])
	base := func() DVNRequest {
		return DVNRequest{
			VID:           packet.DestinationEID,
			ReceiveULN:    common.HexToAddress("0x" + strings.Repeat("cc", 20)),
			Packet:        packet,
			Confirmations: vectorConfirmations,
			Expiration:    big.NewInt(vectorExpiration),
			Signer:        signer,
		}
	}
	if _, err := BuildDVNInstruction(base()); err != nil {
		t.Fatalf("BuildDVNInstruction rejected the valid request: %v", err)
	}
	tooLarge := new(big.Int).Lsh(big.NewInt(1), maxUint256Bits)
	for _, test := range []struct {
		name   string
		mutate func(*DVNRequest)
	}{
		{"zero vid", func(request *DVNRequest) { request.VID = 0 }},
		{"nil expiration", func(request *DVNRequest) { request.Expiration = nil }},
		{"zero expiration", func(request *DVNRequest) { request.Expiration = big.NewInt(0) }},
		{"negative expiration", func(request *DVNRequest) { request.Expiration = big.NewInt(-1) }},
		{"expiration above uint256", func(request *DVNRequest) { request.Expiration = tooLarge }},
		{"zero receive ULN", func(request *DVNRequest) { request.ReceiveULN = common.Address{} }},
		{"short packet header", func(request *DVNRequest) {
			request.Packet = Packet{Header: packet.Header[:PacketHeaderBytes-1], PayloadHash: packet.PayloadHash}
		}},
		{"missing signer", func(request *DVNRequest) { request.Signer = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := base()
			test.mutate(&request)
			if _, err := BuildDVNInstruction(request); err == nil {
				t.Fatal("BuildDVNInstruction accepted an invalid request")
			}
		})
	}
}

func TestEncodersRejectUnencodableInput(t *testing.T) {
	document := loadVectors(t)
	packet, err := DecodePacket(mustHex(t, document.LayerZeroPackets[0].EncodedPacket))
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if _, err := EncodeDVNExecute(DVNInstruction{VID: packet.DestinationEID, Expiration: nil}); err == nil {
		t.Error("EncodeDVNExecute accepted a nil expiration")
	}
	nonEVM := packet
	nonEVM.Receiver[0] = 1
	if _, err := EncodeExecutorSubmission(nonEVM, vectorGasLimit); err == nil {
		t.Error("EncodeExecutorSubmission accepted a non-EVM receiver")
	}
}

func eventTopic(t *testing.T, contract interface {
	EventTopic(string) (common.Hash, error)
}, name string) common.Hash {
	t.Helper()
	topic, err := contract.EventTopic(name)
	if err != nil {
		t.Fatalf("event topic %s: %v", name, err)
	}
	return topic
}
