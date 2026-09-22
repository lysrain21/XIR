package hyperlane

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

// The layout vectors below are pinned against values computed outside this
// package with `cast keccak` / `cast sig` / `cast wallet address`
// (/home/ubuntu/.foundry/bin/cast, foundry), so a change in this package's
// digest composition cannot pass by agreeing with itself.
const (
	// vectorMessage is FormatMessage(3, 1, 31337, sender, 31338, recipient, "XIR")
	// with sender = 0x00..00dd..dd and recipient = 0x00..00ee..ee:
	// version[0] || nonce[1:5] || origin[5:9] || sender[9:41] || destination[41:45]
	// || recipient[45:77] || body[77:] (Message.sol:33-52).
	vectorMessage = "0x030000000100007a69000000000000000000000000dddddddddddddddddddddddddddddddddddddddd00007a6a000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee584952"

	// vectorMessageID is cast keccak of vectorMessage (Message.sol:59-61).
	vectorMessageID = "0x8b9dcbed27d82d99f2b1a7a9a868a9d9a36545795a6be230356927b037411b78"

	// vectorOriginDomain, vectorHook, vectorRoot and vectorIndex are the checkpoint
	// inputs the digest vectors were computed from.
	vectorOriginDomain = uint32(31337)
	vectorHook         = "0x1111111111111111111111111111111111111111"
	vectorRoot         = "0x2222222222222222222222222222222222222222222222222222222222222222"
	vectorIndex        = uint32(5)

	// vectorDomainHash is cast keccak of the 44-byte preimage
	// abi.encodePacked(uint32 31337, bytes32 hook, "HYPERLANE")
	// (CheckpointLib.sol:80-91).
	vectorDomainHash = "0xbf6e61acfa618e3081642d2345843ab79d4caac18f03d6c0329f9f804a3ffa1e"

	// vectorSigningHash is cast keccak of the 100-byte preimage
	// domainHash || root || uint32 5 || messageID (CheckpointLib.sol:39-44): the
	// value a validator signs with eth_sign.
	vectorSigningHash = "0x2a43dd208a4311a928fa0efbd2eae40033c8ebab43c4af40938f72678825e08d"

	// vectorISMDigest is cast keccak of the EIP-191 preimage
	// "\x19Ethereum Signed Message:\n32" || vectorSigningHash: the 32-byte value
	// AbstractMultisigIsm.verify passes to ECDSA.recover (:110).
	vectorISMDigest = "0x577403f6f78eeb6ad829f39b6ab5af233a79d8df774f2272b981607f5ddbb202"

	// vectorProcessSelector is cast sig "process(bytes,bytes)" (Mailbox.sol:202-207).
	vectorProcessSelector = "0x7c39d130"

	// vectorValidatorAddress is cast wallet address of the fixture validator key in
	// go-runtime/testdata/vectors.json (constants.fixture_keys.validator).
	vectorValidatorAddress = "0xC9aFf155a8DF8FEA85741236eFe4BF3062802a3D"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		t.Fatalf("decode %s: %v", value, err)
	}
	return decoded
}

func mustHash(t *testing.T, value string) common.Hash {
	t.Helper()
	decoded := mustHex(t, value)
	if len(decoded) != 32 {
		t.Fatalf("hash %s has length %d", value, len(decoded))
	}
	var hash common.Hash
	copy(hash[:], decoded)
	return hash
}

func mustBytes32(t *testing.T, value string) [32]byte {
	t.Helper()
	return [32]byte(mustHash(t, value))
}

func mustAddress(t *testing.T, value string) common.Address {
	t.Helper()
	return common.HexToAddress(value)
}

// vectorMessageBytes rebuilds the pinned message from its fields, so the layout
// test asserts both the packing order and the accessors against the same bytes.
func vectorMessageBytes(t *testing.T) []byte {
	t.Helper()
	var sender, recipient [32]byte
	copy(sender[12:], bytes.Repeat([]byte{0xdd}, 20))
	copy(recipient[12:], bytes.Repeat([]byte{0xee}, 20))
	return FormatMessage(Version, 1, vectorOriginDomain, sender, 31338, recipient, []byte("XIR"))
}

func TestFormatMessageLayoutAndID(t *testing.T) {
	message := vectorMessageBytes(t)
	if "0x"+hex.EncodeToString(message) != vectorMessage {
		t.Fatalf("FormatMessage = 0x%s, want %s", hex.EncodeToString(message), vectorMessage)
	}
	if len(message) != HeaderLength+3 {
		t.Fatalf("message length %d, want %d", len(message), HeaderLength+3)
	}
	decoded := Message(message)
	var sender, recipient [32]byte
	copy(sender[12:], bytes.Repeat([]byte{0xdd}, 20))
	copy(recipient[12:], bytes.Repeat([]byte{0xee}, 20))
	for _, field := range []struct {
		name string
		got  any
		want any
	}{
		{"version", decoded.Version(), Version},
		{"nonce", decoded.Nonce(), uint32(1)},
		{"origin", decoded.Origin(), vectorOriginDomain},
		{"sender", decoded.Sender(), sender},
		{"destination", decoded.Destination(), uint32(31338)},
		{"recipient", decoded.Recipient(), recipient},
		{"body", hex.EncodeToString(decoded.Body()), hex.EncodeToString([]byte("XIR"))},
	} {
		if field.got != field.want {
			t.Errorf("message %s = %v, want %v", field.name, field.got, field.want)
		}
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if _, err := decoded.SenderAddress(); err != nil {
		t.Errorf("SenderAddress: %v", err)
	}
	if _, err := decoded.RecipientAddress(); err != nil {
		t.Errorf("RecipientAddress: %v", err)
	}
	if got := MessageID(message); got != mustHash(t, vectorMessageID) {
		t.Errorf("MessageID = %s, want %s", got, vectorMessageID)
	}
	if got := decoded.ID(); got != MessageID(message) {
		t.Errorf("Message.ID = %s, want %s", got, MessageID(message))
	}
	// A second, independent keccak implementation over the same bytes.
	if got := crypto.Keccak256Hash(message); got != mustHash(t, vectorMessageID) {
		t.Errorf("crypto.Keccak256Hash = %s, want %s", got, vectorMessageID)
	}
}

func TestMessageAccessorsOnShortInput(t *testing.T) {
	truncated := vectorMessageBytes(t)[:HeaderLength-1]
	decoded := Message(truncated)
	if err := decoded.Validate(); err == nil {
		t.Fatal("Validate accepted a message shorter than the header")
	}
	if decoded.Body() != nil {
		t.Errorf("Body = %x, want nil", decoded.Body())
	}
	if decoded.Recipient() != ([32]byte{}) {
		t.Errorf("Recipient = %x, want zero", decoded.Recipient())
	}
}

func TestTypeCasts(t *testing.T) {
	address := mustAddress(t, vectorHook)
	encoded := AddressToBytes32(address)
	if !bytes.Equal(encoded[:12], make([]byte, 12)) || !bytes.Equal(encoded[12:], address.Bytes()) {
		t.Fatalf("AddressToBytes32 = %x", encoded)
	}
	decoded, err := Bytes32ToAddress(encoded)
	if err != nil {
		t.Fatalf("Bytes32ToAddress: %v", err)
	}
	if decoded != address {
		t.Fatalf("Bytes32ToAddress = %s, want %s", decoded, address)
	}
	overflowing := encoded
	overflowing[0] = 1
	if _, err := Bytes32ToAddress(overflowing); err == nil {
		t.Fatal("Bytes32ToAddress accepted a value with non-zero upper bits")
	}
}

func TestCheckpointDigestComposition(t *testing.T) {
	hook := mustAddress(t, vectorHook)
	root := mustBytes32(t, vectorRoot)
	messageID := mustHash(t, vectorMessageID)

	if got := DomainHash(vectorOriginDomain, hook); got != mustHash(t, vectorDomainHash) {
		t.Errorf("DomainHash = %s, want %s", got, vectorDomainHash)
	}

	checkpoint := Checkpoint{Domain: vectorOriginDomain, Root: root, Index: vectorIndex}
	signingHash := checkpoint.Hash(hook, messageID)
	if signingHash != mustHash(t, vectorSigningHash) {
		t.Errorf("Checkpoint.Hash = %s, want %s", signingHash, vectorSigningHash)
	}
	if got := checkpoint.Digest(hook, messageID); got != mustHash(t, vectorISMDigest) {
		t.Errorf("Checkpoint.Digest = %s, want %s", got, vectorISMDigest)
	}
	if signingHash == checkpoint.Digest(hook, messageID) {
		t.Fatal("Checkpoint.Hash and Checkpoint.Digest must differ: the digest is prefixed")
	}

	// Locally assembled expectation: the same preimages CheckpointLib hashes,
	// built here from raw bytes with no help from this package's helpers.
	encodedHook := AddressToBytes32(hook)
	domainPreimage := append([]byte{0x00, 0x00, 0x7a, 0x69}, encodedHook[:]...)
	domainPreimage = append(domainPreimage, []byte("HYPERLANE")...)
	if len(domainPreimage) != 45 {
		t.Fatalf("domain preimage length %d, want 45", len(domainPreimage))
	}
	expectedDomain := crypto.Keccak256Hash(domainPreimage)
	if expectedDomain != mustHash(t, vectorDomainHash) {
		t.Errorf("locally computed domain hash = %s, want %s", expectedDomain, vectorDomainHash)
	}
	indexPreimage := make([]byte, 0, 100)
	indexPreimage = append(indexPreimage, expectedDomain[:]...)
	indexPreimage = append(indexPreimage, root[:]...)
	indexPreimage = append(indexPreimage, 0x00, 0x00, 0x00, 0x05)
	indexPreimage = append(indexPreimage, messageID[:]...)
	if len(indexPreimage) != 100 {
		t.Fatalf("preimage length %d, want 100", len(indexPreimage))
	}
	expectedSigningHash := crypto.Keccak256Hash(indexPreimage)
	if expectedSigningHash != signingHash {
		t.Errorf("locally computed signing hash = %s, want %s", expectedSigningHash, signingHash)
	}
	expectedDigest := crypto.Keccak256Hash(
		append([]byte("\x19Ethereum Signed Message:\n32"), expectedSigningHash[:]...),
	)
	if expectedDigest != checkpoint.Digest(hook, messageID) {
		t.Errorf("locally computed digest = %s, want %s", expectedDigest, checkpoint.Digest(hook, messageID))
	}

	// The free function is the same derivation, and refuses to sign for a tree
	// address that cannot exist.
	free, err := CheckpointDigest(vectorOriginDomain, hook, root, vectorIndex, messageID)
	if err != nil {
		t.Fatalf("CheckpointDigest: %v", err)
	}
	if free != signingHash {
		t.Errorf("CheckpointDigest = %s, want %s", free, signingHash)
	}
	if _, err := CheckpointDigest(vectorOriginDomain, common.Address{}, root, vectorIndex, messageID); err == nil {
		t.Error("CheckpointDigest accepted the zero tree hook address")
	}
}

func TestMetadataLayout(t *testing.T) {
	hook := mustAddress(t, vectorHook)
	root := mustBytes32(t, vectorRoot)
	signatureOne := append(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)...)
	signatureOne = append(signatureOne, 27)
	signatureTwo := append(bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32)...)
	signatureTwo = append(signatureTwo, 28)

	if got, want := MetadataLength(1), 133; got != want {
		t.Errorf("MetadataLength(1) = %d, want %d", got, want)
	}
	if got, want := MetadataLength(2), 198; got != want {
		t.Errorf("MetadataLength(2) = %d, want %d", got, want)
	}

	for _, test := range []struct {
		name       string
		signatures []byte
		threshold  int
	}{
		{"threshold-1", signatureOne, 1},
		{"threshold-2", append(append([]byte{}, signatureOne...), signatureTwo...), 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata, err := Metadata(hook, root, vectorIndex, test.signatures)
			if err != nil {
				t.Fatalf("Metadata: %v", err)
			}
			if len(metadata) != MetadataLength(test.threshold) {
				t.Fatalf("metadata length %d, want %d", len(metadata), MetadataLength(test.threshold))
			}
			if !bytes.Equal(metadata[:12], make([]byte, 12)) {
				t.Errorf("metadata[0:12] = %x, want 12 zero bytes", metadata[:12])
			}
			if got := metadata[12:32]; !bytes.Equal(got, hook.Bytes()) {
				t.Errorf("metadata[12:32] = %x, want %x", got, hook.Bytes())
			}
			if got := metadata[32:64]; !bytes.Equal(got, root[:]) {
				t.Errorf("metadata[32:64] = %x, want %x", got, root[:])
			}
			if got := metadata[64:68]; !bytes.Equal(got, []byte{0x00, 0x00, 0x00, 0x05}) {
				t.Errorf("metadata[64:68] = %x, want 00000005", got)
			}
			if got := metadata[68:]; !bytes.Equal(got, test.signatures) {
				t.Errorf("metadata[68:] = %x, want %x", got, test.signatures)
			}
			for index := 0; index < test.threshold; index++ {
				want := test.signatures[index*SignatureLength : (index+1)*SignatureLength]
				got, err := MetadataSignatureAt(metadata, index)
				if err != nil {
					t.Fatalf("MetadataSignatureAt(%d): %v", index, err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("signature %d = %x, want %x", index, got, want)
				}
			}
			decodedHook, err := MetadataOriginMerkleTreeHook(metadata)
			if err != nil {
				t.Fatalf("MetadataOriginMerkleTreeHook: %v", err)
			}
			address, err := Bytes32ToAddress(decodedHook)
			if err != nil {
				t.Fatalf("Bytes32ToAddress: %v", err)
			}
			if address != hook {
				t.Errorf("metadata hook = %s, want %s", address, hook)
			}
			decodedRoot, err := MetadataRoot(metadata)
			if err != nil {
				t.Fatalf("MetadataRoot: %v", err)
			}
			if decodedRoot != root {
				t.Errorf("metadata root = %x, want %x", decodedRoot, root)
			}
			decodedIndex, err := MetadataIndex(metadata)
			if err != nil {
				t.Fatalf("MetadataIndex: %v", err)
			}
			if decodedIndex != vectorIndex {
				t.Errorf("metadata index = %d, want %d", decodedIndex, vectorIndex)
			}
			count, err := SignatureCount(test.signatures)
			if err != nil {
				t.Fatalf("SignatureCount: %v", err)
			}
			if count != test.threshold {
				t.Errorf("SignatureCount = %d, want %d", count, test.threshold)
			}
			// Checkpoint.Metadata takes the root and index from the checkpoint.
			same, err := (Checkpoint{Domain: vectorOriginDomain, Root: root, Index: vectorIndex}).
				Metadata(hook, test.signatures)
			if err != nil {
				t.Fatalf("Checkpoint.Metadata: %v", err)
			}
			if !bytes.Equal(same, metadata) {
				t.Errorf("Checkpoint.Metadata = %x, want %x", same, metadata)
			}
		})
	}
}

func TestMetadataRejectsMalformedSignatures(t *testing.T) {
	hook := mustAddress(t, vectorHook)
	root := mustBytes32(t, vectorRoot)
	valid := append(bytes.Repeat([]byte{0x01}, 64), 27)

	highS := append(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0xff}, 32)...)
	highS = append(highS, 27)
	zeroR := append(make([]byte, 32), bytes.Repeat([]byte{0x02}, 32)...)
	zeroR = append(zeroR, 27)
	badV := append(bytes.Repeat([]byte{0x01}, 64), 26)

	for _, test := range []struct {
		name       string
		signatures []byte
	}{
		{"empty", nil},
		{"truncated", valid[:64]},
		{"overlong", append(append([]byte{}, valid...), 0x00)},
		{"high-s", highS},
		{"zero-r", zeroR},
		{"v-not-27-28", badV},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Metadata(hook, root, vectorIndex, test.signatures); err == nil {
				t.Fatalf("Metadata accepted %s signatures", test.name)
			}
		})
	}

	metadata, err := Metadata(hook, root, vectorIndex, valid)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if _, err := MetadataOriginMerkleTreeHook(metadata[:31]); err == nil {
		t.Error("MetadataOriginMerkleTreeHook accepted a short payload")
	}
	if _, err := MetadataRoot(metadata[:63]); err == nil {
		t.Error("MetadataRoot accepted a short payload")
	}
	if _, err := MetadataIndex(metadata[:67]); err == nil {
		t.Error("MetadataIndex accepted a short payload")
	}
	if _, err := MetadataSignatureAt(metadata, 1); err == nil {
		t.Error("MetadataSignatureAt accepted an index past the signatures")
	}
	if _, err := MetadataSignatureAt(metadata, -1); err == nil {
		t.Error("MetadataSignatureAt accepted a negative index")
	}
}

func TestValidatorSignatureRecovery(t *testing.T) {
	vectors := loadVectors(t)
	signer := fixtureSigner(t, vectors.Constants.FixtureKeys["validator"])
	if got, want := signer.Address(), mustAddress(t, vectorValidatorAddress); got != want {
		t.Fatalf("fixture validator address = %s, want %s", got, want)
	}
	validator, err := NewValidator(signer)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if validator.Address() != signer.Address() {
		t.Fatalf("Validator.Address = %s, want %s", validator.Address(), signer.Address())
	}

	message := vectorMessageBytes(t)
	hook := mustAddress(t, vectorHook)
	checkpoint := Checkpoint{Domain: vectorOriginDomain, Root: mustBytes32(t, vectorRoot), Index: vectorIndex}
	signature, err := validator.SignMessage(hook, checkpoint, message)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(signature) != SignatureLength {
		t.Fatalf("signature length %d, want %d", len(signature), SignatureLength)
	}
	if v := signature[64]; v != 27 && v != 28 {
		t.Fatalf("signature v = %d, want 27 or 28", v)
	}

	digest := checkpoint.Digest(hook, MessageID(message))
	recovered := recoverAddress(t, digest, signature)
	if recovered != signer.Address() {
		t.Fatalf("recovered %s, want %s", recovered, signer.Address())
	}
	// The signature is over the prefixed digest: recovering over the unprefixed
	// signing hash must not yield the validator, which is what would happen if
	// the EIP-191 prefixing were dropped.
	signingHash := checkpoint.Hash(hook, MessageID(message))
	if fromSigningHash := recoverAddress(t, signingHash, signature); fromSigningHash == signer.Address() {
		t.Fatal("signature recovers over the unprefixed hash; the digest must be prefixed")
	}

	// The signature is exactly what lands in the metadata, and it is the same
	// statement SignCheckpoint makes for the already-derived message id.
	direct, err := validator.SignCheckpoint(hook, checkpoint, MessageID(message))
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if !bytes.Equal(direct, signature) {
		t.Fatalf("SignCheckpoint = %x, want %x", direct, signature)
	}
	metadata, err := Metadata(hook, checkpoint.Root, checkpoint.Index, signature)
	if err != nil {
		t.Fatalf("Metadata with a real signature: %v", err)
	}
	carried, err := MetadataSignatureAt(metadata, 0)
	if err != nil {
		t.Fatalf("MetadataSignatureAt: %v", err)
	}
	if !bytes.Equal(carried, signature) {
		t.Fatalf("metadata signature = %x, want %x", carried, signature)
	}

	// A checkpoint for a different origin can never verify: the ISM takes the
	// domain from the message, the relayer from the metadata.
	wrongOrigin := checkpoint
	wrongOrigin.Domain = vectorOriginDomain + 1
	if _, err := validator.SignMessage(hook, wrongOrigin, message); err == nil {
		t.Error("SignMessage accepted a checkpoint whose domain is not the message origin")
	}
	if _, err := validator.SignMessage(hook, checkpoint, message[:HeaderLength-1]); err == nil {
		t.Error("SignMessage accepted a truncated message")
	}
}

func TestEvidenceHashVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors.HyperlaneEvidence) == 0 {
		t.Fatal("testdata/vectors.json has no hyperlane_evidence vectors")
	}
	for _, vector := range vectors.HyperlaneEvidence {
		sender := mustBytes32(t, vector.Sender)
		body := mustHex(t, vector.Body)
		got := EvidenceHash(vector.Domain, sender, body)
		if got != mustHash(t, vector.EvidenceHash) {
			t.Errorf(
				"EvidenceHash(domain=%d, hop=%d) = %s, want %s",
				vector.Domain, vector.HopIndex, got, vector.EvidenceHash,
			)
		}
	}
	// Boundary case: an empty body still encodes three head words plus a zero
	// length word, and the whole encoding is 128 bytes. The expected hash is cast
	// keccak of that preimage.
	if got, want := EvidenceHash(1, [32]byte{}, nil),
		mustHash(t, "0xaa1482fe4a9e0d735888c5ff68d68ed6d50cfe150731168d452902a0df6a2009"); got != want {
		t.Errorf("EvidenceHash with an empty body = %s, want %s", got, want)
	}
}

func TestEventTopics(t *testing.T) {
	for _, test := range []struct {
		name string
		got  common.Hash
		want string
	}{
		{"Dispatch", DispatchTopic, "0x769f711d20c679153d382254f59892613b58a97cc876b249134ac25c80f9c814"},
		{"DispatchId", DispatchIDTopic, "0x788dbc1b7152732178210e7f4d9d010ef016f9eafbe66786bd7169f56e0c353a"},
		{"InsertedIntoTree", InsertedIntoTreeTopic, "0x253a3a04cab70d47c1504809242d9350cd81627b4f1d50753e159cf8cd76ed33"},
		{"Process", ProcessTopic, "0x0d381c2a574ae8f04e213db7cfb4df8df712cdbd427d9868ffef380660ca6574"},
		{"ProcessId", ProcessIDTopic, "0x1cae38cdd3d3919489272725a5ae62a4f48b2989b0dae843d3c279fee18073a9"},
	} {
		if test.got != mustHash(t, test.want) {
			t.Errorf("%sTopic = %s, want %s", test.name, test.got, test.want)
		}
	}
}

func TestPlanProcessCall(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors.HyperlaneEvidence) == 0 {
		t.Fatal("testdata/vectors.json has no hyperlane_evidence vectors")
	}
	signer := fixtureSigner(t, vectors.Constants.FixtureKeys["validator"])
	validator, err := NewValidator(signer)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	// A realistic hop: the dispatched message carries the XIR bundle body the
	// Python runner encodes (multihop_runner.py:1167-1200).
	body := mustHex(t, vectors.HyperlaneEvidence[0].Body)
	var sender, recipient [32]byte
	copy(sender[:], mustHex(t, vectors.HyperlaneEvidence[0].Sender))
	recipientAddress := mustAddress(t, "0x00000000000000000000000000000000000000cc")
	copy(recipient[12:], recipientAddress.Bytes())
	message := FormatMessage(Version, 3, vectorOriginDomain, sender, 31338, recipient, body)

	hook := mustAddress(t, vectorHook)
	checkpoint := Checkpoint{Domain: vectorOriginDomain, Root: mustBytes32(t, vectorRoot), Index: vectorIndex}
	signature, err := validator.SignMessage(hook, checkpoint, message)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	mailbox := mustAddress(t, "0x00000000000000000000000000000000000000ab")

	call, err := Plan(PlanRequest{
		Message:              message,
		OriginMerkleTreeHook: hook,
		Checkpoint:           checkpoint,
		Signatures:           signature,
		DestinationMailbox:   mailbox,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if call.Mailbox != mailbox {
		t.Errorf("Mailbox = %s, want %s", call.Mailbox, mailbox)
	}
	if call.MessageID != MessageID(message) {
		t.Errorf("MessageID = %s, want %s", call.MessageID, MessageID(message))
	}
	if !bytes.Equal(call.Message, message) {
		t.Errorf("Message = %x, want %x", call.Message, message)
	}
	wantMetadata, err := Metadata(hook, checkpoint.Root, checkpoint.Index, signature)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !bytes.Equal(call.Metadata, wantMetadata) {
		t.Errorf("Metadata = %x, want %x", call.Metadata, wantMetadata)
	}
	if got := hex.EncodeToString(call.Calldata[:4]); "0x"+got != vectorProcessSelector {
		t.Fatalf("selector = 0x%s, want %s", got, vectorProcessSelector)
	}

	contract, err := MailboxABI()
	if err != nil {
		t.Fatalf("MailboxABI: %v", err)
	}
	method, ok := contract.ABI().Methods["process"]
	if !ok {
		t.Fatal("Mailbox ABI has no process method")
	}
	if got := "0x" + hex.EncodeToString(method.ID); got != vectorProcessSelector {
		t.Errorf("ABI method id = %s, want %s", got, vectorProcessSelector)
	}
	arguments, err := method.Inputs.Unpack(call.Calldata[4:])
	if err != nil {
		t.Fatalf("unpack process calldata: %v", err)
	}
	if len(arguments) != 2 {
		t.Fatalf("process calldata carries %d arguments, want 2", len(arguments))
	}
	if !bytes.Equal(arguments[0].([]byte), call.Metadata) {
		t.Errorf("calldata metadata = %x, want %x", arguments[0].([]byte), call.Metadata)
	}
	if !bytes.Equal(arguments[1].([]byte), message) {
		t.Errorf("calldata message = %x, want %x", arguments[1].([]byte), message)
	}
}

func TestPlanRejectsInconsistentInputs(t *testing.T) {
	hook := mustAddress(t, vectorHook)
	signature := append(bytes.Repeat([]byte{0x01}, 64), 27)
	message := vectorMessageBytes(t)
	checkpoint := Checkpoint{Domain: vectorOriginDomain, Root: mustBytes32(t, vectorRoot), Index: vectorIndex}
	mailbox := mustAddress(t, "0x00000000000000000000000000000000000000ab")

	for _, test := range []struct {
		name    string
		request PlanRequest
	}{
		{"truncated-message", PlanRequest{
			Message: message[:HeaderLength-1], OriginMerkleTreeHook: hook,
			Checkpoint: checkpoint, Signatures: signature, DestinationMailbox: mailbox,
		}},
		{"wrong-version", PlanRequest{
			Message:              FormatMessage(2, 1, vectorOriginDomain, [32]byte{}, 31338, [32]byte{}, nil),
			OriginMerkleTreeHook: hook, Checkpoint: checkpoint, Signatures: signature,
			DestinationMailbox: mailbox,
		}},
		{"domain-mismatch", PlanRequest{
			Message: message, OriginMerkleTreeHook: hook,
			Checkpoint: Checkpoint{Domain: vectorOriginDomain + 1, Root: checkpoint.Root, Index: checkpoint.Index},
			Signatures: signature, DestinationMailbox: mailbox,
		}},
		{"zero-mailbox", PlanRequest{
			Message: message, OriginMerkleTreeHook: hook, Checkpoint: checkpoint,
			Signatures: signature,
		}},
		{"bad-signature", PlanRequest{
			Message: message, OriginMerkleTreeHook: hook, Checkpoint: checkpoint,
			Signatures: signature[:64], DestinationMailbox: mailbox,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Plan(test.request); err == nil {
				t.Fatalf("Plan accepted %s", test.name)
			}
		})
	}
}

func TestDispatchedMessage(t *testing.T) {
	contract, err := MailboxABI()
	if err != nil {
		t.Fatalf("MailboxABI: %v", err)
	}
	sender := mustAddress(t, "0x00000000000000000000000000000000000000dd")
	message := vectorMessageBytes(t)
	log := dispatchLog(t, contract, sender, 31338, message)

	receipt := &types.Receipt{
		TxHash: mustHash(t, vectorMessageID),
		Logs:   []*types.Log{log},
	}
	dispatched, err := DispatchedMessage(receipt, contract)
	if err != nil {
		t.Fatalf("DispatchedMessage: %v", err)
	}
	if !bytes.Equal(dispatched.Message, message) {
		t.Errorf("Message = %x, want %x", dispatched.Message, message)
	}
	if dispatched.MessageID != mustHash(t, vectorMessageID) {
		t.Errorf("MessageID = %s, want %s", dispatched.MessageID, vectorMessageID)
	}
	if dispatched.Nonce != 1 {
		t.Errorf("Nonce = %d, want 1", dispatched.Nonce)
	}
	if dispatched.Destination != 31338 {
		t.Errorf("Destination = %d, want 31338", dispatched.Destination)
	}
	if dispatched.Sender != sender {
		t.Errorf("Sender = %s, want %s", dispatched.Sender, sender)
	}
	if got, want := dispatched.Recipient, Message(message).Recipient(); got != want {
		t.Errorf("Recipient = %x, want %x", got, want)
	}

	// A receipt from any other transaction, and a receipt whose dispatch log has
	// the wrong topic layout, are both errors rather than empty results.
	if _, err := DispatchedMessage(&types.Receipt{}, contract); err == nil {
		t.Error("DispatchedMessage accepted a receipt without a Dispatch log")
	}
	truncated := *log
	truncated.Topics = log.Topics[:3]
	if _, err := DispatchedMessage(&types.Receipt{Logs: []*types.Log{&truncated}}, contract); err == nil {
		t.Error("DispatchedMessage accepted a Dispatch log with 3 topics")
	}
	if _, err := DispatchedMessage(nil, contract); err == nil {
		t.Error("DispatchedMessage accepted a nil receipt")
	}
}

// dispatchLog builds the Mailbox `Dispatch` log of one message with the topic
// layout solidity/contracts/interfaces/IMailbox.sol:16-21 declares.
func dispatchLog(
	t *testing.T,
	contract *abiutil.Contract,
	sender common.Address,
	destination uint32,
	message []byte,
) *types.Log {
	t.Helper()
	event, ok := contract.ABI().Events["Dispatch"]
	if !ok {
		t.Fatal("Mailbox ABI has no Dispatch event")
	}
	data, err := event.Inputs.NonIndexed().Pack(message)
	if err != nil {
		t.Fatalf("pack Dispatch data: %v", err)
	}
	recipient := Message(message).Recipient()
	return &types.Log{
		Address: mustAddress(t, "0x00000000000000000000000000000000000000ab"),
		Topics: []common.Hash{
			DispatchTopic,
			common.BytesToHash(common.LeftPadBytes(sender.Bytes(), 32)),
			common.BigToHash(new(big.Int).SetUint64(uint64(destination))),
			common.Hash(recipient),
		},
		Data: data,
	}
}

type vectorDocument struct {
	Constants struct {
		FixtureKeys map[string]string `json:"fixture_keys"`
	} `json:"constants"`
	HyperlaneEvidence []struct {
		HopIndex     int    `json:"hop_index"`
		Domain       uint32 `json:"domain"`
		Sender       string `json:"sender"`
		Body         string `json:"body"`
		EvidenceHash string `json:"evidence_hash"`
	} `json:"hyperlane_evidence"`
}

func loadVectors(t *testing.T) vectorDocument {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var document vectorDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}

// fixtureSigner builds the personal-message signer shape this package expects
// from internal/evm's Signer: EIP-191 prefixing over the 32-byte digest, then
// ECDSA with go-ethereum's own recovery id convention.
func fixtureSigner(t *testing.T, privateKeyHex string) testSigner {
	t.Helper()
	if privateKeyHex == "" {
		t.Fatal("testdata/vectors.json has no constants.fixture_keys.validator")
	}
	key, err := crypto.HexToECDSA(privateKeyHex[2:])
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}
	return testSigner{key: key}
}

type testSigner struct {
	key *ecdsa.PrivateKey
}

// recoverAddress recovers the signer of one digest, converting the metadata
// signature's {27,28} recovery id to the {0,1} convention go-ethereum's
// `crypto.Ecrecover` expects.
func recoverAddress(t *testing.T, digest [32]byte, signature []byte) common.Address {
	t.Helper()
	recoveryID := append([]byte(nil), signature...)
	if recoveryID[64] >= 27 {
		recoveryID[64] -= 27
	}
	publicKey, err := crypto.Ecrecover(digest[:], recoveryID)
	if err != nil {
		t.Fatalf("Ecrecover: %v", err)
	}
	unmarshalled, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		t.Fatalf("UnmarshalPubkey: %v", err)
	}
	return crypto.PubkeyToAddress(*unmarshalled)
}

func (s testSigner) Address() common.Address {
	return crypto.PubkeyToAddress(s.key.PublicKey)
}

func (s testSigner) SignPersonalDigest(digest [32]byte) ([]byte, error) {
	prefixed := crypto.Keccak256Hash(
		append([]byte("\x19Ethereum Signed Message:\n32"), digest[:]...),
	)
	return crypto.Sign(prefixed[:], s.key)
}
