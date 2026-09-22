package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// vectorDocument is the subset of testdata/vectors.json this package proves
// parity against: the Python runtime's root signatures over each envelope rid.
type vectorDocument struct {
	SchemaVersion string `json:"schema_version"`
	Constants     struct {
		// FixtureKeys holds the signing keys the generator derives from the
		// fixed seed; they are only ever used by tests.
		FixtureKeys map[string]string `json:"fixture_keys"`
		ChainIDs    []uint64          `json:"chain_ids"`
	} `json:"constants"`
	Envelopes []struct {
		RID           string `json:"rid"`
		MID           string `json:"mid"`
		RootSignature string `json:"root_signature"`
	} `json:"envelopes"`
}

func loadVectors(t *testing.T) vectorDocument {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var document vectorDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("cannot decode %s: %v", path, err)
	}
	if len(document.Envelopes) == 0 {
		t.Fatalf("%s carries no envelopes", path)
	}
	return document
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatalf("cannot decode %q: %v", value, err)
	}
	return decoded
}

// TestSignPersonalDigestMatchesPythonVectors proves byte parity with
// eth_account.messages.encode_defunct(primitive=rid) +
// Account.sign_message(...), which is how the Python runtime signs XIR roots
// (runner.py, root_signer.py, layerzero.py).
func TestSignPersonalDigestMatchesPythonVectors(t *testing.T) {
	document := loadVectors(t)
	privateKey := document.Constants.FixtureKeys["root_signer"]
	if privateKey == "" {
		t.Fatal("vectors carry no root_signer fixture key")
	}
	signer, err := NewSigner(privateKey, big.NewInt(int64(document.Constants.ChainIDs[0])))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	for index, envelope := range document.Envelopes {
		var digest [32]byte
		copy(digest[:], mustHex(t, envelope.RID))
		signature, err := signer.SignPersonalDigest(digest)
		if err != nil {
			t.Fatalf("envelope %d: SignPersonalDigest: %v", index, err)
		}
		want := mustHex(t, envelope.RootSignature)
		if len(signature) != len(want) {
			t.Fatalf("envelope %d: signature is %d bytes, want %d", index, len(signature), len(want))
		}
		for offset := range signature {
			if signature[offset] != want[offset] {
				t.Fatalf(
					"envelope %d: signature = 0x%x, want 0x%x",
					index, signature, want,
				)
			}
		}
		recovered, err := RecoverPersonalDigest(digest, signature)
		if err != nil {
			t.Fatalf("envelope %d: RecoverPersonalDigest: %v", index, err)
		}
		if recovered != signer.Address() {
			t.Fatalf("envelope %d: recovered %s, want %s", index, recovered, signer.Address())
		}
	}
}

// TestRecoverPersonalDigestNormalizesRecoveryID proves that both the 27/28
// spelling produced by Solidity tooling and the 0/1 spelling geth's low-level
// recovery expects resolve to the same signer. XIRGateway._recover accepts both
// (`if (v < 27) v += 27;`), so the Go runtime must too.
func TestRecoverPersonalDigestNormalizesRecoveryID(t *testing.T) {
	document := loadVectors(t)
	signer, err := NewSigner(document.Constants.FixtureKeys["root_signer"], big.NewInt(31337))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	var digest [32]byte
	copy(digest[:], mustHex(t, document.Envelopes[0].RID))
	signature, err := signer.SignPersonalDigest(digest)
	if err != nil {
		t.Fatalf("SignPersonalDigest: %v", err)
	}
	ethereumSpelling := append([]byte(nil), signature...)
	rawSpelling := append([]byte(nil), signature...)
	rawSpelling[64] -= 27
	for name, candidate := range map[string][]byte{
		"27/28": ethereumSpelling,
		"0/1":   rawSpelling,
	} {
		recovered, err := RecoverPersonalDigest(digest, candidate)
		if err != nil {
			t.Fatalf("%s: RecoverPersonalDigest: %v", name, err)
		}
		if recovered != signer.Address() {
			t.Fatalf("%s: recovered %s, want %s", name, recovered, signer.Address())
		}
	}
	invalid := append([]byte(nil), signature...)
	invalid[64] = 7
	if _, err := RecoverPersonalDigest(digest, invalid); err == nil {
		t.Fatal("an out-of-range recovery id must be rejected")
	}
	if _, err := RecoverPersonalDigest(digest, signature[:64]); err == nil {
		t.Fatal("a 64 byte signature must be rejected")
	}
}

// TestSignRawDigestSignsTheDigestItself proves SignRawDigest applies no EIP-191
// prefix (the Hyperlane checkpoint convention) while SignPersonalDigest does.
func TestSignRawDigestSignsTheDigestItself(t *testing.T) {
	document := loadVectors(t)
	signer, err := NewSigner(document.Constants.FixtureKeys["validator"], big.NewInt(31337))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	var digest [32]byte
	copy(digest[:], mustHex(t, document.Envelopes[0].MID))
	raw, err := signer.SignRawDigest(digest)
	if err != nil {
		t.Fatalf("SignRawDigest: %v", err)
	}
	personal, err := signer.SignPersonalDigest(digest)
	if err != nil {
		t.Fatalf("SignPersonalDigest: %v", err)
	}
	if string(raw) == string(personal) {
		t.Fatal("the raw digest signature must differ from the personal digest signature")
	}
	// Verify the raw signature against the digest directly, with a different
	// code path from the recovery helper.
	recovered, err := crypto.SigToPub(digest[:], normalizeRecoveryID(t, raw))
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	if crypto.PubkeyToAddress(*recovered) != signer.Address() {
		t.Fatalf("raw signature recovers %s, want %s", crypto.PubkeyToAddress(*recovered), signer.Address())
	}
	prefixed := personalDigestHash(digest)
	if !crypto.VerifySignature(crypto.FromECDSAPub(&signer.key.PublicKey), digest[:], normalizeRecoveryID(t, raw)[:64]) {
		t.Fatal("the raw signature does not verify against the bare digest")
	}
	if crypto.VerifySignature(crypto.FromECDSAPub(&signer.key.PublicKey), prefixed[:], normalizeRecoveryID(t, raw)[:64]) {
		t.Fatal("the raw signature verifies against the personal digest, so it carries a prefix")
	}
	if !crypto.VerifySignature(crypto.FromECDSAPub(&signer.key.PublicKey), prefixed[:], normalizeRecoveryID(t, personal)[:64]) {
		t.Fatal("the personal signature does not verify against the personal digest")
	}
	if raw[64] != 27 && raw[64] != 28 {
		t.Fatalf("raw digest recovery id = %d, want 27 or 28 (eth_account convention)", raw[64])
	}
}

func normalizeRecoveryID(t *testing.T, signature []byte) []byte {
	t.Helper()
	normalized := append([]byte(nil), signature...)
	if normalized[64] >= 27 {
		normalized[64] -= 27
	}
	return normalized
}

func TestNewSignerRejectsInvalidKeysWithoutEchoingThem(t *testing.T) {
	const secret = "0x" + "zz"
	_, err := NewSigner(secret, big.NewInt(1))
	if err == nil {
		t.Fatal("a non-hexadecimal key must be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error message leaks the key: %v", err)
	}
	if _, err := NewSigner("0x00", big.NewInt(1)); err == nil {
		t.Fatal("a short key must be rejected")
	}
	if _, err := NewSigner("0x"+strings.Repeat("11", 32), nil); err == nil {
		t.Fatal("a nil chain id must be rejected")
	}
}

func dialFake(t *testing.T, node *fakeNode) *Client {
	t.Helper()
	server := fakeNodeServer(t, node)
	client, err := Dial(context.Background(), server.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestFinalizedNumberPrefersTheFinalizedTag(t *testing.T) {
	node := newFakeNode(t, withFinalizedTag(9), withHead(12, 0))
	client := dialFake(t, node)
	number, rule, err := client.FinalizedNumber(context.Background())
	if err != nil {
		t.Fatalf("FinalizedNumber: %v", err)
	}
	if number != 9 || rule != "rpc-finalized-tag" {
		t.Fatalf("FinalizedNumber = %d, %q; want 9, rpc-finalized-tag", number, rule)
	}
	if node.requestCount("qbft_getValidatorsByBlockNumber") != 0 {
		t.Error("the QBFT fallback must not run when the finalized tag works")
	}
}

// TestFinalizedNumberQBFTFallback reproduces
// root_signer.Web3RootCreationSource._finalized_number on a private QBFT chain:
// the finalized tag is rejected, the validator quorum is read from
// qbft_getValidatorsByBlockNumber, and the head only becomes final once one
// successor block exists and the observed block is still canonical.
func TestFinalizedNumberQBFTFallback(t *testing.T) {
	node := newFakeNode(t, withHead(7, 1), withValidators(4))
	client := dialFake(t, node)
	number, rule, err := client.FinalizedNumber(context.Background())
	if err != nil {
		t.Fatalf("FinalizedNumber: %v", err)
	}
	if number != 8 {
		t.Fatalf("finalized number = %d, want 8 (head 7 plus one successor)", number)
	}
	if rule != "qbft-committed-plus-1" {
		t.Fatalf("finality rule = %q, want qbft-committed-plus-1", rule)
	}
	if node.requestCount("eth_getBlockByNumber") == 0 || node.requestCount("qbft_getValidatorsByBlockNumber") == 0 {
		t.Errorf("requests = %v, want both block and validator lookups", node.requests)
	}
}

func TestFinalizedNumberQBFTRequiresValidatorQuorum(t *testing.T) {
	node := newFakeNode(t, withHead(7, 1), withValidators(2))
	client := dialFake(t, node)
	_, rule, err := client.FinalizedNumber(context.Background())
	if err == nil {
		t.Fatalf("FinalizedNumber = %q, want a quorum failure", rule)
	}
	if !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("error = %v, want a quorum failure", err)
	}
}

func TestFinalizedNumberQBFTRejectsNonCanonicalBlock(t *testing.T) {
	node := newFakeNode(t, withHead(8, 0), withValidators(4))
	client := dialFake(t, node)
	header, err := client.HeaderByNumber(context.Background(), big.NewInt(7))
	if err != nil {
		t.Fatalf("HeaderByNumber: %v", err)
	}
	number, rule, err := client.FinalizedNumberFor(context.Background(), 7, header.Hash())
	if err != nil {
		t.Fatalf("FinalizedNumberFor: %v", err)
	}
	if number != 8 || rule != "qbft-committed-plus-1" {
		t.Fatalf("FinalizedNumberFor = %d, %q; want 8, qbft-committed-plus-1", number, rule)
	}
	if _, _, err := client.FinalizedNumberFor(
		context.Background(), 7, common.HexToHash("0xdead"),
	); err == nil {
		t.Fatal("a block outside the canonical chain must be rejected")
	}
}

func TestWaitMinedTimesOutWithoutAReceipt(t *testing.T) {
	node := newFakeNode(t, withoutMining())
	client := dialFake(t, node)
	_, err := client.WaitMined(context.Background(), common.HexToHash("0x01"), 200*time.Millisecond)
	if err == nil {
		t.Fatal("WaitMined must fail when no receipt appears")
	}
	if !strings.Contains(err.Error(), "was not mined") {
		t.Fatalf("error = %v, want a not-mined failure", err)
	}
}

func TestReceiptIsNilBeforeMining(t *testing.T) {
	node := newFakeNode(t, withoutMining())
	client := dialFake(t, node)
	receipt, err := client.Receipt(context.Background(), common.HexToHash("0x01"))
	if err != nil {
		t.Fatalf("Receipt: %v", err)
	}
	if receipt != nil {
		t.Fatalf("Receipt = %+v, want nil", receipt)
	}
}

type rpcFailureError struct {
	code    int
	message string
}

func (e rpcFailureError) Error() string  { return e.message }
func (e rpcFailureError) ErrorCode() int { return e.code }

type transportFailure struct{}

func (transportFailure) Error() string   { return "connection reset by peer" }
func (transportFailure) Timeout() bool   { return false }
func (transportFailure) Temporary() bool { return true }

var _ net.Error = transportFailure{}

func TestIsTransientRPCError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("reverted"), false},
		{"transport", transportFailure{}, true},
		{"eof", io.EOF, true},
		{"deadline", context.DeadlineExceeded, true},
		{"cancelled", context.Canceled, false},
		{
			"besu catch-up",
			rpcFailureError{code: -32000, message: "Transaction pool not enabled. Node not yet in sync."},
			true,
		},
		{
			"pool disabled only",
			rpcFailureError{code: -32000, message: "transaction pool not enabled"},
			false,
		},
		{"insufficient funds", rpcFailureError{code: -32000, message: "insufficient funds for gas * price + value"}, false},
	}
	for _, testCase := range cases {
		if observed := IsTransientRPCError(testCase.err); observed != testCase.want {
			t.Errorf("%s: IsTransientRPCError = %v, want %v", testCase.name, observed, testCase.want)
		}
	}
	priorSubmission := rpcFailureError{code: -32000, message: "already known"}
	if !IsAcceptedPriorSubmission(priorSubmission) {
		t.Error("'already known' must be accepted as a prior submission")
	}
	if IsTransientRPCError(priorSubmission) {
		t.Error("a prior submission is not a transient transport failure")
	}
	for _, message := range []string{
		"already known",
		"ALREADY KNOWN transaction",
		"known transaction: 0xabc",
		"nonce too low: next nonce 7, tx nonce 5",
	} {
		if !IsAcceptedPriorSubmission(rpcFailureError{code: -32000, message: message}) {
			t.Errorf("%q must be accepted as a prior submission", message)
		}
	}
	if IsAcceptedPriorSubmission(errors.New("insufficient funds")) {
		t.Error("a funding failure is not a prior submission")
	}
}
