package evm

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	_ "modernc.org/sqlite"

	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

const testPrivateKey = "0x1111111111111111111111111111111111111111111111111111111111111111"

type harness struct {
	node       *fakeNode
	client     *Client
	signer     *Signer
	store      *state.Store
	transactor *Transactor
	spoolRoot  string
}

// withTransactionTimeout shortens the receipt wait so a test that expects a
// missing receipt does not spend the production timeout.
func withTransactionTimeout(timeout time.Duration) harnessOption {
	return func(configuration *harnessConfiguration) { configuration.timeout = timeout }
}

type harnessConfiguration struct {
	timeout time.Duration
}

type harnessOption func(*harnessConfiguration)

func newHarness(t *testing.T, options ...any) *harness {
	t.Helper()
	configuration := harnessConfiguration{timeout: 5 * time.Second}
	var nodeOptions []fakeNodeOption
	for _, option := range options {
		switch typed := option.(type) {
		case harnessOption:
			typed(&configuration)
		case fakeNodeOption:
			nodeOptions = append(nodeOptions, typed)
		default:
			t.Fatalf("unsupported harness option %T", option)
		}
	}
	node := newFakeNode(t, nodeOptions...)
	client := dialFake(t, node)
	signer, err := NewSigner(testPrivateKey, big.NewInt(int64(node.chainID)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "runner", "runner.sqlite"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	spoolRoot := filepath.Join(t.TempDir(), "private-raw")
	transactor, err := NewTransactor(client, signer, store, spoolRoot, configuration.timeout)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	return &harness{
		node:       node,
		client:     client,
		signer:     signer,
		store:      store,
		transactor: transactor,
		spoolRoot:  spoolRoot,
	}
}

func destination(t *testing.T) common.Address {
	t.Helper()
	return common.HexToAddress("0x00000000000000000000000000000000000000aa")
}

// TestExecuteFreezesIntentSignsSpoolsAndSucceeds walks the whole
// intent -> frozen calldata -> signed -> submitted -> receipt chain and checks
// every durable artifact it produces.
func TestExecuteFreezesIntentSignsSpoolsAndSucceeds(t *testing.T) {
	subject := newHarness(t, withPendingNonce(4))
	target := destination(t)
	request := TxRequest{
		ActionID:  "action-fresh",
		AttemptID: "attempt-1",
		Stage:     "root_create",
		ChainRole: "a",
		To:        target,
		Value:     big.NewInt(1),
		Gas:       21_000,
	}
	result, err := subject.transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.TransactionHash == "" || result.GasUsed != 21_000 || result.BlockNumber == 0 {
		t.Fatalf("result = %+v", result)
	}
	action, err := subject.store.Action(request.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if action.State != state.ActionSucceeded {
		t.Fatalf("action state = %q, want succeeded", action.State)
	}
	if action.Nonce != 4 {
		t.Errorf("frozen nonce = %d, want the chain's pending nonce 4", action.Nonce)
	}
	if action.To != strings.ToLower(target.Hex()) || action.Gas != 21_000 || action.Value != "1" {
		t.Errorf("frozen action = %+v", action)
	}
	if action.CalldataSHA256 != sha256Hex(nil) || action.CalldataBytes != 0 {
		t.Errorf("frozen calldata digest = %s/%d", action.CalldataSHA256, action.CalldataBytes)
	}
	if err := state.VerifyActionIdentity(action); err != nil {
		t.Fatalf("VerifyActionIdentity: %v", err)
	}
	// The raw signed transaction and the receipt are both in the private spool,
	// mode 0600, and the receipt digest matches the file.
	rawPath := filepath.Join(subject.spoolRoot, strings.TrimPrefix(result.TransactionHash, "0x")+".raw")
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("raw spool: %v", err)
	}
	if hex.EncodeToString(raw) != strings.TrimPrefix(action.RawTransactionHex, "0x") {
		t.Fatal("the spooled raw transaction differs from the durable row")
	}
	if observed := crypto.Keccak256Hash(raw).Hex(); observed != result.TransactionHash {
		t.Fatalf("spooled raw hashes to %s, want %s", observed, result.TransactionHash)
	}
	receiptContents, err := os.ReadFile(result.ReceiptPath)
	if err != nil {
		t.Fatalf("receipt spool: %v", err)
	}
	if observed := sha256Hex(receiptContents); observed != result.ReceiptSHA256 {
		t.Fatalf("receipt digest = %s, want %s", observed, result.ReceiptSHA256)
	}
	if action.ReceiptSHA256 != result.ReceiptSHA256 || action.ReceiptPath != result.ReceiptPath {
		t.Fatalf("durable receipt evidence = %s/%s", action.ReceiptPath, action.ReceiptSHA256)
	}
	if !strings.HasSuffix(result.ReceiptPath, ".json") || !strings.HasSuffix(rawPath, ".raw") {
		t.Errorf("spool paths = %s, %s", result.ReceiptPath, rawPath)
	}
	for name, path := range map[string]string{"receipt": result.ReceiptPath, "raw": rawPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s stat: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, mode)
		}
	}
	if mode, err := os.Stat(subject.spoolRoot); err != nil {
		t.Fatalf("spool root stat: %v", err)
	} else if perm := mode.Mode().Perm(); perm != 0o700 {
		t.Errorf("spool root mode = %o, want 700", perm)
	}
	if result.Detail["receipt"] != result.ReceiptPath ||
		result.Detail["receipt_sha256"] != result.ReceiptSHA256 ||
		result.Detail["calldata_bytes"] != 0 ||
		result.Detail["gas_used"] != uint64(21_000) ||
		result.Detail["block_number"] != result.BlockNumber {
		t.Fatalf("result detail = %#v", result.Detail)
	}
	// The Python runner ledger is mirrored when the action carries a stage.
	stage, err := subject.store.Stage(request.AttemptID, request.Stage)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if stage == nil || stage.State != state.ActionSucceeded || stage.TransactionHash == nil ||
		*stage.TransactionHash != result.TransactionHash {
		t.Fatalf("mirrored stage = %+v", stage)
	}
	if durable := rawQueryInt(t, subject.store,
		"SELECT COUNT(*) FROM durable_signed_transactions WHERE attempt_id = ? AND stage = ?",
		request.AttemptID, request.Stage); durable != 1 {
		t.Errorf("durable signed rows = %d, want 1", durable)
	}
	if len(subject.node.recordedBroadcasts()) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(subject.node.recordedBroadcasts()))
	}
}

// TestExecuteReportsSucceededActionWithoutSecondBroadcast is the restart case:
// a previous process signed and submitted, then died. The resumed process finds
// the receipt already on chain and must not broadcast again.
func TestExecuteReportsSucceededActionWithoutSecondBroadcast(t *testing.T) {
	subject := newHarness(t, withPendingNonce(9))
	target := destination(t)
	data := []byte{0x12, 0x34}

	// Reconstruct what the previous process left behind: a frozen intent, the
	// signed bytes and a submitted boundary.
	nonce := uint64(9)
	gas := uint64(60_000)
	transaction := &types.DynamicFeeTx{
		ChainID:   big.NewInt(int64(subject.node.chainID)),
		Nonce:     nonce,
		GasTipCap: new(big.Int),
		GasFeeCap: big.NewInt(3_000_000_000),
		Gas:       gas,
		To:        &target,
		Value:     big.NewInt(2),
		Data:      data,
	}
	signed, err := subject.signer.SignDynamicFee(transaction)
	if err != nil {
		t.Fatalf("SignDynamicFee: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	frozen, err := subject.store.Intend(state.Action{
		ActionID:       "action-resumed",
		AttemptID:      "attempt-1",
		Stage:          "hop_0_h_dispatch",
		ChainRole:      "a",
		ChainID:        subject.node.chainID,
		Sender:         strings.ToLower(subject.signer.Address().Hex()),
		To:             strings.ToLower(target.Hex()),
		CalldataHex:    "0x" + hex.EncodeToString(data),
		CalldataBytes:  len(data),
		CalldataSHA256: sha256Hex(data),
		Value:          "2",
		Gas:            gas,
		Nonce:          nonce,
		DetailJSON:     `{"role": "a"}`,
	})
	if err != nil {
		t.Fatalf("Intend: %v", err)
	}
	if err := subject.store.RecordSigned(frozen.ActionID, raw, signed.Hash().Hex()); err != nil {
		t.Fatalf("RecordSigned: %v", err)
	}
	if err := subject.store.Observe(frozen.ActionID, state.ActionSubmitted, nil); err != nil {
		t.Fatalf("Observe submitted: %v", err)
	}
	subject.node.seedReceipt(signed.Hash(), 1, 31, 42_000, nil)

	result, err := subject.transactor.Execute(context.Background(), TxRequest{
		ActionID:  frozen.ActionID,
		AttemptID: "attempt-1",
		Stage:     "hop_0_h_dispatch",
		ChainRole: "a",
		To:        target,
		Value:     big.NewInt(2),
		Data:      data,
		Gas:       gas,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if broadcasts := subject.node.recordedBroadcasts(); len(broadcasts) != 0 {
		t.Fatalf("broadcasts = %d, want 0 for an action whose receipt already exists", len(broadcasts))
	}
	if result.TransactionHash != signed.Hash().Hex() || result.BlockNumber != 31 || result.GasUsed != 42_000 {
		t.Fatalf("result = %+v", result)
	}
	if result.ReceiptSHA256 == "" {
		t.Fatal("the resumed action must spool its receipt")
	}
	contents, err := os.ReadFile(result.ReceiptPath)
	if err != nil {
		t.Fatalf("receipt spool: %v", err)
	}
	if observed := sha256Hex(contents); observed != result.ReceiptSHA256 {
		t.Fatalf("receipt digest = %s, want %s", observed, result.ReceiptSHA256)
	}
	action, err := subject.store.Action(frozen.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if action.State != state.ActionSucceeded || action.BlockNumber != 31 {
		t.Fatalf("action after resume = %+v", action)
	}
	// A second replay is answered from the ledger and still does not broadcast.
	replayed, err := subject.transactor.Execute(context.Background(), TxRequest{
		ActionID: frozen.ActionID, ChainRole: "a",
	})
	if err != nil {
		t.Fatalf("Execute replay: %v", err)
	}
	if replayed.TransactionHash != result.TransactionHash || replayed.ReceiptSHA256 != result.ReceiptSHA256 {
		t.Fatalf("replayed result = %+v", replayed)
	}
	if broadcasts := subject.node.recordedBroadcasts(); len(broadcasts) != 0 {
		t.Fatalf("replay broadcast %d transactions, want 0", len(broadcasts))
	}
}

// TestExecuteAcceptsPriorSubmission proves the three node answers that mean "this
// transaction is already known" are treated as an accepted broadcast, matching
// multihop_runner._transact.
func TestExecuteAcceptsPriorSubmission(t *testing.T) {
	for _, message := range []string{"already known", "known transaction: 0xdead", "nonce too low"} {
		t.Run(message, func(t *testing.T) {
			subject := newHarness(t, withBroadcastError(message))
			result, err := subject.transactor.Execute(context.Background(), TxRequest{
				ActionID:  "action-prior",
				ChainRole: "a",
				To:        destination(t),
				Value:     big.NewInt(1),
				Gas:       21_000,
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.TransactionHash == "" || result.ReceiptSHA256 == "" {
				t.Fatalf("result = %+v", result)
			}
			if broadcasts := subject.node.recordedBroadcasts(); len(broadcasts) != 1 {
				t.Fatalf("broadcast attempts = %d, want 1", len(broadcasts))
			}
			action, err := subject.store.Action("action-prior")
			if err != nil {
				t.Fatalf("Action: %v", err)
			}
			if action.State != state.ActionSucceeded {
				t.Fatalf("action state = %q, want succeeded", action.State)
			}
		})
	}
}

// TestExecuteRejectsHardBroadcastFailure keeps the action replayable: a failure
// that is not a prior submission must leave the signed action intact, so the
// caller can retry without re-freezing the intent.
func TestExecuteRejectsHardBroadcastFailure(t *testing.T) {
	subject := newHarness(
		t,
		withBroadcastError("insufficient funds for gas * price + value"),
		withoutMining(),
		withTransactionTimeout(300*time.Millisecond),
	)
	_, err := subject.transactor.Execute(context.Background(), TxRequest{
		ActionID:  "action-hard-failure",
		ChainRole: "a",
		To:        destination(t),
		Value:     big.NewInt(1),
		Gas:       21_000,
	})
	if err == nil {
		t.Fatal("a hard broadcast failure must surface")
	}
	action, lookupErr := subject.store.Action("action-hard-failure")
	if lookupErr != nil {
		t.Fatalf("Action: %v", lookupErr)
	}
	if action.State != state.ActionSigned {
		t.Fatalf("action state = %q, want signed so the transaction can be resubmitted", action.State)
	}
	if err := state.VerifyActionIdentity(action); err != nil {
		t.Fatalf("VerifyActionIdentity after a failed broadcast: %v", err)
	}
}

// TestExecuteReturnsTheDeployedAddress covers contract creation: the mined
// receipt's contract address is durable, so re-running a deployment after a
// crash returns the same address instead of losing it.
func TestExecuteReturnsTheDeployedAddress(t *testing.T) {
	subject := newHarness(t, withPendingNonce(1))
	created := common.HexToAddress("0x00000000000000000000000000000000000000dd")
	initCode := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
	request := TxRequest{
		ActionID:   "action-deploy",
		ChainRole:  "deployment",
		DeployCode: initCode,
		Gas:        500_000,
	}
	// Mine the creation receipt the deployment will produce.
	subject.node.mineCreation = &created
	result, err := subject.transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.ContractAddress != created.Hex() {
		t.Fatalf("ContractAddress = %q, want %q", result.ContractAddress, created.Hex())
	}
	replayed, err := subject.transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute replay: %v", err)
	}
	if replayed.ContractAddress != created.Hex() {
		t.Fatalf("replayed ContractAddress = %q, want %q", replayed.ContractAddress, created.Hex())
	}
	if broadcasts := subject.node.recordedBroadcasts(); len(broadcasts) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(broadcasts))
	}
	action, err := subject.store.Action(request.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if action.To != "" {
		t.Fatalf("a creation must not freeze a destination, got %q", action.To)
	}
}

// TestExecuteRejectsMutatedLedgerRow proves a durable row edited behind the
// store's back cannot be rebroadcast: the frozen fields are re-derived from the
// signed bytes before the second attempt.
func TestExecuteRejectsMutatedLedgerRow(t *testing.T) {
	mutations := map[string]string{
		"gas":          "UPDATE actions SET gas = 1 WHERE action_id = ?",
		"nonce":        "UPDATE actions SET nonce = 77 WHERE action_id = ?",
		"value":        "UPDATE actions SET value = '999' WHERE action_id = ?",
		"chain_id":     "UPDATE actions SET chain_id = 1 WHERE action_id = ?",
		"calldata_hex": "UPDATE actions SET calldata_hex = '0xdead' WHERE action_id = ?",
		"transaction":  "UPDATE actions SET transaction_hash = '0x' || printf('%.64d', 0) WHERE action_id = ?",
	}
	for name, statement := range mutations {
		t.Run(name, func(t *testing.T) {
			subject := newHarness(t, withPendingNonce(3), withoutMining(), withTransactionTimeout(300*time.Millisecond))
			request := TxRequest{
				ActionID:  "action-mutated",
				ChainRole: "a",
				To:        destination(t),
				Value:     big.NewInt(1),
				Gas:       21_000,
			}
			if _, err := subject.transactor.Execute(context.Background(), request); err == nil {
				t.Fatal("the first attempt must fail without a receipt")
			}
			rawExec(t, subject.store, statement, request.ActionID)
			_, err := subject.transactor.Execute(context.Background(), TxRequest{
				ActionID:  request.ActionID,
				ChainRole: "a",
			})
			if err == nil {
				t.Fatal("a mutated durable row must be rejected")
			}
			if !errors.Is(err, state.ErrDrift) {
				t.Fatalf("error = %v, want ErrDrift", err)
			}
		})
	}
}

// TestExecuteRejectsAChangedRequest rejects a caller whose replay disagrees with
// the frozen intent, which is how a wrong calldata or target is caught before it
// is signed.
func TestExecuteRejectsAChangedRequest(t *testing.T) {
	subject := newHarness(t, withPendingNonce(2), withoutMining(), withTransactionTimeout(300*time.Millisecond))
	request := TxRequest{
		ActionID:  "action-changed",
		ChainRole: "a",
		To:        destination(t),
		Data:      []byte{0x01, 0x02},
		Gas:       21_000,
	}
	if _, err := subject.transactor.Execute(context.Background(), request); err == nil {
		t.Fatal("the first attempt must fail without a receipt")
	}
	changed := request
	changed.Data = []byte{0x03, 0x04}
	if _, err := subject.transactor.Execute(context.Background(), changed); !errors.Is(err, state.ErrDrift) {
		t.Fatalf("changed calldata error = %v, want ErrDrift", err)
	}
	changed = request
	changed.To = common.HexToAddress("0x00000000000000000000000000000000000000bb")
	if _, err := subject.transactor.Execute(context.Background(), changed); !errors.Is(err, state.ErrDrift) {
		t.Fatalf("changed target error = %v, want ErrDrift", err)
	}
	changed = request
	changed.Gas = 30_000
	if _, err := subject.transactor.Execute(context.Background(), changed); !errors.Is(err, state.ErrDrift) {
		t.Fatalf("changed gas error = %v, want ErrDrift", err)
	}
	changed = request
	changed.ChainRole = "b"
	if _, err := subject.transactor.Execute(context.Background(), changed); !errors.Is(err, state.ErrDrift) {
		t.Fatalf("changed chain role error = %v, want ErrDrift", err)
	}
}

// TestReserveNonceDoesNotReuseADurableNonce reproduces
// multihop_runner's startup rule: the reserved nonce starts above every nonce the
// ledger already holds, so a signed transaction that never reached the network
// cannot be overwritten by a different action.
func TestReserveNonceDoesNotReuseADurableNonce(t *testing.T) {
	subject := newHarness(t, withPendingNonce(1))
	if _, err := subject.store.Intend(state.Action{
		ActionID:       "action-unbroadcast",
		ChainRole:      "a",
		ChainID:        subject.node.chainID,
		Sender:         strings.ToLower(subject.signer.Address().Hex()),
		To:             strings.ToLower(destination(t).Hex()),
		CalldataHex:    "0x01",
		CalldataBytes:  1,
		CalldataSHA256: sha256Hex([]byte{0x01}),
		Value:          "0",
		Gas:            21_000,
		Nonce:          12,
	}); err != nil {
		t.Fatalf("Intend: %v", err)
	}
	nonce, err := subject.transactor.ReserveNonce(context.Background())
	if err != nil {
		t.Fatalf("ReserveNonce: %v", err)
	}
	if nonce != 13 {
		t.Fatalf("reserved nonce = %d, want 13 (above the durable nonce 12)", nonce)
	}
	next, err := subject.transactor.ReserveNonce(context.Background())
	if err != nil {
		t.Fatalf("ReserveNonce: %v", err)
	}
	if next != 14 {
		t.Fatalf("second reserved nonce = %d, want 14", next)
	}
}

// rawQueryInt and rawExec touch the database from outside the store, the way a
// stray manual edit or a truncated spill file would.
func rawQueryInt(t *testing.T, store *state.Store, statement string, args ...any) int64 {
	t.Helper()
	connection := openRawConnection(t, store)
	defer connection.Close()
	var value int64
	if err := connection.QueryRow(statement, args...).Scan(&value); err != nil {
		t.Fatalf("raw query: %v", err)
	}
	return value
}

func rawExec(t *testing.T, store *state.Store, statement string, args ...any) {
	t.Helper()
	connection := openRawConnection(t, store)
	defer connection.Close()
	if _, err := connection.Exec(statement, args...); err != nil {
		t.Fatalf("raw exec: %v", err)
	}
}

func openRawConnection(t *testing.T, store *state.Store) *sql.DB {
	t.Helper()
	connection, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	return connection
}

// TestExecuteSignsAFrozenIntentAfterACrash covers the restart window between the
// durable intent and the signature: the process froze the calldata and the fee
// caps, then died. The resumed process must sign exactly that intent instead of
// choosing new fees.
func TestExecuteSignsAFrozenIntentAfterACrash(t *testing.T) {
	subject := newHarness(t, withPendingNonce(6))
	target := destination(t)
	subject.node.mineCreation = nil
	data := []byte{0xaa, 0xbb, 0xcc}
	frozenFee := new(big.Int).SetUint64(7_000_000_000)
	detail, err := state.CanonicalJSON(map[string]any{
		"role":                     "a",
		"nonce":                    6,
		"target":                   strings.ToLower(target.Hex()),
		"calldata_sha256":          sha256Hex(data),
		"calldata_bytes":           len(data),
		"chain_id":                 subject.node.chainID,
		"max_fee_per_gas":          frozenFee.String(),
		"max_priority_fee_per_gas": "0",
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if _, err := subject.store.Intend(state.Action{
		ActionID:       "action-frozen-intent",
		ChainRole:      "a",
		ChainID:        subject.node.chainID,
		Sender:         strings.ToLower(subject.signer.Address().Hex()),
		To:             strings.ToLower(target.Hex()),
		CalldataHex:    "0x" + hex.EncodeToString(data),
		CalldataBytes:  len(data),
		CalldataSHA256: sha256Hex(data),
		Value:          "0",
		Gas:            45_000,
		Nonce:          6,
		DetailJSON:     detail,
	}); err != nil {
		t.Fatalf("Intend: %v", err)
	}
	result, err := subject.transactor.Execute(context.Background(), TxRequest{
		ActionID:  "action-frozen-intent",
		ChainRole: "a",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	broadcasts := subject.node.recordedBroadcasts()
	if len(broadcasts) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(broadcasts))
	}
	var signed types.Transaction
	if err := signed.UnmarshalBinary(broadcasts[0]); err != nil {
		t.Fatalf("the broadcast bytes are not a transaction: %v", err)
	}
	if signed.GasFeeCap().Cmp(frozenFee) != 0 {
		t.Fatalf("signed fee cap = %s, want the frozen %s", signed.GasFeeCap(), frozenFee)
	}
	if signed.GasTipCap().Sign() != 0 {
		t.Fatalf("signed priority fee = %s, want 0", signed.GasTipCap())
	}
	if signed.Nonce() != 6 || signed.Gas() != 45_000 || signed.Value().Sign() != 0 {
		t.Fatalf("signed transaction = nonce %d, gas %d, value %s", signed.Nonce(), signed.Gas(), signed.Value())
	}
	if signed.To() == nil || *signed.To() != target {
		t.Fatalf("signed target = %v, want %s", signed.To(), target)
	}
	if string(signed.Data()) != string(data) {
		t.Fatalf("signed calldata = 0x%x, want 0x%x", signed.Data(), data)
	}
	if result.TransactionHash != signed.Hash().Hex() {
		t.Fatalf("result hash = %s, want %s", result.TransactionHash, signed.Hash().Hex())
	}
}

// TestReserveNonceIsScopedToOneAccount is the regression guard for the reported
// route blocker: the runner and the embedded protocol agents share a chain, each
// with its own nonce space. A durable action signed by another account must not
// raise the runner's floor, while the runner's own durable action still must.
func TestReserveNonceIsScopedToOneAccount(t *testing.T) {
	subject := newHarness(t, withPendingNonce(0), withoutMining(),
		withTransactionTimeout(300*time.Millisecond))
	otherKey := loadVectors(t).Constants.FixtureKeys["validator"]
	if otherKey == "" || otherKey == testPrivateKey {
		t.Fatal("the vectors must carry a second distinct fixture key")
	}
	otherSigner, err := NewSigner(otherKey, big.NewInt(int64(subject.node.chainID)))
	if err != nil {
		t.Fatalf("NewSigner(other): %v", err)
	}
	// The other account consumed nonce 0 on this chain.
	target := destination(t)
	transaction := &types.DynamicFeeTx{
		ChainID:   big.NewInt(int64(subject.node.chainID)),
		Nonce:     0,
		GasTipCap: new(big.Int),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21_000,
		To:        &target,
		Value:     big.NewInt(0),
	}
	signed, err := otherSigner.SignDynamicFee(transaction)
	if err != nil {
		t.Fatalf("SignDynamicFee: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	foreign, err := subject.store.Intend(state.Action{
		ActionID:       "action-foreign-account",
		ChainRole:      "b",
		ChainID:        subject.node.chainID,
		Sender:         strings.ToLower(otherSigner.Address().Hex()),
		To:             strings.ToLower(target.Hex()),
		CalldataHex:    "0x",
		CalldataBytes:  0,
		CalldataSHA256: sha256Hex(nil),
		Value:          "0",
		Gas:            21_000,
		Nonce:          0,
	})
	if err != nil {
		t.Fatalf("Intend: %v", err)
	}
	if err := subject.store.RecordSigned(foreign.ActionID, raw, signed.Hash().Hex()); err != nil {
		t.Fatalf("RecordSigned: %v", err)
	}
	// The runner account has sent nothing, so its first transaction must be
	// frozen with nonce 0 even though another account already holds nonce 0 on
	// the same chain. The transaction is not mined by the fake node, so Execute
	// stops at the receipt wait; the frozen intent is what this test reads.
	own := TxRequest{
		ActionID:  "action-own-account",
		ChainRole: "b",
		To:        target,
		Gas:       21_000,
	}
	if _, err := subject.transactor.Execute(context.Background(), own); err == nil {
		t.Fatal("Execute must fail while no receipt appears")
	}
	frozen, err := subject.store.Action(own.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if frozen.Nonce != 0 {
		t.Fatalf("frozen nonce = %d, want 0: another account's actions must not raise the floor", frozen.Nonce)
	}
	if frozen.Sender != strings.ToLower(subject.signer.Address().Hex()) {
		t.Fatalf("frozen sender = %q", frozen.Sender)
	}
	// The runner's own durable nonce 0 does raise it, so a restarted transactor
	// cannot hand nonce 0 out a second time.
	restarted, err := NewTransactor(subject.client, subject.signer, subject.store, subject.spoolRoot, time.Second)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	nonce, err := restarted.ReserveNonce(context.Background())
	if err != nil {
		t.Fatalf("ReserveNonce: %v", err)
	}
	if nonce != 1 {
		t.Fatalf("reserved nonce = %d, want 1 (above this account's durable nonce 0)", nonce)
	}
	// A second transactor signing with another key is unaffected by the above.
	nonce, err = otherTransactor(t, subject, otherKey).ReserveNonce(context.Background())
	if err != nil {
		t.Fatalf("ReserveNonce(other): %v", err)
	}
	if nonce != 1 {
		t.Fatalf("reserved nonce for the other account = %d, want 1", nonce)
	}
}

func otherTransactor(t *testing.T, subject *harness, privateKey string) *Transactor {
	t.Helper()
	signer, err := NewSigner(privateKey, big.NewInt(int64(subject.node.chainID)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	transactor, err := NewTransactor(subject.client, signer, subject.store, subject.spoolRoot, time.Second)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	return transactor
}

func TestNewTransactorRejectsAMismatchedChain(t *testing.T) {
	node := newFakeNode(t)
	client := dialFake(t, node)
	signer, err := NewSigner(testPrivateKey, big.NewInt(99))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "runner.sqlite"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer store.Close()
	if _, err := NewTransactor(client, signer, store, filepath.Join(t.TempDir(), "raw"), 0); err == nil {
		t.Fatal("a signer bound to another chain must be rejected")
	}
}

func TestExecuteFreezesCallerIntentAndRejectsDrift(t *testing.T) {
	h := newHarness(t)
	request := TxRequest{ActionID: "caller-intent", ChainRole: "a", To: destination(t), Gas: 100000, IntentDetail: map[string]any{"record_nonce": uint64(7)}}
	first, err := h.transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	action, err := h.store.Action(request.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := action.Detail()
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := state.CanonicalJSON(detail["intent_detail"])
	expected, _ := state.CanonicalJSON(request.IntentDetail)
	if err != nil || frozen != expected {
		t.Fatalf("intent not persisted: %s %v", frozen, err)
	}
	again, err := h.transactor.Execute(context.Background(), request)
	if err != nil || again.TransactionHash != first.TransactionHash {
		t.Fatalf("replay: %+v %v", again, err)
	}
	request.IntentDetail["record_nonce"] = uint64(8)
	if _, err := h.transactor.Execute(context.Background(), request); !errors.Is(err, state.ErrDrift) {
		t.Fatalf("changed intent was not rejected: %v", err)
	}
}
