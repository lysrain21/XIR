package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

// anvilBinaryCandidates are the locations the runtime uses for the local node;
// the integration test skips only when none of them exists.
var anvilBinaryCandidates = []string{
	"anvil",
	"/home/ubuntu/.foundry/bin/anvil",
}

// firstAvailableBinary resolves the first candidate that exists, so the
// integration tests skip only when every documented location is genuinely
// absent.
func firstAvailableBinary(candidates []string) (string, bool) {
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, true
		}
	}
	return "", false
}

func findAnvil(t *testing.T) string {
	t.Helper()
	path, found := firstAvailableBinary(anvilBinaryCandidates)
	if !found {
		t.Skip("anvil is not installed, so the anvil integration test is skipped")
	}
	return path
}

// TestAnvilSkipCondition proves the skip above fires only for a genuinely
// missing binary, and that this host runs the integration tests for real.
func TestAnvilSkipCondition(t *testing.T) {
	if path, found := firstAvailableBinary([]string{"/nonexistent/xir-anvil-probe"}); found {
		t.Fatalf("an absent binary resolved to %q", path)
	}
	if _, found := firstAvailableBinary(anvilBinaryCandidates); !found {
		t.Skip("anvil is genuinely absent on this host, so the integration tests skip")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot reserve a port: %v", err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address %T", listener.Addr())
	}
	return address.Port
}

type anvilNode struct {
	endpoint string
	command  *exec.Cmd
	output   strings.Builder
	mu       sync.Mutex
}

// startAnvil launches a disposable local chain and waits until it answers RPC.
func startAnvil(t *testing.T) *anvilNode {
	t.Helper()
	binary := findAnvil(t)
	port := freePort(t)
	node := &anvilNode{endpoint: fmt.Sprintf("http://127.0.0.1:%d", port)}
	node.command = exec.Command(binary, "--port", fmt.Sprint(port), "--silent")
	node.command.Stdout = &node.output
	node.command.Stderr = &node.output
	if err := node.command.Start(); err != nil {
		t.Fatalf("cannot start anvil: %v", err)
	}
	t.Cleanup(func() {
		if node.command.Process != nil {
			_ = node.command.Process.Kill()
		}
		_ = node.command.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := rpc.DialContext(context.Background(), node.endpoint)
		if err == nil {
			var chainID string
			if err := connection.CallContext(context.Background(), &chainID, "eth_chainId"); err == nil {
				connection.Close()
				return node
			}
			connection.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("anvil did not become ready at %s:\n%s", node.endpoint, node.output.String())
	return nil
}

func (n *anvilNode) logs() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.output.String()
}

// fund credits an account through anvil's administrative RPC, so the test signs
// with the repository fixture keys instead of a well-known development key.
func (n *anvilNode) fund(t *testing.T, address common.Address, wei *big.Int) {
	t.Helper()
	connection, err := rpc.DialContext(context.Background(), n.endpoint)
	if err != nil {
		t.Fatalf("cannot dial anvil: %v", err)
	}
	defer connection.Close()
	var accepted bool
	if err := connection.CallContext(
		context.Background(), &accepted, "anvil_setBalance", address, hexutil.EncodeBig(wei),
	); err != nil {
		t.Fatalf("anvil_setBalance: %v", err)
	}
}

// TestAnvilTransactorRoundTrip sends one EIP-1559 value transfer through the
// transactor, proves the persisted receipt digest matches the spooled receipt,
// and proves the action is still succeeded after the store is reopened.
func TestAnvilTransactorRoundTrip(t *testing.T) {
	node := startAnvil(t)
	vectors := loadVectors(t)
	privateKey := vectors.Constants.FixtureKeys["validator"]
	if privateKey == "" {
		t.Fatal("vectors carry no validator fixture key")
	}
	client, err := Dial(context.Background(), node.endpoint, 10*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	signer, err := NewSigner(privateKey, chainID)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	node.fund(t, signer.Address(), new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18)))

	databasePath := filepath.Join(t.TempDir(), "runtime", "runner.sqlite")
	store, err := state.Open(databasePath)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	spoolRoot := filepath.Join(t.TempDir(), "private-raw")
	transactor, err := NewTransactor(client, signer, store, spoolRoot, 30*time.Second)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000b0")
	request := TxRequest{
		ActionID:  ActionID("a", 0, "anvil-transfer", nil),
		AttemptID: "attempt-anvil-1",
		Stage:     "root_create",
		ChainRole: "a",
		To:        recipient,
		Value:     big.NewInt(1),
		Gas:       21_000,
	}
	result, err := transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute: %v\n%s", err, node.logs())
	}
	if result.BlockNumber == 0 || result.GasUsed != 21_000 {
		t.Fatalf("result = %+v", result)
	}
	if result.ContractAddress != "" {
		t.Errorf("a value transfer reported a contract address %q", result.ContractAddress)
	}
	// The receipt evidence on disk matches the digest recorded in the ledger.
	contents, err := os.ReadFile(result.ReceiptPath)
	if err != nil {
		t.Fatalf("receipt file: %v", err)
	}
	if observed := sha256Hex(contents); observed != result.ReceiptSHA256 {
		t.Fatalf("receipt digest = %s, want %s", observed, result.ReceiptSHA256)
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("the spooled receipt is not JSON: %v", err)
	}
	if hash, ok := document["transactionHash"].(string); !ok || hash != result.TransactionHash {
		t.Fatalf("spooled receipt transactionHash = %#v, want %s", document["transactionHash"], result.TransactionHash)
	}
	// The document is rendered the way the Python runner renders it (sorted keys,
	// two-space indent, trailing newline), so re-rendering it reproduces the file
	// byte for byte.
	reRendered, err := state.CanonicalJSONIndent(document, 2)
	if err != nil {
		t.Fatalf("CanonicalJSONIndent: %v", err)
	}
	if string(contents) != reRendered+"\n" {
		t.Fatalf("the spooled receipt is not in the canonical Python layout:\n%s", contents)
	}
	if !strings.HasSuffix(reRendered, "}") {
		t.Fatalf("re-rendered receipt = %q", reRendered)
	}
	for name, path := range map[string]string{
		"receipt": result.ReceiptPath,
		"raw":     filepath.Join(spoolRoot, strings.TrimPrefix(result.TransactionHash, "0x")+".raw"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, mode)
		}
	}
	// The chain agrees: the transaction is mined and the value arrived.
	onChain, err := client.Receipt(context.Background(), common.HexToHash(result.TransactionHash))
	if err != nil {
		t.Fatalf("Receipt: %v", err)
	}
	if onChain == nil || onChain.Status != 1 {
		t.Fatalf("on-chain receipt = %+v", onChain)
	}
	balance, err := client.BalanceAt(context.Background(), recipient)
	if err != nil {
		t.Fatalf("BalanceAt: %v", err)
	}
	if balance.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("recipient balance = %s, want 1 wei", balance)
	}
	action, err := store.Action(request.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	if action.State != state.ActionSucceeded || action.TransactionHash != result.TransactionHash {
		t.Fatalf("action = %+v", action)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A restart must find the same evidence.
	reopened, err := state.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	persisted, err := reopened.Action(request.ActionID)
	if err != nil {
		t.Fatalf("Action after reopen: %v", err)
	}
	if persisted == nil {
		t.Fatal("the action disappeared across the reopen")
	}
	if persisted.State != state.ActionSucceeded {
		t.Fatalf("action state after reopen = %q, want succeeded", persisted.State)
	}
	if persisted.TransactionHash != result.TransactionHash ||
		persisted.ReceiptSHA256 != result.ReceiptSHA256 ||
		persisted.ReceiptPath != result.ReceiptPath ||
		persisted.BlockNumber != result.BlockNumber ||
		persisted.GasUsed != result.GasUsed {
		t.Fatalf("persisted action = %+v, want %+v", persisted, result)
	}
	if err := state.VerifyActionIdentity(persisted); err != nil {
		t.Fatalf("VerifyActionIdentity: %v", err)
	}
	// Resuming the reopened action must not broadcast a second transfer.
	resumed, err := NewTransactor(client, signer, reopened, spoolRoot, 30*time.Second)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	replayed, err := resumed.Execute(context.Background(), TxRequest{
		ActionID:  request.ActionID,
		ChainRole: "a",
	})
	if err != nil {
		t.Fatalf("Execute after restart: %v", err)
	}
	if replayed.TransactionHash != result.TransactionHash || replayed.ReceiptSHA256 != result.ReceiptSHA256 {
		t.Fatalf("replayed result = %+v", replayed)
	}
	balance, err = client.BalanceAt(context.Background(), recipient)
	if err != nil {
		t.Fatalf("BalanceAt: %v", err)
	}
	if balance.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("recipient balance after the resumed action = %s, want 1 wei", balance)
	}
}

// TestAnvilExecuteEstimatesGasWhenUnset proves a request without a gas limit
// follows deployer.py's rule: estimate, add 30%, and clamp to
// [100_000, 29_000_000]. A 21_000 gas transfer therefore freezes the 100_000
// floor.
func TestAnvilExecuteEstimatesGasWhenUnset(t *testing.T) {
	node := startAnvil(t)
	vectors := loadVectors(t)
	client, err := Dial(context.Background(), node.endpoint, 10*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	signer, err := NewSigner(vectors.Constants.FixtureKeys["validator"], chainID)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	node.fund(t, signer.Address(), new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18)))
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime", "runner.sqlite"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer store.Close()
	transactor, err := NewTransactor(client, signer, store, filepath.Join(t.TempDir(), "raw"), 30*time.Second)
	if err != nil {
		t.Fatalf("NewTransactor: %v", err)
	}
	request := TxRequest{
		ActionID:  "action-estimated",
		ChainRole: "a",
		To:        common.HexToAddress("0x00000000000000000000000000000000000000b1"),
		Value:     big.NewInt(3),
	}
	result, err := transactor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute: %v\n%s", err, node.logs())
	}
	action, err := store.Action(request.ActionID)
	if err != nil {
		t.Fatalf("Action: %v", err)
	}
	const wantGas = 100_000
	if action.Gas != wantGas {
		t.Fatalf("frozen gas = %d, want the %d floor", action.Gas, wantGas)
	}
	if result.GasUsed != 21_000 {
		t.Fatalf("gas used = %d, want 21_000", result.GasUsed)
	}
	detail, err := action.Detail()
	if err != nil {
		t.Fatalf("Detail: %v", err)
	}
	frozenFee, ok := detail["max_fee_per_gas"].(string)
	if !ok {
		t.Fatalf("the intent did not freeze its fee cap: %#v", detail)
	}
	rawTransaction, err := hexutil.Decode(action.RawTransactionHex)
	if err != nil {
		t.Fatalf("raw transaction: %v", err)
	}
	var signed types.Transaction
	if err := signed.UnmarshalBinary(rawTransaction); err != nil {
		t.Fatalf("raw transaction: %v", err)
	}
	if signed.GasFeeCap().String() != frozenFee {
		t.Fatalf("signed fee cap %s differs from the frozen %s", signed.GasFeeCap(), frozenFee)
	}
}

// TestAnvilClientReadSurface exercises the remaining transport calls against a
// real node: code, nonce, headers, logs and gas estimation.
func TestAnvilClientReadSurface(t *testing.T) {
	node := startAnvil(t)
	client, err := Dial(context.Background(), node.endpoint, 10*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	target := common.HexToAddress("0x00000000000000000000000000000000000000c0")
	code, err := client.CodeAt(context.Background(), target)
	if err != nil {
		t.Fatalf("CodeAt: %v", err)
	}
	if len(code) != 0 {
		t.Fatalf("CodeAt = 0x%x, want no code for a fresh address", code)
	}
	number, err := client.BlockNumber(context.Background())
	if err != nil {
		t.Fatalf("BlockNumber: %v", err)
	}
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		t.Fatalf("HeaderByNumber: %v", err)
	}
	if header == nil || header.Number.Uint64() != number {
		t.Fatalf("HeaderByNumber = %+v, want block %d", header, number)
	}
	logs, err := client.Logs(context.Background(), ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(0),
		ToBlock:   new(big.Int).SetUint64(number),
	})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("Logs = %d entries, want none on a fresh chain", len(logs))
	}
	estimate, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:  target,
		To:    &target,
		Value: big.NewInt(0),
	})
	if err != nil {
		t.Fatalf("EstimateGas: %v", err)
	}
	// A transfer to an empty account costs the base 21_000 gas; an estimation
	// allowance for the zero-value call may be higher, but never zero.
	if estimate == 0 {
		t.Fatalf("EstimateGas = 0, want a positive estimate")
	}
}
