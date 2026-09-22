// Package lab starts disposable local EVM chains for runtime tests.
//
// The frozen XIR campaign runs on a five-chain Besu QBFT topology that needs
// more CPU and memory than a development host can spare. The Go runtime's
// integration tests therefore use anvil chains with the same chain IDs, the
// same one-second block period, and the same contracts deployed from the same
// Forge artifacts. This package is test infrastructure: it never produces
// campaign evidence and its chains are explicitly not the frozen lab.
package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Spec describes one chain to start.
type Spec struct {
	Role        string
	ChainID     uint64
	BlockPeriod time.Duration
	GasLimit    uint64
	// Fund lists addresses that must hold a balance before the chain is used.
	Fund []FundRequest
}

// FundRequest is one balance assignment applied through anvil_setBalance.
type FundRequest struct {
	Address string
	Wei     string
}

// Chain is one running anvil process.
type Chain struct {
	Role    string
	ChainID uint64
	URL     string

	command *exec.Cmd
	cancel  context.CancelFunc
	dir     string
	logPath string
	wait    sync.Once
	done    chan struct{}
	err     error
	client  *http.Client
}

// Options configure chain startup.
type Options struct {
	// AnvilPath overrides the anvil binary location.
	AnvilPath string
	// Dir is the parent directory for per-chain state; defaults to a temp dir.
	Dir string
	// LogWriter receives anvil output when set.
	LogWriter io.Writer
}

// AnvilPath resolves the anvil binary, returning "" when it is unavailable.
func AnvilPath(override string) string {
	if override != "" {
		return override
	}
	if path, err := exec.LookPath("anvil"); err == nil {
		return path
	}
	for _, candidate := range []string{"/home/ubuntu/.foundry/bin/anvil", "/usr/local/bin/anvil"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// StartChains starts one anvil chain per spec on an allocated loopback port.
func StartChains(ctx context.Context, specs []Spec, options Options) ([]*Chain, error) {
	binary := AnvilPath(options.AnvilPath)
	if binary == "" {
		return nil, fmt.Errorf("lab: anvil binary is unavailable")
	}
	root := options.Dir
	if root == "" {
		created, err := os.MkdirTemp("", "xir-lab-")
		if err != nil {
			return nil, fmt.Errorf("lab: create chain root: %w", err)
		}
		root = created
	}
	chains := make([]*Chain, 0, len(specs))
	for _, spec := range specs {
		chain, err := startChain(ctx, binary, root, spec, options)
		if err != nil {
			for _, started := range chains {
				started.Stop()
			}
			return nil, err
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

func startChain(ctx context.Context, binary, root string, spec Spec, options Options) (*Chain, error) {
	if spec.Role == "" || spec.ChainID == 0 {
		return nil, fmt.Errorf("lab: chain spec needs a role and chain id")
	}
	port, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, spec.Role)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("lab: create chain directory: %w", err)
	}
	logPath := filepath.Join(dir, "anvil.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("lab: create chain log: %w", err)
	}
	defer func() { _ = logFile.Close() }()

	arguments := []string{
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--chain-id", strconv.FormatUint(spec.ChainID, 10),
		"--hardfork", "cancun",
	}
	if spec.BlockPeriod > 0 {
		arguments = append(arguments, "--block-time", strconv.FormatInt(int64(spec.BlockPeriod/time.Second), 10))
	}
	if spec.GasLimit > 0 {
		arguments = append(arguments, "--gas-limit", strconv.FormatUint(spec.GasLimit, 10))
	}
	processContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	command := exec.CommandContext(processContext, binary, arguments...)
	command.Dir = dir
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("lab: start anvil for %s: %w", spec.Role, err)
	}
	chain := &Chain{
		Role:    spec.Role,
		ChainID: spec.ChainID,
		URL:     "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		command: command,
		cancel:  cancel,
		dir:     dir,
		logPath: logPath,
		done:    make(chan struct{}),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
	go func() {
		chain.err = command.Wait()
		close(chain.done)
	}()
	if err := chain.waitReady(ctx, 30*time.Second); err != nil {
		chain.Stop()
		return nil, err
	}
	for _, request := range spec.Fund {
		if err := chain.SetBalance(ctx, request.Address, request.Wei); err != nil {
			chain.Stop()
			return nil, err
		}
	}
	return chain, nil
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return 0, fmt.Errorf("lab: allocate loopback port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (c *Chain) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-c.done:
			return fmt.Errorf("lab: anvil for %s exited early: %s", c.Role, c.TailLogs())
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var observed string
		if err := c.call(ctx, "eth_chainId", nil, &observed); err == nil {
			value, err := strconv.ParseUint(observed, 0, 64)
			if err != nil {
				return fmt.Errorf("lab: chain %s reported chain id %q", c.Role, observed)
			}
			if value != c.ChainID {
				return fmt.Errorf("lab: chain %s reports chain id %d, want %d", c.Role, value, c.ChainID)
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("lab: anvil for %s did not become ready: %s", c.Role, c.TailLogs())
}

// SetBalance assigns a balance through anvil_setBalance.
func (c *Chain) SetBalance(ctx context.Context, address, wei string) error {
	var ignored any
	if err := c.call(ctx, "anvil_setBalance", []any{address, wei}, &ignored); err != nil {
		return fmt.Errorf("lab: fund %s on %s: %w", address, c.Role, err)
	}
	return nil
}

// Mine advances the chain through anvil_mine, which tests use to force a
// block without sending a transaction.
func (c *Chain) Mine(ctx context.Context, blocks uint64) error {
	var ignored any
	quantity := "0x" + strconv.FormatUint(blocks, 16)
	if err := c.call(ctx, "anvil_mine", []any{quantity}, &ignored); err != nil {
		return fmt.Errorf("lab: mine %d blocks on %s: %w", blocks, c.Role, err)
	}
	return nil
}

// BalanceOf returns the balance of one address as a hexadecimal quantity.
func (c *Chain) BalanceOf(ctx context.Context, address string) (string, error) {
	var observed string
	if err := c.call(ctx, "eth_getBalance", []any{address, "latest"}, &observed); err != nil {
		return "", err
	}
	return observed, nil
}

// BlockNumber returns the current head of this chain.
func (c *Chain) BlockNumber(ctx context.Context) (uint64, error) {
	var observed string
	if err := c.call(ctx, "eth_blockNumber", nil, &observed); err != nil {
		return 0, err
	}
	return strconv.ParseUint(observed, 0, 64)
}

func (c *Chain) call(ctx context.Context, method string, params []any, into any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return fmt.Errorf("lab: encode %s request: %w", method, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("lab: build %s request: %w", method, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("lab: %s call: %w", method, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("lab: read %s response: %w", method, err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("lab: decode %s response: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("lab: %s failed: %s", method, envelope.Error.Message)
	}
	if into == nil || len(envelope.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, into); err != nil {
		return fmt.Errorf("lab: decode %s result: %w", method, err)
	}
	return nil
}

// TailLogs returns the last part of the chain log for diagnostics.
func (c *Chain) TailLogs() string {
	payload, err := os.ReadFile(c.logPath)
	if err != nil {
		return ""
	}
	if len(payload) > 4096 {
		payload = payload[len(payload)-4096:]
	}
	return string(payload)
}

// Dir returns the per-chain working directory that holds the log.
func (c *Chain) Dir() string { return c.dir }

// Stop terminates the chain and waits for the process to exit.
func (c *Chain) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wait.Do(func() {
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			if c.command != nil && c.command.Process != nil {
				_ = c.command.Process.Kill()
			}
			<-c.done
		}
	})
}

// StopChains terminates every chain.
func StopChains(chains []*Chain) {
	for _, chain := range chains {
		chain.Stop()
	}
}
