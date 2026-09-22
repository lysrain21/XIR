package runner

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

// bound is one deployed contract on one chain, with the client and transactor
// that reach it.
type bound struct {
	role       string
	key        string
	address    common.Address
	artifact   artifacts.Artifact
	client     *evm.Client
	transactor *evm.Transactor
	gasLimit   uint64
}

// call performs an eth_call and returns the decoded outputs.
func (b *bound) call(ctx context.Context, name string, args ...any) ([]any, error) {
	data, err := b.artifact.ABI.PackCall(name, args...)
	if err != nil {
		return nil, err
	}
	output, err := b.client.CallContract(ctx, b.address, data)
	if err != nil {
		return nil, fmt.Errorf("runner: call %s.%s on %s: %w", b.key, name, b.role, err)
	}
	method, ok := b.artifact.ABI.ABI().Methods[name]
	if !ok {
		return nil, fmt.Errorf("runner: %s has no method %q", b.key, name)
	}
	if len(method.Outputs) == 0 {
		return nil, nil
	}
	return method.Outputs.Unpack(output)
}

// send executes one state-changing call through the durable transactor.
func (b *bound) send(
	ctx context.Context,
	attemptID string,
	stage string,
	name string,
	args []any,
	value *big.Int,
) (state.ActionResult, error) {
	data, err := b.artifact.ABI.PackCall(name, args...)
	if err != nil {
		return state.ActionResult{}, err
	}
	result, err := b.transactor.Execute(ctx, evm.TxRequest{
		ActionID:  actionID(attemptID, stage),
		AttemptID: attemptID,
		Stage:     stage,
		ChainRole: b.role,
		To:        b.address,
		Data:      data,
		Value:     value,
		Gas:       b.gasLimit,
	})
	if err != nil {
		return state.ActionResult{}, fmt.Errorf("runner: %s.%s on %s: %w", b.key, name, b.role, err)
	}
	return result, nil
}

// events returns the logs of the mined receipt that match the given event.
// The durable receipt file remains the evidence artifact; this read only drives
// control flow.
func (b *bound) events(ctx context.Context, result state.ActionResult, name string) ([]map[string]any, error) {
	receipt, err := b.client.Receipt(ctx, common.HexToHash(result.TransactionHash))
	if err != nil {
		return nil, err
	}
	topic, err := b.artifact.ABI.EventTopic(name)
	if err != nil {
		return nil, err
	}
	matches := make([]map[string]any, 0, 1)
	for index := range receipt.Logs {
		log := receipt.Logs[index]
		if log.Address != b.address || len(log.Topics) == 0 || log.Topics[0] != topic {
			continue
		}
		decoded, err := b.artifact.ABI.UnpackLog(name, log)
		if err != nil {
			return nil, err
		}
		matches = append(matches, decoded)
	}
	return matches, nil
}

// actionID identifies one durable action inside an attempt.
func actionID(attemptID, stage string) string {
	return attemptID + ":" + stage
}

// artifactFor maps a deployment manifest key to the Forge artifact that
// implements it. Route keys carry the hop index, and the route string decides
// which carrier contract the adapter key refers to.
func artifactFor(key, route string) (string, string, error) {
	switch key {
	case "registry":
		return "XIRRegistry.sol", "XIRRegistry", nil
	case "gateway":
		return "XIRGateway.sol", "XIRGateway", nil
	case "receiver":
		return "NativeMultihopReceiver.sol", "NativeMultihopReceiver", nil
	case "transition_recorder":
		return "NativeMultihopTransitionRecorder.sol", "NativeMultihopTransitionRecorder", nil
	}
	if !strings.HasPrefix(key, "route_") {
		return "", "", fmt.Errorf("runner: unknown contract key %q", key)
	}
	parts := strings.Split(key, "_")
	if len(parts) != 5 {
		return "", "", fmt.Errorf("runner: malformed adapter key %q", key)
	}
	hopIndex, err := parseHopIndex(parts[3])
	if err != nil {
		return "", "", fmt.Errorf("runner: adapter key %q: %w", key, err)
	}
	if hopIndex < 1 || hopIndex > len(route) {
		return "", "", fmt.Errorf("runner: adapter key %q is outside route %q", key, route)
	}
	if route[hopIndex-1] == 'H' {
		return "HyperlaneAdapter.sol", "HyperlaneAdapter", nil
	}
	return "LayerZeroAdapter.sol", "LayerZeroAdapter", nil
}

func parseHopIndex(value string) (int, error) {
	index := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("hop %q is not numeric", value)
		}
		index = index*10 + int(char-'0')
	}
	return index, nil
}

// contractSet resolves and caches bound contracts for every chain.
type contractSet struct {
	chains     map[string]*roleChain
	artifacts  string
	deployment *Deployment
	route      string
	gasLimit   uint64
	store      *state.Store
	rawRoot    string
}

// recordEvent appends one event row to the durable ledger.
func (s *contractSet) recordEvent(row state.EventRow) error {
	return s.store.RecordEvent(row)
}

// close releases every chain client.
func (s *contractSet) close() {
	for _, chain := range s.chains {
		chain.client.Close()
	}
}

// roleChain is one chain with its client, the runner transactor, and any
// chain-external agent transactors the carriers need.
type roleChain struct {
	config     ChainConfig
	client     *evm.Client
	transactor *evm.Transactor
	store      *state.Store
	rawRoot    string
	gasLimit   uint64
	revealer   *evm.Signer
	bindings   map[string]*bound
	worker     map[string]*evm.Transactor
}

// transactorGasLimit returns the gas limit runtime transactions use.
func (c *roleChain) transactorGasLimit() uint64 { return c.gasLimit }

// agentTransactor returns a transactor signed with one chain-external agent
// key, for example the LayerZero DVN/Executor key or the Hyperlane relayer key.
func (c *roleChain) agentTransactor(privateKey string) (*evm.Transactor, error) {
	if existing, ok := c.worker[privateKey]; ok {
		return existing, nil
	}
	signer, err := evm.NewSigner(privateKey, new(big.Int).SetUint64(c.config.ChainID))
	if err != nil {
		return nil, fmt.Errorf("runner: agent signer for %s: %w", c.config.Role, err)
	}
	transactor, err := evm.NewTransactor(c.client, signer, c.store, c.rawRoot, 3*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("runner: agent transactor for %s: %w", c.config.Role, err)
	}
	c.worker[privateKey] = transactor
	return transactor, nil
}

func (s *contractSet) chain(role string) (*roleChain, error) {
	chain, ok := s.chains[role]
	if !ok {
		return nil, fmt.Errorf("runner: no configured chain for role %q", role)
	}
	return chain, nil
}

// bind resolves one contract of the current route.
func (s *contractSet) bind(role, key string) (*bound, error) {
	chain, err := s.chain(role)
	if err != nil {
		return nil, err
	}
	if existing, ok := chain.bindings[key]; ok {
		return existing, nil
	}
	sourceName, contractName, err := artifactFor(key, s.route)
	if err != nil {
		return nil, err
	}
	address, err := s.deployment.Contract(role, key)
	if err != nil {
		return nil, err
	}
	artifact, err := artifacts.Load(s.artifacts, contractName)
	if err != nil {
		return nil, fmt.Errorf("runner: load %s: %w", sourceName, err)
	}
	resolved := &bound{
		role:       role,
		key:        key,
		address:    address,
		artifact:   artifact,
		client:     chain.client,
		transactor: chain.transactor,
		gasLimit:   s.gasLimit,
	}
	chain.bindings[key] = resolved
	return resolved, nil
}

// SetRoute selects the route whose adapter artifacts are resolved.
func (s *contractSet) SetRoute(route string) { s.route = route }

// infrastructure resolves one protocol infrastructure address of a chain.
func (s *contractSet) infrastructure(ctx context.Context, artifactRoot, role, key, sourceName, contractName string) (*bound, error) {
	chain, err := s.chain(role)
	if err != nil {
		return nil, err
	}
	cacheKey := "infra:" + key
	if existing, ok := chain.bindings[cacheKey]; ok {
		return existing, nil
	}
	address, err := s.deployment.Infra(role, key)
	if err != nil {
		return nil, err
	}
	artifact, err := artifacts.Load(artifactRoot, contractName)
	if err != nil {
		return nil, fmt.Errorf("runner: load %s: %w", sourceName, err)
	}
	resolved := &bound{
		role:       role,
		key:        cacheKey,
		address:    address,
		artifact:   artifact,
		client:     chain.client,
		transactor: chain.transactor,
		gasLimit:   s.gasLimit,
	}
	chain.bindings[cacheKey] = resolved
	return resolved, nil
}
