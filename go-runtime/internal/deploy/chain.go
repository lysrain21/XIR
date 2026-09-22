package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

// chainRuntime is one chain of the deployment: the client that reaches it, the
// transactor that makes every send durable, and the per-chain action ordinal
// that keeps action ids stable across a re-run.
type chainRuntime struct {
	spec       ChainSpec
	client     *evm.Client
	transactor *evm.Transactor
	store      *state.Store
	deployer   common.Address
	ordinal    int
	journal    *journal
	owner      *deployment
	phase      string
}

func newChainRuntime(
	ctx context.Context,
	spec ChainSpec,
	options Options,
	store *state.Store,
	spoolRoot string,
	entries *journal,
) (*chainRuntime, error) {
	client, err := evm.Dial(ctx, spec.RPCEndpoint, rpcTimeout)
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", spec.Role, err)
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain %s: read chain id: %w", spec.Role, err)
	}
	if chainID.Uint64() != spec.ChainID {
		return nil, fmt.Errorf(
			"chain %s reports chain id %s but the spec says %d",
			spec.Role, chainID, spec.ChainID,
		)
	}
	signer, err := evm.NewSigner(options.DeployerKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("chain %s: %w", spec.Role, err)
	}
	transactor, err := evm.NewTransactor(client, signer, store, spoolRoot, txTimeout)
	if err != nil {
		return nil, fmt.Errorf("chain %s: create transactor: %w", spec.Role, err)
	}
	return &chainRuntime{
		spec:       spec,
		client:     client,
		transactor: transactor,
		store:      store,
		deployer:   signer.Address(),
		journal:    entries,
	}, nil
}

// deploy broadcasts one CREATE and returns the deployed address.
func (c *chainRuntime) deploy(
	ctx context.Context,
	key string,
	artifact artifacts.Artifact,
	args ...any,
) (common.Address, error) {
	data, err := artifact.ConstructorData(args...)
	if err != nil {
		return common.Address{}, err
	}
	label := fmt.Sprintf("deploy:%s:%s", key, artifact.Name)
	record, err := c.execute(ctx, label, artifact.SHA256, evm.TxRequest{
		DeployCode: data,
		Value:      new(big.Int),
	})
	if err != nil {
		return common.Address{}, err
	}
	address := common.HexToAddress(record.Target)
	code, err := c.client.CodeAt(ctx, address)
	if err != nil {
		return common.Address{}, fmt.Errorf("chain %s: read runtime code of %s: %w", c.spec.Role, key, err)
	}
	if len(code) == 0 {
		return common.Address{}, fmt.Errorf(
			"chain %s: deployed %s at %s has no runtime code",
			c.spec.Role, artifact.Name, address,
		)
	}
	return address, nil
}

// call broadcasts one state-changing call and returns its record.
func (c *chainRuntime) call(
	ctx context.Context,
	key string,
	to common.Address,
	artifact artifacts.Artifact,
	method string,
	args ...any,
) (actionRecord, error) {
	data, err := artifact.ABI.PackCall(method, args...)
	if err != nil {
		return actionRecord{}, err
	}
	label := fmt.Sprintf("call:%s:%s", key, method)
	return c.execute(ctx, label, artifact.SHA256, evm.TxRequest{
		To:    to,
		Data:  data,
		Value: new(big.Int),
	})
}

// callResult broadcasts one state-changing call whose return value the
// deployment needs, which is read with a preceding eth_call at the same
// address and calldata. Only the factory that creates the ISM needs this.
func (c *chainRuntime) callResult(
	ctx context.Context,
	key string,
	to common.Address,
	artifact artifacts.Artifact,
	method string,
	args ...any,
) ([]byte, error) {
	data, err := artifact.ABI.PackCall(method, args...)
	if err != nil {
		return nil, err
	}
	output, err := c.client.CallContract(ctx, to, data)
	if err != nil {
		return nil, fmt.Errorf("chain %s: simulate %s.%s: %w", c.spec.Role, key, method, err)
	}
	if _, err := c.call(ctx, key, to, artifact, method, args...); err != nil {
		return nil, err
	}
	return output, nil
}

// execute sends one transaction through the durable transactor and appends its
// provenance to the deployment journal.
//
// An action the ledger already holds as succeeded is returned from the durable
// row without a second broadcast, and does not add a second journal row: a
// re-run of the same deployment against the same runtime root therefore
// reproduces the same document instead of duplicating sends or evidence.
func (c *chainRuntime) execute(
	ctx context.Context,
	label string,
	artifactSHA256 string,
	request evm.TxRequest,
) (actionRecord, error) {
	c.ordinal++
	payload := request.Data
	if len(request.DeployCode) > 0 {
		payload = request.DeployCode
	}
	calldataSHA256 := sha256Hex(payload)
	request.ActionID = actionID(c.spec.Role, c.spec.ChainID, c.ordinal, label, calldataSHA256)
	request.AttemptID = deploymentAttempt
	request.Stage = actionStage(c.spec.Role, c.ordinal, label)
	request.ChainRole = c.spec.Role
	previous, err := c.store.Action(request.ActionID)
	if err != nil {
		return actionRecord{}, fmt.Errorf("chain %s: read action %s: %w", c.spec.Role, label, err)
	}
	replay := previous != nil && previous.State == state.ActionSucceeded
	result, err := c.transactor.Execute(ctx, request)
	if err != nil {
		return actionRecord{}, fmt.Errorf("chain %s: %s: %w", c.spec.Role, label, err)
	}
	record, err := c.provenance(
		ctx, request.ActionID, label, artifactSHA256, payload, calldataSHA256, result,
	)
	if err != nil {
		return actionRecord{}, err
	}
	c.owner.addAction(c.phase, record)
	if replay {
		return record, nil
	}
	if err := c.journal.append(record); err != nil {
		return actionRecord{}, err
	}
	return record, nil
}

// provenance assembles the durable evidence row of one action: the transaction
// identity, the receipt the transactor persisted, and the on-chain facts the
// Python deployment document records for the same action.
func (c *chainRuntime) provenance(
	ctx context.Context,
	actionID string,
	label string,
	artifactSHA256 string,
	payload []byte,
	calldataSHA256 string,
	result state.ActionResult,
) (actionRecord, error) {
	target := common.HexToAddress(result.ContractAddress)
	if target == (common.Address{}) && result.Detail != nil {
		target = common.HexToAddress(detailString(result.Detail, "target"))
	}
	record := actionRecord{
		ActionID:        actionID,
		Role:            c.spec.Role,
		ChainID:         c.spec.ChainID,
		Nonce:           detailUint64(result.Detail, "nonce"),
		Action:          label,
		Target:          target.Hex(),
		CalldataSHA256:  calldataSHA256,
		CalldataBytes:   len(payload),
		TransactionHash: result.TransactionHash,
		RawSHA256:       detailString(result.Detail, "raw_sha256"),
		ReceiptPath:     result.ReceiptPath,
		ReceiptSHA256:   result.ReceiptSHA256,
		// The transactor fails an action whose receipt reverted, so a
		// returned result is always a status 1 receipt.
		Status:         1,
		GasUsed:        result.GasUsed,
		BlockNumber:    result.BlockNumber,
		ArtifactSHA256: artifactSHA256,
	}
	code, err := c.client.CodeAt(ctx, target)
	if err != nil {
		return actionRecord{}, fmt.Errorf("chain %s: read runtime code of %s: %w", c.spec.Role, label, err)
	}
	if len(code) == 0 {
		return actionRecord{}, fmt.Errorf(
			"chain %s: %s produced no runtime code at %s", c.spec.Role, label, target,
		)
	}
	runtimeDigest := sha256.Sum256(code)
	record.RuntimeCodeSHA256 = hex.EncodeToString(runtimeDigest[:])
	if header, err := c.client.HeaderByNumber(ctx, new(big.Int).SetUint64(result.BlockNumber)); err == nil {
		record.BlockTimestamp = header.Time
	}
	return record, nil
}

// actionID identifies one durable deployment action. The Python deployer
// hashes the reserved nonce into the id; the Go transactor reserves the nonce
// itself, so the per-chain action ordinal takes that place and the id stays
// reproducible across a re-run.
func actionID(role string, chainID uint64, ordinal int, label, calldataSHA256 string) string {
	return sha256Hex([]byte(fmt.Sprintf(
		"%s:%d:%d:%s:%s", role, chainID, ordinal, label, calldataSHA256,
	)))
}

// actionStage is the ledger key of one action. It carries the role and the
// ordinal because the same label repeats on several chains and, for prior
// verifier bindings, several times on one adapter.
func actionStage(role string, ordinal int, label string) string {
	return fmt.Sprintf("%s_%03d_%s", role, ordinal, label)
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// detailString reads one string out of the transactor's receipt detail, which
// is a JSON document restored from the durable row.
func detailString(detail map[string]any, key string) string {
	if detail == nil {
		return ""
	}
	value, ok := detail[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64, bool, int64, uint64:
		return fmt.Sprintf("%v", typed)
	default:
		return ""
	}
}

// detailUint64 reads one numeric field out of the receipt detail.
func detailUint64(detail map[string]any, key string) uint64 {
	if detail == nil {
		return 0
	}
	value, ok := detail[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case uint64:
		return typed
	case int64:
		return uint64(typed)
	case float64:
		return uint64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0
		}
		return uint64(parsed)
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

// rpcTimeout bounds one JSON-RPC request and txTimeout one mined receipt wait,
// matching the Python deployer's 180 second receipt window.
const (
	rpcTimeout = 30 * time.Second
	txTimeout  = 180 * time.Second
)
