package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// roles are the topology chain roles in route order.
var roles = []string{"a", "b", "c", "d", "e"}

const (
	// policyLabel is the policy hash preimage of every campaign profile.
	policyLabel = "XIR_NATIVE_MULTIHOP_POLICY_V1"
	// defaultGasLimit bounds runtime transactions the way the Python runner's
	// provider-side estimate did.
	defaultGasLimit = 6_000_000
	// defaultPollInterval is the adapter verify poll period.
	defaultPollInterval = 500 * time.Millisecond
	// defaultAttemptTimeout bounds one attempt end to end.
	defaultAttemptTimeout = 10 * time.Minute
	// defaultFinalityTimeout bounds one confirmation wait.
	defaultFinalityTimeout = 2 * time.Minute
	// finalizedPollInterval is the confirmation poll period.
	finalizedPollInterval = 250 * time.Millisecond
)

// Runner executes multihop attempts against one deployed application.
type Runner struct {
	config      Config
	chains      *contractSet
	deployment  *Deployment
	state       *state.Store
	carriers    map[string]Carrier
	chainConfig map[string]ChainConfig
	runnerKeys  map[string]*evm.Signer
}

// Summary reports one Run.
type Summary struct {
	Attempts  int      `json:"attempts"`
	Succeeded int      `json:"succeeded"`
	Skipped   int      `json:"skipped"`
	Failures  []string `json:"failures"`
	RouteIDs  []string `json:"route_ids"`
}

// New validates the configuration, opens durable state, and connects to the
// configured chains. The caller closes the returned Runner.
func New(config Config) (*Runner, error) {
	if len(config.Attempts) == 0 {
		return nil, fmt.Errorf("runner: no attempts configured")
	}
	if len(config.Chains) == 0 {
		return nil, fmt.Errorf("runner: no chains configured")
	}
	if config.StatePath == "" || config.RawRoot == "" {
		return nil, fmt.Errorf("runner: state path and raw root are required")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultAttemptTimeout
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.GasLimit == 0 {
		config.GasLimit = defaultGasLimit
	}
	if config.ArtifactsRoot == "" {
		config.ArtifactsRoot = "contracts/out"
	}
	if config.PolicyLabel == "" {
		config.PolicyLabel = policyLabel
	}
	store, err := state.Open(config.StatePath)
	if err != nil {
		return nil, err
	}
	deployment, err := LoadDeployment(config.DeploymentPath)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	runner := &Runner{
		config:      config,
		deployment:  deployment,
		state:       store,
		carriers:    map[string]Carrier{},
		chainConfig: map[string]ChainConfig{},
		runnerKeys:  map[string]*evm.Signer{},
	}
	if err := runner.connect(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return runner, nil
}

// Close releases the durable state handle.
func (r *Runner) Close() error {
	r.chains.close()
	return r.state.Close()
}

func (r *Runner) connect() error {
	chains := &contractSet{
		chains:     map[string]*roleChain{},
		artifacts:  r.config.ArtifactsRoot,
		deployment: r.deployment,
		gasLimit:   r.config.GasLimit,
		store:      r.state,
		rawRoot:    r.config.RawRoot,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, chain := range r.config.Chains {
		r.chainConfig[chain.Role] = chain
		client, err := evm.Dial(ctx, chain.RPCURL, 30*time.Second)
		if err != nil {
			return fmt.Errorf("runner: dial chain %s: %w", chain.Role, err)
		}
		chainID, err := client.ChainID(ctx)
		if err != nil {
			return fmt.Errorf("runner: chain id for %s: %w", chain.Role, err)
		}
		if chainID.Uint64() != chain.ChainID {
			return fmt.Errorf(
				"runner: chain %s reports id %d, configuration says %d",
				chain.Role, chainID.Uint64(), chain.ChainID,
			)
		}
		runnerSigner, err := evm.NewSigner(r.config.Keys.Runner, chainID)
		if err != nil {
			return fmt.Errorf("runner: signer for %s: %w", chain.Role, err)
		}
		transactor, err := evm.NewTransactor(client, runnerSigner, r.state, r.config.RawRoot, 3*time.Minute)
		if err != nil {
			return fmt.Errorf("runner: transactor for %s: %w", chain.Role, err)
		}
		chains.chains[chain.Role] = &roleChain{
			config:     chain,
			client:     client,
			transactor: transactor,
			store:      r.state,
			rawRoot:    r.config.RawRoot,
			gasLimit:   r.config.GasLimit,
			bindings:   map[string]*bound{},
			worker:     map[string]*evm.Transactor{},
		}
	}
	r.chains = chains
	hyperlane := newHyperlaneCarrier(chains, r.config.ProtocolRoot, r.config.Chains, r.config.Keys, r.config)
	layerzero, err := newLayerZeroCarrier(chains, r.config.ProtocolRoot, r.config.Chains, r.config.Keys, r.config)
	if err != nil {
		return err
	}
	r.carriers["H"] = hyperlane
	r.carriers["L"] = layerzero
	return nil
}

// Run executes every configured attempt in order.
func (r *Runner) Run(ctx context.Context) (Summary, error) {
	summary := Summary{Attempts: len(r.config.Attempts)}
	for _, attempt := range r.config.Attempts {
		if err := r.checkStop(); err != nil {
			return summary, err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
		err := r.runAttempt(attemptCtx, attempt)
		cancel()
		if err != nil {
			summary.Failures = append(summary.Failures, fmt.Sprintf("%s: %v", attempt.AttemptID, err))
			if recordErr := r.state.RecordError(attempt.AttemptID, "runner", err.Error()); recordErr != nil {
				summary.Failures = append(summary.Failures, fmt.Sprintf("%s: record error: %v", attempt.AttemptID, recordErr))
			}
			continue
		}
		summary.Succeeded++
	}
	if len(summary.Failures) > 0 {
		return summary, fmt.Errorf("runner: %d of %d attempts failed", len(summary.Failures), summary.Attempts)
	}
	return summary, nil
}

// runAttempt performs one route execution end to end.
func (r *Runner) runAttempt(ctx context.Context, attempt Attempt) error {
	if attempt.Route == "" || attempt.RouteSequence > ^uint64(0)>>1 {
		return fmt.Errorf("runner: attempt %s has an invalid route", attempt.AttemptID)
	}
	if len(attempt.Route)+1 > len(roles) {
		return fmt.Errorf("runner: route %q exceeds the five-chain topology", attempt.Route)
	}
	coordinates, err := state.CanonicalJSON(map[string]any{
		"route":          attempt.Route,
		"route_sequence": attempt.RouteSequence,
		"switch_count":   attempt.SwitchCount,
		"hop_count":      len(attempt.Route),
	})
	if err != nil {
		return err
	}
	first, err := r.state.BeginAttempt(state.AttemptRow{
		AttemptID:       attempt.AttemptID,
		Phase:           attempt.Phase,
		Route:           attempt.Route,
		RouteSequence:   int(attempt.RouteSequence),
		CoordinatesJSON: coordinates,
		Status:          "running",
	})
	if err != nil {
		return err
	}
	if !first {
		return nil
	}
	r.chains.SetRoute(attempt.Route)
	payload, err := r.applicationPayload(attempt)
	if err != nil {
		return err
	}
	record, context, rid, signature, err := r.createRoot(ctx, attempt, payload)
	if err != nil {
		return err
	}
	receipts, err := r.walkHops(ctx, attempt, payload, record, context, signature, rid)
	if err != nil {
		return err
	}
	if err := r.deliver(ctx, attempt, payload, record, context, signature, receipts); err != nil {
		return err
	}
	if err := r.state.FinishAttempt(attempt.AttemptID); err != nil {
		return err
	}
	completed, err := eventRow(
		attempt.AttemptID, StageDestinationDelivery, "completed", "coordinator",
		roles[len(attempt.Route)], len(attempt.Route), "",
		map[string]any{
			"rid":           xir.FormatDigest(rid),
			"receipt_count": len(receipts),
			"route":         attempt.Route,
		},
	)
	if err != nil {
		return err
	}
	return r.state.RecordEvent(completed)
}

// applicationPayload rebuilds the frozen application payload of one attempt.
func (r *Runner) applicationPayload(attempt Attempt) ([]byte, error) {
	application, err := xir.ApplicationBytes(
		r.config.FixedSeed, attempt.Phase, attempt.RouteSequence, r.config.PayloadSchedule,
	)
	if err != nil {
		return nil, err
	}
	if attempt.PayloadSHA256 != "" {
		digest := sha256.Sum256(application)
		if hex.EncodeToString(digest[:]) != strings.ToLower(strings.TrimPrefix(attempt.PayloadSHA256, "0x")) {
			return nil, fmt.Errorf("runner: attempt %s payload differs from the frozen plan", attempt.AttemptID)
		}
	}
	attemptKey := xir.Keccak256([]byte(attempt.AttemptID))
	payload, err := abiutil.PackArgument(payloadArgumentJSON, xir.ApplicationPayload(
		attemptKey, attempt.Route, attempt.RouteSequence, application,
	))
	if err != nil {
		return nil, fmt.Errorf("runner: encode application payload: %w", err)
	}
	return payload, nil
}

const payloadArgumentJSON = `{"name":"payload","type":"tuple","components":[` +
	`{"name":"attemptId","type":"bytes32"},{"name":"route","type":"bytes"},` +
	`{"name":"routeSequence","type":"uint64"},{"name":"applicationPayload","type":"bytes"}]}`

// createRoot creates the XIR record on the source chain and returns the signed
// certificate that every hop carries.
func (r *Runner) createRoot(
	ctx context.Context,
	attempt Attempt,
	payload []byte,
) (xir.Record, xir.Context, [32]byte, []byte, error) {
	sourceRole := roles[0]
	destinationRole := roles[len(attempt.Route)]
	gateway, err := r.chains.bind(sourceRole, "gateway")
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	receiver, err := r.chains.bind(destinationRole, "receiver")
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	runnerSigner, err := r.signerFor(sourceRole)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	gatewayID, err := xir.GatewayTypedID(r.chainConfig[sourceRole].ChainID)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	sourceApp, err := xir.NewEVMID(runnerSigner.Address().Bytes())
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	destinationApp, err := xir.NewEVMID(receiver.address.Bytes())
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	nonce, err := r.rootNonce(ctx, attempt, gateway, runnerSigner.Address())
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	record := xir.Record{
		SourceGateway:  gatewayID,
		SourceApp:      sourceApp,
		DestinationApp: destinationApp,
		Nonce:          nonce,
		PayloadHash:    xir.Keccak256(payload),
	}
	context := xir.Context{RequiredSecurity: 1, PolicyHash: xir.Keccak256([]byte(r.config.PolicyLabel))}
	rid, err := xir.RootID(record, context, xir.RegistryVersion)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	rootIntent := map[string]any{"record_nonce": record.Nonce}
	// Legacy actions did not freeze caller metadata; keep their intent intact.
	existing, err := r.state.Action(actionID(attempt.AttemptID, StageRootCreate))
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	if existing != nil {
		detail, err := existing.Detail()
		if err != nil {
			return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
		}
		if _, ok := detail["intent_detail"]; !ok {
			rootIntent = nil
		}
	}
	result, err := gateway.sendWithIntent(
		ctx,
		attempt.AttemptID,
		StageRootCreate,
		"createRecord",
		[]any{record.DestinationApp.ABI(), payload, context.ABI(), xir.RegistryVersion},
		nil,
		rootIntent,
	)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	if err := r.verifyRootCreation(ctx, gateway, attempt, record, context, rid, result); err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	rootStage, err := stageRow(attempt.AttemptID, StageRootCreate, result.TransactionHash, map[string]any{
		"record_nonce":        record.Nonce,
		"record_payload_hash": xir.FormatDigest(record.PayloadHash),
		"gateway":             gateway.address.Hex(),
		"rid":                 xir.FormatDigest(rid),
	})
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	if err := r.state.RecordStage(rootStage); err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	if err := r.fault(StageRootCreate); err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	rootSigner, err := r.rootSignerFor(sourceRole)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	signature, err := rootSigner.SignPersonalDigest(rid)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	row, err := eventRow(
		attempt.AttemptID, "root_certificate_ready", "ready", "root_signer",
		sourceRole, 0, result.TransactionHash,
		map[string]any{
			"rid":                   xir.FormatDigest(rid),
			"root_signer":           rootSigner.Address().Hex(),
			"root_transaction_hash": result.TransactionHash,
			"record_nonce":          record.Nonce,
		},
	)
	if err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	if err := r.state.RecordEvent(row); err != nil {
		return xir.Record{}, xir.Context{}, [32]byte{}, nil, err
	}
	return record, context, rid, signature, nil
}

// verifyRootCreation checks the mined record against the finalized creation the
// Python root signer reconstructs before it signs.
func (r *Runner) verifyRootCreation(
	ctx context.Context,
	gateway *bound,
	attempt Attempt,
	record xir.Record,
	context xir.Context,
	rid [32]byte,
	result state.ActionResult,
) error {
	receipt, err := gateway.client.Receipt(ctx, common.HexToHash(result.TransactionHash))
	if err != nil {
		return err
	}
	if receipt.Status != 1 {
		return fmt.Errorf("runner: root creation transaction failed")
	}
	if _, err := r.awaitFinality(ctx, gateway.client, receipt); err != nil {
		return err
	}
	events, err := gateway.events(ctx, result, "RootCreated")
	if err != nil {
		return err
	}
	if len(events) != 1 {
		return fmt.Errorf("runner: root creation emitted %d RootCreated events", len(events))
	}
	observed, ok := events[0]["rid"].([32]byte)
	if !ok || observed != rid {
		return fmt.Errorf("runner: RootCreated rid does not match the reconstructed root")
	}
	expectedMid, err := xir.MessageID(rid, record.DestinationApp)
	if err != nil {
		return err
	}
	observedMid, ok := events[0]["mid"].([32]byte)
	if !ok || observedMid != expectedMid {
		return fmt.Errorf("runner: RootCreated mid does not match the reconstructed message id")
	}
	if nonce, err := asUint64(events[0]["nonce"]); err != nil || nonce != record.Nonce {
		return fmt.Errorf("runner: RootCreated nonce does not match the reserved nonce")
	}
	if sender, ok := events[0]["sender"].(common.Address); !ok || sender != r.mustRunnerAddress(roles[0]) {
		return fmt.Errorf("runner: RootCreated sender is not the configured runner")
	}
	// The signed bytes live in the durable spool; decoding them there proves the
	// transaction the runtime froze is the one the chain accepted.
	raw, err := os.ReadFile(spoolPath(gateway, result.TransactionHash))
	if err != nil {
		return fmt.Errorf("runner: read the frozen root creation transaction: %w", err)
	}
	transaction := &types.Transaction{}
	if err := transaction.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("runner: decode the frozen root creation transaction: %w", err)
	}
	if to := transaction.To(); to == nil || *to != gateway.address {
		return fmt.Errorf("runner: root creation transaction targets another contract")
	}
	document := gateway.artifact.ABI.ABI()
	method, err := document.MethodById(transaction.Data()[:4])
	if err != nil {
		return fmt.Errorf("runner: decode root creation transaction: %w", err)
	}
	if method.RawName != "createRecord" {
		return fmt.Errorf("runner: root creation transaction is not createRecord")
	}
	arguments, err := method.Inputs.Unpack(transaction.Data()[4:])
	if err != nil {
		return fmt.Errorf("runner: decode root creation arguments: %w", err)
	}
	if len(arguments) != 4 {
		return fmt.Errorf("runner: createRecord has %d arguments", len(arguments))
	}
	observedPayload, ok := arguments[1].([]byte)
	if !ok || xir.Keccak256(observedPayload) != record.PayloadHash {
		return fmt.Errorf("runner: root creation payload hash differs from the record")
	}
	observedContext, ok := abi.ConvertType(arguments[2], xir.ContextABI{}).(xir.ContextABI)
	if !ok {
		return fmt.Errorf("runner: root creation context has an unexpected shape")
	}
	if observedContext.RequiredSecurity != context.RequiredSecurity || observedContext.PolicyHash != context.PolicyHash {
		return fmt.Errorf("runner: root creation context differs from the record context")
	}
	version, ok := arguments[3].(uint32)
	if !ok || version != xir.RegistryVersion {
		return fmt.Errorf("runner: root creation registry version differs")
	}
	_ = attempt
	return nil
}

// awaitFinality applies the configured confirmation rule to one mined
// receipt and returns the rule that accepted it.
func (r *Runner) awaitFinality(ctx context.Context, client *evm.Client, receipt *types.Receipt) (string, error) {
	blockNumber := receipt.BlockNumber.Uint64()
	blockHash := receipt.BlockHash
	timeout := r.config.Finality.Timeout
	if timeout <= 0 {
		timeout = defaultFinalityTimeout
	}
	switch r.config.Finality.Mode {
	case "", FinalityRPCFinalized:
		deadline := time.Now().Add(timeout)
		for {
			finalized, rule, err := client.FinalizedNumberFor(ctx, blockNumber, blockHash)
			if err != nil {
				return "", err
			}
			if blockNumber <= finalized {
				return rule, nil
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf(
					"runner: block %d has not reached the finalized height %d under %s",
					blockNumber, finalized, rule,
				)
			}
			if err := sleepContext(ctx, finalizedPollInterval); err != nil {
				return "", err
			}
		}
	case FinalityConfirmations:
		required := blockNumber + r.config.Finality.Confirmations
		deadline := time.Now().Add(timeout)
		for {
			head, err := client.BlockNumber(ctx)
			if err != nil {
				return "", err
			}
			if head >= required {
				canonical, err := client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
				if err != nil {
					return "", err
				}
				if canonical == nil || canonical.Hash() != blockHash {
					return "", fmt.Errorf("runner: block %d left the canonical chain", blockNumber)
				}
				return fmt.Sprintf("confirmations-%d", r.config.Finality.Confirmations), nil
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf(
					"runner: block %d has %d successors of %d required",
					blockNumber, head-blockNumber, r.config.Finality.Confirmations,
				)
			}
			if err := sleepContext(ctx, finalizedPollInterval); err != nil {
				return "", err
			}
		}
	case FinalityNone:
		return "none-test-only", nil
	default:
		return "", fmt.Errorf("runner: unsupported finality mode %q", r.config.Finality.Mode)
	}
}

// sleepContext waits for one poll interval or until the context ends.
func sleepContext(ctx context.Context, interval time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(interval):
		return nil
	}
}

// rootNonce returns the gateway record nonce of one attempt. A resumed attempt
// reuses its pre-signing intent nonce, or recovers legacy roots from their
// receipt/stage. A fresh attempt takes max(nextNonce, next reserved nonce)
// so another durable intent cannot reuse the same record nonce.
func (r *Runner) rootNonce(ctx context.Context, attempt Attempt, gateway *bound, runner common.Address) (uint64, error) {
	action, err := r.state.Action(actionID(attempt.AttemptID, StageRootCreate))
	if err != nil {
		return 0, err
	}
	if action != nil {
		if err := state.VerifyActionIdentity(action); err != nil {
			return 0, err
		}
		detail, err := action.Detail()
		if err != nil {
			return 0, err
		}
		if frozen, ok := detail["intent_detail"]; ok {
			encoded, err := state.CanonicalJSON(frozen)
			if err != nil {
				return 0, err
			}
			if nonce, ok := recordNonceFromDetail(encoded); ok {
				return nonce, nil
			}
			return 0, fmt.Errorf("runner: root action has invalid frozen record nonce")
		}
		// Upgrade recovery for roots mined by the previous runtime, whose
		// current stage may lack record_nonce after a finality timeout.
		if action.TransactionHash != "" {
			receipt, err := gateway.client.Receipt(ctx, common.HexToHash(action.TransactionHash))
			if err != nil {
				return 0, err
			}
			if receipt != nil && receipt.Status == types.ReceiptStatusSuccessful {
				events, err := gateway.events(ctx, state.ActionResult{TransactionHash: action.TransactionHash}, "RootCreated")
				if err != nil {
					return 0, err
				}
				if len(events) != 1 {
					return 0, fmt.Errorf("runner: existing root has %d creation events", len(events))
				}
				return asUint64(events[0]["nonce"])
			}
		}
	}
	stage, err := r.state.Stage(attempt.AttemptID, StageRootCreate)
	if err != nil {
		return 0, err
	}
	if stage != nil && stage.DetailJSON != "" && stage.DetailJSON != "{}" {
		if recorded, ok := recordNonceFromDetail(stage.DetailJSON); ok {
			return recorded, nil
		}
	}
	values, err := gateway.call(ctx, "nextNonce", runner)
	if err != nil {
		return 0, err
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("runner: nextNonce returned %d values", len(values))
	}
	chainNonce, err := asUint64(values[0])
	if err != nil {
		return 0, fmt.Errorf("runner: nextNonce: %w", err)
	}
	reserved, err := r.state.NextReservedRootNonce()
	if err != nil {
		return 0, err
	}
	if chainNonce > reserved {
		return chainNonce, nil
	}
	return reserved, nil
}

// asUint64 accepts the integer shapes the ABI codec produces for uint64 and
// uint256 outputs.
func asUint64(value any) (uint64, error) {
	switch typed := value.(type) {
	case uint64:
		return typed, nil
	case uint32:
		return uint64(typed), nil
	case uint16:
		return uint64(typed), nil
	case uint8:
		return uint64(typed), nil
	case *big.Int:
		if typed.Sign() < 0 || !typed.IsUint64() {
			return 0, fmt.Errorf("value %s is not a uint64", typed)
		}
		return typed.Uint64(), nil
	default:
		return 0, fmt.Errorf("value %T is not an integer", value)
	}
}

// recordNonceFromDetail reads the frozen record nonce of a root stage row.
func recordNonceFromDetail(document string) (uint64, bool) {
	var detail struct {
		RecordNonce *uint64 `json:"record_nonce"`
	}
	if err := json.Unmarshal([]byte(document), &detail); err != nil {
		return 0, false
	}
	if detail.RecordNonce == nil {
		return 0, false
	}
	return *detail.RecordNonce, true
}

// fault aborts the attempt when the caller injected a fault at this stage.
func (r *Runner) fault(stage string) error {
	if r.config.FaultAfterStage != "" && r.config.FaultAfterStage == stage {
		return fmt.Errorf("runner: injected fault after stage %s", stage)
	}
	return nil
}

// walkHops dispatches and confirms every hop, recording the carrier switch.
func (r *Runner) walkHops(
	ctx context.Context,
	attempt Attempt,
	payload []byte,
	record xir.Record,
	context xir.Context,
	signature []byte,
	rid [32]byte,
) ([]xir.Receipt, error) {
	receipts := make([]xir.Receipt, 0, len(attempt.Route))
	prefix := xir.RootPrefix(rid)
	for index := 0; index < len(attempt.Route); index++ {
		hopIndex := index + 1
		protocol := attempt.Route[index : index+1]
		sourceRole := roles[index]
		destinationRole := roles[index+1]
		profile, err := xir.ProfileHash(attempt.Route, hopIndex)
		if err != nil {
			return nil, err
		}
		sourceGatewayID, err := xir.GatewayTypedID(r.chainConfig[sourceRole].ChainID)
		if err != nil {
			return nil, err
		}
		destinationGatewayID, err := xir.GatewayTypedID(r.chainConfig[destinationRole].ChainID)
		if err != nil {
			return nil, err
		}
		transition, err := xir.TransitionHash(record, context, sourceGatewayID, destinationGatewayID)
		if err != nil {
			return nil, err
		}
		sourceAdapter, err := r.chains.bind(sourceRole, mustAdapterKey(attempt.Route, hopIndex, "out"))
		if err != nil {
			return nil, err
		}
		destinationAdapter, err := r.chains.bind(destinationRole, mustAdapterKey(attempt.Route, hopIndex, "in"))
		if err != nil {
			return nil, err
		}
		verifiers, err := r.verifiers(attempt, hopIndex, sourceRole, len(receipts))
		if err != nil {
			return nil, err
		}
		request := HopRequest{
			Route:              attempt.Route,
			AttemptID:          attempt.AttemptID,
			HopIndex:           hopIndex,
			Protocol:           protocol,
			SourceRole:         sourceRole,
			DestinationRole:    destinationRole,
			SourceAdapter:      sourceAdapter,
			DestinationAdapter: destinationAdapter,
			Verifiers:          verifiers,
			PriorReceipts:      receipts,
			CurrentProfile:     profile,
			CurrentTransition:  transition,
		}
		carrier, ok := r.carriers[protocol]
		if !ok {
			return nil, fmt.Errorf("runner: unsupported carrier %q", protocol)
		}
		dispatched, err := carrier.Dispatch(ctx, request)
		if err != nil {
			return nil, err
		}
		stage, err := stageRow(attempt.AttemptID, dispatched.Stage, dispatched.Transaction, dispatched.Evidence.Detail)
		if err != nil {
			return nil, err
		}
		if err := r.state.RecordStage(stage); err != nil {
			return nil, err
		}
		if err := r.fault(dispatched.Stage); err != nil {
			return nil, err
		}
		if err := carrier.Confirm(ctx, request, dispatched); err != nil {
			return nil, err
		}
		receipts = append(receipts, xir.Receipt{
			SourceGateway:      sourceGatewayID,
			DestinationGateway: destinationGatewayID,
			ProfileHash:        profile,
			EvidenceHash:       dispatched.Evidence.Hash,
			TransitionHash:     transition,
			PriorPrefix:        prefix,
		})
		next, err := xir.NextPrefix(prefix, receipts[len(receipts)-1])
		if err != nil {
			return nil, err
		}
		prefix = next
		if hopIndex < len(attempt.Route) && attempt.Route[hopIndex:hopIndex+1] != protocol {
			if err := r.recordTransition(ctx, attempt, payload, record, context, signature, receipts, hopIndex); err != nil {
				return nil, err
			}
		}
	}
	return receipts, nil
}

// verifiers returns the approved prior verifier list of one hop: the inbound
// adapter of the previous hop, repeated once per prior receipt.
func (r *Runner) verifiers(
	attempt Attempt,
	hopIndex int,
	sourceRole string,
	priorCount int,
) ([]common.Address, error) {
	if hopIndex == 1 || priorCount == 0 {
		return []common.Address{}, nil
	}
	previous, err := r.chains.bind(sourceRole, mustAdapterKey(attempt.Route, hopIndex-1, "in"))
	if err != nil {
		return nil, err
	}
	verifiers := make([]common.Address, 0, priorCount)
	for index := 0; index < priorCount; index++ {
		verifiers = append(verifiers, previous.address)
	}
	return verifiers, nil
}

// recordTransition records a carrier switch on the intermediate chain.
func (r *Runner) recordTransition(
	ctx context.Context,
	attempt Attempt,
	payload []byte,
	record xir.Record,
	context xir.Context,
	signature []byte,
	receipts []xir.Receipt,
	hopIndex int,
) error {
	role := roles[hopIndex]
	recorder, err := r.chains.bind(role, "transition_recorder")
	if err != nil {
		return err
	}
	nextProfile, err := xir.ProfileHash(attempt.Route, hopIndex+1)
	if err != nil {
		return err
	}
	envelope := xir.Envelope{
		Record:          record,
		Context:         context,
		RegistryVersion: xir.RegistryVersion,
		Signature:       signature,
		Receipts:        receipts,
	}
	stage := transitionStage(hopIndex + 1)
	result, err := recorder.send(
		ctx, attempt.AttemptID, stage, "record",
		[]any{payload, envelope.ABI(), uint8(hopIndex), nextProfile},
		nil,
	)
	if err != nil {
		return err
	}
	if err := r.fault(stage); err != nil {
		return err
	}
	events, err := recorder.events(ctx, result, "NativeMultihopTransitionRecorded")
	if err != nil {
		return err
	}
	if len(events) != 1 {
		return fmt.Errorf("runner: switch at hop %d emitted %d transition events", hopIndex, len(events))
	}
	observed, ok := events[0]["outboundProfileHash"].([32]byte)
	if !ok || observed != nextProfile {
		return fmt.Errorf("runner: recorded transition does not carry the outbound profile")
	}
	return nil
}

// deliver submits the envelope to the destination gateway and verifies the
// application effect.
func (r *Runner) deliver(
	ctx context.Context,
	attempt Attempt,
	payload []byte,
	record xir.Record,
	context xir.Context,
	signature []byte,
	receipts []xir.Receipt,
) error {
	destinationRole := roles[len(attempt.Route)]
	receiver, err := r.chains.bind(destinationRole, "receiver")
	if err != nil {
		return err
	}
	gateway, err := r.chains.bind(destinationRole, "gateway")
	if err != nil {
		return err
	}
	envelope := xir.Envelope{
		Record:          record,
		Context:         context,
		RegistryVersion: xir.RegistryVersion,
		Signature:       signature,
		Receipts:        receipts,
	}
	result, err := gateway.send(
		ctx, attempt.AttemptID, StageDestinationDelivery, "deliver",
		[]any{envelope.ABI(), payload, receiver.address},
		nil,
	)
	if err != nil {
		return err
	}
	if err := r.fault(StageDestinationDelivery); err != nil {
		return err
	}
	events, err := receiver.events(ctx, result, "NativeMultihopEffectApplied")
	if err != nil {
		return err
	}
	if len(events) != 1 {
		return fmt.Errorf("runner: delivery emitted %d effect events", len(events))
	}
	attemptKey := xir.Keccak256([]byte(attempt.AttemptID))
	if observed, ok := events[0]["attemptId"].([32]byte); !ok || observed != attemptKey {
		return fmt.Errorf("runner: effect attempt id differs from the attempt")
	}
	rid, err := xir.RootID(record, context, xir.RegistryVersion)
	if err != nil {
		return err
	}
	expectedMid, err := xir.MessageID(rid, record.DestinationApp)
	if err != nil {
		return err
	}
	if observed, ok := events[0]["messageId"].([32]byte); !ok || observed != expectedMid {
		return fmt.Errorf("runner: effect message id differs from the derived mid")
	}
	if observed, ok := events[0]["routeSequence"].(uint64); !ok || observed != attempt.RouteSequence {
		return fmt.Errorf("runner: effect route sequence differs from the attempt")
	}
	consumed, err := receiver.call(ctx, "consumedAttempts", attemptKey)
	if err != nil {
		return err
	}
	if len(consumed) != 1 {
		return fmt.Errorf("runner: consumedAttempts returned %d values", len(consumed))
	}
	if value, ok := consumed[0].(bool); !ok || !value {
		return fmt.Errorf("runner: destination effect is not visible")
	}
	observed, err := eventRow(
		attempt.AttemptID, "destination_effect_observation", "observed", "coordinator_read",
		destinationRole, len(attempt.Route), result.TransactionHash,
		map[string]any{
			"receiver":             receiver.address.Hex(),
			"attempt_key":          xir.FormatDigest(attemptKey),
			"mid":                  xir.FormatDigest(expectedMid),
			"route_sequence":       attempt.RouteSequence,
			"delivery_transaction": result.TransactionHash,
			"effect_event_count":   1,
		},
	)
	if err != nil {
		return err
	}
	return r.state.RecordEvent(observed)
}

func (r *Runner) checkStop() error {
	if r.config.StopFile == "" {
		return nil
	}
	if _, err := os.Stat(r.config.StopFile); err == nil {
		return fmt.Errorf("runner: submissions stopped by %s", r.config.StopFile)
	}
	return nil
}

func (r *Runner) signerFor(role string) (*evm.Signer, error) {
	if signer, ok := r.runnerKeys[role]; ok {
		return signer, nil
	}
	chain, ok := r.chainConfig[role]
	if !ok {
		return nil, fmt.Errorf("runner: no chain configuration for role %q", role)
	}
	signer, err := evm.NewSigner(r.config.Keys.Runner, new(big.Int).SetUint64(chain.ChainID))
	if err != nil {
		return nil, err
	}
	r.runnerKeys[role] = signer
	return signer, nil
}

func (r *Runner) mustRunnerAddress(role string) common.Address {
	signer, err := r.signerFor(role)
	if err != nil {
		return common.Address{}
	}
	return signer.Address()
}

// rootSignerFor returns the root signer of the source chain.
func (r *Runner) rootSignerFor(role string) (*evm.Signer, error) {
	chain, ok := r.chainConfig[role]
	if !ok {
		return nil, fmt.Errorf("runner: no chain configuration for role %q", role)
	}
	return evm.NewSigner(r.config.Keys.RootSigner, new(big.Int).SetUint64(chain.ChainID))
}

// spoolPath returns the durable raw-transaction path of one action, matching
// the naming the transactor uses (<spool root>/<canonical hash>.raw).
func spoolPath(b *bound, transactionHash string) string {
	canonical := strings.ToLower(strings.TrimPrefix(transactionHash, "0x"))
	return filepath.Join(b.transactor.SpoolRoot(), canonical+".raw")
}

func mustAdapterKey(route string, hopIndex int, direction string) string {
	key, err := xir.AdapterKey(route, hopIndex, direction)
	if err != nil {
		panic(err)
	}
	return key
}

var _ = artifacts.Artifact{}
