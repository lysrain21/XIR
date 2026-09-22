package runner

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/hyperlane"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// hyperlaneDelivery is the protocol-private data one Hyperlane hop needs after
// dispatch: the dispatched message and the origin mailbox it came from.
type hyperlaneDelivery struct {
	Message           []byte
	MessageID         [32]byte
	DestinationDomain uint32
	OriginDomain      uint32
	OriginHook        common.Address
	InsertedIndex     uint32
	SourceResult      state.ActionResult
	SourceRole        string
}

type hyperlaneCarrier struct {
	chains       *contractSet
	protocolRoot string
	domains      map[string]uint32
	chainsByRole map[string]ChainConfig
	validatorKey string
	relayerKey   string
	embedded     bool
	poll         time.Duration
	timeout      time.Duration
	gasLimit     uint64
}

func newHyperlaneCarrier(
	chains *contractSet,
	protocolRoot string,
	configs []ChainConfig,
	keys KeySet,
	config Config,
) *hyperlaneCarrier {
	domains := map[string]uint32{}
	byRole := map[string]ChainConfig{}
	for _, chain := range configs {
		domains[chain.Role] = chain.HyperlaneDomain
		byRole[chain.Role] = chain
	}
	return &hyperlaneCarrier{
		chains:       chains,
		protocolRoot: protocolRoot,
		domains:      domains,
		chainsByRole: byRole,
		validatorKey: keys.HyperlaneValidator,
		relayerKey:   keys.HyperlaneRelayer,
		embedded:     config.EmbeddedAgents,
		poll:         config.PollInterval,
		timeout:      config.Timeout,
		gasLimit:     config.GasLimit,
	}
}

// Dispatch submits sendSourceBundle (first hop) or forwardInFlightBundle.
func (c *hyperlaneCarrier) Dispatch(ctx context.Context, request HopRequest) (DispatchResult, error) {
	adapter := request.SourceAdapter
	profiles := make([][32]byte, 0, len(request.PriorReceipts))
	evidences := make([][32]byte, 0, len(request.PriorReceipts))
	transitions := make([][32]byte, 0, len(request.PriorReceipts))
	for _, receipt := range request.PriorReceipts {
		profiles = append(profiles, receipt.ProfileHash)
		evidences = append(evidences, receipt.EvidenceHash)
		transitions = append(transitions, receipt.TransitionHash)
	}
	bundle := hyperlaneRequestABI{
		Verifiers:             request.Verifiers,
		ProfileHashes:         profiles,
		EvidenceHashes:        evidences,
		TransitionHashes:      transitions,
		CurrentProfileHash:    request.CurrentProfile,
		CurrentTransitionHash: request.CurrentTransition,
	}
	stage := dispatchStage(request.HopIndex, request.Protocol)
	fee, err := dispatchFee(c.chains.store, actionID(request.AttemptID, stage), func() (*big.Int, error) {
		quoted, err := adapter.call(ctx, "quoteBundle", bundle)
		if err != nil {
			return nil, err
		}
		return singleBigInt(quoted)
	})
	if err != nil {
		return DispatchResult{}, fmt.Errorf("runner: hyperlane dispatch fee: %w", err)
	}

	name := "sendSourceBundle"
	if request.HopIndex > 1 {
		name = "forwardInFlightBundle"
	}
	result, err := adapter.send(ctx, request.AttemptID, stage, name, []any{bundle}, fee)
	if err != nil {
		return DispatchResult{}, err
	}
	evidence, messageID, err := c.evidenceFor(ctx, adapter, request, result)
	if err != nil {
		return DispatchResult{}, err
	}
	delivery, err := c.collectDelivery(ctx, adapter, request, result)
	if err != nil {
		return DispatchResult{}, err
	}
	return DispatchResult{
		Evidence: Evidence{
			Hash:            evidence,
			NativeMessageID: "0x" + common.Bytes2Hex(messageID[:]),
			Detail: map[string]any{
				"protocol":             "H",
				"hop_index":            request.HopIndex,
				"native_message_id":    messageID,
				"quote_native_fee_wei": fee.String(),
				"destination_domain":   c.domains[request.DestinationRole],
			},
		},
		Stage:       stage,
		Transaction: result.TransactionHash,
		delivery:    delivery,
	}, nil
}

// evidenceFor derives the Hyperlane evidence hash the adapter committed to and
// reads the dispatched message id from the adapter event.
func (c *hyperlaneCarrier) evidenceFor(
	ctx context.Context,
	adapter *bound,
	request HopRequest,
	result state.ActionResult,
) ([32]byte, [32]byte, error) {
	inner := hyperlaneInnerABI{
		CurrentProfile:    request.CurrentProfile,
		CurrentTransition: request.CurrentTransition,
		PriorProfiles:     priorField(request.PriorReceipts, func(receipt xir.Receipt) [32]byte { return receipt.ProfileHash }),
		PriorEvidence:     priorField(request.PriorReceipts, func(receipt xir.Receipt) [32]byte { return receipt.EvidenceHash }),
		PriorTransitions:  priorField(request.PriorReceipts, func(receipt xir.Receipt) [32]byte { return receipt.TransitionHash }),
	}
	innerBytes, err := abiutil.PackArgument(
		`{"name":"inner","type":"tuple","components":`+hyperlaneInnerFragments+`}`, inner,
	)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	body, err := abiutil.PackEncode(hyperlaneBodyFragments, uint8(3), innerBytes)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	domain := c.domains[request.SourceRole]
	sender := bytes32FromAddress(adapter.address)
	evidence := hyperlane.EvidenceHash(domain, sender, body)

	events, err := adapter.events(ctx, result, "HyperlaneDispatched")
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	if len(events) != 1 {
		return [32]byte{}, [32]byte{}, fmt.Errorf(
			"runner: hop %d dispatch emitted %d HyperlaneDispatched events", request.HopIndex, len(events),
		)
	}
	messageID, ok := events[0]["messageId"].([32]byte)
	if !ok {
		return [32]byte{}, [32]byte{}, fmt.Errorf("runner: HyperlaneDispatched messageId is missing")
	}
	return evidence, messageID, nil
}

// collectDelivery reads the dispatched message and the origin tree hook that
// inserted it, so Confirm can reproduce the checkpoint.
func (c *hyperlaneCarrier) collectDelivery(
	ctx context.Context,
	adapter *bound,
	request HopRequest,
	result state.ActionResult,
) (hyperlaneDelivery, error) {
	mailbox := &bound{
		role:       adapter.role,
		key:        "mailbox",
		client:     adapter.client,
		transactor: adapter.transactor,
		gasLimit:   adapter.gasLimit,
	}
	address, err := c.chains.deployment.Infra(request.SourceRole, "mailbox")
	if err != nil {
		return hyperlaneDelivery{}, err
	}
	mailbox.address = address
	if mailbox.artifact, err = loadProtocol(c.protocolRoot, "Mailbox"); err != nil {
		return hyperlaneDelivery{}, err
	}
	receipt, err := adapter.client.Receipt(ctx, common.HexToHash(result.TransactionHash))
	if err != nil {
		return hyperlaneDelivery{}, err
	}
	dispatched, err := hyperlane.DispatchedMessage(receipt, mailbox.artifact.ABI)
	if err != nil {
		return hyperlaneDelivery{}, fmt.Errorf("runner: hop %d dispatch: %w", request.HopIndex, err)
	}
	hook := common.Address{}
	index := uint32(0)
	found := false
	for _, log := range receipt.Logs {
		if len(log.Topics) == 0 || log.Topics[0] != hyperlane.InsertedIntoTreeTopic {
			continue
		}
		messageID, insertedIndex, ok := insertedIntoTree(log)
		if !ok || messageID != dispatched.MessageID {
			continue
		}
		hook = log.Address
		index = insertedIndex
		found = true
	}
	if !found {
		return hyperlaneDelivery{}, fmt.Errorf(
			"runner: hop %d dispatch was not inserted into an origin tree", request.HopIndex,
		)
	}
	return hyperlaneDelivery{
		Message:           dispatched.Message,
		MessageID:         dispatched.MessageID,
		DestinationDomain: dispatched.Destination,
		OriginDomain:      c.domains[request.SourceRole],
		OriginHook:        hook,
		InsertedIndex:     index,
		SourceResult:      result,
		SourceRole:        request.SourceRole,
	}, nil
}

// Confirm delivers the message with the runtime's validator/relayer roles and
// then waits for the destination adapter to verify the bundle.
func (c *hyperlaneCarrier) Confirm(ctx context.Context, request HopRequest, dispatched DispatchResult) error {
	delivery, ok := dispatched.delivery.(hyperlaneDelivery)
	if !ok {
		return fmt.Errorf("runner: hyperlane dispatch result is missing delivery data")
	}
	if c.embedded {
		if err := c.deliver(ctx, request, delivery); err != nil {
			return err
		}
	}
	return awaitVerified(ctx, c.chains, request, Evidence{Hash: dispatched.Evidence.Hash}, c.poll, c.timeout)
}

// deliver signs the origin checkpoint and submits Mailbox.process on the
// destination chain.
func (c *hyperlaneCarrier) deliver(ctx context.Context, request HopRequest, delivery hyperlaneDelivery) error {
	destination, err := c.chains.chain(request.DestinationRole)
	if err != nil {
		return err
	}
	source, err := c.chains.chain(delivery.SourceRole)
	if err != nil {
		return err
	}
	validator, err := evm.NewSigner(c.validatorKey, big.NewInt(int64(source.config.ChainID)))
	if err != nil {
		return fmt.Errorf("runner: hyperlane validator key: %w", err)
	}
	checkpoint, err := readCheckpoint(ctx, c.protocolRoot, source, delivery)
	if err != nil {
		return err
	}
	digest, err := hyperlane.CheckpointDigest(
		delivery.OriginDomain, delivery.OriginHook, checkpoint.Root, checkpoint.Index, delivery.MessageID,
	)
	if err != nil {
		return err
	}
	signature, err := validator.SignPersonalDigest(digest)
	if err != nil {
		return fmt.Errorf("runner: sign hyperlane checkpoint: %w", err)
	}
	mailboxAddress, err := c.chains.deployment.Infra(request.DestinationRole, "mailbox")
	if err != nil {
		return err
	}
	plan, err := hyperlane.Plan(hyperlane.PlanRequest{
		Message:              delivery.Message,
		OriginMerkleTreeHook: delivery.OriginHook,
		Checkpoint: hyperlane.Checkpoint{
			Domain: delivery.OriginDomain,
			Root:   checkpoint.Root,
			Index:  checkpoint.Index,
		},
		Signatures:         signature,
		DestinationMailbox: mailboxAddress,
	})
	if err != nil {
		return fmt.Errorf("runner: hyperlane process plan: %w", err)
	}
	stage := hyperlaneProcessStage(request.HopIndex)
	transactor, err := destination.agentTransactor(c.relayerKey)
	if err != nil {
		return err
	}
	result, err := transactor.Execute(ctx, evm.TxRequest{
		ActionID:  actionID(request.AttemptID, stage),
		AttemptID: request.AttemptID,
		Stage:     stage,
		ChainRole: request.DestinationRole,
		To:        plan.Mailbox,
		Data:      plan.Calldata,
		Gas:       c.gasLimit,
	})
	if err != nil {
		return fmt.Errorf("runner: hyperlane process: %w", err)
	}
	mailbox := &bound{
		role:       request.DestinationRole,
		key:        "mailbox",
		address:    plan.Mailbox,
		client:     destination.client,
		transactor: transactor,
		gasLimit:   c.gasLimit,
	}
	if mailbox.artifact, err = loadProtocol(c.protocolRoot, "Mailbox"); err != nil {
		return err
	}
	events, err := mailbox.events(ctx, result, "Process")
	if err != nil {
		return err
	}
	if len(events) != 1 {
		return fmt.Errorf("runner: hop %d process emitted %d Process events", request.HopIndex, len(events))
	}
	row, err := eventRow(
		request.AttemptID, stage, "succeeded", "embedded-relayer",
		request.DestinationRole, request.HopIndex, result.TransactionHash,
		map[string]any{
			"validator":        validator.Address().Hex(),
			"origin_hook":      delivery.OriginHook.Hex(),
			"checkpoint_root":  xir.FormatDigest(checkpoint.Root),
			"checkpoint_index": checkpoint.Index,
			"message_id":       xir.FormatDigest(delivery.MessageID),
		},
	)
	if err != nil {
		return err
	}
	if err := c.chains.recordEvent(row); err != nil {
		return err
	}
	return nil
}

func priorField(receipts []xir.Receipt, pick func(xir.Receipt) [32]byte) [][32]byte {
	values := make([][32]byte, 0, len(receipts))
	for _, receipt := range receipts {
		values = append(values, pick(receipt))
	}
	return values
}

func bytes32FromAddress(address common.Address) [32]byte {
	var out [32]byte
	copy(out[12:], address.Bytes())
	return out
}

func singleBigInt(values []any) (*big.Int, error) {
	if len(values) != 1 {
		return nil, fmt.Errorf("expected one value, got %d", len(values))
	}
	value, ok := values[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("expected a numeric value, got %T", values[0])
	}
	return value, nil
}
