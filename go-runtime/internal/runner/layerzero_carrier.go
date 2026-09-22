package runner

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/layerzero"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// nativeFee reads the native fee of a LayerZero quote. The adapter returns the
// MessagingFee tuple, matching src/xir_lab/native/multihop_runner.py, which
// takes element zero of the quoted tuple.
func nativeFee(quoted []any) (*big.Int, error) {
	if len(quoted) != 1 {
		return nil, fmt.Errorf("quote returned %d values", len(quoted))
	}
	if fee, ok := quoted[0].(*big.Int); ok {
		return fee, nil
	}
	fee, ok := abi.ConvertType(quoted[0], messagingFeeABI{}).(messagingFeeABI)
	if !ok || fee.NativeFee == nil {
		return nil, fmt.Errorf("quote returned %T without a native fee", quoted[0])
	}
	return fee.NativeFee, nil
}

const (
	// defaultConfirmations is the source confirmation count the DVN attests.
	defaultConfirmations uint64 = 1
	// defaultDeliveryGasLimit is the executor gas limit of one delivery.
	defaultDeliveryGasLimit uint64 = 1_500_000
)

// layerZeroDelivery is the protocol-private data one LayerZero hop needs after
// dispatch: the packet the source endpoint emitted.
type layerZeroDelivery struct {
	Packet       layerzero.Packet
	SourceResult state.ActionResult
	SourceRole   string
}

type layerZeroCarrier struct {
	chains          *contractSet
	protocolRoot    string
	eids            map[string]uint32
	chainsByRole    map[string]ChainConfig
	workerKey       string
	embedded        bool
	poll            time.Duration
	timeout         time.Duration
	confirmations   uint64
	gasLimit        uint64
	transactionGas  uint64
	options         []byte
	faultAfterStage string
}

func newLayerZeroCarrier(
	chains *contractSet,
	protocolRoot string,
	configs []ChainConfig,
	keys KeySet,
	config Config,
) (*layerZeroCarrier, error) {
	eids := map[string]uint32{}
	byRole := map[string]ChainConfig{}
	for _, chain := range configs {
		eids[chain.Role] = chain.LayerZeroEID
		byRole[chain.Role] = chain
	}
	options := config.OptionsOverride
	if len(options) == 0 {
		generated, err := layerzero.ReceiveOptions(1_500_000)
		if err != nil {
			return nil, fmt.Errorf("runner: layerzero options: %w", err)
		}
		options = generated
	}
	return &layerZeroCarrier{
		chains:          chains,
		protocolRoot:    protocolRoot,
		eids:            eids,
		chainsByRole:    byRole,
		workerKey:       keys.LayerZeroWorker,
		embedded:        config.EmbeddedAgents,
		poll:            config.PollInterval,
		timeout:         config.Timeout,
		confirmations:   defaultConfirmations,
		gasLimit:        defaultDeliveryGasLimit,
		transactionGas:  layerzero.DefaultTransactionGas,
		options:         options,
		faultAfterStage: config.FaultAfterStage,
	}, nil
}

// Dispatch submits sendSource (first hop) or forwardInFlight with the enforced
// executor options, and returns the LayerZero GUID reported by the adapter.
func (c *layerZeroCarrier) Dispatch(ctx context.Context, request HopRequest) (DispatchResult, error) {
	adapter := request.SourceAdapter
	profiles := make([][32]byte, 0, len(request.PriorReceipts))
	evidences := make([][32]byte, 0, len(request.PriorReceipts))
	transitions := make([][32]byte, 0, len(request.PriorReceipts))
	for _, receipt := range request.PriorReceipts {
		profiles = append(profiles, receipt.ProfileHash)
		evidences = append(evidences, receipt.EvidenceHash)
		transitions = append(transitions, receipt.TransitionHash)
	}
	forward := adapterRequestABI{
		Verifiers:             request.Verifiers,
		ProfileHashes:         profiles,
		EvidenceHashes:        evidences,
		TransitionHashes:      transitions,
		CurrentProfileHash:    request.CurrentProfile,
		CurrentTransitionHash: request.CurrentTransition,
		Options:               c.options,
	}
	stage := dispatchStage(request.HopIndex, request.Protocol)
	fee, err := dispatchFee(c.chains.store, actionID(request.AttemptID, stage), func() (*big.Int, error) {
		quoted, err := adapter.call(ctx, "quoteForward", forward)
		if err != nil {
			return nil, err
		}
		return nativeFee(quoted)
	})
	if err != nil {
		return DispatchResult{}, fmt.Errorf("runner: layerzero dispatch fee: %w", err)
	}

	name := "sendSource"
	if request.HopIndex > 1 {
		name = "forwardInFlight"
	}
	result, err := adapter.send(ctx, request.AttemptID, stage, name, []any{forward}, fee)
	if err != nil {
		return DispatchResult{}, err
	}
	events, err := adapter.events(ctx, result, "VerifiedEvidenceForwarded")
	if err != nil {
		return DispatchResult{}, err
	}
	if len(events) != 1 {
		return DispatchResult{}, fmt.Errorf(
			"runner: hop %d dispatch emitted %d VerifiedEvidenceForwarded events", request.HopIndex, len(events),
		)
	}
	guid, ok := events[0]["guid"].([32]byte)
	if !ok {
		return DispatchResult{}, fmt.Errorf("runner: VerifiedEvidenceForwarded guid is missing")
	}
	packet, err := c.readPacket(ctx, adapter, request, result)
	if err != nil {
		return DispatchResult{}, err
	}
	return DispatchResult{
		Evidence: Evidence{
			Hash:            guid,
			NativeMessageID: "0x" + common.Bytes2Hex(guid[:]),
			Detail: map[string]any{
				"protocol":             "L",
				"hop_index":            request.HopIndex,
				"native_message_id":    "0x" + common.Bytes2Hex(guid[:]),
				"quote_native_fee_wei": fee.String(),
				"destination_eid":      c.eids[request.DestinationRole],
				"packet_nonce":         packet.Nonce,
			},
		},
		Stage:       stage,
		Transaction: result.TransactionHash,
		delivery: layerZeroDelivery{
			Packet:       packet,
			SourceResult: result,
			SourceRole:   request.SourceRole,
		},
	}, nil
}

// readPacket extracts the PacketSent payload of this dispatch from the source
// endpoint logs and decodes it.
func (c *layerZeroCarrier) readPacket(
	ctx context.Context,
	adapter *bound,
	request HopRequest,
	result state.ActionResult,
) (layerzero.Packet, error) {
	endpoint, err := c.chains.deployment.Infra(request.SourceRole, "endpoint_v2")
	if err != nil {
		return layerzero.Packet{}, err
	}
	receipt, err := adapter.client.Receipt(ctx, common.HexToHash(result.TransactionHash))
	if err != nil {
		return layerzero.Packet{}, err
	}
	packet, err := layerzero.ExtractPacket(receipt, c.eids[request.SourceRole])
	if err != nil {
		return layerzero.Packet{}, fmt.Errorf("runner: hop %d dispatch: %w", request.HopIndex, err)
	}
	_ = endpoint
	return packet, nil
}

// Confirm runs the self-hosted DVN and Executor stages when this runtime owns
// them, then waits for the destination adapter to verify the bundle.
func (c *layerZeroCarrier) Confirm(ctx context.Context, request HopRequest, dispatched DispatchResult) error {
	delivery, ok := dispatched.delivery.(layerZeroDelivery)
	if !ok {
		return fmt.Errorf("runner: layerzero dispatch result is missing delivery data")
	}
	if c.embedded {
		if err := c.deliver(ctx, request, delivery); err != nil {
			return err
		}
	}
	return awaitVerified(ctx, c.chains, request, dispatched.Evidence, c.poll, c.timeout)
}

// deliver submits the official DVN, ReceiveUln302, and Executor transactions.
func (c *layerZeroCarrier) deliver(ctx context.Context, request HopRequest, delivery layerZeroDelivery) error {
	destination, err := c.chains.chain(request.DestinationRole)
	if err != nil {
		return err
	}
	dvn, err := c.chains.deployment.Infra(request.DestinationRole, "dvn")
	if err != nil {
		return err
	}
	receiveULN, err := c.chains.deployment.Infra(request.DestinationRole, "receive_uln_302")
	if err != nil {
		return err
	}
	executor, err := c.chains.deployment.Infra(request.DestinationRole, "executor")
	if err != nil {
		return err
	}
	transactor, err := destination.agentTransactor(c.workerKey)
	if err != nil {
		return err
	}
	workerSigner, err := evm.NewSigner(c.workerKey, new(big.Int).SetUint64(destination.config.ChainID))
	if err != nil {
		return fmt.Errorf("runner: layerzero worker signer: %w", err)
	}
	expiration := big.NewInt(time.Now().Add(time.Hour).Unix())
	frozen, err := c.chains.store.Action(actionID(request.AttemptID, layerZeroStage(request.HopIndex, layerzero.StageDVNExecute)))
	if err != nil {
		return err
	}
	if frozen != nil {
		if err := state.VerifyActionIdentity(frozen); err != nil {
			return err
		}
		data, err := abiutil.DecodeHex(frozen.CalldataHex)
		if err != nil {
			return err
		}
		expiration, err = layerzero.DVNExpiration(data)
		if err != nil {
			return fmt.Errorf("runner: frozen DVN expiration: %w", err)
		}
	}

	actions, err := layerzero.Plan(delivery.Packet, layerzero.PlanConfig{
		DVN:            dvn,
		ReceiveULN:     receiveULN,
		Executor:       executor,
		Confirmations:  c.confirmations,
		GasLimit:       c.gasLimit,
		TransactionGas: c.transactionGas,
		Expiration:     expiration,
	}, workerSigner)
	if err != nil {
		return fmt.Errorf("runner: layerzero delivery plan: %w", err)
	}
	for _, action := range actions {
		stage := layerZeroStage(request.HopIndex, action.Stage)
		result, err := transactor.Execute(ctx, evm.TxRequest{
			ActionID:  actionID(request.AttemptID, stage),
			AttemptID: request.AttemptID,
			Stage:     stage,
			ChainRole: request.DestinationRole,
			To:        action.Target,
			Data:      action.CallData,
			Gas:       action.Gas,
		})
		if err != nil {
			return fmt.Errorf("runner: layerzero %s: %w", action.Stage, err)
		}
		if c.faultAfterStage == stage {
			return fmt.Errorf("runner: injected fault after stage %s", stage)
		}
		if err := verifyStageTopic(ctx, destination.client, result, action.ExpectedTopic, action.Stage); err != nil {
			return err
		}
		row, err := eventRow(
			request.AttemptID, stage, "succeeded", "embedded-worker",
			request.DestinationRole, request.HopIndex, result.TransactionHash,
			map[string]any{
				"guid":     xir.FormatDigest(delivery.Packet.GUID),
				"target":   action.Target.Hex(),
				"stage":    action.Stage,
				"nonce":    delivery.Packet.Nonce,
				"gas_used": result.GasUsed,
			},
		)
		if err != nil {
			return err
		}
		if err := c.chains.recordEvent(row); err != nil {
			return err
		}
	}
	return nil
}

// awaitVerified polls the destination adapter until every receipt of the
// current bundle is accepted.
func awaitVerified(
	ctx context.Context,
	chains *contractSet,
	request HopRequest,
	evidence Evidence,
	poll time.Duration,
	timeout time.Duration,
) error {
	bundle := bundleWithCurrent(request, evidence)
	adapter := request.DestinationAdapter
	deadline := time.Now().Add(timeout)
	for {
		verified, err := bundleVerified(ctx, adapter, bundle)
		if err != nil {
			return err
		}
		if verified {
			row, err := eventRow(
				request.AttemptID, callbackStage(request.HopIndex, request.Protocol),
				"accepted", "coordinator_read", request.DestinationRole, request.HopIndex, "",
				map[string]any{
					"adapter":              adapter.address.Hex(),
					"verified_tuple_count": len(bundle),
					"profile_hash":         xir.FormatDigest(request.CurrentProfile),
					"evidence_hash":        xir.FormatDigest(evidence.Hash),
				},
			)
			if err != nil {
				return err
			}
			return chains.recordEvent(row)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"runner: timed out waiting for hop %d bundle at %s:%s",
				request.HopIndex, adapter.role, adapter.key,
			)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func bundleVerified(ctx context.Context, adapter *bound, bundle []xir.Receipt) (bool, error) {
	for _, receipt := range bundle {
		values, err := adapter.call(
			ctx, "verify", receipt.ProfileHash, receipt.EvidenceHash, receipt.TransitionHash,
		)
		if err != nil {
			return false, err
		}
		if len(values) != 1 {
			return false, fmt.Errorf("runner: adapter verify returned %d values", len(values))
		}
		accepted, ok := values[0].(bool)
		if !ok {
			return false, fmt.Errorf("runner: adapter verify returned %T", values[0])
		}
		if !accepted {
			return false, nil
		}
	}
	return true, nil
}
