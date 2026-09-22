package runner

import (
	"context"
	"fmt"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// Evidence is one hop's on-chain evidence as the destination adapter records it.
type Evidence struct {
	// Hash is the evidence hash the XIR receipt commits to.
	Hash [32]byte
	// NativeMessageID is the carrier message identifier, for the ledger only.
	NativeMessageID string
	// Detail is copied into the durable stage row.
	Detail map[string]any
}

// HopRequest is everything a carrier needs to move one hop.
type HopRequest struct {
	Route              string
	AttemptID          string
	HopIndex           int
	Protocol           string
	SourceRole         string
	DestinationRole    string
	SourceAdapter      *bound
	DestinationAdapter *bound
	Verifiers          []common.Address
	PriorReceipts      []xir.Receipt
	CurrentProfile     [32]byte
	CurrentTransition  [32]byte
}

// DispatchResult is the outcome of one dispatch plus the protocol-private data
// the confirmation step needs.
type DispatchResult struct {
	Evidence    Evidence
	Stage       string
	Transaction string
	delivery    any
}

// Carrier moves one hop and confirms the destination adapter accepted it.
type Carrier interface {
	// Dispatch submits the source-chain dispatch of one hop.
	Dispatch(ctx context.Context, request HopRequest) (DispatchResult, error)
	// Confirm delivers the message when this runtime owns the carrier's
	// chain-external roles, then waits until the destination adapter reports
	// every receipt of the current bundle as verified.
	Confirm(ctx context.Context, request HopRequest, dispatched DispatchResult) error
}

// bundleWithCurrent returns the receipts the destination adapter must accept:
// the prior receipts followed by this hop's receipt.
func bundleWithCurrent(request HopRequest, evidence Evidence) []xir.Receipt {
	bundle := make([]xir.Receipt, 0, len(request.PriorReceipts)+1)
	bundle = append(bundle, request.PriorReceipts...)
	bundle = append(bundle, xir.Receipt{
		ProfileHash:    request.CurrentProfile,
		EvidenceHash:   evidence.Hash,
		TransitionHash: request.CurrentTransition,
	})
	return bundle
}

// dispatchFee reuses the original payable amount on recovery. Re-quoting an
// already frozen dispatch against newer gas prices would change its identity.
func dispatchFee(store *state.Store, id string, quote func() (*big.Int, error)) (*big.Int, error) {
	action, err := store.Action(id)
	if err != nil {
		return nil, err
	}
	if action == nil {
		return quote()
	}
	if err := state.VerifyActionIdentity(action); err != nil {
		return nil, err
	}
	fee, ok := new(big.Int).SetString(action.Value, 10)
	if !ok || fee.Sign() < 0 {
		return nil, fmt.Errorf("runner: invalid frozen dispatch fee")
	}
	return fee, nil
}
