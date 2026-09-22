package runner

import (
	"github.com/lysrain21/XIR/go-runtime/internal/state"
)

// The ledger helpers keep every durable row in the same shape the Python
// runtime writes: details are canonical JSON with sorted keys, and stage rows
// always carry the chain role and hop index their events carry.

func stageRow(
	attemptID string,
	stage string,
	transactionHash string,
	detail map[string]any,
) (state.StageRow, error) {
	document, err := state.CanonicalJSON(detail)
	if err != nil {
		return state.StageRow{}, err
	}
	row := state.StageRow{
		AttemptID:  attemptID,
		Stage:      stage,
		State:      "succeeded",
		DetailJSON: document,
	}
	if transactionHash != "" {
		hash := transactionHash
		row.TransactionHash = &hash
	}
	return row, nil
}

func eventRow(
	attemptID string,
	stage string,
	event string,
	source string,
	chainRole string,
	hopIndex int,
	transactionHash string,
	detail map[string]any,
) (state.EventRow, error) {
	document, err := state.CanonicalJSON(detail)
	if err != nil {
		return state.EventRow{}, err
	}
	index := hopIndex
	return state.EventRow{
		AttemptID:       attemptID,
		Stage:           stage,
		Event:           event,
		Source:          source,
		ChainRole:       chainRole,
		HopIndex:        &index,
		TransactionHash: transactionHash,
		DetailJSON:      document,
	}, nil
}
