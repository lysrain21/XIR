package hyperlane

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

// Dispatched is a decoded Mailbox `Dispatch` log.
type Dispatched struct {
	// Sender is the origin adapter that called `dispatch` (the Mailbox emits
	// `msg.sender`, solidity/contracts/Mailbox.sol:302 and :434-457), i.e. the
	// address half of the evidence sender field.
	Sender common.Address

	// Destination is the destination domain of the message.
	Destination uint32

	// Recipient is the destination adapter as bytes32.
	Recipient [32]byte

	// Message is the raw dispatched message.
	Message []byte

	// MessageID is keccak256(Message), the value the origin MerkleTreeHook
	// inserted as a leaf and `DispatchId` carries.
	MessageID [32]byte

	// Nonce is the origin Mailbox nonce of the message.
	Nonce uint32
}

// DispatchedMessage returns the first Mailbox `Dispatch` log of a receipt with
// its message, message id, nonce and destination domain.
//
// contract is a Mailbox ABI (MailboxABI, or the Hyperlane artifact's ABI); the
// log is matched by its `Dispatch(address,uint32,bytes32,bytes)` topic, which is
// only emitted by a Mailbox, so the origin mailbox address is not required. The
// first match wins, which is the rule the Python reference uses when it reads a
// dispatch receipt (src/xir_lab/native/multihop_runner.py:1230-1239); a receipt
// without a dispatch log is an error, not an empty result.
//
// Note that the XIR adapters re-emit the id themselves: the Python runner takes
// `native_message_id` from the adapter's `HyperlaneDispatched` topic, which is a
// different (adapter) event on the same receipt.
func DispatchedMessage(receipt *types.Receipt, contract *abiutil.Contract) (Dispatched, error) {
	if receipt == nil {
		return Dispatched{}, errors.New("hyperlane: nil receipt")
	}
	if contract == nil {
		return Dispatched{}, errors.New("hyperlane: nil Mailbox ABI")
	}
	event, ok := contract.ABI().Events["Dispatch"]
	if !ok {
		return Dispatched{}, errors.New("hyperlane: Mailbox ABI has no Dispatch event")
	}
	for _, log := range receipt.Logs {
		if log == nil || len(log.Topics) == 0 || log.Topics[0] != event.ID {
			continue
		}
		values, err := contract.UnpackLog("Dispatch", log)
		if err != nil {
			return Dispatched{}, err
		}
		sender, err := typedValue[common.Address](values, "sender")
		if err != nil {
			return Dispatched{}, err
		}
		destination, err := typedValue[uint32](values, "destination")
		if err != nil {
			return Dispatched{}, err
		}
		recipient, err := typedValue[[32]byte](values, "recipient")
		if err != nil {
			return Dispatched{}, err
		}
		message, err := typedValue[[]byte](values, "message")
		if err != nil {
			return Dispatched{}, err
		}
		return Dispatched{
			Sender:      sender,
			Destination: destination,
			Recipient:   recipient,
			Message:     message,
			MessageID:   MessageID(message),
			Nonce:       Message(message).Nonce(),
		}, nil
	}
	return Dispatched{}, fmt.Errorf(
		"hyperlane: receipt %s has no Mailbox Dispatch log", receipt.TxHash.Hex(),
	)
}

// typedValue pulls one named, already decoded event argument out of the map
// abiutil.UnpackLog returns.
func typedValue[T any](values map[string]any, field string) (T, error) {
	var zero T
	value, ok := values[field]
	if !ok {
		return zero, fmt.Errorf("hyperlane: Dispatch log lacks the %s field", field)
	}
	typed, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("hyperlane: Dispatch log %s has type %T", field, value)
	}
	return typed, nil
}
