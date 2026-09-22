package hyperlane

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

// mailboxABI is the Mailbox surface this package packs and decodes with: the
// single relayer entry point `process(bytes,bytes)`
// (solidity/contracts/Mailbox.sol:202-247, declared at
// solidity/contracts/interfaces/IMailbox.sol:103-106) and the `Dispatch` event a
// relayer reads a dispatched message back from (IMailbox.sol:16-21).
//
// It is a fragment rather than a Forge artifact so this package stays usable
// without `contracts/out`; internal/artifacts loads the full artifact when the
// caller has one.
const mailboxABI = `[
  {
    "type": "function",
    "name": "process",
    "stateMutability": "payable",
    "inputs": [
      {"name": "_metadata", "type": "bytes"},
      {"name": "_message", "type": "bytes"}
    ],
    "outputs": []
  },
  {
    "type": "event",
    "name": "Dispatch",
    "anonymous": false,
    "inputs": [
      {"name": "sender", "type": "address", "indexed": true},
      {"name": "destination", "type": "uint32", "indexed": true},
      {"name": "recipient", "type": "bytes32", "indexed": true},
      {"name": "message", "type": "bytes", "indexed": false}
    ]
  }
]`

var (
	mailboxOnce     sync.Once
	mailboxContract *abiutil.Contract
	mailboxError    error
)

// MailboxABI returns the parsed Mailbox fragment, so callers can pack and decode
// against the same ABI document this package uses.
func MailboxABI() (*abiutil.Contract, error) {
	mailboxOnce.Do(func() {
		mailboxContract, mailboxError = abiutil.New(mailboxABI)
	})
	if mailboxError != nil {
		return nil, mailboxError
	}
	return mailboxContract, nil
}

// PlanRequest is everything the relayer derives off chain before submitting the
// destination call: the dispatched message, the origin tree the validators
// signed for, the checkpoint they signed, their signatures, and the destination
// Mailbox the call goes to.
type PlanRequest struct {
	Message []byte

	// OriginMerkleTreeHook is the origin MerkleTreeHook address, i.e. metadata
	// field [0:32] and the tree half of the signing domain. It is not the origin
	// Mailbox: the ISM binds the tree address cryptographically and would not
	// recover the validators from a mailbox address.
	OriginMerkleTreeHook common.Address

	// Checkpoint is the signed checkpoint of this message's leaf: the root and
	// index validators signed, plus the origin domain.
	Checkpoint Checkpoint

	// Signatures are the validators' 65-byte `r || s || v` signatures, ordered
	// as the ISM's validator array is ordered.
	Signatures []byte

	// DestinationMailbox is the Mailbox on the destination domain, whose
	// `localDomain` must equal the message's destination field.
	DestinationMailbox common.Address
}

// ProcessCall is the one destination-chain action that delivers a dispatched hop.
type ProcessCall struct {
	// Mailbox is the destination Mailbox the call is sent to.
	Mailbox common.Address

	// Message is the dispatched message, submitted verbatim.
	Message []byte

	// MessageID is keccak256(Message); the destination Mailbox refuses a second
	// delivery of the same id (Mailbox.sol:216-217).
	MessageID [32]byte

	// Metadata is the ISM metadata paired with the message.
	Metadata []byte

	// Calldata is `process(bytes,bytes)` with the metadata and the message: the
	// calldata of the destination transaction, and the only argument the
	// destination chain is called with.
	Calldata []byte
}

// Plan derives the destination `process` call for one dispatched hop.
//
// The plan is pure: it validates the inputs the relayer already holds and packs
// the calldata. Everything that needs chain state stays on the caller's side —
// the origin tree root and leaf index come from the origin MerkleTreeHook
// (`root()`, `count()`, or the `InsertedIntoTree` log of this dispatch), and the
// destination Mailbox's own `localDomain` check happens on chain.
func Plan(request PlanRequest) (ProcessCall, error) {
	message := Message(request.Message)
	if err := message.Validate(); err != nil {
		return ProcessCall{}, err
	}
	if version := message.Version(); version != Version {
		return ProcessCall{}, fmt.Errorf(
			"hyperlane: message version %d, want %d (Mailbox: bad version)", version, Version,
		)
	}
	if origin := message.Origin(); origin != request.Checkpoint.Domain {
		return ProcessCall{}, fmt.Errorf(
			"hyperlane: checkpoint domain %d does not match message origin %d",
			request.Checkpoint.Domain, origin,
		)
	}
	if request.DestinationMailbox == (common.Address{}) {
		return ProcessCall{}, errors.New("hyperlane: destination mailbox is the zero address")
	}
	metadata, err := Metadata(
		request.OriginMerkleTreeHook,
		request.Checkpoint.Root,
		request.Checkpoint.Index,
		request.Signatures,
	)
	if err != nil {
		return ProcessCall{}, err
	}
	contract, err := MailboxABI()
	if err != nil {
		return ProcessCall{}, err
	}
	calldata, err := contract.PackCall("process", metadata, request.Message)
	if err != nil {
		return ProcessCall{}, err
	}
	return ProcessCall{
		Mailbox:   request.DestinationMailbox,
		Message:   request.Message,
		MessageID: MessageID(request.Message),
		Metadata:  metadata,
		Calldata:  calldata,
	}, nil
}
