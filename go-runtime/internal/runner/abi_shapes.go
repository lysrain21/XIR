package runner

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// adapterRequestABI is the request tuple of LayerZeroAdapter.sendSource,
// forwardInFlight, and quoteForward.
type adapterRequestABI struct {
	Verifiers             []common.Address `abi:"verifiers"`
	ProfileHashes         [][32]byte       `abi:"profileHashes"`
	EvidenceHashes        [][32]byte       `abi:"evidenceHashes"`
	TransitionHashes      [][32]byte       `abi:"transitionHashes"`
	CurrentProfileHash    [32]byte         `abi:"currentProfileHash"`
	CurrentTransitionHash [32]byte         `abi:"currentTransitionHash"`
	Options               []byte           `abi:"options"`
}

// hyperlaneRequestABI is the request tuple of HyperlaneAdapter.sendSourceBundle,
// forwardInFlightBundle, and quoteBundle: the same tuple without options.
type hyperlaneRequestABI struct {
	Verifiers             []common.Address `abi:"verifiers"`
	ProfileHashes         [][32]byte       `abi:"profileHashes"`
	EvidenceHashes        [][32]byte       `abi:"evidenceHashes"`
	TransitionHashes      [][32]byte       `abi:"transitionHashes"`
	CurrentProfileHash    [32]byte         `abi:"currentProfileHash"`
	CurrentTransitionHash [32]byte         `abi:"currentTransitionHash"`
}

// messagingFeeABI is the LayerZero MessagingFee tuple (nativeFee, lzTokenFee)
// that the adapter's quote functions return.
type messagingFeeABI struct {
	NativeFee  *big.Int `abi:"nativeFee"`
	LzTokenFee *big.Int `abi:"lzTokenFee"`
}

// hyperlaneInnerABI is the DeliveryBundle inner encoding of HyperlaneAdapter.
type hyperlaneInnerABI struct {
	CurrentProfile    [32]byte   `abi:"currentProfile"`
	CurrentTransition [32]byte   `abi:"currentTransition"`
	PriorProfiles     [][32]byte `abi:"priorProfiles"`
	PriorEvidence     [][32]byte `abi:"priorEvidence"`
	PriorTransitions  [][32]byte `abi:"priorTransitions"`
}

// hyperlaneBodyABI is the adapter message body: (uint8 kind, bytes inner).
type hyperlaneBodyABI struct {
	Kind  uint8  `abi:"kind"`
	Inner []byte `abi:"inner"`
}

// hyperlaneEvidenceABI is the preimage of the Hyperlane evidence hash.
type hyperlaneEvidenceABI struct {
	Domain uint32   `abi:"domain"`
	Sender [32]byte `abi:"sender"`
	Body   []byte   `abi:"body"`
}

// The fragments below mirror the Solidity types the adapters and the Python
// coordinator encode (src/xir_lab/native/multihop_runner.py _dispatch_hop).
const (
	hyperlaneInnerFragments = `[{"name":"currentProfile","type":"bytes32"},` +
		`{"name":"currentTransition","type":"bytes32"},` +
		`{"name":"priorProfiles","type":"bytes32[]"},` +
		`{"name":"priorEvidence","type":"bytes32[]"},` +
		`{"name":"priorTransitions","type":"bytes32[]"}]`

	hyperlaneBodyFragments = `[{"name":"kind","type":"uint8"},{"name":"inner","type":"bytes"}]`

	hyperlaneEvidenceFragments = `[{"name":"domain","type":"uint32"},` +
		`{"name":"sender","type":"bytes32"},{"name":"body","type":"bytes"}]`
)
