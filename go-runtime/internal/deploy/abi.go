package deploy

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// This file holds the Go shapes of the ABI tuples the deployment packs. Every
// field carries an explicit `abi:"name"` tag so go-ethereum maps it to the
// component name of the artifact ABI, and a tag that no longer matches the
// artifact is a hard error instead of a silently reordered tuple.

// registryRootSnapshot is the XIRRegistry.RootSnapshot tuple that
// `setRoot(version, snapshot)` takes.
type registryRootSnapshot struct {
	GatewayHash [32]byte       `abi:"gatewayHash"`
	Signer      common.Address `abi:"signer"`
	ValidAfter  uint64         `abi:"validAfter"`
	ValidUntil  uint64         `abi:"validUntil"`
	Enabled     bool           `abi:"enabled"`
}

// registryProfileSnapshot is the XIRRegistry.ProfileSnapshot tuple that
// `setProfile(profileHash, snapshot)` takes.
type registryProfileSnapshot struct {
	SourceHash      [32]byte       `abi:"srcHash"`
	DestinationHash [32]byte       `abi:"dstHash"`
	Adapter         common.Address `abi:"adapter"`
	SecurityLevel   uint8          `abi:"securityLevel"`
	ValidAfter      uint64         `abi:"validAfter"`
	ValidUntil      uint64         `abi:"validUntil"`
	Enabled         bool           `abi:"enabled"`
}

// ulnConfig is the LayerZero UlnConfig tuple.
type ulnConfig struct {
	Confirmations        uint64           `abi:"confirmations"`
	RequiredDVNCount     uint8            `abi:"requiredDVNCount"`
	OptionalDVNCount     uint8            `abi:"optionalDVNCount"`
	OptionalDVNThreshold uint8            `abi:"optionalDVNThreshold"`
	RequiredDVNs         []common.Address `abi:"requiredDVNs"`
	OptionalDVNs         []common.Address `abi:"optionalDVNs"`
}

// setDefaultUlnConfigParam is one element of SendUln302/ReceiveUln302
// `setDefaultUlnConfigs`.
type setDefaultUlnConfigParam struct {
	EID    uint32    `abi:"eid"`
	Config ulnConfig `abi:"config"`
}

// executorConfig is the LayerZero ExecutorConfig tuple.
type executorConfig struct {
	MaxMessageSize uint32         `abi:"maxMessageSize"`
	Executor       common.Address `abi:"executor"`
}

// setDefaultExecutorConfigParam is one element of SendUln302
// `setDefaultExecutorConfigs`.
type setDefaultExecutorConfigParam struct {
	EID    uint32         `abi:"eid"`
	Config executorConfig `abi:"config"`
}

// dvnDstConfigParam is one element of DVN `setDstConfig`.
type dvnDstConfigParam struct {
	DestinationEID uint32   `abi:"dstEid"`
	Gas            uint64   `abi:"gas"`
	MultiplierBps  uint16   `abi:"multiplierBps"`
	FloorMarginUSD *big.Int `abi:"floorMarginUSD"`
}

// executorDstConfigParam is one element of Executor `setDstConfig`.
type executorDstConfigParam struct {
	DestinationEID   uint32   `abi:"dstEid"`
	LzReceiveBaseGas uint64   `abi:"lzReceiveBaseGas"`
	LzComposeBaseGas uint64   `abi:"lzComposeBaseGas"`
	MultiplierBps    uint16   `abi:"multiplierBps"`
	FloorMarginUSD   *big.Int `abi:"floorMarginUSD"`
	NativeCap        *big.Int `abi:"nativeCap"`
}

// priceFeedPrice is the ILayerZeroPriceFeed.Price tuple.
type priceFeedPrice struct {
	PriceRatio     *big.Int `abi:"priceRatio"`
	GasPriceInUnit uint64   `abi:"gasPriceInUnit"`
	GasPerByte     uint32   `abi:"gasPerByte"`
}

// priceFeedUpdate is one element of PriceFeed `setPrice`.
type priceFeedUpdate struct {
	EID   uint32         `abi:"eid"`
	Price priceFeedPrice `abi:"price"`
}

// receiveOptions builds the official Type-3 Executor LZ_RECEIVE options with
// zero native value, byte for byte
// `src/xir_lab/native/layerzero.py:executor_lz_receive_options`. Slice D owns
// internal/layerzero; this copy exists because that package does not exist yet
// and the deployment needs the same bytes to configure the adapters.
func receiveOptions(gasLimit uint64) ([]byte, error) {
	if gasLimit == 0 {
		return nil, fmt.Errorf("deploy: layerzero executor gas limit is out of uint128 range")
	}
	options := make([]byte, 0, 22)
	options = append(options, 0x00, 0x03) // option type 3, one option
	options = append(options, 0x01)       // option length
	options = append(options, 0x00, 0x11) // worker id 17, the executor
	options = append(options, 0x01)       // option length
	var limit [16]byte
	for index := len(limit) - 1; index >= 0; index-- {
		limit[index] = byte(gasLimit)
		gasLimit >>= 8
	}
	return append(options, limit[:]...), nil
}

// receiveOptionsGasLimit is the gas limit every adapter is configured with
// (src/xir_lab/native/multihop_deployer.py `_configure_route_adapters`).
const receiveOptionsGasLimit uint64 = 1_500_000
