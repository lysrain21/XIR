package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Carrier bootstrap document identity, the schema versions
// `DeployHyperlaneNative.s.sol` and `DeployLayerZeroNative.s.sol` write.
const (
	hyperlaneSchemaVersion = "xir-lab-hyperlane-native-deployment-v1"
	layerZeroSchemaVersion = "xir-lab-layerzero-deployment-v1"
)

// hyperlaneProject and layerZeroProject are the protocol project directories
// inside Options.ProtocolArtifactsRoot.
const (
	hyperlaneProject = "hyperlane-native"
	layerZeroProject = "layerzero-native"
)

// HyperlaneDeploymentDocument is the Hyperlane bootstrap of one chain, with
// the keys `DeployHyperlaneNative.s.sol` writes.
type HyperlaneDeploymentDocument struct {
	SchemaVersion string            `json:"schema_version"`
	LocalDomain   uint32            `json:"local_domain"`
	Contracts     map[string]string `json:"contracts"`
}

// LayerZeroDeploymentDocument is the LayerZero bootstrap of one chain, with
// the keys `DeployLayerZeroNative.s.sol` writes.
type LayerZeroDeploymentDocument struct {
	SchemaVersion string            `json:"schema_version"`
	LocalEID      uint32            `json:"local_eid"`
	Contracts     map[string]string `json:"contracts"`
}

// ProtocolDeploymentDocument is the carrier bootstrap of one chain, including
// the chain coordinates the document's address maps deliberately do not carry.
// The RPC endpoint is not recorded: the document is evidence, and an endpoint
// URL may carry credentials.
type ProtocolDeploymentDocument struct {
	ChainID         uint64                      `json:"chain_id"`
	HyperlaneDomain uint32                      `json:"hyperlane_domain"`
	LayerZeroEID    uint32                      `json:"layerzero_eid"`
	Hyperlane       HyperlaneDeploymentDocument `json:"hyperlane"`
	LayerZero       LayerZeroDeploymentDocument `json:"layerzero"`
}

// protocolStack is one chain's deployed carriers.
type protocolStack struct {
	document ProtocolDeploymentDocument

	mailbox                           common.Address
	merkleTreeHook                    common.Address
	validatorAnnounce                 common.Address
	defaultIsm                        common.Address
	staticMessageIDMultisigIsmFactory common.Address
	protocolFee                       common.Address
	interchainGasPaymaster            common.Address

	endpointV2              common.Address
	sendUln302              common.Address
	receiveUln302           common.Address
	dvn                     common.Address
	executor                common.Address
	priceFeed               common.Address
	treasury                common.Address
	dvnFeeLib               common.Address
	executorFeeLib          common.Address
	priceFeedImplementation common.Address
	executorImplementation  common.Address
}

// infrastructureDocument merges the carrier addresses of every chain under the
// names the runtime resolves them by: the Hyperlane registry names and the
// LayerZero deployment names, so both a Go reader and a Python reader find
// what they expect.
func (r *deployment) infrastructureDocument() map[string]map[string]string {
	out := make(map[string]map[string]string, len(r.order))
	for _, role := range r.order {
		stack := r.stack[role]
		addresses := map[string]string{}
		for key, address := range stack.hyperlaneContracts() {
			addresses[key] = address.Hex()
		}
		for key, address := range stack.layerZeroContracts() {
			addresses[key] = address.Hex()
		}
		out[role] = addresses
	}
	return out
}

// hyperlaneContracts returns the registry addresses of one chain in the key
// order `DeployHyperlaneNative.s.sol` writes.
func (s *protocolStack) hyperlaneContracts() map[string]common.Address {
	return map[string]common.Address{
		"mailbox":                           s.mailbox,
		"merkleTreeHook":                    s.merkleTreeHook,
		"validatorAnnounce":                 s.validatorAnnounce,
		"defaultIsm":                        s.defaultIsm,
		"staticMessageIdMultisigIsmFactory": s.staticMessageIDMultisigIsmFactory,
		"protocolFee":                       s.protocolFee,
	}
}

// layerZeroContracts returns the deployment addresses of one chain in the key
// order `DeployLayerZeroNative.s.sol` writes.
func (s *protocolStack) layerZeroContracts() map[string]common.Address {
	return map[string]common.Address{
		"endpoint_v2":               s.endpointV2,
		"send_uln_302":              s.sendUln302,
		"receive_uln_302":           s.receiveUln302,
		"dvn":                       s.dvn,
		"executor":                  s.executor,
		"price_feed":                s.priceFeed,
		"treasury":                  s.treasury,
		"dvn_fee_lib":               s.dvnFeeLib,
		"executor_fee_lib":          s.executorFeeLib,
		"price_feed_implementation": s.priceFeedImplementation,
		"executor_implementation":   s.executorImplementation,
	}
}

// bootstrapProtocols deploys both carriers on every chain, in chain order.
func (r *deployment) bootstrapProtocols(ctx context.Context) error {
	for index, role := range r.order {
		spec := r.specs[index]
		stack := &protocolStack{}
		if err := r.bootstrapHyperlane(ctx, role, stack); err != nil {
			return err
		}
		if err := r.bootstrapLayerZero(ctx, role, remoteEIDs(r.specs, role), stack); err != nil {
			return err
		}
		stack.document = ProtocolDeploymentDocument{
			ChainID:         spec.ChainID,
			HyperlaneDomain: spec.HyperlaneDomain,
			LayerZeroEID:    spec.LayerZeroEID,
			Hyperlane: HyperlaneDeploymentDocument{
				SchemaVersion: hyperlaneSchemaVersion,
				LocalDomain:   spec.HyperlaneDomain,
				Contracts:     addressStrings(stack.hyperlaneContracts()),
			},
			LayerZero: LayerZeroDeploymentDocument{
				SchemaVersion: layerZeroSchemaVersion,
				LocalEID:      spec.LayerZeroEID,
				Contracts:     addressStrings(stack.layerZeroContracts()),
			},
		}
		r.stack[role] = stack
		r.protocolDocuments[role] = stack.document
		if err := r.writeProtocolDocuments(role, spec, stack); err != nil {
			return err
		}
	}
	return nil
}

// bootstrapHyperlane reproduces
// `DeployHyperlaneNative.s.sol`: Mailbox, the static multisig ISM factory and
// the ISM it deploys, MerkleTreeHook, ProtocolFee, ValidatorAnnounce, then
// `initialize`.
func (r *deployment) bootstrapHyperlane(ctx context.Context, role string, stack *protocolStack) error {
	chain := r.chains[role]
	spec := chain.spec
	mailboxArtifact, err := r.loadHyperlane("Mailbox.sol", "Mailbox")
	if err != nil {
		return err
	}
	factoryArtifact, err := r.loadHyperlane("StaticMultisigIsm.sol", "StaticMessageIdMultisigIsmFactory")
	if err != nil {
		return err
	}
	hookArtifact, err := r.loadHyperlane("MerkleTreeHook.sol", "MerkleTreeHook")
	if err != nil {
		return err
	}
	feeArtifact, err := r.loadHyperlane("ProtocolFee.sol", "ProtocolFee")
	if err != nil {
		return err
	}
	announceArtifact, err := r.loadHyperlane("ValidatorAnnounce.sol", "ValidatorAnnounce")
	if err != nil {
		return err
	}

	mailbox, err := chain.deploy(ctx, "mailbox", mailboxArtifact, spec.HyperlaneDomain)
	if err != nil {
		return err
	}
	factory, err := chain.deploy(ctx, "staticMessageIdMultisigIsmFactory", factoryArtifact)
	if err != nil {
		return err
	}
	validators := []common.Address{r.options.HyperlaneValidator}
	output, err := chain.callResult(ctx, "defaultIsm", factory, factoryArtifact, "deploy", validators, uint8(1))
	if err != nil {
		return err
	}
	var ism common.Address
	if err := factoryArtifact.ABI.UnpackOutputs("deploy", output, &ism); err != nil {
		return fmt.Errorf("chain %s: decode ISM address: %w", role, err)
	}
	if code, err := chain.client.CodeAt(ctx, ism); err != nil {
		return fmt.Errorf("chain %s: read ISM runtime code: %w", role, err)
	} else if len(code) == 0 {
		return fmt.Errorf("chain %s: the ISM factory deployed no code at %s", role, ism)
	}
	merkleTreeHook, err := chain.deploy(ctx, "merkleTreeHook", hookArtifact, mailbox)
	if err != nil {
		return err
	}
	protocolFee, err := chain.deploy(ctx, "protocolFee", feeArtifact,
		new(big.Int), new(big.Int), r.deployer, r.deployer,
	)
	if err != nil {
		return err
	}
	validatorAnnounce, err := chain.deploy(ctx, "validatorAnnounce", announceArtifact, mailbox)
	if err != nil {
		return err
	}
	if _, err := chain.call(ctx, "mailbox", mailbox, mailboxArtifact, "initialize",
		r.deployer, ism, protocolFee, merkleTreeHook,
	); err != nil {
		return err
	}
	stack.mailbox = mailbox
	stack.staticMessageIDMultisigIsmFactory = factory
	stack.defaultIsm = ism
	stack.merkleTreeHook = merkleTreeHook
	stack.protocolFee = protocolFee
	// The registry aliases the interchain gas paymaster to the protocol fee
	// hook, exactly as `materialize_multihop_hyperlane_registry` does.
	stack.interchainGasPaymaster = protocolFee
	stack.validatorAnnounce = validatorAnnounce
	return nil
}

// bootstrapLayerZero reproduces `DeployLayerZeroNative.s.sol`: the endpoint,
// both ULN 302 libraries, the treasury, the upgradeable price feed and
// executor, the DVN, the fee libraries, and every default configuration call.
func (r *deployment) bootstrapLayerZero(
	ctx context.Context,
	role string,
	remoteEIDs []uint32,
	stack *protocolStack,
) error {
	chain := r.chains[role]
	spec := chain.spec
	endpointArtifact, err := r.loadLayerZero("EndpointV2.sol", "EndpointV2")
	if err != nil {
		return err
	}
	sendUlnArtifact, err := r.loadLayerZero("SendUln302.sol", "SendUln302")
	if err != nil {
		return err
	}
	receiveUlnArtifact, err := r.loadLayerZero("ReceiveUln302.sol", "ReceiveUln302")
	if err != nil {
		return err
	}
	treasuryArtifact, err := r.loadLayerZero("Treasury.sol", "Treasury")
	if err != nil {
		return err
	}
	priceFeedArtifact, err := r.loadLayerZero("PriceFeed.sol", "PriceFeed")
	if err != nil {
		return err
	}
	dvnArtifact, err := r.loadLayerZero("DVN.sol", "DVN")
	if err != nil {
		return err
	}
	dvnFeeLibArtifact, err := r.loadLayerZero("DVNFeeLib.sol", "DVNFeeLib")
	if err != nil {
		return err
	}
	executorArtifact, err := r.loadLayerZero("Executor.sol", "Executor")
	if err != nil {
		return err
	}
	executorFeeLibArtifact, err := r.loadLayerZero("ExecutorFeeLib.sol", "ExecutorFeeLib")
	if err != nil {
		return err
	}
	proxyArtifact, err := r.loadLayerZero("ERC1967Proxy.sol", "ERC1967Proxy")
	if err != nil {
		return err
	}

	endpoint, err := chain.deploy(ctx, "endpoint_v2", endpointArtifact, spec.LayerZeroEID, r.deployer)
	if err != nil {
		return err
	}
	sendUln, err := chain.deploy(ctx, "send_uln_302", sendUlnArtifact,
		endpoint, big.NewInt(100_000), big.NewInt(100_000),
	)
	if err != nil {
		return err
	}
	receiveUln, err := chain.deploy(ctx, "receive_uln_302", receiveUlnArtifact, endpoint)
	if err != nil {
		return err
	}
	treasury, err := chain.deploy(ctx, "treasury", treasuryArtifact)
	if err != nil {
		return err
	}
	if _, err := chain.call(ctx, "send_uln_302", sendUln, sendUlnArtifact, "setTreasury", treasury); err != nil {
		return err
	}

	priceFeedImplementation, err := chain.deploy(ctx, "price_feed_implementation", priceFeedArtifact)
	if err != nil {
		return err
	}
	priceFeedInit, err := priceFeedArtifact.ABI.PackCall("initialize", r.deployer)
	if err != nil {
		return err
	}
	priceFeed, err := chain.deploy(ctx, "price_feed", proxyArtifact, priceFeedImplementation, priceFeedInit)
	if err != nil {
		return err
	}
	nativePrice := new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)
	if _, err := chain.call(ctx, "price_feed", priceFeed, priceFeedArtifact,
		"setNativeTokenPriceUSD", nativePrice,
	); err != nil {
		return err
	}
	prices := make([]priceFeedUpdate, 0, len(remoteEIDs))
	for _, eid := range remoteEIDs {
		prices = append(prices, priceFeedUpdate{
			EID:   eid,
			Price: priceFeedPrice{PriceRatio: nativePrice, GasPriceInUnit: 1, GasPerByte: 1},
		})
	}
	if _, err := chain.call(ctx, "price_feed", priceFeed, priceFeedArtifact, "setPrice", prices); err != nil {
		return err
	}

	messageLibs := []common.Address{sendUln, receiveUln}
	signers := []common.Address{r.options.LayerZeroWorker}
	admins := []common.Address{r.deployer, r.options.LayerZeroWorker}
	dvn, err := chain.deploy(ctx, "dvn", dvnArtifact,
		spec.LayerZeroEID, spec.LayerZeroEID, messageLibs, priceFeed, signers, uint64(1), admins,
	)
	if err != nil {
		return err
	}
	dvnFeeLib, err := chain.deploy(ctx, "dvn_fee_lib", dvnFeeLibArtifact,
		spec.LayerZeroEID, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	)
	if err != nil {
		return err
	}
	if _, err := chain.call(ctx, "dvn", dvn, dvnArtifact, "setWorkerFeeLib", dvnFeeLib); err != nil {
		return err
	}

	executorImplementation, err := chain.deploy(ctx, "executor_implementation", executorArtifact)
	if err != nil {
		return err
	}
	executorInit, err := executorArtifact.ABI.PackCall(
		"initialize", endpoint, common.Address{}, messageLibs, priceFeed, r.deployer, admins,
	)
	if err != nil {
		return err
	}
	executor, err := chain.deploy(ctx, "executor", proxyArtifact, executorImplementation, executorInit)
	if err != nil {
		return err
	}
	executorFeeLib, err := chain.deploy(ctx, "executor_fee_lib", executorFeeLibArtifact,
		spec.LayerZeroEID, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	)
	if err != nil {
		return err
	}
	if _, err := chain.call(ctx, "executor", executor, executorArtifact,
		"setWorkerFeeLib", executorFeeLib,
	); err != nil {
		return err
	}

	dvnConfigs := make([]dvnDstConfigParam, 0, len(remoteEIDs))
	executorConfigs := make([]executorDstConfigParam, 0, len(remoteEIDs))
	sendExecutorConfigs := make([]setDefaultExecutorConfigParam, 0, len(remoteEIDs))
	ulnConfigs := make([]setDefaultUlnConfigParam, 0, len(remoteEIDs))
	requiredDVNs := []common.Address{dvn}
	for _, eid := range remoteEIDs {
		dvnConfigs = append(dvnConfigs, dvnDstConfigParam{
			DestinationEID: eid,
			Gas:            5_000,
			MultiplierBps:  10_000,
			FloorMarginUSD: big.NewInt(0),
		})
		executorConfigs = append(executorConfigs, executorDstConfigParam{
			DestinationEID:   eid,
			LzReceiveBaseGas: 5_000,
			LzComposeBaseGas: 0,
			MultiplierBps:    10_000,
			FloorMarginUSD:   big.NewInt(0),
			NativeCap:        new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
		})
		ulnConfigs = append(ulnConfigs, setDefaultUlnConfigParam{
			EID: eid,
			Config: ulnConfig{
				Confirmations:    1,
				RequiredDVNCount: 1,
				RequiredDVNs:     requiredDVNs,
				OptionalDVNs:     []common.Address{},
			},
		})
		sendExecutorConfigs = append(sendExecutorConfigs, setDefaultExecutorConfigParam{
			EID:    eid,
			Config: executorConfig{MaxMessageSize: 1_000, Executor: executor},
		})
	}
	if _, err := chain.call(ctx, "dvn", dvn, dvnArtifact, "setDstConfig", dvnConfigs); err != nil {
		return err
	}
	if _, err := chain.call(ctx, "executor", executor, executorArtifact,
		"setDstConfig", executorConfigs,
	); err != nil {
		return err
	}
	if _, err := chain.call(ctx, "send_uln_302", sendUln, sendUlnArtifact,
		"setDefaultUlnConfigs", ulnConfigs,
	); err != nil {
		return err
	}
	if _, err := chain.call(ctx, "send_uln_302", sendUln, sendUlnArtifact,
		"setDefaultExecutorConfigs", sendExecutorConfigs,
	); err != nil {
		return err
	}
	if _, err := chain.call(ctx, "receive_uln_302", receiveUln, receiveUlnArtifact,
		"setDefaultUlnConfigs", ulnConfigs,
	); err != nil {
		return err
	}
	for _, library := range []common.Address{sendUln, receiveUln} {
		if _, err := chain.call(ctx, "endpoint_v2", endpoint, endpointArtifact,
			"registerLibrary", library,
		); err != nil {
			return err
		}
	}
	for _, eid := range remoteEIDs {
		if _, err := chain.call(ctx, "endpoint_v2", endpoint, endpointArtifact,
			"setDefaultSendLibrary", eid, sendUln,
		); err != nil {
			return err
		}
		if _, err := chain.call(ctx, "endpoint_v2", endpoint, endpointArtifact,
			"setDefaultReceiveLibrary", eid, receiveUln, big.NewInt(0),
		); err != nil {
			return err
		}
	}

	stack.endpointV2 = endpoint
	stack.sendUln302 = sendUln
	stack.receiveUln302 = receiveUln
	stack.treasury = treasury
	stack.priceFeedImplementation = priceFeedImplementation
	stack.priceFeed = priceFeed
	stack.dvn = dvn
	stack.dvnFeeLib = dvnFeeLib
	stack.executorImplementation = executorImplementation
	stack.executor = executor
	stack.executorFeeLib = executorFeeLib
	return nil
}

// writeProtocolDocuments writes the carrier documents where the Python tooling
// reads them: the Hyperlane native deployment, the Hyperlane registry entry of
// the chain, and the LayerZero deployment.
func (r *deployment) writeProtocolDocuments(
	role string,
	spec ChainSpec,
	stack *protocolStack,
) error {
	hyperlanePayload, err := json.MarshalIndent(stack.document.Hyperlane, "", "  ")
	if err != nil {
		return fmt.Errorf("deploy: encode Hyperlane deployment: %w", err)
	}
	if err := writeAtomic(
		filepath.Join(r.layout.hyperlaneNative, fmt.Sprintf("%d.json", spec.ChainID)),
		append(hyperlanePayload, '\n'),
	); err != nil {
		return err
	}
	layerZeroPayload, err := json.MarshalIndent(stack.document.LayerZero, "", "  ")
	if err != nil {
		return fmt.Errorf("deploy: encode LayerZero deployment: %w", err)
	}
	if err := writeAtomic(
		filepath.Join(r.layout.layerZero, fmt.Sprintf("%d.json", spec.ChainID)),
		append(layerZeroPayload, '\n'),
	); err != nil {
		return err
	}
	registry := map[string]string{}
	for key, address := range stack.hyperlaneContracts() {
		registry[key] = address.Hex()
	}
	registry["interchainGasPaymaster"] = stack.interchainGasPaymaster.Hex()
	path := filepath.Join(
		r.layout.hyperlaneRegistry, "xirlocalchain"+role, "addresses.yaml",
	)
	return writeAtomic(path, []byte(renderAddressYAML(registry)))
}

// renderAddressYAML renders a flat address mapping with sorted keys, the shape
// `materialize_multihop_hyperlane_registry` writes for the Hyperlane registry.
func renderAddressYAML(addresses map[string]string) string {
	var builder strings.Builder
	for _, key := range sortedKeys(addresses) {
		builder.WriteString(key)
		builder.WriteString(": \"")
		builder.WriteString(addresses[key])
		builder.WriteString("\"\n")
	}
	return builder.String()
}

func addressStrings(addresses map[string]common.Address) map[string]string {
	out := make(map[string]string, len(addresses))
	for key, address := range addresses {
		out[key] = address.Hex()
	}
	return out
}

// remoteEIDs returns the endpoint ids of every other chain, in chain order,
// which is what `DeployLayerZeroNative.remoteEidsFor` produces.
func remoteEIDs(specs []ChainSpec, local string) []uint32 {
	out := make([]uint32, 0, len(specs))
	for _, spec := range specs {
		if spec.Role != local {
			out = append(out, spec.LayerZeroEID)
		}
	}
	return out
}

// ensureDirectory creates a private runtime directory.
func ensureDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("deploy: create %s: %w", path, err)
	}
	return nil
}
