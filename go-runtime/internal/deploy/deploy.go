// Package deploy deploys one XIR application and the protocol stacks it runs
// on, then records what was deployed.
//
// The sequence is the Go port of two Python/Solidity references:
//
//   - `src/xir_lab/native/multihop_deployer.py`, which deploys the registries,
//     gateways, receivers, transition recorders and route adapters of one
//     A..E application and configures the adapters and registries;
//   - `protocol-projects/hyperlane-native/script/DeployHyperlaneNative.s.sol`
//     and `protocol-projects/layerzero-native/script/DeployLayerZeroNative.s.sol`,
//     which bootstrap the Hyperlane and LayerZero native stacks on each chain
//     from the same Forge artifacts, with the same constructors, the same
//     configuration calls, and the same order.
//
// Every send goes through internal/evm's durable transactor, so the intent, the
// signed bytes and the receipt are committed before the corresponding network
// step, and the receipt is spooled under the private runtime root. The
// deployment journal records one row per completed action and the deployment
// document describes the deployed contracts, the carrier bootstrap, the
// classification of the gas the application actions consumed, and the digest of
// the journal.
//
// Three deliberate differences from the Python deployer:
//
//   - only the routes the caller requests are deployed and configured, where
//     the Python campaign always deploys the whole route universe;
//   - the durable ledger is the transactor's action table, so the journal holds
//     one row per action instead of the Python journal's intent/signed/
//     submitted/succeeded lifecycle;
//   - the carrier documents are also written where the Python tooling reads
//     them (<RuntimeRoot>/hyperlane/... and <RuntimeRoot>/layerzero/...), so a
//     Python consumer sees the tree it expects. The evidence pipeline's start
//     and end block bookkeeping is not reproduced: it belongs to analysis, not
//     to deployment.
package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// Deployment document identity. The schema version and the namespace are the
// ones `multihop_deployer._deployment_document` writes, so a Python consumer
// reads the file unchanged.
const (
	documentSchemaVersion = "xir-lab-native-multihop-deployment-v1"
	deploymentNamespace   = "native-multihop-switching-v1"

	// deploymentAttempt and the action stage keys label the durable ledger
	// rows of a deployment, which is not an attempt of the runner.
	deploymentAttempt = "deployment"
)

// chainRoles is the frozen role order of the five-chain profile
// (multihop_deployer.CHAIN_ROLES).
var chainRoles = []string{"a", "b", "c", "d", "e"}

// routeOrder is the preregistered route universe
// (multihop_scalability.ROUTE_ORDER). Only the routes a caller requests are
// deployed and configured.
var routeOrder = []string{
	"H", "L", "HH", "HHH", "HHHH", "HL", "HLH", "HLHL", "LHLH", "HHL", "HHHL",
}

// ChainSpec is one chain the deployment writes to.
type ChainSpec struct {
	// Role is the profile role, "a" through "e".
	Role string
	// ChainID is the EVM chain id the endpoint must report.
	ChainID uint64
	// RPCEndpoint is the HTTP JSON-RPC endpoint.
	RPCEndpoint string
	// HyperlaneDomain is the local Hyperlane domain of the chain.
	HyperlaneDomain uint32
	// LayerZeroEID is the LayerZero endpoint id of the chain.
	LayerZeroEID uint32
}

// RoleAddresses are the addresses the deployed contracts bind to. The
// deployment only sends from the caller's deployer key, so none of them needs
// a balance.
type RoleAddresses struct {
	// Runner is the XIR runner: the adapter administrator-approved sender and
	// the transition recorder's authority.
	Runner common.Address
	// RootSigner signs XIR roots that the registries accept.
	RootSigner common.Address
	// LayerZeroWorker is the LayerZero DVN signer and Executor submitter.
	LayerZeroWorker common.Address
	// HyperlaneValidator is the validator of the Hyperlane multisig ISM.
	HyperlaneValidator common.Address
	// HyperlaneRelayer submits Hyperlane process calls. No on-chain binding
	// exists for a relayer, so the deployment only records it.
	HyperlaneRelayer common.Address
}

// Options configure one deployment.
type Options struct {
	// ArtifactsRoot is the XIR application forge output, normally
	// <repository>/contracts/out.
	ArtifactsRoot string
	// ProtocolArtifactsRoot is the protocol project root, normally
	// <repository>/protocol-projects; the Hyperlane and LayerZero artifacts
	// are read from <root>/hyperlane-native/out and <root>/layerzero-native/out.
	ProtocolArtifactsRoot string
	// RuntimeRoot holds the private deployment journal, the receipt spool and
	// the chain registry documents. Nothing here is committed to the repository.
	RuntimeRoot string
	// DeployerKey is the hex private key that signs every deployment
	// transaction. It is never logged or written.
	DeployerKey string
	// OutputPath is the deployment document to write, atomically.
	OutputPath string
	// Routes selects the preregistered routes to deploy and configure, a
	// subset of routeOrder. The order of the slice does not matter.
	Routes []string
	// RoleAddresses are the addresses the contracts bind to.
	RoleAddresses
}

// GatewayTypedIDDocument is the typed gateway identifier of one chain.
type GatewayTypedIDDocument struct {
	Kind  uint8  `json:"kind"`
	Value string `json:"value"`
	Hash  string `json:"hash"`
}

// RouteHopDocument is one hop of a deployed route.
type RouteHopDocument struct {
	HopIndex         int    `json:"hop_index"`
	Protocol         string `json:"protocol"`
	SourceChain      string `json:"source_chain"`
	DestinationChain string `json:"destination_chain"`
	ProfileHash      string `json:"profile_hash"`
	OutboundAdapter  string `json:"outbound_adapter"`
	InboundAdapter   string `json:"inbound_adapter"`
}

// RouteDocument is one deployed route.
type RouteDocument struct {
	DestinationChain string             `json:"destination_chain"`
	Receiver         string             `json:"receiver"`
	Hops             []RouteHopDocument `json:"hops"`
}

// RoleAddressesDocument records the addresses every deployed contract binds to.
type RoleAddressesDocument struct {
	Runner             string `json:"runner"`
	RootSigner         string `json:"root_signer"`
	LayerZeroWorker    string `json:"layerzero_worker"`
	HyperlaneValidator string `json:"hyperlane_validator"`
	HyperlaneRelayer   string `json:"hyperlane_relayer"`
}

// ClassifiedGasDocument is one gas classification of the deployment.
type ClassifiedGasDocument struct {
	Classification   string `json:"classification"`
	TransactionCount int    `json:"transaction_count"`
	GasUsed          uint64 `json:"gas_used"`
}

// ComponentGasDocument summarises the unit observations of one component.
type ComponentGasDocument struct {
	Component        string  `json:"component"`
	ObservationCount int     `json:"observation_count"`
	MinimumGas       uint64  `json:"minimum_gas"`
	MaximumGas       uint64  `json:"maximum_gas"`
	MeanGas          float64 `json:"mean_gas"`
}

// DeploymentGasDocument is the gas accounting of the application deployment,
// shaped like `multihop_deployer._deployment_document`'s `deployment_gas`.
type DeploymentGasDocument struct {
	TransactionCount               int                     `json:"transaction_count"`
	GasUsed                        uint64                  `json:"gas_used"`
	Scope                          string                  `json:"scope"`
	ReusedNativeCarrierGasIncluded bool                    `json:"reused_native_carrier_gas_included"`
	ReusedNativeCarrierComponents  []string                `json:"reused_native_carrier_components"`
	ClassifiedTotals               []ClassifiedGasDocument `json:"classified_totals"`
	ComponentUnitObservations      []ComponentGasDocument  `json:"component_unit_observations"`
	Receipts                       []actionRecord          `json:"receipts"`
}

// ChainGasDocument is the gas of one chain's protocol bootstrap.
type ChainGasDocument struct {
	TransactionCount int    `json:"transaction_count"`
	GasUsed          uint64 `json:"gas_used"`
}

// ProtocolGasDocument is the gas of the carrier bootstrap, which the Python
// deployment document does not classify because the carriers are reused.
type ProtocolGasDocument struct {
	TransactionCount int                         `json:"transaction_count"`
	GasUsed          uint64                      `json:"gas_used"`
	ByChain          map[string]ChainGasDocument `json:"by_chain"`
	Hyperlane        ChainGasDocument            `json:"hyperlane"`
	LayerZero        ChainGasDocument            `json:"layerzero"`
}

// Document is the deployment document written to Options.OutputPath.
type Document struct {
	SchemaVersion       string                                `json:"schema_version"`
	Namespace           string                                `json:"namespace"`
	Deployer            string                                `json:"deployer"`
	Runner              string                                `json:"runner"`
	RootSigner          string                                `json:"root_signer"`
	RegistryVersion     uint32                                `json:"registry_version"`
	GatewayTypedIDs     map[string]GatewayTypedIDDocument     `json:"gateway_typed_ids"`
	Routes              map[string]RouteDocument              `json:"routes"`
	Chains              map[string]map[string]string          `json:"chains"`
	Infrastructure      map[string]map[string]string          `json:"infrastructure"`
	RoleAddresses       RoleAddressesDocument                 `json:"role_addresses"`
	ProtocolDeployments map[string]ProtocolDeploymentDocument `json:"protocol_deployments"`
	ProtocolGas         ProtocolGasDocument                   `json:"protocol_gas"`
	DeploymentGas       DeploymentGasDocument                 `json:"deployment_gas"`
	JournalSHA256       string                                `json:"journal_sha256"`
	// DeploymentSHA256 is the digest of the written document. It is returned
	// in memory only, exactly as `multihop_deployer.run` does, so the digest
	// of the file on disk stays reproducible.
	DeploymentSHA256 string `json:"deployment_sha256,omitempty"`
}

// actionRecord is one durable deployment action, the journal row and the
// receipt provenance entry of the deployment document.
type actionRecord struct {
	ActionID          string `json:"action_id"`
	Role              string `json:"role"`
	ChainID           uint64 `json:"chain_id"`
	Nonce             uint64 `json:"nonce"`
	Action            string `json:"action"`
	Target            string `json:"target_or_created_address"`
	CalldataSHA256    string `json:"calldata_sha256"`
	CalldataBytes     int    `json:"calldata_bytes"`
	TransactionHash   string `json:"transaction_hash"`
	RawSHA256         string `json:"raw_sha256,omitempty"`
	ReceiptPath       string `json:"receipt_path,omitempty"`
	ReceiptSHA256     string `json:"receipt_sha256"`
	Status            uint64 `json:"status"`
	GasUsed           uint64 `json:"gas_used"`
	BlockNumber       uint64 `json:"block_number"`
	BlockTimestamp    uint64 `json:"block_timestamp_utc_seconds,omitempty"`
	RuntimeCodeSHA256 string `json:"runtime_code_sha256"`
	ArtifactSHA256    string `json:"compiled_artifact_sha256,omitempty"`
	Classification    string `json:"cost_classification,omitempty"`
}

// Deploy deploys the protocol stacks and one XIR application, writes the
// deployment document to Options.OutputPath, and returns it.
func Deploy(ctx context.Context, chains []ChainSpec, options Options) (Document, error) {
	run, err := newDeployment(ctx, chains, options)
	if err != nil {
		return Document{}, err
	}
	defer run.close()
	if err := run.bootstrapProtocols(ctx); err != nil {
		return Document{}, err
	}
	if err := run.deployApplication(ctx); err != nil {
		return Document{}, err
	}
	return run.document()
}

// deployment is one running deployment.
type deployment struct {
	options           Options
	specs             []ChainSpec
	routes            []string
	layout            layout
	chains            map[string]*chainRuntime
	order             []string
	store             *state.Store
	entries           *journal
	deployer          common.Address
	manifest          map[string]map[string]string
	stack             map[string]*protocolStack
	appRecords        []actionRecord
	protocolRecords   []actionRecord
	gatewayIDs        map[string]xir.TypedID
	gatewayHashes     map[string][32]byte
	profileHashes     map[string]map[int][32]byte
	artifactCache     map[string]artifactCacheEntry
	protocolDocuments map[string]ProtocolDeploymentDocument
}

// layout is the private runtime tree of one deployment.
type layout struct {
	work              string
	journal           string
	spool             string
	state             string
	hyperlaneNative   string
	hyperlaneRegistry string
	layerZero         string
}

func newLayout(runtimeRoot string) layout {
	work := filepath.Join(runtimeRoot, "deploy")
	return layout{
		work:              work,
		journal:           filepath.Join(work, "deployment-journal.jsonl"),
		spool:             filepath.Join(work, "receipts"),
		state:             filepath.Join(work, "deployment.sqlite"),
		hyperlaneNative:   filepath.Join(runtimeRoot, "hyperlane", "native-deployments"),
		hyperlaneRegistry: filepath.Join(runtimeRoot, "hyperlane", "registry", "chains"),
		layerZero:         filepath.Join(runtimeRoot, "layerzero", "deployments"),
	}
}

type artifactCacheEntry struct {
	artifact artifacts.Artifact
	err      error
}

func (r *deployment) close() {
	if r.entries != nil {
		_ = r.entries.close()
	}
	if r.store != nil {
		_ = r.store.Close()
	}
}

// document assembles the deployment document, writes it atomically, and
// returns it with the digest of the written bytes.
func (r *deployment) document() (Document, error) {
	journalSHA256, err := r.entries.digest()
	if err != nil {
		return Document{}, err
	}
	document := Document{
		SchemaVersion:       documentSchemaVersion,
		Namespace:           deploymentNamespace,
		Deployer:            strings.ToLower(r.deployer.Hex()),
		Runner:              strings.ToLower(r.options.Runner.Hex()),
		RootSigner:          strings.ToLower(r.options.RootSigner.Hex()),
		RegistryVersion:     xir.RegistryVersion,
		GatewayTypedIDs:     r.gatewayDocuments(),
		Routes:              r.routeDocuments(),
		Chains:              r.manifest,
		Infrastructure:      r.infrastructureDocument(),
		RoleAddresses:       r.roleAddressesDocument(),
		ProtocolDeployments: r.protocolDocuments,
		ProtocolGas:         r.protocolGasDocument(),
		DeploymentGas:       r.deploymentGasDocument(),
		JournalSHA256:       journalSHA256,
	}
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return Document{}, fmt.Errorf("deploy: encode deployment document: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeAtomic(r.options.OutputPath, payload); err != nil {
		return Document{}, err
	}
	digest := sha256.Sum256(payload)
	document.DeploymentSHA256 = hex.EncodeToString(digest[:])
	return document, nil
}

func (r *deployment) gatewayDocuments() map[string]GatewayTypedIDDocument {
	out := make(map[string]GatewayTypedIDDocument, len(r.gatewayIDs))
	for _, role := range r.order {
		identifier := r.gatewayIDs[role]
		out[strings.ToUpper(role)] = GatewayTypedIDDocument{
			Kind:  identifier.Kind,
			Value: "0x" + hex.EncodeToString(identifier.Value),
			Hash:  xir.FormatDigest(r.gatewayHashes[role]),
		}
	}
	return out
}

func (r *deployment) routeDocuments() map[string]RouteDocument {
	out := make(map[string]RouteDocument, len(r.routes))
	for _, route := range r.routes {
		hops := make([]RouteHopDocument, 0, len(route))
		for hopIndex := 1; hopIndex <= len(route); hopIndex++ {
			source := r.order[hopIndex-1]
			destination := r.order[hopIndex]
			outboundKey, _ := xir.AdapterKey(route, hopIndex, "out")
			inboundKey, _ := xir.AdapterKey(route, hopIndex, "in")
			hops = append(hops, RouteHopDocument{
				HopIndex:         hopIndex,
				Protocol:         string(route[hopIndex-1]),
				SourceChain:      strings.ToUpper(source),
				DestinationChain: strings.ToUpper(destination),
				ProfileHash:      xir.FormatDigest(r.profileHashes[route][hopIndex]),
				OutboundAdapter:  strings.ToLower(r.manifest[source][outboundKey]),
				InboundAdapter:   strings.ToLower(r.manifest[destination][inboundKey]),
			})
		}
		destination := r.order[len(route)]
		out[route] = RouteDocument{
			DestinationChain: strings.ToUpper(destination),
			Receiver:         strings.ToLower(r.manifest[destination]["receiver"]),
			Hops:             hops,
		}
	}
	return out
}

func (r *deployment) roleAddressesDocument() RoleAddressesDocument {
	return RoleAddressesDocument{
		Runner:             strings.ToLower(r.options.Runner.Hex()),
		RootSigner:         strings.ToLower(r.options.RootSigner.Hex()),
		LayerZeroWorker:    strings.ToLower(r.options.LayerZeroWorker.Hex()),
		HyperlaneValidator: strings.ToLower(r.options.HyperlaneValidator.Hex()),
		HyperlaneRelayer:   strings.ToLower(r.options.HyperlaneRelayer.Hex()),
	}
}

// deploymentGasDocument classifies the application actions exactly like
// `multihop_deployer.classify_multihop_deployment_costs`: contract deployments
// are XIR-only cost, every configuration call initialises a profile, root or
// peer binding. The carrier bootstrap is reported separately because the
// carriers are reused by the campaign.
func (r *deployment) deploymentGasDocument() DeploymentGasDocument {
	componentGas := map[string][]uint64{}
	classifiedGas := map[string][]uint64{}
	records := make([]actionRecord, 0, len(r.appRecords))
	for _, record := range r.appRecords {
		classification := "xir_profile_root_peer_binding_initialization"
		component := "configuration_call"
		if strings.HasPrefix(record.Action, "deploy:") {
			classification = "xir_only_contract_deployment"
			component = record.Action[strings.LastIndex(record.Action, ":")+1:]
		}
		record.Classification = classification
		componentGas[component] = append(componentGas[component], record.GasUsed)
		classifiedGas[classification] = append(classifiedGas[classification], record.GasUsed)
		records = append(records, record)
	}
	total := uint64(0)
	for _, record := range records {
		total += record.GasUsed
	}
	document := DeploymentGasDocument{
		TransactionCount:               len(records),
		GasUsed:                        total,
		Scope:                          "experiment_route_isolation_total_not_single_gateway_cost",
		ReusedNativeCarrierGasIncluded: false,
		ReusedNativeCarrierComponents: []string{
			"Hyperlane Mailbox/ISM/validator/relayer",
			"LayerZero Endpoint/ULN/DVN/Executor/worker",
		},
		Receipts: records,
	}
	for _, classification := range sortedKeys(classifiedGas) {
		values := classifiedGas[classification]
		document.ClassifiedTotals = append(document.ClassifiedTotals, ClassifiedGasDocument{
			Classification:   classification,
			TransactionCount: len(values),
			GasUsed:          sum(values),
		})
	}
	for _, component := range sortedKeys(componentGas) {
		values := componentGas[component]
		document.ComponentUnitObservations = append(
			document.ComponentUnitObservations,
			ComponentGasDocument{
				Component:        component,
				ObservationCount: len(values),
				MinimumGas:       minimum(values),
				MaximumGas:       maximum(values),
				MeanGas:          float64(sum(values)) / float64(len(values)),
			},
		)
	}
	return document
}

func (r *deployment) protocolGasDocument() ProtocolGasDocument {
	document := ProtocolGasDocument{ByChain: map[string]ChainGasDocument{}}
	for _, role := range r.order {
		gas := ChainGasDocument{}
		for _, record := range r.protocolRecords {
			if record.Role != role {
				continue
			}
			gas.TransactionCount++
			gas.GasUsed += record.GasUsed
			if strings.Contains(record.Action, ":hyperlane:") {
				document.Hyperlane.TransactionCount++
				document.Hyperlane.GasUsed += record.GasUsed
			} else {
				document.LayerZero.TransactionCount++
				document.LayerZero.GasUsed += record.GasUsed
			}
		}
		document.ByChain[role] = gas
		document.TransactionCount += gas.TransactionCount
		document.GasUsed += gas.GasUsed
	}
	return document
}

// writeAtomic writes payload to path through a temporary file in the same
// directory, fsynced before the rename, so a reader never sees a partial
// document.
func writeAtomic(path string, payload []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("deploy: create %s: %w", directory, err)
	}
	file, err := os.CreateTemp(directory, ".deployment-*.json")
	if err != nil {
		return fmt.Errorf("deploy: create temporary document: %w", err)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if _, err := file.Write(payload); err != nil {
		file.Close()
		return fmt.Errorf("deploy: write %s: %w", temporary, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("deploy: sync %s: %w", temporary, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("deploy: close %s: %w", temporary, err)
	}
	if err := os.Chmod(temporary, 0o644); err != nil {
		return fmt.Errorf("deploy: chmod %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("deploy: publish %s: %w", path, err)
	}
	return nil
}

func sortedKeys[V any](values map[string]V) []string {
	return slices.Sorted(maps.Keys(values))
}

func sum(values []uint64) uint64 {
	total := uint64(0)
	for _, value := range values {
		total += value
	}
	return total
}

func minimum(values []uint64) uint64 {
	if len(values) == 0 {
		return 0
	}
	return slices.Min(values)
}

func maximum(values []uint64) uint64 {
	if len(values) == 0 {
		return 0
	}
	return slices.Max(values)
}
