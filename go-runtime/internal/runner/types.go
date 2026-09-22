package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// ChainConfig is one local chain the runtime may talk to.
type ChainConfig struct {
	Role            string
	ChainID         uint64
	RPCURL          string
	HyperlaneDomain uint32
	LayerZeroEID    uint32
}

// Attempt is one route execution the runtime must perform.
type Attempt struct {
	AttemptID     string
	Phase         string
	Route         string
	RouteSequence uint64
	SwitchCount   int
	PayloadSHA256 string
}

// Stage names follow src/xir_lab/native/multihop_scalability.py
// expected_stage_sequence so the Go ledger stays readable by the Python
// analysis tooling.
const (
	StageRootCreate          = "root_create"
	StageDestinationDelivery = "destination_verify_deliver"
)

func transitionStage(hopIndex int) string {
	return fmt.Sprintf("hop_%d_xir_transition", hopIndex)
}

func dispatchStage(hopIndex int, protocol string) string {
	return fmt.Sprintf("hop_%d_%s_dispatch", hopIndex, strings.ToLower(protocol))
}

func hyperlaneProcessStage(hopIndex int) string {
	return fmt.Sprintf("hop_%d_hyperlane_process", hopIndex)
}

func layerZeroStage(hopIndex int, stage string) string {
	return fmt.Sprintf("hop_%d_layerzero_%s", hopIndex, stage)
}

func callbackStage(hopIndex int, protocol string) string {
	return fmt.Sprintf("hop_%d_%s_callback", hopIndex, strings.ToLower(protocol))
}

// KeySet holds the private keys the runtime signs with. Keys are supplied by the
// caller (environment or an external custody file) and never persisted.
type KeySet struct {
	Runner             string
	RootSigner         string
	LayerZeroWorker    string
	HyperlaneValidator string
	HyperlaneRelayer   string
}

// Config is one runtime invocation.
type Config struct {
	Attempts       []Attempt
	Chains         []ChainConfig
	DeploymentPath string
	ArtifactsRoot  string
	// ProtocolRoot is the protocol-projects directory that holds the pinned
	// Hyperlane and LayerZero Forge artifacts.
	ProtocolRoot    string
	PayloadSchedule xir.PayloadSchedule
	FixedSeed       string
	PolicyLabel     string
	Timeout         time.Duration
	PollInterval    time.Duration
	Concurrency     int
	StopFile        string
	StatePath       string
	RawRoot         string
	Keys            KeySet
	// EmbeddedAgents runs the LayerZero DVN/Executor and the Hyperlane
	// validator/relayer roles inside this process. When false the runtime only
	// dispatches and waits for external agents to deliver.
	EmbeddedAgents bool
	// OptionsOverride replaces the LayerZero executor options when set.
	OptionsOverride []byte
	// FaultAfterStage aborts an attempt right after the named stage is durably
	// recorded. It exists for recovery tests and mirrors the fault injector the
	// Python campaign uses in src/xir_lab/native/faults_v1.py.
	FaultAfterStage string
	// Finality is the confirmation rule applied before a creation is treated as
	// signable. The default is the RPC finalized tag with the private-QBFT
	// fallback, which is what the frozen lab uses.
	Finality Finality
	// GasLimit is the gas limit of runtime transactions.
	GasLimit uint64
}

// Finality modes.
const (
	// FinalityRPCFinalized requires the creation block to reach the finalized
	// height the node reports, falling back to the QBFT rule when the node does
	// not implement the tag.
	FinalityRPCFinalized = "rpc-finalized"
	// FinalityConfirmations requires N successor blocks and confirms the
	// creation block is still canonical. It is the rule for development chains
	// that pin the finalized tag at genesis.
	FinalityConfirmations = "confirmations"
	// FinalityNone accepts the mined receipt. It is a test-only rule and is
	// recorded as such in the ledger.
	FinalityNone = "none"
)

// Finality is the confirmation rule of one runtime invocation.
type Finality struct {
	// Mode is one of FinalityRPCFinalized, FinalityConfirmations, or
	// FinalityNone.
	Mode string
	// Confirmations is the successor depth the confirmations mode requires.
	Confirmations uint64
	// Timeout bounds one confirmation wait.
	Timeout time.Duration
}

// Deployment is the contract manifest produced by internal/deploy.
type Deployment struct {
	SchemaVersion  string                       `json:"schema_version"`
	Chains         map[string]map[string]string `json:"chains"`
	Infrastructure map[string]map[string]string `json:"infrastructure"`
	Path           string                       `json:"-"`
	SHA256         string                       `json:"-"`
}

// LoadDeployment reads a deployment document.
func LoadDeployment(path string) (*Deployment, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runner: read deployment: %w", err)
	}
	var document Deployment
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("runner: decode deployment: %w", err)
	}
	if len(document.Chains) == 0 {
		return nil, fmt.Errorf("runner: deployment %s has no chains", path)
	}
	document.Path = path
	document.SHA256 = digestHex(payload)
	return &document, nil
}

// Contract resolves one application contract address by chain role and key.
func (d *Deployment) Contract(role, key string) (common.Address, error) {
	chain, ok := d.Chains[role]
	if !ok {
		return common.Address{}, fmt.Errorf("runner: deployment has no chain %q", role)
	}
	value, ok := chain[key]
	if !ok || value == "" {
		return common.Address{}, fmt.Errorf("runner: chain %s has no contract %q", role, key)
	}
	if !common.IsHexAddress(value) {
		return common.Address{}, fmt.Errorf("runner: chain %s contract %q is not an address", role, key)
	}
	return common.HexToAddress(value), nil
}

// Infra resolves one protocol infrastructure address by chain role and key.
func (d *Deployment) Infra(role, key string) (common.Address, error) {
	chain, ok := d.Infrastructure[role]
	if !ok {
		return common.Address{}, fmt.Errorf("runner: deployment has no infrastructure for chain %q", role)
	}
	value, ok := chain[key]
	if !ok || value == "" {
		return common.Address{}, fmt.Errorf("runner: chain %s has no infrastructure %q", role, key)
	}
	if !common.IsHexAddress(value) {
		return common.Address{}, fmt.Errorf("runner: chain %s infrastructure %q is not an address", role, key)
	}
	return common.HexToAddress(value), nil
}

func digestHex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
