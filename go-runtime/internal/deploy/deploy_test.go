package deploy_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/deploy"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/lab"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// hlRouteSpecs are the three chains of the HL route with the frozen profile
// coordinates (configs/profiles/native-multihop-five-chain-v1.json).
func hlRouteSpecs() []deploy.ChainSpec {
	return []deploy.ChainSpec{
		{Role: "a", ChainID: 3133701, HyperlaneDomain: 3133701, LayerZeroEID: 49001},
		{Role: "b", ChainID: 3133702, HyperlaneDomain: 3133702, LayerZeroEID: 49002},
		{Role: "c", ChainID: 3133703, HyperlaneDomain: 3133703, LayerZeroEID: 49003},
	}
}

// infrastructureKeys are the carrier addresses the document must expose per
// chain, under the names the runtime resolves them by.
var infrastructureKeys = []string{
	"mailbox",
	"merkleTreeHook",
	"validatorAnnounce",
	"defaultIsm",
	"staticMessageIdMultisigIsmFactory",
	"protocolFee",
	"endpoint_v2",
	"send_uln_302",
	"receive_uln_302",
	"dvn",
	"executor",
	"price_feed",
	"treasury",
	"dvn_fee_lib",
	"executor_fee_lib",
	"price_feed_implementation",
	"executor_implementation",
}

// expectedChainKeys is the exact contract set of the HL application: the
// registry and gateway of every chain, the receiver of every non-source chain,
// the transition recorder of the intermediate chain, and one adapter per
// direction of each hop.
var expectedChainKeys = map[string][]string{
	"a": {"gateway", "registry", "route_hl_hop_1_out"},
	"b": {
		"gateway",
		"receiver",
		"registry",
		"route_hl_hop_1_in",
		"route_hl_hop_2_out",
		"transition_recorder",
	},
	"c": {"gateway", "receiver", "registry", "route_hl_hop_2_in", "transition_recorder"},
}

// TestDeployHLRouteApplication deploys both carrier stacks and the HL route
// application on three disposable anvil chains, then checks the result against
// what `multihop_deployer.py` writes and `multihop_preflight.py` accepts: the
// registry root and profile bindings, the bidirectional peer bindings, the
// carrier configuration, and the absence of accepted evidence before any hop
// has run.
func TestDeployHLRouteApplication(t *testing.T) {
	anvilPath := lab.AnvilPath("")
	if anvilPath == "" {
		t.Skip("anvil binary is unavailable: foundry is not installed and anvil is not on PATH")
	}
	repository := repositoryRoot(t)
	protocolRoot := requireProtocolArtifacts(t, repository)
	vectors := fixtureKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	deployerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate deployer key: %v", err)
	}
	deployer := crypto.PubkeyToAddress(deployerKey.PublicKey)
	deployerKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(deployerKey))
	role := deploy.RoleAddresses{
		Runner:             keyAddress(t, vectors["root_signer"]),
		RootSigner:         keyAddress(t, vectors["validator"]),
		LayerZeroWorker:    keyAddress(t, vectors["dvn_signer"]),
		HyperlaneValidator: keyAddress(t, vectors["validator"]),
		HyperlaneRelayer:   common.HexToAddress("0x0000000000000000000000000000000000001234"),
	}
	if role.Runner == role.RootSigner {
		t.Fatal("the test needs a runner address distinct from the root signer")
	}

	specs := hlRouteSpecs()
	chainSpecs := make([]lab.Spec, 0, len(specs))
	for _, spec := range specs {
		chainSpecs = append(chainSpecs, lab.Spec{
			Role:    spec.Role,
			ChainID: spec.ChainID,
			Fund:    []lab.FundRequest{{Address: deployer.Hex(), Wei: "0x21e19e0c9bab2400000"}},
		})
	}
	chains, err := lab.StartChains(ctx, chainSpecs, lab.Options{Dir: t.TempDir(), AnvilPath: anvilPath})
	if err != nil {
		t.Fatalf("start anvil chains: %v", err)
	}
	defer lab.StopChains(chains)
	if len(chains) != len(specs) {
		t.Fatalf("started %d chains, want %d", len(chains), len(specs))
	}
	for index := range specs {
		specs[index].RPCEndpoint = chains[index].URL
	}

	runtimeRoot := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "deployment.json")
	options := deploy.Options{
		ArtifactsRoot:         filepath.Join(repository, "contracts", "out"),
		ProtocolArtifactsRoot: protocolRoot,
		RuntimeRoot:           runtimeRoot,
		DeployerKey:           deployerKeyHex,
		OutputPath:            outputPath,
		Routes:                []string{"HL"},
		RoleAddresses:         role,
	}
	document, err := deploy.Deploy(ctx, specs, options)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	harness := newHarness(t, ctx, specs, document, repository, runtimeRoot, outputPath, deployer, role)
	harness.checkDocument()
	harness.checkSecrets()
	harness.checkRegistries()
	harness.checkAdapters()
	harness.checkHyperlane()
	harness.checkLayerZero()
	harness.checkRestart(specs, options)
}

// TestDeployRejectsInvalidRequests covers the requests a deployment must refuse
// before it dials or signs anything.
func TestDeployRejectsInvalidRequests(t *testing.T) {
	vectors := fixtureKeys(t)
	valid := deploy.ChainSpec{Role: "a", ChainID: 3133701, RPCEndpoint: "http://127.0.0.1:1", HyperlaneDomain: 3133701, LayerZeroEID: 49001}
	second := deploy.ChainSpec{Role: "b", ChainID: 3133702, RPCEndpoint: "http://127.0.0.1:1", HyperlaneDomain: 3133702, LayerZeroEID: 49002}
	// Empty artifact roots keep this table independent of any forge output:
	// every case below is refused before an artifact is read, and the two cases
	// that are about artifacts point at paths that do not exist.
	artifactsRoot := t.TempDir()
	protocolRoot := t.TempDir()
	base := deploy.Options{
		ArtifactsRoot:         artifactsRoot,
		ProtocolArtifactsRoot: protocolRoot,
		RuntimeRoot:           t.TempDir(),
		DeployerKey:           "0x2222222222222222222222222222222222222222222222222222222222222222",
		OutputPath:            filepath.Join(t.TempDir(), "deployment.json"),
		// One hop, which the two chains below can carry; the route cases change
		// it to what they are about.
		Routes: []string{"H"},
		RoleAddresses: deploy.RoleAddresses{
			Runner:             keyAddress(t, vectors["root_signer"]),
			RootSigner:         keyAddress(t, vectors["validator"]),
			LayerZeroWorker:    keyAddress(t, vectors["dvn_signer"]),
			HyperlaneValidator: keyAddress(t, vectors["validator"]),
		},
	}
	for _, testCase := range []struct {
		name    string
		chains  []deploy.ChainSpec
		mutate  func(*deploy.Options)
		message string
	}{
		{"one chain", []deploy.ChainSpec{valid}, nil, "between 2 and 5 chains"},
		{
			"non-contiguous roles",
			[]deploy.ChainSpec{valid, {Role: "c", ChainID: 3, RPCEndpoint: "http://127.0.0.1:1"}},
			nil,
			`want "b"`,
		},
		{
			"duplicate chain id",
			[]deploy.ChainSpec{valid, {Role: "b", ChainID: valid.ChainID, RPCEndpoint: "http://127.0.0.1:1"}},
			nil,
			"share chain id",
		},
		{"route longer than the chains", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.Routes = []string{"HLH"} }, "needs 4 chains"},
		{"unregistered route", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.Routes = []string{"HHHHHH"} }, "not preregistered"},
		{"no routes", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.Routes = nil }, "no routes were requested"},
		{"runner is the root signer", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.RootSigner = options.Runner }, "must be distinct"},
		{"no runner", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.Runner = common.Address{} }, "runner address is not set"},
		{"no layerzero worker", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.LayerZeroWorker = common.Address{} }, "worker address is not set"},
		{"no validator", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.HyperlaneValidator = common.Address{} }, "validator address is not set"},
		{"invalid deployer key", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) { options.DeployerKey = "0xzz" }, "invalid deployer key"},
		// The artifact cases come last because a request is always checked
		// before the artifact trees are resolved.
		{"missing artifacts root", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) {
				options.ArtifactsRoot = filepath.Join(artifactsRoot, "missing")
			},
			"not a directory"},
		{"missing protocol artifacts", []deploy.ChainSpec{valid, second},
			func(options *deploy.Options) {
				options.ProtocolArtifactsRoot = filepath.Join(protocolRoot, "absent")
			},
			"are missing"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := base
			if testCase.mutate != nil {
				testCase.mutate(&options)
			}
			// The runtime root is shared with the table above, so give every
			// case its own private tree.
			options.RuntimeRoot = t.TempDir()
			_, err := deploy.Deploy(context.Background(), testCase.chains, options)
			if err == nil {
				t.Fatalf("invalid request was accepted")
			}
			if !strings.Contains(err.Error(), testCase.message) {
				t.Fatalf("error = %q, want it to mention %q", err, testCase.message)
			}
		})
	}
}

// harness reads the deployed contracts back through the same clients the
// deployment wrote through.
type harness struct {
	t           *testing.T
	ctx         context.Context
	specs       []deploy.ChainSpec
	document    deploy.Document
	repository  string
	runtimeRoot string
	outputPath  string
	deployer    common.Address
	role        deploy.RoleAddresses
	clients     map[string]*evm.Client
	cache       map[string]artifacts.Artifact
}

func newHarness(
	t *testing.T,
	ctx context.Context,
	specs []deploy.ChainSpec,
	document deploy.Document,
	repository, runtimeRoot, outputPath string,
	deployer common.Address,
	role deploy.RoleAddresses,
) *harness {
	t.Helper()
	clients := map[string]*evm.Client{}
	for _, spec := range specs {
		client, err := evm.Dial(ctx, spec.RPCEndpoint, 30*time.Second)
		if err != nil {
			t.Fatalf("dial chain %s: %v", spec.Role, err)
		}
		clients[spec.Role] = client
	}
	return &harness{
		t:           t,
		ctx:         ctx,
		specs:       specs,
		document:    document,
		repository:  repository,
		runtimeRoot: runtimeRoot,
		outputPath:  outputPath,
		deployer:    deployer,
		role:        role,
		clients:     clients,
		cache:       map[string]artifacts.Artifact{},
	}
}

func (h *harness) contract(contract string) artifacts.Artifact {
	h.t.Helper()
	if cached, ok := h.cache["app:"+contract]; ok {
		return cached
	}
	artifact, err := artifacts.Load(filepath.Join(h.repository, "contracts", "out"), contract)
	if err != nil {
		h.t.Fatalf("load %s: %v", contract, err)
	}
	h.cache["app:"+contract] = artifact
	return artifact
}

func (h *harness) protocolArtifact(project, sourceFile, contract string) artifacts.Artifact {
	h.t.Helper()
	key := project + ":" + contract
	if cached, ok := h.cache[key]; ok {
		return cached
	}
	artifact, err := artifacts.LoadFrom(
		filepath.Join(h.repository, "protocol-projects", project, "out"), sourceFile, contract,
	)
	if err != nil {
		h.t.Fatalf("load %s: %v", contract, err)
	}
	h.cache[key] = artifact
	return artifact
}

// application resolves one deployed application contract by chain role and key.
func (h *harness) application(role, key string) common.Address {
	h.t.Helper()
	chain, ok := h.document.Chains[role]
	if !ok {
		h.t.Fatalf("the document has no chain %q", role)
	}
	value, ok := chain[key]
	if !ok {
		h.t.Fatalf("chain %s has no contract %q", role, key)
	}
	return common.HexToAddress(value)
}

// infrastructure resolves one carrier contract by chain role and key.
func (h *harness) infrastructure(role, key string) common.Address {
	h.t.Helper()
	chain, ok := h.document.Infrastructure[role]
	if !ok {
		h.t.Fatalf("the document has no infrastructure for chain %q", role)
	}
	value, ok := chain[key]
	if !ok {
		h.t.Fatalf("chain %s has no infrastructure %q", role, key)
	}
	return common.HexToAddress(value)
}

// read performs one eth_call and decodes its outputs.
func (h *harness) read(
	role string,
	artifact artifacts.Artifact,
	to common.Address,
	method string,
	args []any,
	outputs ...any,
) {
	h.t.Helper()
	data, err := artifact.ABI.PackCall(method, args...)
	if err != nil {
		h.t.Fatalf("pack %s.%s: %v", artifact.Name, method, err)
	}
	out, err := h.clients[role].CallContract(h.ctx, to, data)
	if err != nil {
		h.t.Fatalf("call %s.%s at %s: %v", artifact.Name, method, to, err)
	}
	if err := artifact.ABI.UnpackOutputs(method, out, outputs...); err != nil {
		h.t.Fatalf("unpack %s.%s: %v", artifact.Name, method, err)
	}
}

func (h *harness) checkDocument() {
	h.t.Helper()
	document := h.document
	if document.SchemaVersion != "xir-lab-native-multihop-deployment-v1" {
		h.t.Errorf("schema version = %q", document.SchemaVersion)
	}
	if document.Namespace != "native-multihop-switching-v1" {
		h.t.Errorf("namespace = %q", document.Namespace)
	}
	if document.RegistryVersion != 1 {
		h.t.Errorf("registry version = %d, want 1", document.RegistryVersion)
	}
	if document.Deployer != strings.ToLower(h.deployer.Hex()) {
		h.t.Errorf("deployer = %q, want %q", document.Deployer, h.deployer.Hex())
	}
	if document.Runner != strings.ToLower(h.role.Runner.Hex()) ||
		document.RootSigner != strings.ToLower(h.role.RootSigner.Hex()) {
		h.t.Errorf("document roles = %+v", document.RoleAddresses)
	}
	for _, spec := range h.specs {
		chain, ok := document.Chains[spec.Role]
		if !ok {
			h.t.Fatalf("the document has no chain %q", spec.Role)
		}
		if keys := sortedKeys(chain); !slices.Equal(keys, expectedChainKeys[spec.Role]) {
			h.t.Errorf("chain %s contracts = %v, want %v", spec.Role, keys, expectedChainKeys[spec.Role])
		}
		infrastructure := document.Infrastructure[spec.Role]
		expected := slices.Clone(infrastructureKeys)
		slices.Sort(expected)
		if keys := sortedKeys(infrastructure); !slices.Equal(keys, expected) {
			h.t.Errorf("chain %s infrastructure = %v, want %v", spec.Role, keys, expected)
		}
		for key, value := range infrastructure {
			if !common.IsHexAddress(value) {
				h.t.Errorf("chain %s infrastructure %s = %q", spec.Role, key, value)
			}
		}
		for key, value := range chain {
			if !common.IsHexAddress(value) {
				h.t.Errorf("chain %s contract %s = %q", spec.Role, key, value)
			}
		}
	}
	if len(document.Routes) != 1 {
		h.t.Fatalf("routes = %v, want only HL", sortedKeys(document.Routes))
	}
	route, ok := document.Routes["HL"]
	if !ok {
		h.t.Fatal("the document has no HL route")
	}
	if route.DestinationChain != "C" {
		h.t.Errorf("route destination = %q, want C", route.DestinationChain)
	}
	if route.Receiver != strings.ToLower(document.Chains["c"]["receiver"]) {
		h.t.Errorf("route receiver = %q, want the C receiver", route.Receiver)
	}
	if len(route.Hops) != 2 {
		h.t.Fatalf("route hops = %d, want 2", len(route.Hops))
	}
	for index, want := range []deploy.RouteHopDocument{
		{
			HopIndex:         1,
			Protocol:         "H",
			SourceChain:      "A",
			DestinationChain: "B",
			OutboundAdapter:  strings.ToLower(document.Chains["a"]["route_hl_hop_1_out"]),
			InboundAdapter:   strings.ToLower(document.Chains["b"]["route_hl_hop_1_in"]),
		},
		{
			HopIndex:         2,
			Protocol:         "L",
			SourceChain:      "B",
			DestinationChain: "C",
			OutboundAdapter:  strings.ToLower(document.Chains["b"]["route_hl_hop_2_out"]),
			InboundAdapter:   strings.ToLower(document.Chains["c"]["route_hl_hop_2_in"]),
		},
	} {
		hop := route.Hops[index]
		if hop.HopIndex != want.HopIndex || hop.Protocol != want.Protocol ||
			hop.SourceChain != want.SourceChain || hop.DestinationChain != want.DestinationChain ||
			hop.OutboundAdapter != want.OutboundAdapter || hop.InboundAdapter != want.InboundAdapter {
			h.t.Errorf("hop %d = %+v, want %+v", index+1, hop, want)
		}
		profileHash, err := xir.ProfileHash("HL", index+1)
		if err != nil {
			h.t.Fatalf("profile hash: %v", err)
		}
		if hop.ProfileHash != xir.FormatDigest(profileHash) {
			h.t.Errorf(
				"hop %d profile hash = %s, want %s", index+1, hop.ProfileHash, xir.FormatDigest(profileHash),
			)
		}
	}
	for _, spec := range h.specs {
		identifier, err := xir.GatewayTypedID(spec.ChainID)
		if err != nil {
			h.t.Fatalf("gateway typed id: %v", err)
		}
		hash, err := identifier.Hash()
		if err != nil {
			h.t.Fatalf("gateway typed id hash: %v", err)
		}
		entry, ok := document.GatewayTypedIDs[strings.ToUpper(spec.Role)]
		if !ok {
			h.t.Fatalf("the document has no gateway typed id for %s", spec.Role)
		}
		if entry.Hash != xir.FormatDigest(hash) {
			h.t.Errorf("chain %s gateway hash = %s, want %s", spec.Role, entry.Hash, xir.FormatDigest(hash))
		}
		if entry.Value != "0x"+hex.EncodeToString(identifier.Value) || entry.Kind != xir.KindEVM {
			h.t.Errorf("chain %s gateway id = %+v", spec.Role, entry)
		}
	}

	// The document on disk is what its digest covers, the digest of the
	// journal is the digest of the journal the deployment wrote, and the
	// journal holds exactly one row per transaction.
	payload, err := os.ReadFile(h.outputPath)
	if err != nil {
		h.t.Fatalf("read deployment document: %v", err)
	}
	digest := sha256.Sum256(payload)
	if document.DeploymentSHA256 != hex.EncodeToString(digest[:]) {
		h.t.Errorf(
			"deployment digest = %q, want %q", document.DeploymentSHA256, hex.EncodeToString(digest[:]),
		)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(payload, &onDisk); err != nil {
		h.t.Fatalf("decode deployment document: %v", err)
	}
	if _, present := onDisk["deployment_sha256"]; present {
		h.t.Error("the document on disk contains its own digest")
	}
	journal, err := os.ReadFile(filepath.Join(h.runtimeRoot, "deploy", "deployment-journal.jsonl"))
	if err != nil {
		h.t.Fatalf("read journal: %v", err)
	}
	journalDigest := sha256.Sum256(journal)
	if document.JournalSHA256 != hex.EncodeToString(journalDigest[:]) {
		h.t.Errorf(
			"journal digest = %q, want %q", document.JournalSHA256, hex.EncodeToString(journalDigest[:]),
		)
	}
	rows := strings.Split(strings.TrimSpace(string(journal)), "\n")
	transactions := document.DeploymentGas.TransactionCount + document.ProtocolGas.TransactionCount
	if len(rows) != transactions {
		h.t.Errorf("journal has %d rows, want %d transactions", len(rows), transactions)
	}

	// The gas accounting classifies the application actions only, and every
	// receipt carries the provenance the Python document records.
	gas := document.DeploymentGas
	if gas.TransactionCount == 0 || gas.GasUsed == 0 {
		h.t.Fatalf("deployment gas = %+v, want a non-empty accounting", gas)
	}
	if len(gas.Receipts) != gas.TransactionCount {
		h.t.Errorf("gas receipts = %d, want %d", len(gas.Receipts), gas.TransactionCount)
	}
	classifications := map[string]bool{}
	for _, entry := range gas.ClassifiedTotals {
		classifications[entry.Classification] = true
	}
	for _, want := range []string{
		"xir_only_contract_deployment",
		"xir_profile_root_peer_binding_initialization",
	} {
		if !classifications[want] {
			h.t.Errorf("gas classification %q is missing", want)
		}
	}
	deployed, configured := 0, 0
	for _, receipt := range gas.Receipts {
		if receipt.GasUsed == 0 || receipt.BlockNumber == 0 {
			h.t.Errorf("receipt %s has no gas or block", receipt.Action)
		}
		if len(receipt.CalldataSHA256) != 64 || len(receipt.RuntimeCodeSHA256) != 64 {
			h.t.Errorf("receipt %s lacks digests: %+v", receipt.Action, receipt)
		}
		if len(receipt.ArtifactSHA256) != 64 {
			h.t.Errorf("receipt %s has no artifact digest", receipt.Action)
		}
		if !common.IsHexAddress(receipt.Target) {
			h.t.Errorf("receipt %s target = %q", receipt.Action, receipt.Target)
		}
		switch receipt.Classification {
		case "xir_only_contract_deployment":
			deployed++
		case "xir_profile_root_peer_binding_initialization":
			configured++
		default:
			h.t.Errorf("receipt %s has classification %q", receipt.Action, receipt.Classification)
		}
	}
	// Three registries, three gateways, two receivers, two transition
	// recorders, four adapters.
	if want := 3 + 3 + 2 + 2 + 4; deployed != want {
		h.t.Errorf("classified deployments = %d, want %d", deployed, want)
	}
	// Four peer bindings and two enforced-options calls, one prior verifier
	// binding, three registry profiles and two roots.
	if want := 4 + 2 + 1 + 3 + 2; configured != want {
		h.t.Errorf("classified configuration calls = %d, want %d", configured, want)
	}
	if document.ProtocolGas.TransactionCount == 0 {
		h.t.Error("the protocol bootstrap has no gas accounting")
	}
	for _, spec := range h.specs {
		entry, ok := document.ProtocolDeployments[spec.Role]
		if !ok {
			h.t.Fatalf("chain %s has no protocol deployment document", spec.Role)
		}
		if len(entry.Hyperlane.Contracts) != 6 || len(entry.LayerZero.Contracts) != 11 {
			h.t.Errorf(
				"chain %s carrier documents have %d and %d contracts",
				spec.Role, len(entry.Hyperlane.Contracts), len(entry.LayerZero.Contracts),
			)
		}
		if entry.Hyperlane.LocalDomain != spec.HyperlaneDomain || entry.LayerZero.LocalEID != spec.LayerZeroEID {
			h.t.Errorf("chain %s carrier coordinates = %+v", spec.Role, entry)
		}
		if entry.ChainID != spec.ChainID {
			h.t.Errorf("chain %s carrier chain id = %d, want %d", spec.Role, entry.ChainID, spec.ChainID)
		}
		gas, ok := document.ProtocolGas.ByChain[spec.Role]
		if !ok || gas.TransactionCount == 0 {
			h.t.Errorf("chain %s has no protocol gas accounting", spec.Role)
		}
		// Seven Hyperlane actions (Mailbox, ISM factory, ISM, MerkleTreeHook,
		// ProtocolFee, ValidatorAnnounce, initialize) and twenty-seven
		// LayerZero actions, exactly as the two forge scripts broadcast.
		if want := 7 + 27; gas.TransactionCount != want {
			h.t.Errorf("chain %s protocol transactions = %d, want %d", spec.Role, gas.TransactionCount, want)
		}
	}
}

// checkSecrets proves the deployment never echoed a signing key into the
// document, the journal, or the carrier documents.
func (h *harness) checkSecrets() {
	h.t.Helper()
	secrets := []string{}
	for _, key := range fixtureKeys(h.t) {
		secrets = append(secrets, strings.ToLower(strings.TrimPrefix(key, "0x")))
	}
	check := func(path string) {
		payload, err := os.ReadFile(path)
		if err != nil {
			h.t.Fatalf("read %s: %v", path, err)
		}
		text := strings.ToLower(string(payload))
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				h.t.Errorf("%s contains a fixture private key", path)
			}
		}
	}
	check(h.outputPath)
	check(filepath.Join(h.runtimeRoot, "deploy", "deployment-journal.jsonl"))
	err := filepath.Walk(
		filepath.Join(h.runtimeRoot, "hyperlane"),
		func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			check(path)
			return nil
		},
	)
	if err != nil {
		h.t.Fatalf("walk carrier documents: %v", err)
	}
}

func (h *harness) checkRegistries() {
	h.t.Helper()
	registry := h.contract("XIRRegistry")
	sourceHash := h.gatewayHash(0)
	for _, role := range []string{"b", "c"} {
		var root rootSnapshotEnvelope
		h.read(role, registry, h.application(role, "registry"), "rootAt", []any{uint32(1)}, &root)
		if root.Snapshot.GatewayHash != sourceHash {
			h.t.Errorf("chain %s root gateway hash = %x, want %x", role, root.Snapshot.GatewayHash, sourceHash)
		}
		if root.Snapshot.Signer != h.role.RootSigner {
			h.t.Errorf("chain %s root signer = %s, want %s", role, root.Snapshot.Signer, h.role.RootSigner)
		}
		if !root.Snapshot.Enabled || root.Snapshot.ValidAfter != 0 || root.Snapshot.ValidUntil != 0 {
			h.t.Errorf("chain %s root = %+v, want an enabled, unbounded root", role, root.Snapshot)
		}
	}
	// B completes hop 1, so its profile points at its inbound Hyperlane
	// adapter; C completes both hops, so both of its profiles point at its
	// inbound LayerZero adapter.
	for _, want := range []struct {
		role    string
		hop     int
		adapter string
	}{
		{"b", 1, "route_hl_hop_1_in"},
		{"c", 1, "route_hl_hop_2_in"},
		{"c", 2, "route_hl_hop_2_in"},
	} {
		profileHash, err := xir.ProfileHash("HL", want.hop)
		if err != nil {
			h.t.Fatalf("profile hash: %v", err)
		}
		var profile profileSnapshotEnvelope
		h.read(
			want.role, registry, h.application(want.role, "registry"),
			"profileAt", []any{profileHash}, &profile,
		)
		address := h.application(want.role, want.adapter)
		if profile.Snapshot.Adapter != address {
			h.t.Errorf(
				"chain %s profile %d adapter = %s, want %s",
				want.role, want.hop, profile.Snapshot.Adapter, address,
			)
		}
		if profile.Snapshot.SecurityLevel != 1 || !profile.Snapshot.Enabled {
			h.t.Errorf("chain %s profile %d = %+v", want.role, want.hop, profile.Snapshot)
		}
		if profile.Snapshot.SourceHash != h.gatewayHash(want.hop-1) ||
			profile.Snapshot.DestinationHash != h.gatewayHash(want.hop) {
			h.t.Errorf(
				"chain %s profile %d gateway bindings = %x/%x",
				want.role, want.hop, profile.Snapshot.SourceHash, profile.Snapshot.DestinationHash,
			)
		}
	}
}

// checkAdapters verifies the bidirectional peer bindings of the deployed route,
// the enforced LayerZero options, the authority bindings, and that no adapter
// has accepted evidence before any hop has run.
func (h *harness) checkAdapters() {
	h.t.Helper()
	hyperlane := h.contract("HyperlaneAdapter")
	layerZero := h.contract("LayerZeroAdapter")
	adapters := map[string]struct{ role, key, contract string }{}
	for _, hop := range h.document.Routes["HL"].Hops {
		sourceRole := strings.ToLower(hop.SourceChain)
		destinationRole := strings.ToLower(hop.DestinationChain)
		sourceKey := h.keyByAddress(sourceRole, hop.OutboundAdapter)
		destinationKey := h.keyByAddress(destinationRole, hop.InboundAdapter)
		sourceAddress := h.application(sourceRole, sourceKey)
		destinationAddress := h.application(destinationRole, destinationKey)
		if hop.Protocol == "H" {
			var remote [32]byte
			var expected [32]byte
			copy(expected[12:], destinationAddress.Bytes())
			h.read(sourceRole, hyperlane, sourceAddress, "remoteAdapter", nil, &remote)
			if remote != expected {
				h.t.Errorf("%s remote adapter = %x, want %x", sourceKey, remote, expected)
			}
			copy(expected[12:], sourceAddress.Bytes())
			h.read(destinationRole, hyperlane, destinationAddress, "remoteAdapter", nil, &remote)
			if remote != expected {
				h.t.Errorf("%s remote adapter = %x, want %x", destinationKey, remote, expected)
			}
			for _, side := range []struct{ role, key string }{
				{sourceRole, sourceKey}, {destinationRole, destinationKey},
			} {
				var mailbox common.Address
				h.read(side.role, hyperlane, h.application(side.role, side.key), "mailbox", nil, &mailbox)
				if mailbox != h.infrastructure(side.role, "mailbox") {
					h.t.Errorf("%s mailbox = %s", side.key, mailbox)
				}
			}
			adapters[sourceKey] = struct{ role, key, contract string }{sourceRole, sourceKey, "HyperlaneAdapter"}
			adapters[destinationKey] = struct{ role, key, contract string }{
				destinationRole, destinationKey, "HyperlaneAdapter",
			}
			continue
		}
		expectedOptions := crypto.Keccak256Hash(layerZeroReceiveOptions(1_500_000))
		for _, side := range []struct {
			role, key    string
			address      common.Address
			remoteEID    uint32
			expectedPeer [32]byte
		}{
			{sourceRole, sourceKey, sourceAddress, h.specByRole(destinationRole).LayerZeroEID, bytes32Address(destinationAddress)},
			{destinationRole, destinationKey, destinationAddress, h.specByRole(sourceRole).LayerZeroEID, bytes32Address(sourceAddress)},
		} {
			var peer [32]byte
			h.read(side.role, layerZero, side.address, "remotePeer", nil, &peer)
			if peer != side.expectedPeer {
				h.t.Errorf("%s remote peer = %x, want %x", side.key, peer, side.expectedPeer)
			}
			var remoteEID uint32
			h.read(side.role, layerZero, side.address, "remoteEid", nil, &remoteEID)
			if remoteEID != side.remoteEID {
				h.t.Errorf("%s remote eid = %d, want %d", side.key, remoteEID, side.remoteEID)
			}
			var options [32]byte
			h.read(side.role, layerZero, side.address, "enforcedOptionsHash", nil, &options)
			if options != expectedOptions {
				h.t.Errorf("%s enforced options = %x, want %x", side.key, options, expectedOptions)
			}
			var endpoint common.Address
			h.read(side.role, layerZero, side.address, "endpoint", nil, &endpoint)
			if endpoint != h.infrastructure(side.role, "endpoint_v2") {
				h.t.Errorf("%s endpoint = %s", side.key, endpoint)
			}
			adapters[side.key] = struct{ role, key, contract string }{
				side.role, side.key, "LayerZeroAdapter",
			}
		}
	}
	if len(adapters) != 4 {
		h.t.Fatalf("the route wired %d adapters, want 4", len(adapters))
	}
	// The authority bindings every adapter gates dispatch on.
	for _, adapter := range adapters {
		artifact := h.contract(adapter.contract)
		address := h.application(adapter.role, adapter.key)
		var administrator, runner common.Address
		h.read(adapter.role, artifact, address, "administrator", nil, &administrator)
		h.read(adapter.role, artifact, address, "runner", nil, &runner)
		if administrator != h.deployer {
			h.t.Errorf("%s administrator = %s, want the deployer", adapter.key, administrator)
		}
		if runner != h.role.Runner {
			h.t.Errorf("%s runner = %s, want %s", adapter.key, runner, h.role.Runner)
		}
	}
	// No adapter has accepted evidence: verify is false for zero digests and
	// for arbitrary digests, whether or not they look like a real hop.
	for _, adapter := range adapters {
		artifact := h.contract(adapter.contract)
		address := h.application(adapter.role, adapter.key)
		profileHash, err := xir.ProfileHash("HL", 1)
		if err != nil {
			h.t.Fatalf("profile hash: %v", err)
		}
		for _, digest := range [][3][32]byte{
			{},
			{{0x01}, {0x02}, {0x03}},
			{profileHash, {0x02}, {0x03}},
		} {
			var accepted bool
			h.read(
				adapter.role, artifact, address, "verify",
				[]any{digest[0], digest[1], digest[2]}, &accepted,
			)
			if accepted {
				h.t.Errorf("%s accepted evidence %x", adapter.key, digest)
			}
		}
	}
}

// checkHyperlane verifies the Mailbox initialization, the ISM the factory
// deployed for the configured validator, and the registry entry the Hyperlane
// agents read.
func (h *harness) checkHyperlane() {
	h.t.Helper()
	mailbox := h.protocolArtifact("hyperlane-native", "Mailbox.sol", "Mailbox")
	ism := h.protocolArtifact("hyperlane-native", "StaticMultisigIsm.sol", "StaticMessageIdMultisigIsm")
	for _, spec := range h.specs {
		address := h.infrastructure(spec.Role, "mailbox")
		var domain uint32
		var owner, defaultIsm, defaultHook, requiredHook common.Address
		h.read(spec.Role, mailbox, address, "localDomain", nil, &domain)
		h.read(spec.Role, mailbox, address, "owner", nil, &owner)
		h.read(spec.Role, mailbox, address, "defaultIsm", nil, &defaultIsm)
		h.read(spec.Role, mailbox, address, "defaultHook", nil, &defaultHook)
		h.read(spec.Role, mailbox, address, "requiredHook", nil, &requiredHook)
		if domain != spec.HyperlaneDomain {
			h.t.Errorf("chain %s mailbox domain = %d, want %d", spec.Role, domain, spec.HyperlaneDomain)
		}
		if owner != h.deployer {
			h.t.Errorf("chain %s mailbox owner = %s, want the deployer", spec.Role, owner)
		}
		if defaultIsm != h.infrastructure(spec.Role, "defaultIsm") {
			h.t.Errorf("chain %s default ISM = %s", spec.Role, defaultIsm)
		}
		if defaultHook != h.infrastructure(spec.Role, "protocolFee") {
			h.t.Errorf("chain %s default hook = %s, want the protocol fee hook", spec.Role, defaultHook)
		}
		if requiredHook != h.infrastructure(spec.Role, "merkleTreeHook") {
			h.t.Errorf("chain %s required hook = %s, want the merkle tree hook", spec.Role, requiredHook)
		}

		var validators []common.Address
		var threshold uint8
		h.read(
			spec.Role, ism, h.infrastructure(spec.Role, "defaultIsm"),
			"validatorsAndThreshold", []any{[]byte{}}, &validators, &threshold,
		)
		if len(validators) != 1 || validators[0] != h.role.HyperlaneValidator {
			h.t.Errorf("chain %s ISM validators = %v, want the configured validator", spec.Role, validators)
		}
		if threshold != 1 {
			h.t.Errorf("chain %s ISM threshold = %d, want 1", spec.Role, threshold)
		}

		payload, err := os.ReadFile(filepath.Join(
			h.runtimeRoot, "hyperlane", "registry", "chains", "xirlocalchain"+spec.Role, "addresses.yaml",
		))
		if err != nil {
			h.t.Fatalf("read Hyperlane registry entry: %v", err)
		}
		for _, field := range []string{
			"mailbox",
			"validatorAnnounce",
			"merkleTreeHook",
			"interchainGasPaymaster",
			"defaultIsm",
			"staticMessageIdMultisigIsmFactory",
			"protocolFee",
		} {
			if !strings.Contains(string(payload), field+":") {
				h.t.Errorf("chain %s registry entry has no %s", spec.Role, field)
			}
		}
	}
}

// checkLayerZero verifies the endpoint, the registered libraries, the default
// send and receive libraries of every remote chain, and the DVN signer set.
func (h *harness) checkLayerZero() {
	h.t.Helper()
	endpoint := h.protocolArtifact("layerzero-native", "EndpointV2.sol", "EndpointV2")
	dvn := h.protocolArtifact("layerzero-native", "DVN.sol", "DVN")
	priceFeed := h.protocolArtifact("layerzero-native", "PriceFeed.sol", "PriceFeed")
	for _, spec := range h.specs {
		address := h.infrastructure(spec.Role, "endpoint_v2")
		var eid uint32
		h.read(spec.Role, endpoint, address, "eid", nil, &eid)
		if eid != spec.LayerZeroEID {
			h.t.Errorf("chain %s endpoint eid = %d, want %d", spec.Role, eid, spec.LayerZeroEID)
		}
		for _, library := range []struct{ key, product string }{
			{"send_uln_302", "defaultSendLibrary"},
			{"receive_uln_302", "defaultReceiveLibrary"},
		} {
			expected := h.infrastructure(spec.Role, library.key)
			for _, remote := range h.remoteEIDs(spec.Role) {
				var registered common.Address
				h.read(spec.Role, endpoint, address, library.product, []any{remote}, &registered)
				if registered != expected {
					h.t.Errorf(
						"chain %s %s(%d) = %s, want %s",
						spec.Role, library.product, remote, registered, expected,
					)
				}
			}
			var registered bool
			h.read(spec.Role, endpoint, address, "isRegisteredLibrary", []any{expected}, &registered)
			if !registered {
				h.t.Errorf("chain %s library %s is not registered", spec.Role, library.key)
			}
		}
		var signers []common.Address
		var quorum uint64
		h.read(spec.Role, dvn, h.infrastructure(spec.Role, "dvn"), "getSigners", nil, &signers)
		h.read(spec.Role, dvn, h.infrastructure(spec.Role, "dvn"), "quorum", nil, &quorum)
		if len(signers) != 1 || signers[0] != h.role.LayerZeroWorker {
			h.t.Errorf("chain %s DVN signers = %v, want the LayerZero worker", spec.Role, signers)
		}
		if quorum != 1 {
			h.t.Errorf("chain %s DVN quorum = %d, want 1", spec.Role, quorum)
		}
		// The price feed is behind an ERC1967 proxy and must answer with the
		// price the script configured for every remote chain.
		for _, remote := range h.remoteEIDs(spec.Role) {
			var price priceEnvelope
			h.read(
				spec.Role, priceFeed, h.infrastructure(spec.Role, "price_feed"),
				"getPrice", []any{uint32(remote)}, &price,
			)
			nativePrice := new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)
			if price.Price.PriceRatio.Cmp(nativePrice) != 0 || price.Price.GasPriceInUnit != 1 ||
				price.Price.GasPerByte != 1 {
				h.t.Errorf("chain %s price feed %d = %+v, want 1e20/1/1", spec.Role, remote, price.Price)
			}
		}
	}
}

// checkRestart re-runs the same deployment against the same runtime root and
// proves that nothing was broadcast twice: no account nonce moved, the journal
// did not grow, and the second document is byte for byte the first one.
func (h *harness) checkRestart(specs []deploy.ChainSpec, options deploy.Options) {
	h.t.Helper()
	nonces := map[string]uint64{}
	for _, spec := range h.specs {
		nonce, err := h.clients[spec.Role].PendingNonce(h.ctx, h.deployer)
		if err != nil {
			h.t.Fatalf("read pending nonce of chain %s: %v", spec.Role, err)
		}
		nonces[spec.Role] = nonce
	}
	journalPath := filepath.Join(h.runtimeRoot, "deploy", "deployment-journal.jsonl")
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		h.t.Fatalf("read journal: %v", err)
	}
	first, err := os.ReadFile(h.outputPath)
	if err != nil {
		h.t.Fatalf("read deployment document: %v", err)
	}

	restartOptions := options
	restartOptions.OutputPath = filepath.Join(h.t.TempDir(), "restart.json")
	second, err := deploy.Deploy(h.ctx, specs, restartOptions)
	if err != nil {
		h.t.Fatalf("restart deploy: %v", err)
	}
	for _, spec := range h.specs {
		nonce, err := h.clients[spec.Role].PendingNonce(h.ctx, h.deployer)
		if err != nil {
			h.t.Fatalf("read pending nonce of chain %s: %v", spec.Role, err)
		}
		if nonce != nonces[spec.Role] {
			h.t.Errorf(
				"the restart sent transactions on chain %s: nonce %d became %d",
				spec.Role, nonces[spec.Role], nonce,
			)
		}
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil {
		h.t.Fatalf("read journal: %v", err)
	}
	if !slices.Equal(journalBefore, journalAfter) {
		h.t.Error("the restart appended journal rows for actions it did not send")
	}
	if second.JournalSHA256 != h.document.JournalSHA256 {
		h.t.Errorf("restart journal digest = %q, want %q", second.JournalSHA256, h.document.JournalSHA256)
	}
	if !reflect.DeepEqual(second.Chains, h.document.Chains) {
		h.t.Errorf("restart chain manifest = %v, want %v", second.Chains, h.document.Chains)
	}
	if !reflect.DeepEqual(second.DeploymentGas.ClassifiedTotals, h.document.DeploymentGas.ClassifiedTotals) {
		h.t.Errorf("restart gas classification = %+v, want %+v",
			second.DeploymentGas.ClassifiedTotals, h.document.DeploymentGas.ClassifiedTotals)
	}
	payload, err := os.ReadFile(restartOptions.OutputPath)
	if err != nil {
		h.t.Fatalf("read restart document: %v", err)
	}
	if !slices.Equal(first, payload) {
		h.t.Error("the restart document differs from the first deployment document")
	}
	if second.DeploymentSHA256 != h.document.DeploymentSHA256 {
		h.t.Errorf("restart digest = %q, want %q", second.DeploymentSHA256, h.document.DeploymentSHA256)
	}
}

// keyByAddress finds the manifest key a route hop names, which proves the
// document's hop wiring refers to the contracts it deployed.
func (h *harness) keyByAddress(role, address string) string {
	h.t.Helper()
	for key, value := range h.document.Chains[role] {
		if strings.EqualFold(value, address) {
			return key
		}
	}
	h.t.Fatalf("chain %s has no contract at %s", role, address)
	return ""
}

func (h *harness) specByRole(role string) deploy.ChainSpec {
	h.t.Helper()
	for _, spec := range h.specs {
		if spec.Role == role {
			return spec
		}
	}
	h.t.Fatalf("no spec for role %s", role)
	return deploy.ChainSpec{}
}

func (h *harness) gatewayHash(index int) [32]byte {
	h.t.Helper()
	identifier, err := xir.GatewayTypedID(h.specs[index].ChainID)
	if err != nil {
		h.t.Fatalf("gateway typed id: %v", err)
	}
	hash, err := identifier.Hash()
	if err != nil {
		h.t.Fatalf("gateway typed id hash: %v", err)
	}
	return hash
}

func (h *harness) remoteEIDs(role string) []uint32 {
	out := []uint32{}
	for _, spec := range h.specs {
		if spec.Role != role {
			out = append(out, spec.LayerZeroEID)
		}
	}
	return out
}

// rootSnapshotEnvelope carries the single tuple output of rootAt.
type rootSnapshotEnvelope struct {
	Snapshot rootSnapshot
}

type rootSnapshot struct {
	GatewayHash [32]byte
	Signer      common.Address
	ValidAfter  uint64
	ValidUntil  uint64
	Enabled     bool
}

// priceEnvelope carries the single tuple output of PriceFeed.getPrice.
type priceEnvelope struct {
	Price priceTuple
}

type priceTuple struct {
	PriceRatio     *big.Int
	GasPriceInUnit uint64
	GasPerByte     uint32
}

// profileSnapshotEnvelope carries the single tuple output of profileAt.
type profileSnapshotEnvelope struct {
	Snapshot profileSnapshot
}

type profileSnapshot struct {
	SourceHash      [32]byte
	DestinationHash [32]byte
	Adapter         common.Address
	SecurityLevel   uint8
	ValidAfter      uint64
	ValidUntil      uint64
	Enabled         bool
}

// layerZeroReceiveOptions rebuilds the type-3 executor LZ_RECEIVE options
// independently of the deployment, so the test compares against the bytes
// `executor_lz_receive_options` builds rather than the bytes the deployment
// happened to write.
func layerZeroReceiveOptions(gasLimit uint64) []byte {
	options := []byte{0x00, 0x03, 0x01, 0x00, 0x11, 0x01}
	limit := make([]byte, 16)
	binary.BigEndian.PutUint64(limit[8:], gasLimit)
	return append(options, limit...)
}

func bytes32Address(address common.Address) [32]byte {
	var out [32]byte
	copy(out[12:], address.Bytes())
	return out
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func keyAddress(t *testing.T, privateKeyHex string) common.Address {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}
	return crypto.PubkeyToAddress(key.PublicKey)
}

// fixtureKeys reads the parity vector fixture keys, the only private keys the
// repository carries.
func fixtureKeys(t *testing.T) map[string]string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), "go-runtime", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read parity vectors: %v", err)
	}
	var vectors struct {
		Constants struct {
			FixtureKeys map[string]string `json:"fixture_keys"`
		} `json:"constants"`
	}
	if err := json.Unmarshal(payload, &vectors); err != nil {
		t.Fatalf("decode parity vectors: %v", err)
	}
	for _, name := range []string{"root_signer", "validator", "dvn_signer"} {
		if vectors.Constants.FixtureKeys[name] == "" {
			t.Fatalf("the parity vectors have no %s key", name)
		}
	}
	return vectors.Constants.FixtureKeys
}

// requireProtocolArtifacts returns the protocol project root, or skips when the
// carrier stacks have no forge output. CI builds `contracts/out` only, so the
// Hyperlane and LayerZero artifacts are absent there and the carrier bootstrap
// cannot be exercised; the deployment document's carrier sections are also
// derived from those artifacts, so the whole integration test is skipped rather
// than weakened.
func requireProtocolArtifacts(t *testing.T, repository string) string {
	t.Helper()
	root := filepath.Join(repository, "protocol-projects")
	for _, stack := range []string{"hyperlane-native", "layerzero-native"} {
		path := filepath.Join(root, stack, "out")
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Skipf("protocol artifacts are absent: %s is not a directory", path)
		}
	}
	return root
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
