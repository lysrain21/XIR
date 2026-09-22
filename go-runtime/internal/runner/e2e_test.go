package runner

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/deploy"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/lab"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// The integration tests deploy the real Hyperlane and LayerZero contract stacks
// from Forge artifacts onto disposable anvil chains with the frozen local chain
// ids, then execute a multihop attempt through them. They are the runtime's
// end-to-end proof; the frozen five-chain Besu topology remains the environment
// of record for published measurements.

// testRoute is one preregistered route of the frozen order (H, L, HH, HHH,
// HHHH, HL, HLH, HLHL, LHLH, HHL, HHHL). "HL" needs three chains and exercises
// Hyperlane as the source carrier and LayerZero as the destination carrier.
const testRoute = "HL"

type anvilLab struct {
	root       string
	statePath  string
	rawRoot    string
	document   string
	keys       KeySet
	roles      deploy.RoleAddresses
	chains     []*lab.Chain
	chainSpecs []deploy.ChainSpec
	byRole     map[string]*lab.Chain
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "contracts", "src", "XIRGateway.sol")); err != nil {
		t.Fatalf("repository root %s does not hold the contracts: %v", root, err)
	}
	return root
}

func requireArtifacts(t *testing.T, root string) {
	t.Helper()
	required := []string{
		filepath.Join(root, "contracts", "out", "XIRGateway.sol", "XIRGateway.json"),
		filepath.Join(root, "protocol-projects", "hyperlane-native", "out", "Mailbox.sol", "Mailbox.json"),
		filepath.Join(root, "protocol-projects", "layerzero-native", "out", "EndpointV2.sol", "EndpointV2.json"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			if os.Getenv("XIR_REQUIRE_E2E") == "1" {
				t.Fatalf("required protocol artifact missing: %s: %v", path, err)
			}
			t.Skipf("integration test needs Forge artifacts: run `forge build --root contracts` and `scripts/bootstrap_native_protocols.sh` (%v)", err)
		}
	}
}

func freshKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key, "0x" + hex.EncodeToString(crypto.FromECDSA(key))
}

func addressOf(key *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(key.PublicKey)
}

func startAnvilLab(t *testing.T, routes []string) *anvilLab {
	t.Helper()
	root := repoRoot(t)
	requireArtifacts(t, root)
	if lab.AnvilPath("") == "" {
		if os.Getenv("XIR_REQUIRE_E2E") == "1" {
			t.Fatal("required anvil binary missing")
		}
		t.Skip("integration test needs the anvil binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	deployerKey, deployerKeyHex := freshKey(t)
	runnerKey, runnerKeyHex := freshKey(t)
	rootKey, rootKeyHex := freshKey(t)
	workerKey, workerKeyHex := freshKey(t)
	validatorKey, validatorKeyHex := freshKey(t)
	relayerKey, relayerKeyHex := freshKey(t)
	runnerAddress := addressOf(runnerKey)
	rootAddress := addressOf(rootKey)
	workerAddress := addressOf(workerKey)
	validatorAddress := addressOf(validatorKey)
	relayerAddress := addressOf(relayerKey)

	specs := []lab.Spec{
		{Role: "a", ChainID: 3133701, Fund: []lab.FundRequest{}},
		{Role: "b", ChainID: 3133702},
		{Role: "c", ChainID: 3133703},
	}
	fundAddresses := []common.Address{
		addressOf(deployerKey), runnerAddress, rootAddress, workerAddress,
		validatorAddress, relayerAddress,
	}
	for index := range specs {
		for _, address := range fundAddresses {
			specs[index].Fund = append(specs[index].Fund, lab.FundRequest{
				Address: address.Hex(),
				Wei:     "0x3635c9adc5dea00000", // 1000 ether
			})
		}
	}
	chains, err := lab.StartChains(ctx, specs, lab.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("start chains: %v", err)
	}
	lab := &anvilLab{
		root:      root,
		chains:    chains,
		byRole:    map[string]*lab.Chain{},
		statePath: filepath.Join(t.TempDir(), "runner.sqlite"),
		rawRoot:   filepath.Join(t.TempDir(), "raw"),
		document:  filepath.Join(t.TempDir(), "deployment.json"),
		keys: KeySet{
			Runner:             runnerKeyHex,
			RootSigner:         rootKeyHex,
			LayerZeroWorker:    workerKeyHex,
			HyperlaneValidator: validatorKeyHex,
			HyperlaneRelayer:   relayerKeyHex,
		},
		roles: deploy.RoleAddresses{
			Runner:             runnerAddress,
			RootSigner:         rootAddress,
			LayerZeroWorker:    workerAddress,
			HyperlaneValidator: validatorAddress,
			HyperlaneRelayer:   relayerAddress,
		},
	}
	eids := map[string]uint32{"a": 49001, "b": 49002, "c": 49003}
	for index, chain := range chains {
		role := specs[index].Role
		lab.byRole[role] = chain
		lab.chainSpecs = append(lab.chainSpecs, deploy.ChainSpec{
			Role:            role,
			ChainID:         chain.ChainID,
			RPCEndpoint:     chain.URL,
			HyperlaneDomain: uint32(chain.ChainID),
			LayerZeroEID:    eids[role],
		})
	}
	if _, err := deploy.Deploy(ctx, lab.chainSpecs, deploy.Options{
		ArtifactsRoot:         filepath.Join(root, "contracts", "out"),
		ProtocolArtifactsRoot: filepath.Join(root, "protocol-projects"),
		RuntimeRoot:           filepath.Join(t.TempDir(), "deploy-runtime"),
		DeployerKey:           deployerKeyHex,
		OutputPath:            lab.document,
		Routes:                routes,
		RoleAddresses:         lab.roles,
	}); err != nil {
		lab.stop()
		t.Fatalf("deploy application: %v", err)
	}
	t.Cleanup(lab.stop)
	return lab
}

func (l *anvilLab) stop() {
	lab.StopChains(l.chains)
}

func (l *anvilLab) config(t *testing.T, attempt Attempt, fault string) Config {
	t.Helper()
	keys := l.keys
	return Config{
		Attempts: []Attempt{attempt},
		Chains: []ChainConfig{
			{Role: "a", ChainID: 3133701, RPCURL: l.byRole["a"].URL, HyperlaneDomain: 3133701, LayerZeroEID: 49001},
			{Role: "b", ChainID: 3133702, RPCURL: l.byRole["b"].URL, HyperlaneDomain: 3133702, LayerZeroEID: 49002},
			{Role: "c", ChainID: 3133703, RPCURL: l.byRole["c"].URL, HyperlaneDomain: 3133703, LayerZeroEID: 49003},
		},
		DeploymentPath:  l.document,
		ArtifactsRoot:   filepath.Join(l.root, "contracts", "out"),
		ProtocolRoot:    filepath.Join(l.root, "protocol-projects"),
		PayloadSchedule: xir.PayloadSchedule{MinimumBytes: 32, SizeBucketCount: 4, SizeStepBytes: 32},
		FixedSeed:       "xir-go-runtime-integration",
		PolicyLabel:     policyLabel,
		Timeout:         5 * time.Minute,
		PollInterval:    200 * time.Millisecond,
		StatePath:       l.statePath,
		RawRoot:         l.rawRoot,
		Keys:            keys,
		EmbeddedAgents:  true,
		GasLimit:        defaultGasLimit,
		FaultAfterStage: fault,
		// anvil pins the RPC finalized tag at genesis and mines only when there is
		// work, so the integration tests accept the mined block; the frozen Besu
		// lab uses the tag with the private-QBFT fallback instead.
		Finality: Finality{Mode: FinalityConfirmations},
	}
}

func (l *anvilLab) client(t *testing.T, role string) *evm.Client {
	t.Helper()
	client, err := evm.Dial(context.Background(), l.byRole[role].URL, 30*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", role, err)
	}
	t.Cleanup(client.Close)
	return client
}

func (l *anvilLab) deployment(t *testing.T) *Deployment {
	t.Helper()
	document, err := LoadDeployment(l.document)
	if err != nil {
		t.Fatalf("load deployment: %v", err)
	}
	return document
}

// dumpDiagnostics reports the chain heights, the pending nonce of every role
// address, and the durable actions that have not succeeded yet. It runs only on
// a failed attempt, where the alternative is guessing why a submission stalled.
func (l *anvilLab) dumpDiagnostics(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addresses := map[string]common.Address{
		"runner":    l.roles.Runner,
		"root":      l.roles.RootSigner,
		"lz_worker": l.roles.LayerZeroWorker,
		"validator": l.roles.HyperlaneValidator,
		"relayer":   l.roles.HyperlaneRelayer,
	}
	for role, chain := range l.byRole {
		client, err := evm.Dial(ctx, chain.URL, 10*time.Second)
		if err != nil {
			t.Logf("diagnostics: dial %s: %v", role, err)
			continue
		}
		head, err := client.BlockNumber(ctx)
		if err != nil {
			t.Logf("diagnostics: head %s: %v", role, err)
		}
		for name, address := range addresses {
			nonce, err := client.PendingNonce(ctx, address)
			if err != nil {
				t.Logf("diagnostics: %s/%s nonce: %v", role, name, err)
				continue
			}
			t.Logf("diagnostics: chain %s head=%d %s(%s) pending nonce=%d", role, head, name, address.Hex(), nonce)
		}
		client.Close()
	}
	store, err := state.Open(l.statePath)
	if err != nil {
		t.Logf("diagnostics: open state: %v", err)
		return
	}
	defer func() { _ = store.Close() }()
	pending, err := store.PendingActions()
	if err != nil {
		t.Logf("diagnostics: pending actions: %v", err)
		return
	}
	for _, action := range pending {
		t.Logf("diagnostics: action %s chain=%s state=%s nonce=%d hash=%s target=%s",
			action.ActionID, action.ChainRole, action.State, action.Nonce, action.TransactionHash, action.To)
	}
}

// countEvents counts the logs of one contract carrying the given topic.
func countEvents(t *testing.T, client *evm.Client, address common.Address, topic common.Hash) int {
	t.Helper()
	logs, err := client.Logs(context.Background(), ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		Addresses: []common.Address{address},
		Topics:    [][]common.Hash{{topic}},
	})
	if err != nil {
		t.Fatalf("filter logs of %s: %v", address, err)
	}
	return len(logs)
}

func callUint(t *testing.T, client *evm.Client, contract artifacts.Artifact, to common.Address, method string) *big.Int {
	t.Helper()
	data, err := contract.ABI.PackCall(method)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	output, err := client.CallContract(context.Background(), to, data)
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	var value *big.Int
	if err := contract.ABI.UnpackOutputs(method, output, &value); err != nil {
		t.Fatalf("decode %s: %v", method, err)
	}
	return value
}

func TestAnvilRouteDeliversAndAppliesEffect(t *testing.T) {
	lab := startAnvilLab(t, []string{testRoute})
	deployment := lab.deployment(t)
	attempt := Attempt{
		AttemptID:     "go-runtime-integration-" + testRoute,
		Phase:         "smoke",
		Route:         testRoute,
		RouteSequence: 0,
		SwitchCount:   1,
	}
	executor, err := New(lab.config(t, attempt, ""))
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	defer executor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	summary, err := executor.Run(ctx)
	if err != nil {
		lab.dumpDiagnostics(t)
		t.Fatalf("run: %v (failures: %v)", err, summary.Failures)
	}
	if summary.Succeeded != 1 {
		t.Fatalf("run summary: %+v", summary)
	}

	receiverAddress, err := deployment.Contract("c", "receiver")
	if err != nil {
		t.Fatalf("receiver address: %v", err)
	}
	receiverArtifact, err := artifacts.Load(filepath.Join(lab.root, "contracts", "out"), "NativeMultihopReceiver")
	if err != nil {
		t.Fatalf("load receiver artifact: %v", err)
	}
	client := lab.client(t, "c")
	if delivered := callUint(t, client, receiverArtifact, receiverAddress, "deliveryCount"); delivered.Int64() != 1 {
		t.Fatalf("receiver delivery count is %s, want 1", delivered)
	}
	effectTopic, err := receiverArtifact.ABI.EventTopic("NativeMultihopEffectApplied")
	if err != nil {
		t.Fatalf("effect topic: %v", err)
	}
	if count := countEvents(t, client, receiverAddress, effectTopic); count != 1 {
		t.Fatalf("destination emitted %d effect events, want 1", count)
	}

	// The source chain dispatched exactly once through the Hyperlane adapter and
	// the second chain dispatched exactly once through the LayerZero adapter.
	hyperlaneAdapter, err := deployment.Contract("a", mustAdapterKey(testRoute, 1, "out"))
	if err != nil {
		t.Fatalf("hyperlane adapter: %v", err)
	}
	hyperlaneArtifact, err := artifacts.Load(filepath.Join(lab.root, "contracts", "out"), "HyperlaneAdapter")
	if err != nil {
		t.Fatalf("load hyperlane adapter artifact: %v", err)
	}
	dispatchTopic, err := hyperlaneArtifact.ABI.EventTopic("HyperlaneDispatched")
	if err != nil {
		t.Fatalf("dispatch topic: %v", err)
	}
	if count := countEvents(t, lab.client(t, "a"), hyperlaneAdapter, dispatchTopic); count != 1 {
		t.Fatalf("source chain emitted %d Hyperlane dispatches, want 1", count)
	}
	layerzeroAdapter, err := deployment.Contract("b", mustAdapterKey(testRoute, 2, "out"))
	if err != nil {
		t.Fatalf("layerzero adapter: %v", err)
	}
	layerzeroArtifact, err := artifacts.Load(filepath.Join(lab.root, "contracts", "out"), "LayerZeroAdapter")
	if err != nil {
		t.Fatalf("load layerzero adapter artifact: %v", err)
	}
	forwardedTopic, err := layerzeroArtifact.ABI.EventTopic("VerifiedEvidenceForwarded")
	if err != nil {
		t.Fatalf("forwarded topic: %v", err)
	}
	if count := countEvents(t, lab.client(t, "b"), layerzeroAdapter, forwardedTopic); count != 1 {
		t.Fatalf("intermediate chain emitted %d LayerZero dispatches, want 1", count)
	}
}

func TestAnvilRestartResumesWithoutDuplicateDispatch(t *testing.T) {
	lab := startAnvilLab(t, []string{testRoute})
	deployment := lab.deployment(t)
	attempt := Attempt{
		AttemptID:     "go-runtime-restart-" + testRoute,
		Phase:         "smoke",
		Route:         testRoute,
		RouteSequence: 1,
		SwitchCount:   1,
	}
	interrupted, err := New(lab.config(t, attempt, dispatchStage(1, "H")))
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	summary, runErr := interrupted.Run(ctx)
	cancel()
	if closeErr := interrupted.Close(); closeErr != nil {
		t.Fatalf("close interrupted runner: %v", closeErr)
	}
	if runErr == nil {
		t.Fatalf("the injected fault did not stop the attempt: %+v", summary)
	}
	if len(summary.Failures) == 0 {
		t.Fatalf("the interrupted run reported no failure")
	}

	// A fresh runner over the same ledger resumes the attempt. The dispatch of
	// hop 1 must not be broadcast a second time.
	resumed, err := New(lab.config(t, attempt, ""))
	if err != nil {
		t.Fatalf("new resumed runner: %v", err)
	}
	defer resumed.Close()
	resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer resumeCancel()
	resumedSummary, err := resumed.Run(resumeCtx)
	if err != nil {
		t.Fatalf("resumed run: %v (failures: %v)", err, resumedSummary.Failures)
	}
	if resumedSummary.Succeeded != 1 {
		t.Fatalf("resumed summary: %+v", resumedSummary)
	}

	hyperlaneAdapter, err := deployment.Contract("a", mustAdapterKey(testRoute, 1, "out"))
	if err != nil {
		t.Fatalf("hyperlane adapter: %v", err)
	}
	hyperlaneArtifact, err := artifacts.Load(filepath.Join(lab.root, "contracts", "out"), "HyperlaneAdapter")
	if err != nil {
		t.Fatalf("load hyperlane adapter artifact: %v", err)
	}
	dispatchTopic, err := hyperlaneArtifact.ABI.EventTopic("HyperlaneDispatched")
	if err != nil {
		t.Fatalf("dispatch topic: %v", err)
	}
	if count := countEvents(t, lab.client(t, "a"), hyperlaneAdapter, dispatchTopic); count != 1 {
		t.Fatalf("after recovery the source chain emitted %d dispatches, want 1", count)
	}
	receiverAddress, err := deployment.Contract("c", "receiver")
	if err != nil {
		t.Fatalf("receiver address: %v", err)
	}
	receiverArtifact, err := artifacts.Load(filepath.Join(lab.root, "contracts", "out"), "NativeMultihopReceiver")
	if err != nil {
		t.Fatalf("load receiver artifact: %v", err)
	}
	if delivered := callUint(t, lab.client(t, "c"), receiverArtifact, receiverAddress, "deliveryCount"); delivered.Int64() != 1 {
		t.Fatalf("after recovery the receiver delivery count is %s, want 1", delivered)
	}
}
