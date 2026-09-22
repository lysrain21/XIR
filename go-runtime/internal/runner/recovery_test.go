package runner

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
	_ "modernc.org/sqlite"
)

func TestReviewLayerZeroDurations(t *testing.T) {
	config := Config{PollInterval: 500 * time.Millisecond, Timeout: 10 * time.Minute}
	carrier, err := newLayerZeroCarrier(nil, "", nil, KeySet{}, config)
	if err != nil {
		t.Fatal(err)
	}
	if carrier.poll != config.PollInterval || carrier.timeout != config.Timeout {
		t.Fatalf("duration changed: poll=%s (want %s), timeout=%s (want %s)", carrier.poll, config.PollInterval, carrier.timeout, config.Timeout)
	}
}

func TestReviewRootFinalityRetry(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	attempt := Attempt{AttemptID: "review-root-finality", Phase: "smoke", Route: testRoute, SwitchCount: 1}
	config := l.config(t, attempt, "")
	config.Finality = Finality{Mode: FinalityConfirmations, Confirmations: 1, Timeout: time.Millisecond}
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := r.Run(context.Background())
	r.Close()
	if err == nil {
		t.Fatal("expected first run to wait for a successor")
	}
	t.Logf("first attempt: %v", summary.Failures)
	frozen := snapshotActions(t, l)
	config.Finality = Finality{Mode: FinalityConfirmations}
	r, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	summary, err = r.Run(context.Background())
	if err != nil {
		t.Fatalf("resume after mined root failed: %v (%v)", err, summary.Failures)
	}
	assertActionsUnchanged(t, frozen, snapshotActions(t, l))
	assertEffects(t, l, 1)
	assertCompletedReplay(t, l, config, r)
}

func TestReviewLayerZeroLateRestart(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	attempt := Attempt{AttemptID: "review-lz-late-restart", Phase: "smoke", Route: testRoute, SwitchCount: 1}
	config := l.config(t, attempt, StageDestinationDelivery)
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := r.Run(context.Background())
	r.Close()
	if err == nil {
		t.Fatal("expected injected fault")
	}
	t.Logf("first attempt: %v", summary.Failures)
	frozen := snapshotActions(t, l)
	balances := snapshotAccounts(t, l)
	time.Sleep(1100 * time.Millisecond)
	config.FaultAfterStage = ""
	r, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	summary, err = r.Run(context.Background())
	if err != nil {
		t.Fatalf("resume after LayerZero delivery failed: %v (%v)", err, summary.Failures)
	}
	assertActionsUnchanged(t, frozen, snapshotActions(t, l))
	if got := snapshotAccounts(t, l); !reflect.DeepEqual(balances, got) {
		t.Fatalf("recovery submitted or paid again: before=%v after=%v", balances, got)
	}
	assertEffects(t, l, 1)
	assertCompletedReplay(t, l, config, r)
}

func TestReviewHyperlaneRetryAfterLaterDispatch(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	first := Attempt{AttemptID: "review-hl-first", Phase: "smoke", Route: testRoute, SwitchCount: 1}
	second := Attempt{AttemptID: "review-hl-second", Phase: "smoke", Route: testRoute, RouteSequence: 1, SwitchCount: 1}
	config := l.config(t, first, dispatchStage(1, "H"))
	config.Attempts = []Attempt{first, second}
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := r.Run(context.Background())
	r.Close()
	if err == nil || len(summary.Failures) != 2 {
		t.Fatalf("expected faults after two source dispatches: %v %v", err, summary.Failures)
	}
	t.Logf("first invocation: %v", summary.Failures)
	frozen := snapshotActions(t, l)
	config.Attempts = []Attempt{first, second}
	config.FaultAfterStage = ""
	r, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	summary, err = r.Run(context.Background())
	if err != nil {
		t.Fatalf("earlier message cannot recover after another dispatch: %v (%v)", err, summary.Failures)
	}
	assertActionsUnchanged(t, frozen, snapshotActions(t, l))
	assertEffects(t, l, 2)
	assertCompletedReplay(t, l, config, r)
}

// Snapshot each durable signed identity, including amount paid. Existing
// transactions must keep identical bytes/hash/nonce/value across recovery.
func snapshotActions(t *testing.T, l *anvilLab) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", l.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT action_id, transaction_hash, raw_transaction_hex, calldata_hex, nonce, value FROM actions WHERE attempt_id != ''`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, hash, raw, data, value string
		var nonce int64
		if err := rows.Scan(&id, &hash, &raw, &data, &nonce, &value); err != nil {
			t.Fatal(err)
		}
		out[id] = fmt.Sprintf("%s/%s/%s/%d/%s", hash, raw, data, nonce, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no durable actions")
	}
	return out
}

func assertActionsUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for id, want := range before {
		if after[id] != want {
			t.Fatalf("durable identity changed: %s", id)
		}
	}
}

func snapshotAccounts(t *testing.T, l *anvilLab) map[string]string {
	t.Helper()
	out := map[string]string{}
	accounts := []common.Address{l.roles.Runner, l.roles.LayerZeroWorker, l.roles.HyperlaneRelayer, l.roles.RootSigner, l.roles.HyperlaneValidator}
	for _, role := range []string{"a", "b", "c"} {
		client := l.client(t, role)
		for _, address := range accounts {
			nonce, err := client.PendingNonce(context.Background(), address)
			if err != nil {
				t.Fatal(err)
			}
			balance, err := client.BalanceAt(context.Background(), address)
			if err != nil {
				t.Fatal(err)
			}
			out[role+address.Hex()] = fmt.Sprintf("%d/%s", nonce, balance)
		}
	}
	return out
}

func assertEffects(t *testing.T, l *anvilLab, want int) {
	t.Helper()
	d := l.deployment(t)
	for _, item := range []struct{ role, key, contract, event string }{
		{"a", "gateway", "XIRGateway", "RootCreated"},
		{"a", mustAdapterKey(testRoute, 1, "out"), "HyperlaneAdapter", "HyperlaneDispatched"},
		{"b", mustAdapterKey(testRoute, 2, "out"), "LayerZeroAdapter", "VerifiedEvidenceForwarded"},
		{"c", "receiver", "NativeMultihopReceiver", "NativeMultihopEffectApplied"},
	} {
		address, err := d.Contract(item.role, item.key)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := artifacts.Load(filepath.Join(l.root, "contracts", "out"), item.contract)
		if err != nil {
			t.Fatal(err)
		}
		topic, err := artifact.ABI.EventTopic(item.event)
		if err != nil {
			t.Fatal(err)
		}
		if got := countEvents(t, l.client(t, item.role), address, topic); got != want {
			t.Fatalf("%s count %d want %d", item.event, got, want)
		}
		if item.key == "receiver" {
			if got := callUint(t, l.client(t, item.role), artifact, address, "deliveryCount"); got.Cmp(big.NewInt(int64(want))) != 0 {
				t.Fatalf("deliveryCount=%s want %d", got, want)
			}
		}
	}
}

func assertCompletedReplay(t *testing.T, l *anvilLab, config Config, r *Runner) {
	t.Helper()
	before := snapshotAccounts(t, l)
	actions := snapshotActions(t, l)
	summary, err := r.Run(context.Background())
	if err != nil || summary.Succeeded != len(config.Attempts) {
		t.Fatalf("completed replay: %v %+v", err, summary)
	}
	if after := snapshotAccounts(t, l); !reflect.DeepEqual(before, after) {
		t.Fatal("completed replay sent another transaction or paid gas")
	}
	if after := snapshotActions(t, l); !reflect.DeepEqual(actions, after) {
		t.Fatal("completed replay changed durable transactions")
	}
}

// Existing ledgers from 294db67 have no intent_detail. Recover the original
// nonce from the creation event rather than from the gateway's nextNonce.
func TestReviewLegacyRootRecovery(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	a := Attempt{AttemptID: "legacy-root", Phase: "smoke", Route: testRoute, SwitchCount: 1}
	config := l.config(t, a, "")
	config.Finality = Finality{Mode: FinalityConfirmations, Confirmations: 1, Timeout: time.Millisecond}
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := r.Run(context.Background())
	r.Close()
	if err == nil || !strings.Contains(strings.Join(summary.Failures, " "), "successors") {
		t.Fatalf("expected finality timeout: %v %+v", err, summary)
	}
	db, err := sql.Open("sqlite", l.statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"actions", "stages"} {
		if _, err := db.Exec("UPDATE " + table + " SET detail_json=json_remove(detail_json,'$.intent_detail') WHERE stage='root_create'"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	before := snapshotActions(t, l)
	config.Finality = Finality{Mode: FinalityConfirmations}
	r, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	summary, err = r.Run(context.Background())
	if err != nil {
		t.Fatalf("legacy root recovery: %v %+v", err, summary)
	}
	assertActionsUnchanged(t, before, snapshotActions(t, l))
	assertEffects(t, l, 1)
}

// A reserved root nonce must survive even before the transaction is signed.
func TestReviewRootNonceReservation(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	a := Attempt{AttemptID: "reserved-root", Phase: "smoke", Route: testRoute}
	r, err := New(l.config(t, a, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.state.Intend(state.Action{ActionID: actionID(a.AttemptID, StageRootCreate), AttemptID: a.AttemptID, Stage: StageRootCreate, ChainRole: "a", ChainID: 3133701, Sender: strings.ToLower(l.roles.Runner.Hex()), To: l.roles.Runner.Hex(), CalldataHex: "0x", CalldataBytes: 0, CalldataSHA256: digestHex(nil), Value: "0", Gas: 100000, DetailJSON: `{"intent_detail":{"record_nonce":7}}`})
	if err != nil {
		t.Fatal(err)
	}
	next, err := r.state.NextReservedRootNonce()
	if err != nil || next != 8 {
		t.Fatalf("reservation floor: %d %v", next, err)
	}
	gateway, err := r.chains.bind("a", "gateway")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := r.rootNonce(context.Background(), a, gateway, l.roles.Runner)
	if err != nil || nonce != 7 {
		t.Fatalf("frozen nonce: %d %v", nonce, err)
	}
}

func TestReviewLayerZeroStageRestarts(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	for i, stage := range []string{"hop_2_layerzero_dvn_execute", "hop_2_layerzero_commit_verification", "hop_2_layerzero_executor_execute"} {
		t.Run(stage, func(t *testing.T) {
			a := Attempt{AttemptID: "lz-stage-" + stage, Phase: "smoke", Route: testRoute, RouteSequence: uint64(i), SwitchCount: 1}
			config := l.config(t, a, stage)
			r, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := r.Run(context.Background())
			r.Close()
			if err == nil || !strings.Contains(strings.Join(summary.Failures, " "), "injected fault after stage "+stage) {
				t.Fatalf("wrong interruption: %v %+v", err, summary)
			}
			frozen := snapshotActions(t, l)
			client := l.client(t, "c")
			beforeNonce, err := client.PendingNonce(context.Background(), l.roles.LayerZeroWorker)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(1100 * time.Millisecond)
			config.FaultAfterStage = ""
			r, err = New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			summary, err = r.Run(context.Background())
			if err != nil {
				t.Fatalf("stage recovery: %v %+v", err, summary)
			}
			assertActionsUnchanged(t, frozen, snapshotActions(t, l))
			assertEffects(t, l, i+1)
			afterNonce, err := client.PendingNonce(context.Background(), l.roles.LayerZeroWorker)
			if err != nil {
				t.Fatal(err)
			}
			if afterNonce-beforeNonce != uint64(2-i) {
				t.Fatalf("worker sent %d tx after recovery, want only %d remaining stages", afterNonce-beforeNonce, 2-i)
			}
			assertCompletedReplay(t, l, config, r)
		})
	}
}

// Use a real external-delivery delay: the first verify call must be false and
// subsequent polls must observe the actual destination callback.
type delayedLayerZero struct{ *layerZeroCarrier }

func (c delayedLayerZero) Confirm(ctx context.Context, request HopRequest, dispatched DispatchResult) error {
	done := make(chan error, 1)
	go func() {
		if err := sleepContext(ctx, 150*time.Millisecond); err != nil {
			done <- err
			return
		}
		done <- c.deliver(ctx, request, dispatched.delivery.(layerZeroDelivery))
	}()
	polling := *c.layerZeroCarrier
	polling.embedded = false
	err := polling.Confirm(ctx, request, dispatched)
	deliveryErr := <-done
	if deliveryErr != nil {
		return deliveryErr
	}
	return err
}
func TestReviewLayerZeroExternalPolling(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	a := Attempt{AttemptID: "delayed-external", Phase: "smoke", Route: testRoute, SwitchCount: 1}
	config := l.config(t, a, "")
	config.PollInterval = 20 * time.Millisecond
	config.Timeout = 5 * time.Second
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.carriers["L"] = delayedLayerZero{r.carriers["L"].(*layerZeroCarrier)}
	summary, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("external polling: %v %+v", err, summary)
	}
	assertEffects(t, l, 1)
}

// Two actual Mailbox dispatches in one block require an intra-block checkpoint;
// eth_call at that block exposes only the root after the second insertion.
func TestReviewHyperlaneSameBlockCheckpoint(t *testing.T) {
	l := startAnvilLab(t, []string{testRoute})
	a := Attempt{AttemptID: "same-block", Phase: "smoke", Route: testRoute}
	r, err := New(l.config(t, a, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.chains.SetRoute(testRoute)
	source, err := r.chains.bind("a", mustAdapterKey(testRoute, 1, "out"))
	if err != nil {
		t.Fatal(err)
	}
	dest, err := r.chains.bind("b", mustAdapterKey(testRoute, 1, "in"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := xir.ProfileHash(testRoute, 1)
	if err != nil {
		t.Fatal(err)
	}
	rpcClient, err := rpc.Dial(l.byRole["a"].URL)
	if err != nil {
		t.Fatal(err)
	}
	defer rpcClient.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rpcClient.CallContext(ctx, nil, "evm_setAutomine", false); err != nil {
		t.Fatal(err)
	}
	type result struct {
		request  HopRequest
		dispatch DispatchResult
		err      error
	}
	done := make(chan result, 2)
	// Share one transactor to reserve distinct pending nonces. Bind contracts
	// before launching workers so only the durable send path is concurrent.
	for i := 0; i < 2; i++ {
		request := HopRequest{Route: testRoute, AttemptID: fmt.Sprintf("same-block-%d", i), HopIndex: 1, Protocol: "H", SourceRole: "a", DestinationRole: "b", SourceAdapter: source, DestinationAdapter: dest, CurrentProfile: profile, CurrentTransition: xir.Keccak256([]byte(fmt.Sprint(i)))}
		if _, err := r.state.BeginAttempt(state.AttemptRow{AttemptID: request.AttemptID, Phase: "smoke", Route: testRoute, RouteSequence: i, CoordinatesJSON: "{}"}); err != nil {
			t.Fatal(err)
		}
		go func() { d, err := r.carriers["H"].Dispatch(ctx, request); done <- result{request, d, err} }()
	}
	// Mine only when both signed transactions are in the same local pool.
	for {
		var pending struct {
			Transactions []any `json:"transactions"`
		}
		if err := rpcClient.CallContext(ctx, &pending, "eth_getBlockByNumber", "pending", false); err != nil {
			t.Fatal(err)
		}
		if len(pending.Transactions) == 2 {
			break
		}
		if err := sleepContext(ctx, 10*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.byRole["a"].Mine(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := rpcClient.CallContext(ctx, nil, "evm_setAutomine", true); err != nil {
		t.Fatal(err)
	}
	var sourceBlock uint64
	for i := 0; i < 2; i++ {
		result := <-done
		if result.err != nil {
			t.Fatal(result.err)
		}
		delivery := result.dispatch.delivery.(hyperlaneDelivery)
		if i == 0 {
			sourceBlock = delivery.SourceResult.BlockNumber
		} else if sourceBlock != delivery.SourceResult.BlockNumber {
			t.Fatal("dispatches were not mined in the same block")
		}
		if err := r.carriers["H"].Confirm(ctx, result.request, result.dispatch); err != nil {
			t.Fatalf("same-block message %d recovery: %v", delivery.InsertedIndex, err)
		}
	}
}
