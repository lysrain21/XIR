package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/lab"
)

func TestAwaitFinalityWaitsForSuccessorAndCanonicalBlock(t *testing.T) {
	if lab.AnvilPath("") == "" {
		t.Skip("anvil binary is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	chains, err := lab.StartChains(ctx, []lab.Spec{{Role: "a", ChainID: 3133701}}, lab.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("start chains: %v", err)
	}
	defer lab.StopChains(chains)
	client, err := evm.Dial(ctx, chains[0].URL, 30*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	receipt := &types.Receipt{BlockNumber: header.Number, BlockHash: header.Hash()}

	expected, err := (&Runner{config: Config{
		Finality: Finality{Mode: FinalityConfirmations, Confirmations: 1, Timeout: 30 * time.Second},
	}}).awaitFinality(ctx, client, receipt)
	if err == nil {
		t.Fatalf("a block with no successor was accepted as final (%s)", expected)
	}

	accepting := &Runner{config: Config{Finality: Finality{Mode: FinalityConfirmations}}}
	rule, err := accepting.awaitFinality(ctx, client, receipt)
	if err != nil {
		t.Fatalf("the zero-confirmation rule rejected a mined block: %v", err)
	}
	if rule != "confirmations-0" {
		t.Fatalf("zero-confirmation rule reported %q", rule)
	}

	immediate := &Runner{config: Config{Finality: Finality{Mode: FinalityNone}}}
	if rule, err := immediate.awaitFinality(ctx, client, receipt); err != nil || rule != "none-test-only" {
		t.Fatalf("the none rule reported %q with error %v", rule, err)
	}

	if _, err := (&Runner{config: Config{Finality: Finality{Mode: "unknown"}}}).awaitFinality(ctx, client, receipt); err == nil {
		t.Fatal("an unsupported finality mode was accepted")
	}

	// A successor block satisfies the one-confirmation rule once it is mined.
	waiting := &Runner{config: Config{
		Finality: Finality{Mode: FinalityConfirmations, Confirmations: 1, Timeout: 30 * time.Second},
	}}
	done := make(chan struct {
		rule string
		err  error
	}, 1)
	go func() {
		rule, err := waiting.awaitFinality(ctx, client, receipt)
		done <- struct {
			rule string
			err  error
		}{rule, err}
	}()
	select {
	case result := <-done:
		t.Fatalf("finality returned before the successor block existed: %q %v", result.rule, result.err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := chains[0].Mine(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("finality failed after the successor block: %v", result.err)
		}
		if result.rule != "confirmations-1" {
			t.Fatalf("finality reported %q", result.rule)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("finality did not observe the successor block")
	}
	if head, err := client.BlockNumber(ctx); err != nil || head < 1 {
		t.Fatalf("chain head is %d (err %v), want a mined successor", head, err)
	}
}
