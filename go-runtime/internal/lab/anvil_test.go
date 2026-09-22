package lab

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestStartChainsServesDistinctChainsAndFunding(t *testing.T) {
	if AnvilPath("") == "" {
		t.Skip("anvil binary is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const funded = "0x00000000000000000000000000000000000000aa"
	chains, err := StartChains(ctx, []Spec{
		{Role: "a", ChainID: 3133701, BlockPeriod: time.Second, Fund: []FundRequest{{Address: funded, Wei: "0xde0b6b3a7640000"}}},
		{Role: "b", ChainID: 3133702, BlockPeriod: time.Second},
	}, Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("start chains: %v", err)
	}
	defer StopChains(chains)
	if len(chains) != 2 {
		t.Fatalf("expected two chains, got %d", len(chains))
	}
	if chains[0].URL == chains[1].URL {
		t.Fatalf("chains share a URL: %s", chains[0].URL)
	}
	balance, err := chains[0].BalanceOf(ctx, funded)
	if err != nil {
		t.Fatalf("read funded balance: %v", err)
	}
	observed, ok := new(big.Int).SetString(strings.TrimPrefix(balance, "0x"), 16)
	if !ok {
		t.Fatalf("balance %q is not a hexadecimal quantity", balance)
	}
	if observed.Cmp(big.NewInt(0)) <= 0 {
		t.Fatalf("funded address balance is %s", balance)
	}
	if empty, err := chains[1].BalanceOf(ctx, funded); err != nil {
		t.Fatalf("read unfunded balance: %v", err)
	} else if empty != "0x0" {
		t.Fatalf("second chain funded an address it should not have: %s", empty)
	}
	if err := chains[0].Mine(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	height, err := chains[0].BlockNumber(ctx)
	if err != nil {
		t.Fatalf("read block number: %v", err)
	}
	if height == 0 {
		t.Fatalf("block number did not advance")
	}
}

func TestStopChainsTerminatesProcesses(t *testing.T) {
	if AnvilPath("") == "" {
		t.Skip("anvil binary is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	chains, err := StartChains(ctx, []Spec{{Role: "a", ChainID: 3133701}}, Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("start chains: %v", err)
	}
	chain := chains[0]
	StopChains(chains)
	if _, err := chain.BlockNumber(ctx); err == nil {
		t.Fatalf("stopped chain still answers requests")
	}
}
