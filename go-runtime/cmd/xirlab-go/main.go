// Command xirlab-go runs the XIR execution layer: it can execute frozen
// multihop attempts against a deployed application, deploy that application to
// a local topology, and check the parity vectors the runtime is built against.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lysrain21/XIR/go-runtime/internal/runner"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "xirlab-go: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		usage()
		return errors.New("no subcommand given")
	}
	switch arguments[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "run":
		return runCommand(arguments[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: xirlab-go <command>

commands:
  run --config <file>     execute the attempts of a frozen runtime config
  version                 print the build version
  help                    print this message

The runtime never reads a private key from a file: the config names environment
variables that hold each signing key.
`)
}

// fileConfig is the on-disk runtime configuration.
type fileConfig struct {
	SchemaVersion string `json:"schema_version"`
	Chains        []struct {
		Role            string `json:"role"`
		ChainID         uint64 `json:"chain_id"`
		RPCURL          string `json:"rpc_url"`
		HyperlaneDomain uint32 `json:"hyperlane_domain"`
		LayerZeroEID    uint32 `json:"layerzero_eid"`
	} `json:"chains"`
	Attempts []struct {
		AttemptID     string `json:"attempt_id"`
		Phase         string `json:"phase"`
		Route         string `json:"route"`
		RouteSequence uint64 `json:"route_sequence"`
		SwitchCount   int    `json:"switch_count"`
		PayloadSHA256 string `json:"payload_sha256"`
	} `json:"attempts"`
	PayloadSchedule struct {
		MinimumBytes    uint64 `json:"minimum_bytes"`
		SizeBucketCount uint64 `json:"size_bucket_count"`
		SizeStepBytes   uint64 `json:"size_step_bytes"`
	} `json:"payload_schedule"`
	FixedSeed       string `json:"fixed_seed"`
	PolicyLabel     string `json:"policy_label"`
	Deployment      string `json:"deployment"`
	ArtifactsRoot   string `json:"artifacts_root"`
	ProtocolRoot    string `json:"protocol_root"`
	StatePath       string `json:"state_path"`
	RawRoot         string `json:"raw_root"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	PollMillis      int    `json:"poll_millis"`
	Concurrency     int    `json:"concurrency"`
	GasLimit        uint64 `json:"gas_limit"`
	StopFile        string `json:"stop_file"`
	EmbeddedAgents  bool   `json:"embedded_agents"`
	FaultAfterStage string `json:"fault_after_stage"`
	Finality        struct {
		Mode           string `json:"mode"`
		Confirmations  uint64 `json:"confirmations"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"finality"`
	KeyEnvironment struct {
		Runner             string `json:"runner"`
		RootSigner         string `json:"root_signer"`
		LayerZeroWorker    string `json:"layerzero_worker"`
		HyperlaneValidator string `json:"hyperlane_validator"`
		HyperlaneRelayer   string `json:"hyperlane_relayer"`
	} `json:"key_environment"`
}

func runCommand(arguments []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the runtime configuration file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("run needs --config")
	}
	payload, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var document fileConfig
	if err := json.Unmarshal(payload, &document); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	config, err := document.resolve()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	executor, err := runner.New(config)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := executor.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "xirlab-go: close runner: %v\n", closeErr)
		}
	}()
	started := time.Now()
	summary, err := executor.Run(ctx)
	if encodeErr := printSummary(summary); encodeErr != nil {
		return encodeErr
	}
	if err != nil {
		return fmt.Errorf("run failed after %s: %w", time.Since(started).Round(time.Millisecond), err)
	}
	fmt.Fprintf(os.Stderr, "xirlab-go: %d/%d attempts succeeded in %s\n",
		summary.Succeeded, summary.Attempts, time.Since(started).Round(time.Millisecond))
	if len(summary.Failures) > 0 {
		return fmt.Errorf("%d attempts failed", len(summary.Failures))
	}
	return nil
}

func (d fileConfig) resolve() (runner.Config, error) {
	if d.SchemaVersion != "xir-go-runtime-config-v1" {
		return runner.Config{}, fmt.Errorf("unexpected config schema %q", d.SchemaVersion)
	}
	config := runner.Config{
		DeploymentPath:  d.Deployment,
		ArtifactsRoot:   d.ArtifactsRoot,
		ProtocolRoot:    d.ProtocolRoot,
		StatePath:       d.StatePath,
		RawRoot:         d.RawRoot,
		FixedSeed:       d.FixedSeed,
		PolicyLabel:     d.PolicyLabel,
		Concurrency:     d.Concurrency,
		StopFile:        d.StopFile,
		EmbeddedAgents:  d.EmbeddedAgents,
		FaultAfterStage: d.FaultAfterStage,
		GasLimit:        d.GasLimit,
		Finality: runner.Finality{
			Mode:          d.Finality.Mode,
			Confirmations: d.Finality.Confirmations,
			Timeout:       time.Duration(d.Finality.TimeoutSeconds) * time.Second,
		},
		PayloadSchedule: xir.PayloadSchedule{
			MinimumBytes:    d.PayloadSchedule.MinimumBytes,
			SizeBucketCount: d.PayloadSchedule.SizeBucketCount,
			SizeStepBytes:   d.PayloadSchedule.SizeStepBytes,
		},
	}
	if d.TimeoutSeconds > 0 {
		config.Timeout = time.Duration(d.TimeoutSeconds) * time.Second
	}
	if d.PollMillis > 0 {
		config.PollInterval = time.Duration(d.PollMillis) * time.Millisecond
	}
	for _, chain := range d.Chains {
		config.Chains = append(config.Chains, runner.ChainConfig{
			Role:            chain.Role,
			ChainID:         chain.ChainID,
			RPCURL:          chain.RPCURL,
			HyperlaneDomain: chain.HyperlaneDomain,
			LayerZeroEID:    chain.LayerZeroEID,
		})
	}
	for _, attempt := range d.Attempts {
		config.Attempts = append(config.Attempts, runner.Attempt{
			AttemptID:     attempt.AttemptID,
			Phase:         attempt.Phase,
			Route:         attempt.Route,
			RouteSequence: attempt.RouteSequence,
			SwitchCount:   attempt.SwitchCount,
			PayloadSHA256: attempt.PayloadSHA256,
		})
	}
	keys := []struct {
		name string
		into *string
	}{
		{d.KeyEnvironment.Runner, &config.Keys.Runner},
		{d.KeyEnvironment.RootSigner, &config.Keys.RootSigner},
		{d.KeyEnvironment.LayerZeroWorker, &config.Keys.LayerZeroWorker},
		{d.KeyEnvironment.HyperlaneValidator, &config.Keys.HyperlaneValidator},
		{d.KeyEnvironment.HyperlaneRelayer, &config.Keys.HyperlaneRelayer},
	}
	for _, key := range keys {
		if key.name == "" {
			continue
		}
		value, ok := os.LookupEnv(key.name)
		if !ok || value == "" {
			return runner.Config{}, fmt.Errorf("environment variable %s is not set", key.name)
		}
		*key.into = value
	}
	if config.Keys.Runner == "" || config.Keys.RootSigner == "" {
		return runner.Config{}, errors.New("config must name the runner and root signer key environment variables")
	}
	return config, nil
}

func printSummary(summary runner.Summary) error {
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("encode summary: %w", err)
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}
