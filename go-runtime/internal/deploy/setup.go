package deploy

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/evm"
	"github.com/lysrain21/XIR/go-runtime/internal/state"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// Action phases of one deployment. The protocol bootstrap of a chain is
// reported separately from the application because the carriers are reused by
// the campaign and are not charged to the XIR application.
const (
	phaseProtocol    = "protocol"
	phaseApplication = "application"
)

// newDeployment validates the request, opens the private runtime tree, and
// dials every chain.
func newDeployment(ctx context.Context, chains []ChainSpec, options Options) (*deployment, error) {
	specs, order, routes, err := validate(chains, options)
	if err != nil {
		return nil, err
	}
	layout := newLayout(options.RuntimeRoot)
	if err := ensureDirectory(layout.work, 0o700); err != nil {
		return nil, err
	}
	if err := ensureDirectory(layout.spool, 0o700); err != nil {
		return nil, err
	}
	entries, err := openJournal(layout.journal)
	if err != nil {
		return nil, err
	}
	store, err := state.Open(layout.state)
	if err != nil {
		entries.close()
		return nil, fmt.Errorf("deploy: open state store: %w", err)
	}
	spool, err := filepath.Abs(layout.spool)
	if err != nil {
		store.Close()
		entries.close()
		return nil, fmt.Errorf("deploy: resolve receipt spool: %w", err)
	}
	run := &deployment{
		options:           options,
		specs:             specs,
		routes:            routes,
		layout:            layout,
		chains:            make(map[string]*chainRuntime, len(specs)),
		order:             order,
		store:             store,
		entries:           entries,
		manifest:          make(map[string]map[string]string, len(specs)),
		stack:             make(map[string]*protocolStack, len(specs)),
		gatewayIDs:        make(map[string]xir.TypedID, len(specs)),
		gatewayHashes:     make(map[string][32]byte, len(specs)),
		profileHashes:     make(map[string]map[int][32]byte, len(routes)),
		artifactCache:     map[string]artifactCacheEntry{},
		protocolDocuments: make(map[string]ProtocolDeploymentDocument, len(specs)),
	}
	for index, spec := range specs {
		runtime, err := newChainRuntime(ctx, spec, options, store, spool, entries)
		if err != nil {
			run.close()
			return nil, err
		}
		runtime.owner = run
		runtime.phase = phaseProtocol
		run.chains[spec.Role] = runtime
		run.manifest[spec.Role] = map[string]string{}
		if index == 0 {
			run.deployer = runtime.deployer
		}
		identifier, err := xir.GatewayTypedID(spec.ChainID)
		if err != nil {
			run.close()
			return nil, fmt.Errorf("chain %s: %w", spec.Role, err)
		}
		hash, err := identifier.Hash()
		if err != nil {
			run.close()
			return nil, fmt.Errorf("chain %s: %w", spec.Role, err)
		}
		run.gatewayIDs[spec.Role] = identifier
		run.gatewayHashes[spec.Role] = hash
	}
	for _, route := range routes {
		hashes := make(map[int][32]byte, len(route))
		for hopIndex := 1; hopIndex <= len(route); hopIndex++ {
			hash, err := xir.ProfileHash(route, hopIndex)
			if err != nil {
				run.close()
				return nil, err
			}
			hashes[hopIndex] = hash
		}
		run.profileHashes[route] = hashes
	}
	return run, nil
}

// validate normalises the chain specs and the route selection and rejects a
// request that cannot produce a coherent deployment.
func validate(chains []ChainSpec, options Options) ([]ChainSpec, []string, []string, error) {
	if len(chains) < 2 || len(chains) > len(chainRoles) {
		return nil, nil, nil, fmt.Errorf(
			"deploy: a deployment needs between 2 and %d chains, got %d", len(chainRoles), len(chains),
		)
	}
	specs := make([]ChainSpec, len(chains))
	order := make([]string, len(chains))
	seenChainID := map[uint64]string{}
	seenDomain := map[uint32]string{}
	seenEID := map[uint32]string{}
	for index, spec := range chains {
		if spec.Role != chainRoles[index] {
			return nil, nil, nil, fmt.Errorf(
				"deploy: chain %d has role %q, want %q", index, spec.Role, chainRoles[index],
			)
		}
		if spec.ChainID == 0 {
			return nil, nil, nil, fmt.Errorf("deploy: chain %s has no chain id", spec.Role)
		}
		if spec.RPCEndpoint == "" {
			return nil, nil, nil, fmt.Errorf("deploy: chain %s has no RPC endpoint", spec.Role)
		}
		if other, ok := seenChainID[spec.ChainID]; ok {
			return nil, nil, nil, fmt.Errorf(
				"deploy: chains %s and %s share chain id %d", other, spec.Role, spec.ChainID,
			)
		}
		if other, ok := seenDomain[spec.HyperlaneDomain]; ok {
			return nil, nil, nil, fmt.Errorf(
				"deploy: chains %s and %s share Hyperlane domain %d",
				other, spec.Role, spec.HyperlaneDomain,
			)
		}
		if other, ok := seenEID[spec.LayerZeroEID]; ok {
			return nil, nil, nil, fmt.Errorf(
				"deploy: chains %s and %s share LayerZero eid %d",
				other, spec.Role, spec.LayerZeroEID,
			)
		}
		seenChainID[spec.ChainID] = spec.Role
		seenDomain[spec.HyperlaneDomain] = spec.Role
		seenEID[spec.LayerZeroEID] = spec.Role
		specs[index] = spec
		order[index] = spec.Role
	}
	if err := validateOptions(options); err != nil {
		return nil, nil, nil, err
	}
	routes, err := validateRoutes(options.Routes, len(specs))
	if err != nil {
		return nil, nil, nil, err
	}
	return specs, order, routes, nil
}

func validateOptions(options Options) error {
	if _, err := evm.NewSigner(options.DeployerKey, big.NewInt(1)); err != nil {
		return fmt.Errorf("deploy: invalid deployer key: %w", err)
	}
	for _, required := range []struct {
		field string
		value string
	}{
		{"artifacts root", options.ArtifactsRoot},
		{"protocol artifacts root", options.ProtocolArtifactsRoot},
		{"runtime root", options.RuntimeRoot},
		{"deployment output path", options.OutputPath},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("deploy: %s is not set", required.field)
		}
	}
	if info, err := os.Stat(options.ArtifactsRoot); err != nil || !info.IsDir() {
		return fmt.Errorf("deploy: artifacts root %s is not a directory", options.ArtifactsRoot)
	}
	for _, stack := range []string{hyperlaneProject, layerZeroProject} {
		path := filepath.Join(options.ProtocolArtifactsRoot, stack, "out")
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return fmt.Errorf("deploy: protocol artifacts %s are missing", path)
		}
	}
	if options.RootSigner == (common.Address{}) {
		return fmt.Errorf("deploy: the root signer address is not set")
	}
	if options.Runner == (common.Address{}) {
		return fmt.Errorf("deploy: the runner address is not set")
	}
	if options.Runner == options.RootSigner {
		return fmt.Errorf("deploy: the runner and the root signer must be distinct")
	}
	if options.LayerZeroWorker == (common.Address{}) {
		return fmt.Errorf("deploy: the LayerZero worker address is not set")
	}
	if options.HyperlaneValidator == (common.Address{}) {
		return fmt.Errorf("deploy: the Hyperlane validator address is not set")
	}
	return nil
}

// validateRoutes keeps only preregistered routes, drops duplicates, and
// returns them in preregistration order so the sequence is reproducible
// whatever order the caller used.
func validateRoutes(routes []string, chainCount int) ([]string, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("deploy: no routes were requested")
	}
	requested := map[string]bool{}
	for _, route := range routes {
		found := false
		for _, known := range routeOrder {
			if known == route {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("deploy: route %q is not preregistered", route)
		}
		if len(route)+1 > chainCount {
			return nil, fmt.Errorf(
				"deploy: route %q needs %d chains but only %d were given",
				route, len(route)+1, chainCount,
			)
		}
		requested[route] = true
	}
	selected := make([]string, 0, len(requested))
	for _, route := range routeOrder {
		if requested[route] {
			selected = append(selected, route)
		}
	}
	return selected, nil
}

// loadApp loads one application artifact from the XIR forge output.
func (r *deployment) loadApp(contract string) (artifacts.Artifact, error) {
	return r.loadArtifact("app:"+contract, func() (artifacts.Artifact, error) {
		return artifacts.Load(r.options.ArtifactsRoot, contract)
	})
}

// loadHyperlane loads one artifact of the Hyperlane native project. The source
// file is given explicitly because some contract names differ from their file.
func (r *deployment) loadHyperlane(sourceFile, contract string) (artifacts.Artifact, error) {
	return r.loadArtifact("hyperlane:"+sourceFile+":"+contract, func() (artifacts.Artifact, error) {
		return artifacts.LoadFrom(filepath.Join(r.options.ProtocolArtifactsRoot, hyperlaneProject, "out"), sourceFile, contract)
	})
}

// loadLayerZero loads one artifact of the LayerZero native project.
func (r *deployment) loadLayerZero(sourceFile, contract string) (artifacts.Artifact, error) {
	return r.loadArtifact("layerzero:"+sourceFile+":"+contract, func() (artifacts.Artifact, error) {
		return artifacts.LoadFrom(filepath.Join(r.options.ProtocolArtifactsRoot, layerZeroProject, "out"), sourceFile, contract)
	})
}

func (r *deployment) loadArtifact(key string, load func() (artifacts.Artifact, error)) (artifacts.Artifact, error) {
	if cached, ok := r.artifactCache[key]; ok {
		return cached.artifact, cached.err
	}
	artifact, err := load()
	if err != nil {
		err = fmt.Errorf("deploy: %w", err)
	}
	r.artifactCache[key] = artifactCacheEntry{artifact: artifact, err: err}
	return artifact, err
}

// addAction files one completed action under the phase that produced it.
func (r *deployment) addAction(phase string, record actionRecord) {
	if phase == phaseProtocol {
		r.protocolRecords = append(r.protocolRecords, record)
		return
	}
	r.appRecords = append(r.appRecords, record)
}
