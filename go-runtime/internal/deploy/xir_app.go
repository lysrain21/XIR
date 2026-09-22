package deploy

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lysrain21/XIR/go-runtime/internal/artifacts"
	"github.com/lysrain21/XIR/go-runtime/internal/xir"
)

// transitionRecorderRoles are the chains `_deploy_gateways_and_receivers`
// gives a transition recorder: the intermediate links of the A..E topology.
var transitionRecorderRoles = map[string]bool{"b": true, "c": true, "d": true}

// deployApplication reproduces `NativeMultihopDeployer.run` for the requested
// routes only: registries, gateways, receivers and transition recorders, then
// the route adapters, then the adapter and registry configuration.
//
// Route adapters are deployed per requested route, so a two-hop route needs
// four of them where the full route universe needs sixty-two, and the registry
// profiles and prior verifier bindings are written for exactly the hops that
// were deployed. Requesting every route over five chains deploys the same
// application the Python campaign deploys.
func (r *deployment) deployApplication(ctx context.Context) error {
	for _, role := range r.order {
		r.chains[role].phase = phaseApplication
	}
	if err := r.deployGatewaysAndReceivers(ctx); err != nil {
		return err
	}
	if err := r.deployRouteAdapters(ctx); err != nil {
		return err
	}
	if err := r.configureRouteAdapters(ctx); err != nil {
		return err
	}
	return r.configureRouteRegistries(ctx)
}

func (r *deployment) deployGatewaysAndReceivers(ctx context.Context) error {
	registryArtifact, err := r.loadApp("XIRRegistry")
	if err != nil {
		return err
	}
	gatewayArtifact, err := r.loadApp("XIRGateway")
	if err != nil {
		return err
	}
	receiverArtifact, err := r.loadApp("NativeMultihopReceiver")
	if err != nil {
		return err
	}
	recorderArtifact, err := r.loadApp("NativeMultihopTransitionRecorder")
	if err != nil {
		return err
	}
	for _, role := range r.order {
		chain := r.chains[role]
		registry, err := chain.deploy(ctx, "registry", registryArtifact, r.deployer)
		if err != nil {
			return err
		}
		gateway, err := chain.deploy(ctx, "gateway", gatewayArtifact, registry, r.gatewayIDs[role].ABI())
		if err != nil {
			return err
		}
		r.manifest[role]["registry"] = registry.Hex()
		r.manifest[role]["gateway"] = gateway.Hex()
		if role != r.order[0] {
			initialState := xir.Keccak256([]byte("XIR_NATIVE_MULTIHOP_INITIAL_STATE_V1:" + role))
			receiver, err := chain.deploy(ctx, "receiver", receiverArtifact, gateway, initialState)
			if err != nil {
				return err
			}
			r.manifest[role]["receiver"] = receiver.Hex()
		}
		if transitionRecorderRoles[role] {
			recorder, err := chain.deploy(
				ctx, "transition_recorder", recorderArtifact, gateway, r.options.Runner,
			)
			if err != nil {
				return err
			}
			r.manifest[role]["transition_recorder"] = recorder.Hex()
		}
	}
	return nil
}

func (r *deployment) deployRouteAdapters(ctx context.Context) error {
	hyperlaneArtifact, err := r.loadApp("HyperlaneAdapter")
	if err != nil {
		return err
	}
	layerZeroArtifact, err := r.loadApp("LayerZeroAdapter")
	if err != nil {
		return err
	}
	// The peer placeholder is the deployer address in a bytes32 word; the real
	// peer is bound by `_configure_route_adapters`.
	placeholder := bytes32Address(r.deployer)
	for _, route := range r.routes {
		for hopIndex := 1; hopIndex <= len(route); hopIndex++ {
			source := r.order[hopIndex-1]
			destination := r.order[hopIndex]
			sourceKey, err := xir.AdapterKey(route, hopIndex, "out")
			if err != nil {
				return err
			}
			destinationKey, err := xir.AdapterKey(route, hopIndex, "in")
			if err != nil {
				return err
			}
			var sourceArtifact artifacts.Artifact
			var sourceArgs, destinationArgs []any
			if route[hopIndex-1] == 'H' {
				sourceArtifact = hyperlaneArtifact
				sourceArgs = []any{
					r.stack[source].mailbox,
					r.specs[hopIndex].HyperlaneDomain,
					placeholder,
					r.deployer,
					r.options.Runner,
				}
				destinationArgs = []any{
					r.stack[destination].mailbox,
					r.specs[hopIndex-1].HyperlaneDomain,
					placeholder,
					r.deployer,
					r.options.Runner,
				}
			} else {
				sourceArtifact = layerZeroArtifact
				sourceArgs = []any{
					r.stack[source].endpointV2,
					r.specs[hopIndex].LayerZeroEID,
					placeholder,
					r.deployer,
					r.options.Runner,
				}
				destinationArgs = []any{
					r.stack[destination].endpointV2,
					r.specs[hopIndex-1].LayerZeroEID,
					placeholder,
					r.deployer,
					r.options.Runner,
				}
			}
			if address, err := r.chains[source].deploy(ctx, sourceKey, sourceArtifact, sourceArgs...); err != nil {
				return err
			} else {
				r.manifest[source][sourceKey] = address.Hex()
			}
			if address, err := r.chains[destination].deploy(
				ctx, destinationKey, sourceArtifact, destinationArgs...,
			); err != nil {
				return err
			} else {
				r.manifest[destination][destinationKey] = address.Hex()
			}
		}
	}
	return nil
}

func (r *deployment) configureRouteAdapters(ctx context.Context) error {
	hyperlaneArtifact, err := r.loadApp("HyperlaneAdapter")
	if err != nil {
		return err
	}
	layerZeroArtifact, err := r.loadApp("LayerZeroAdapter")
	if err != nil {
		return err
	}
	options, err := receiveOptions(receiveOptionsGasLimit)
	if err != nil {
		return err
	}
	for _, route := range r.routes {
		for hopIndex := 1; hopIndex <= len(route); hopIndex++ {
			source := r.order[hopIndex-1]
			destination := r.order[hopIndex]
			sourceKey, err := xir.AdapterKey(route, hopIndex, "out")
			if err != nil {
				return err
			}
			destinationKey, err := xir.AdapterKey(route, hopIndex, "in")
			if err != nil {
				return err
			}
			hyperlane := route[hopIndex-1] == 'H'
			artifact := layerZeroArtifact
			setter := "setRemotePeer"
			if hyperlane {
				artifact = hyperlaneArtifact
				setter = "setRemoteAdapter"
			}
			remoteIn := bytes32Address(common.HexToAddress(r.manifest[destination][destinationKey]))
			remoteOut := bytes32Address(common.HexToAddress(r.manifest[source][sourceKey]))
			if _, err := r.chains[source].call(
				ctx, sourceKey, common.HexToAddress(r.manifest[source][sourceKey]),
				artifact, setter, remoteIn,
			); err != nil {
				return err
			}
			if _, err := r.chains[destination].call(
				ctx, destinationKey, common.HexToAddress(r.manifest[destination][destinationKey]),
				artifact, setter, remoteOut,
			); err != nil {
				return err
			}
			if !hyperlane {
				for _, side := range []struct {
					role, key string
				}{{source, sourceKey}, {destination, destinationKey}} {
					if _, err := r.chains[side.role].call(
						ctx, side.key, common.HexToAddress(r.manifest[side.role][side.key]),
						artifact, "setEnforcedOptions", options,
					); err != nil {
						return err
					}
				}
			}
			if hopIndex > 1 {
				priorKey, err := xir.AdapterKey(route, hopIndex-1, "in")
				if err != nil {
					return err
				}
				verifier := common.HexToAddress(r.manifest[source][priorKey])
				for priorHop := 1; priorHop < hopIndex; priorHop++ {
					if _, err := r.chains[source].call(
						ctx, sourceKey, common.HexToAddress(r.manifest[source][sourceKey]),
						artifact, "setPriorVerifier", r.profileHashes[route][priorHop], verifier,
					); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// configureRouteRegistries writes the root of the source gateway into every
// other registry, and every profile of every deployed hop into the registry of
// the chain that completes it.
func (r *deployment) configureRouteRegistries(ctx context.Context) error {
	registryArtifact, err := r.loadApp("XIRRegistry")
	if err != nil {
		return err
	}
	source := r.order[0]
	for _, role := range r.order[1:] {
		if err := r.setRoot(ctx, registryArtifact, role, r.gatewayHashes[source]); err != nil {
			return err
		}
	}
	for _, route := range r.routes {
		for completed := 1; completed <= len(route); completed++ {
			role := r.order[completed]
			inboundKey, err := xir.AdapterKey(route, completed, "in")
			if err != nil {
				return err
			}
			verifier := common.HexToAddress(r.manifest[role][inboundKey])
			for receiptIndex := 1; receiptIndex <= completed; receiptIndex++ {
				if err := r.setProfile(
					ctx,
					registryArtifact,
					role,
					r.profileHashes[route][receiptIndex],
					r.gatewayHashes[r.order[receiptIndex-1]],
					r.gatewayHashes[r.order[receiptIndex]],
					verifier,
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// setRoot registers the source gateway hash as version 1 of the registry of
// one chain (`NativeMultihopDeployer._set_root`).
func (r *deployment) setRoot(
	ctx context.Context,
	artifact artifacts.Artifact,
	role string,
	gatewayHash [32]byte,
) error {
	snapshot := registryRootSnapshot{
		GatewayHash: gatewayHash,
		Signer:      r.options.RootSigner,
		ValidAfter:  0,
		ValidUntil:  0,
		Enabled:     true,
	}
	_, err := r.chains[role].call(
		ctx, "registry", common.HexToAddress(r.manifest[role]["registry"]),
		artifact, "setRoot", xir.RegistryVersion, snapshot,
	)
	return err
}

// setProfile registers one hop profile in the registry of the chain that
// completes the hop (`NativeMultihopDeployer._set_multihop_profile`).
func (r *deployment) setProfile(
	ctx context.Context,
	artifact artifacts.Artifact,
	role string,
	profileHash [32]byte,
	sourceHash [32]byte,
	destinationHash [32]byte,
	adapter common.Address,
) error {
	snapshot := registryProfileSnapshot{
		SourceHash:      sourceHash,
		DestinationHash: destinationHash,
		Adapter:         adapter,
		SecurityLevel:   1,
		ValidAfter:      0,
		ValidUntil:      0,
		Enabled:         true,
	}
	_, err := r.chains[role].call(
		ctx, "registry", common.HexToAddress(r.manifest[role]["registry"]),
		artifact, "setProfile", profileHash, snapshot,
	)
	return err
}

// bytes32Address right-aligns an address in a bytes32 word, the peer encoding
// `_deploy_route_adapters` uses for the placeholder peer.
func bytes32Address(address common.Address) [32]byte {
	var out [32]byte
	copy(out[12:], address.Bytes())
	return out
}
