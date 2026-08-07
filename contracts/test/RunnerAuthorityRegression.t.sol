// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter, IHyperlaneMailbox} from "../src/HyperlaneAdapter.sol";
import {
    ILayerZeroEndpointV2,
    LayerZeroAdapter,
    MessagingFee,
    MessagingParams,
    MessagingReceipt
} from "../src/LayerZeroAdapter.sol";
import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";

contract AlwaysTruePriorVerifier is IXIRCarrierAdapter {
    function verify(bytes32, bytes32, bytes32) external pure returns (bool) {
        return true;
    }

    function verifyBundle(bytes32) external pure returns (bool) {
        return true;
    }
}

/// @dev Reproduces the pre-fix predicate in isolation for regression history.
contract LegacyRunnerSelectedVerifierPredicate {
    function accepts(address verifier, bytes32 profile, bytes32 evidence, bytes32 transition)
        external
        view
        returns (bool)
    {
        return verifier != address(0) && IXIRCarrierAdapter(verifier).verify(profile, evidence, transition);
    }
}

contract AuthorityHyperlaneMailbox is IHyperlaneMailbox {
    uint256 public dispatchCount;

    function dispatch(uint32, bytes32, bytes calldata) external payable returns (bytes32 messageId) {
        dispatchCount++;
        return keccak256(abi.encode(dispatchCount));
    }

    function quoteDispatch(uint32, bytes32, bytes calldata) external pure returns (uint256) {
        return 0;
    }

    function deliver(HyperlaneAdapter adapter, uint32 origin, bytes32 sender, bytes calldata body) external {
        adapter.handle(origin, sender, body);
    }
}

contract AuthorityLayerZeroEndpoint is ILayerZeroEndpointV2 {
    uint64 public sendCount;

    function setDelegate(address) external {}

    function quote(MessagingParams calldata, address) external pure returns (MessagingFee memory) {
        return MessagingFee({nativeFee: 0, lzTokenFee: 0});
    }

    function send(MessagingParams calldata, address) external payable returns (MessagingReceipt memory) {
        sendCount++;
        return MessagingReceipt({
            guid: keccak256(abi.encode(sendCount)), nonce: sendCount, fee: MessagingFee({nativeFee: 0, lzTokenFee: 0})
        });
    }

    function deliver(
        LayerZeroAdapter adapter,
        LayerZeroAdapter.Origin calldata origin,
        bytes32 guid,
        bytes calldata message
    ) external {
        adapter.lzReceive(origin, guid, message, address(this), bytes(""));
    }
}

contract AuthorityRunner {
    function sendHyperlane(HyperlaneAdapter adapter, HyperlaneAdapter.ForwardRequest calldata request) external {
        adapter.sendSourceBundle(request);
    }

    function sendLayerZero(LayerZeroAdapter adapter, LayerZeroAdapter.ForwardRequest calldata request) external {
        adapter.sendSource(request);
    }

    function setHyperlanePriorVerifier(HyperlaneAdapter adapter, bytes32 profile, address verifier) external {
        adapter.setPriorVerifier(profile, verifier);
    }

    function setLayerZeroPriorVerifier(LayerZeroAdapter adapter, bytes32 profile, address verifier) external {
        adapter.setPriorVerifier(profile, verifier);
    }
}

contract RunnerAuthorityRegressionTest {
    bytes32 private constant H_AB = keccak256("native-hyperlane-ab-v1");
    bytes32 private constant L_AB = keccak256("native-layerzero-ab-v1");
    bytes32 private constant EVIDENCE = keccak256("accepted-first-hop");
    bytes32 private constant TRANSITION = keccak256("source-to-intermediate");
    bytes32 private constant CURRENT_PROFILE = keccak256("intermediate-to-destination");
    bytes32 private constant CURRENT_TRANSITION = keccak256("intermediate-to-destination-transition");

    AuthorityRunner private runner;
    AlwaysTruePriorVerifier private fakeVerifier;
    AuthorityHyperlaneMailbox private mailbox;
    AuthorityLayerZeroEndpoint private endpoint;
    HyperlaneAdapter private hyperlaneOut;
    LayerZeroAdapter private layerZeroOut;
    HyperlaneAdapter private hyperlaneIn;
    LayerZeroAdapter private layerZeroIn;

    function setUp() public {
        runner = new AuthorityRunner();
        fakeVerifier = new AlwaysTruePriorVerifier();
        mailbox = new AuthorityHyperlaneMailbox();
        endpoint = new AuthorityLayerZeroEndpoint();
        hyperlaneOut =
            new HyperlaneAdapter(address(mailbox), 31337, bytes32(uint256(0xBEEF)), address(this), address(runner));
        layerZeroOut =
            new LayerZeroAdapter(address(endpoint), 40101, bytes32(uint256(0xCAFE)), address(this), address(runner));
        hyperlaneIn =
            new HyperlaneAdapter(address(mailbox), 31337, bytes32(uint256(0xBEEF)), address(this), address(runner));
        layerZeroIn =
            new LayerZeroAdapter(address(endpoint), 40101, bytes32(uint256(0xCAFE)), address(this), address(runner));
        layerZeroOut.setEnforcedOptions(bytes("options"));
        layerZeroIn.setEnforcedOptions(bytes("options"));
        layerZeroOut.setPriorVerifier(H_AB, address(hyperlaneIn));
        hyperlaneOut.setPriorVerifier(L_AB, address(layerZeroIn));
        _acceptHyperlane(H_AB);
        _acceptHyperlane(L_AB);
        _acceptLayerZero(H_AB);
        _acceptLayerZero(L_AB);
    }

    function testLegacyPredicateAcceptedRunnerSelectedVerifier() public {
        LegacyRunnerSelectedVerifierPredicate legacy = new LegacyRunnerSelectedVerifierPredicate();
        require(
            legacy.accepts(address(fakeVerifier), H_AB, EVIDENCE, TRANSITION), "legacy predicate no longer reproduced"
        );
    }

    function testHLRejectsFakeVerifierAndWrongInboundEndpoint() public {
        _expectLayerZeroConfigurationError(address(fakeVerifier));
        _expectLayerZeroConfigurationError(address(layerZeroIn));
        runner.sendLayerZero(layerZeroOut, _layerZeroRequest(H_AB, address(hyperlaneIn)));
        require(endpoint.sendCount() == 1, "approved HL verifier did not dispatch");
    }

    function testLHRejectsFakeVerifierAndWrongInboundEndpoint() public {
        _expectHyperlaneConfigurationError(address(fakeVerifier));
        _expectHyperlaneConfigurationError(address(hyperlaneIn));
        runner.sendHyperlane(hyperlaneOut, _hyperlaneRequest(L_AB, address(layerZeroIn)));
        require(mailbox.dispatchCount() == 1, "approved LH verifier did not dispatch");
    }

    function testOnlyAdministratorCanChangePriorVerifierBinding() public {
        try runner.setLayerZeroPriorVerifier(layerZeroOut, H_AB, address(fakeVerifier)) {
            revert("runner changed LayerZero prior verifier");
        } catch {}
        try runner.setHyperlanePriorVerifier(hyperlaneOut, L_AB, address(fakeVerifier)) {
            revert("runner changed Hyperlane prior verifier");
        } catch {}
        require(layerZeroOut.approvedPriorVerifiers(H_AB) == address(hyperlaneIn), "HL binding changed");
        require(hyperlaneOut.approvedPriorVerifiers(L_AB) == address(layerZeroIn), "LH binding changed");
    }

    function _expectLayerZeroConfigurationError(address supplied) private {
        LayerZeroAdapter.ForwardRequest memory request = _layerZeroRequest(H_AB, supplied);
        try layerZeroOut.quoteForward(request) {
            revert("HL quote accepted an unapproved verifier");
        } catch (bytes memory reason) {
            require(_selector(reason) == LayerZeroAdapter.UnapprovedPriorVerifier.selector, "wrong HL quote error");
        }
        try runner.sendLayerZero(layerZeroOut, request) {
            revert("HL accepted an unapproved verifier");
        } catch (bytes memory reason) {
            require(_selector(reason) == LayerZeroAdapter.UnapprovedPriorVerifier.selector, "wrong HL error");
        }
        require(endpoint.sendCount() == 0, "rejected HL request dispatched");
    }

    function _expectHyperlaneConfigurationError(address supplied) private {
        HyperlaneAdapter.ForwardRequest memory request = _hyperlaneRequest(L_AB, supplied);
        try hyperlaneOut.quoteBundle(request) {
            revert("LH quote accepted an unapproved verifier");
        } catch (bytes memory reason) {
            require(_selector(reason) == HyperlaneAdapter.UnapprovedPriorVerifier.selector, "wrong LH quote error");
        }
        try runner.sendHyperlane(hyperlaneOut, request) {
            revert("LH accepted an unapproved verifier");
        } catch (bytes memory reason) {
            require(_selector(reason) == HyperlaneAdapter.UnapprovedPriorVerifier.selector, "wrong LH error");
        }
        require(mailbox.dispatchCount() == 0, "rejected LH request dispatched");
    }

    function _acceptHyperlane(bytes32 profile) private {
        mailbox.deliver(
            hyperlaneIn,
            31337,
            bytes32(uint256(0xBEEF)),
            abi.encode(uint8(1), abi.encode(profile, TRANSITION, EVIDENCE))
        );
        require(hyperlaneIn.verify(profile, EVIDENCE, TRANSITION), "Hyperlane fixture missing");
    }

    function _acceptLayerZero(bytes32 profile) private {
        bytes32[] memory empty = new bytes32[](0);
        LayerZeroAdapter.DeliveryBundle memory bundle = LayerZeroAdapter.DeliveryBundle({
            profileHash: profile,
            transitionHash: TRANSITION,
            priorProfiles: empty,
            priorEvidence: empty,
            priorTransitions: empty
        });
        endpoint.deliver(
            layerZeroIn,
            LayerZeroAdapter.Origin({srcEid: 40101, sender: bytes32(uint256(0xCAFE)), nonce: 1}),
            EVIDENCE,
            abi.encode(uint8(1), abi.encode(bundle))
        );
        require(layerZeroIn.verify(profile, EVIDENCE, TRANSITION), "LayerZero fixture missing");
    }

    function _layerZeroRequest(bytes32 profile, address verifier)
        private
        pure
        returns (LayerZeroAdapter.ForwardRequest memory request)
    {
        request.verifiers = _addresses(verifier);
        request.profileHashes = _bytes32s(profile);
        request.evidenceHashes = _bytes32s(EVIDENCE);
        request.transitionHashes = _bytes32s(TRANSITION);
        request.currentProfileHash = CURRENT_PROFILE;
        request.currentTransitionHash = CURRENT_TRANSITION;
        request.options = bytes("options");
    }

    function _hyperlaneRequest(bytes32 profile, address verifier)
        private
        pure
        returns (HyperlaneAdapter.ForwardRequest memory request)
    {
        request.verifiers = _addresses(verifier);
        request.profileHashes = _bytes32s(profile);
        request.evidenceHashes = _bytes32s(EVIDENCE);
        request.transitionHashes = _bytes32s(TRANSITION);
        request.currentProfileHash = CURRENT_PROFILE;
        request.currentTransitionHash = CURRENT_TRANSITION;
    }

    function _addresses(address value) private pure returns (address[] memory values) {
        values = new address[](1);
        values[0] = value;
    }

    function _bytes32s(bytes32 value) private pure returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = value;
    }

    function _selector(bytes memory reason) private pure returns (bytes4 result) {
        if (reason.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            result := mload(add(reason, 32))
        }
    }
}
