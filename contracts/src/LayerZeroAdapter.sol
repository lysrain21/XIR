// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "./IXIRCarrierAdapter.sol";
import {IBaselineCarrier} from "./IBaselineCarrier.sol";
import {IBaselineCarrierReceiver} from "./IBaselineCarrier.sol";
import {OutboundControl} from "./OutboundControl.sol";
import {XIREncoding} from "./XIREncoding.sol";

struct MessagingParams {
    uint32 dstEid;
    bytes32 receiver;
    bytes message;
    bytes options;
    bool payInLzToken;
}

struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

struct MessagingReceipt {
    bytes32 guid;
    uint64 nonce;
    MessagingFee fee;
}

interface ILayerZeroEndpointV2 {
    function setDelegate(address delegate) external;

    function quote(MessagingParams calldata params, address sender) external view returns (MessagingFee memory);

    function send(MessagingParams calldata params, address refundAddress)
        external
        payable
        returns (MessagingReceipt memory);
}

contract LayerZeroAdapter is IXIRCarrierAdapter, IBaselineCarrier, OutboundControl {
    error OnlyEndpoint();
    error OnlyPeer();
    error InvalidBundle();
    error InvalidPeer();
    error UnapprovedPriorVerifier(uint256 index);
    error UnverifiedPriorEvidence(uint256 index);
    error UnknownMessageKind();
    error UnknownBaselineRoute();
    error OptionsNotConfigured();
    error OptionsMismatch();

    struct Origin {
        uint32 srcEid;
        bytes32 sender;
        uint64 nonce;
    }

    struct DeliveryBundle {
        bytes32 profileHash;
        bytes32 transitionHash;
        bytes32[] priorProfiles;
        bytes32[] priorEvidence;
        bytes32[] priorTransitions;
    }

    struct ForwardRequest {
        address[] verifiers;
        bytes32[] profileHashes;
        bytes32[] evidenceHashes;
        bytes32[] transitionHashes;
        bytes32 currentProfileHash;
        bytes32 currentTransitionHash;
        bytes options;
    }

    address public immutable endpoint;
    uint32 public immutable remoteEid;
    bytes32 public remotePeer;
    bytes32 public enforcedOptionsHash;
    mapping(bytes32 => bool) public acceptedEvidence;
    mapping(bytes32 => bool) public acceptedBundles;
    mapping(bytes32 => address) public approvedPriorVerifiers;
    mapping(bytes32 => address) public baselineReceivers;

    uint8 private constant KIND_XIR = 1;
    uint8 private constant KIND_BASELINE = 2;

    event LayerZeroEvidence(
        bytes32 indexed guid,
        bytes32 indexed profileHash,
        bytes32 indexed transitionHash,
        uint32 srcEid,
        uint64 nonce,
        address executor
    );

    event PriorEvidenceCarried(
        bytes32 indexed guid, bytes32 indexed profileHash, bytes32 indexed evidenceHash, bytes32 transitionHash
    );
    event EvidenceBundleAccepted(bytes32 indexed bundleCommitment, uint256 receiptCount);
    event PriorVerifierSet(bytes32 indexed profileHash, address indexed verifier);
    event RemotePeerSet(bytes32 indexed remotePeer);
    event VerifiedEvidenceForwarded(bytes32 indexed guid, uint64 indexed nonce, uint256 nativeFee);
    event BaselineDispatched(bytes32 indexed guid, uint64 indexed nonce, uint256 nativeFee);
    event BaselineReceiverSet(bytes32 indexed routeId, address indexed receiver);
    event EnforcedOptionsSet(bytes32 indexed optionsHash);

    constructor(address endpoint_, uint32 remoteEid_, bytes32 remotePeer_, address administrator_, address runner_)
        OutboundControl(administrator_, runner_)
    {
        if (endpoint_ == address(0) || remotePeer_ == bytes32(0)) revert InvalidPeer();
        endpoint = endpoint_;
        remoteEid = remoteEid_;
        remotePeer = remotePeer_;
        ILayerZeroEndpointV2(endpoint_).setDelegate(administrator_);
    }

    function setRemotePeer(bytes32 remotePeer_) external onlyAdministrator {
        if (remotePeer_ == bytes32(0)) revert InvalidPeer();
        remotePeer = remotePeer_;
        emit RemotePeerSet(remotePeer_);
    }

    function setEnforcedOptions(bytes calldata options) external onlyAdministrator {
        enforcedOptionsHash = keccak256(options);
        emit EnforcedOptionsSet(enforcedOptionsHash);
    }

    function setBaselineReceiver(bytes32 routeId, address receiver) external onlyAdministrator {
        if (routeId == bytes32(0) || receiver == address(0)) revert InvalidPeer();
        baselineReceivers[routeId] = receiver;
        emit BaselineReceiverSet(routeId, receiver);
    }

    /// @notice Binds a prior-hop profile to the inbound adapter authorized to
    /// attest that profile. Setting `verifier` to zero revokes the binding.
    function setPriorVerifier(bytes32 profileHash, address verifier) external onlyAdministrator {
        if (profileHash == bytes32(0)) revert InvalidBundle();
        approvedPriorVerifiers[profileHash] = verifier;
        emit PriorVerifierSet(profileHash, verifier);
    }

    function quoteForward(ForwardRequest calldata request) external view returns (MessagingFee memory) {
        _checkBundle(request);
        _checkPriorVerifierBindings(request);
        _checkOptions(request.options);
        return ILayerZeroEndpointV2(endpoint).quote(_params(request), address(this));
    }

    function quoteBaseline(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        view
        returns (uint256)
    {
        _checkOptions(options);
        return ILayerZeroEndpointV2(endpoint).quote(_rawParams(routeId, message, options), address(this)).nativeFee;
    }

    /// @notice Carries evidence already authenticated on this chain to the next gateway.
    /// The destination Endpoint authenticates this adapter as the configured remote peer.
    function sendSource(ForwardRequest calldata request)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (MessagingReceipt memory receipt)
    {
        return _forwardVerified(request);
    }

    function forwardInFlight(ForwardRequest calldata request)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (MessagingReceipt memory receipt)
    {
        return _forwardVerified(request);
    }

    function _forwardVerified(ForwardRequest calldata request) private returns (MessagingReceipt memory receipt) {
        _checkBundle(request);
        _checkPriorVerifierBindings(request);
        _checkOptions(request.options);
        for (uint256 i = 0; i < request.verifiers.length; i++) {
            address approvedVerifier = approvedPriorVerifiers[request.profileHashes[i]];
            if (!IXIRCarrierAdapter(approvedVerifier)
                    .verify(request.profileHashes[i], request.evidenceHashes[i], request.transitionHashes[i])) revert UnverifiedPriorEvidence(i);
        }
        receipt = ILayerZeroEndpointV2(endpoint).send{value: msg.value}(_params(request), runner);
        emit VerifiedEvidenceForwarded(receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

    function sendBaselineSource(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        return _sendBaseline(routeId, message, options);
    }

    function forwardBaseline(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        return _sendBaseline(routeId, message, options);
    }

    function _sendBaseline(bytes32 routeId, bytes calldata message, bytes calldata options) private returns (bytes32) {
        _checkOptions(options);
        MessagingReceipt memory receipt =
            ILayerZeroEndpointV2(endpoint).send{value: msg.value}(_rawParams(routeId, message, options), runner);
        emit BaselineDispatched(receipt.guid, receipt.nonce, receipt.fee.nativeFee);
        return receipt.guid;
    }

    function lzReceive(Origin calldata origin, bytes32 guid, bytes calldata message, address executor, bytes calldata)
        external
        payable
    {
        if (msg.sender != endpoint) revert OnlyEndpoint();
        if (remotePeer == bytes32(0) || origin.srcEid != remoteEid || origin.sender != remotePeer) {
            revert OnlyPeer();
        }
        (uint8 kind, bytes memory body) = abi.decode(message, (uint8, bytes));
        if (kind == KIND_BASELINE) {
            (bytes32 routeId, bytes memory payload) = abi.decode(body, (bytes32, bytes));
            address receiver = baselineReceivers[routeId];
            if (receiver == address(0)) revert UnknownBaselineRoute();
            IBaselineCarrierReceiver(receiver).baselineCarrierReceive(guid, payload);
            return;
        }
        if (kind != KIND_XIR) revert UnknownMessageKind();
        DeliveryBundle memory bundle = abi.decode(body, (DeliveryBundle));
        if (
            bundle.priorProfiles.length != bundle.priorEvidence.length
                || bundle.priorProfiles.length != bundle.priorTransitions.length
        ) revert InvalidBundle();
        bytes32 bundleCommitment = XIREncoding.bundleStart(bundle.priorProfiles.length + 1);
        acceptedEvidence[keccak256(abi.encode(bundle.profileHash, guid, bundle.transitionHash))] = true;
        emit LayerZeroEvidence(guid, bundle.profileHash, bundle.transitionHash, origin.srcEid, origin.nonce, executor);
        for (uint256 i = 0; i < bundle.priorProfiles.length; i++) {
            bundleCommitment = XIREncoding.bundleStep(
                bundleCommitment, i, bundle.priorProfiles[i], bundle.priorEvidence[i], bundle.priorTransitions[i]
            );
            acceptedEvidence[
                keccak256(abi.encode(bundle.priorProfiles[i], bundle.priorEvidence[i], bundle.priorTransitions[i]))
            ] = true;
            emit PriorEvidenceCarried(
                guid, bundle.priorProfiles[i], bundle.priorEvidence[i], bundle.priorTransitions[i]
            );
        }
        bundleCommitment = XIREncoding.bundleStep(
            bundleCommitment, bundle.priorProfiles.length, bundle.profileHash, guid, bundle.transitionHash
        );
        acceptedBundles[bundleCommitment] = true;
        emit EvidenceBundleAccepted(bundleCommitment, bundle.priorProfiles.length + 1);
    }

    /// @notice LayerZero Endpoint path-initialization hook.
    function allowInitializePath(Origin calldata origin) external view returns (bool) {
        return remotePeer != bytes32(0) && origin.srcEid == remoteEid && origin.sender == remotePeer;
    }

    /// @notice Returning zero selects LayerZero's default unordered delivery mode.
    function nextNonce(uint32, bytes32) external pure returns (uint64) {
        return 0;
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash) external view returns (bool) {
        return acceptedEvidence[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))];
    }

    function verifyBundle(bytes32 bundleCommitment) external view returns (bool) {
        return acceptedBundles[bundleCommitment];
    }

    function _params(ForwardRequest calldata request) private view returns (MessagingParams memory) {
        if (remotePeer == bytes32(0)) revert InvalidPeer();
        return MessagingParams({
            dstEid: remoteEid,
            receiver: remotePeer,
            message: abi.encode(
                KIND_XIR,
                abi.encode(
                    DeliveryBundle({
                        profileHash: request.currentProfileHash,
                        transitionHash: request.currentTransitionHash,
                        priorProfiles: request.profileHashes,
                        priorEvidence: request.evidenceHashes,
                        priorTransitions: request.transitionHashes
                    })
                )
            ),
            options: request.options,
            payInLzToken: false
        });
    }

    function _rawParams(bytes32 routeId, bytes calldata message, bytes calldata options)
        private
        view
        returns (MessagingParams memory)
    {
        if (remotePeer == bytes32(0)) revert InvalidPeer();
        return MessagingParams({
            dstEid: remoteEid,
            receiver: remotePeer,
            message: abi.encode(KIND_BASELINE, abi.encode(routeId, message)),
            options: options,
            payInLzToken: false
        });
    }

    function _checkBundle(ForwardRequest calldata request) private pure {
        if (
            request.verifiers.length != request.profileHashes.length
                || request.verifiers.length != request.evidenceHashes.length
                || request.verifiers.length != request.transitionHashes.length
        ) revert InvalidBundle();
    }

    function _checkPriorVerifierBindings(ForwardRequest calldata request) private view {
        for (uint256 i = 0; i < request.verifiers.length; i++) {
            address approvedVerifier = approvedPriorVerifiers[request.profileHashes[i]];
            if (approvedVerifier == address(0) || request.verifiers[i] != approvedVerifier) {
                revert UnapprovedPriorVerifier(i);
            }
        }
    }

    function _checkOptions(bytes calldata options) private view {
        if (enforcedOptionsHash == bytes32(0)) revert OptionsNotConfigured();
        if (keccak256(options) != enforcedOptionsHash) revert OptionsMismatch();
    }
}
