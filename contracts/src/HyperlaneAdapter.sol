// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "./IXIRCarrierAdapter.sol";
import {IBaselineCarrier} from "./IBaselineCarrier.sol";
import {IBaselineCarrierReceiver} from "./IBaselineCarrier.sol";
import {OutboundControl} from "./OutboundControl.sol";

interface IHyperlaneMailbox {
    function dispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        payable
        returns (bytes32 messageId);

    function quoteDispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        view
        returns (uint256 fee);
}

contract HyperlaneAdapter is IXIRCarrierAdapter, IBaselineCarrier, OutboundControl {
    error OnlyMailbox();
    error OnlyRemote();
    error InvalidEvidence();
    error InvalidPeer();
    error UnsupportedOptions();
    error UnknownMessageKind();
    error UnknownBaselineRoute();
    error InvalidBundle();
    error UnverifiedPriorEvidence(uint256 index);

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
    }

    address public immutable mailbox;
    uint32 public immutable remoteDomain;
    bytes32 public remoteAdapter;
    mapping(bytes32 => bool) public acceptedEvidence;
    mapping(bytes32 => address) public baselineReceivers;

    uint8 private constant KIND_XIR = 1;
    uint8 private constant KIND_BASELINE = 2;
    uint8 private constant KIND_XIR_BUNDLE = 3;

    event HyperlaneEvidence(
        bytes32 indexed evidenceHash,
        bytes32 indexed profileHash,
        bytes32 indexed transitionHash,
        uint32 origin,
        bytes32 sender
    );
    event RemoteAdapterSet(bytes32 indexed remoteAdapter);
    event HyperlaneDispatched(
        bytes32 indexed messageId,
        uint32 indexed destination,
        bytes32 indexed recipient,
        uint256 fee
    );
    event BaselineReceiverSet(bytes32 indexed routeId, address indexed receiver);
    event PriorEvidenceCarried(
        bytes32 indexed messageId,
        bytes32 indexed profileHash,
        bytes32 indexed evidenceHash,
        bytes32 transitionHash
    );

    constructor(
        address mailbox_,
        uint32 remoteDomain_,
        bytes32 remoteAdapter_,
        address administrator_,
        address runner_
    ) OutboundControl(administrator_, runner_) {
        if (mailbox_ == address(0) || remoteAdapter_ == bytes32(0)) revert InvalidPeer();
        mailbox = mailbox_;
        remoteDomain = remoteDomain_;
        remoteAdapter = remoteAdapter_;
    }

    function setRemoteAdapter(bytes32 remoteAdapter_) external onlyAdministrator {
        if (remoteAdapter_ == bytes32(0)) revert InvalidPeer();
        remoteAdapter = remoteAdapter_;
        emit RemoteAdapterSet(remoteAdapter_);
    }

    function setBaselineReceiver(bytes32 routeId, address receiver) external onlyAdministrator {
        if (routeId == bytes32(0) || receiver == address(0)) revert InvalidPeer();
        baselineReceivers[routeId] = receiver;
        emit BaselineReceiverSet(routeId, receiver);
    }

    function quote(bytes calldata body) external view returns (uint256) {
        return IHyperlaneMailbox(mailbox).quoteDispatch(
            remoteDomain, remoteAdapter, abi.encode(KIND_XIR, body)
        );
    }

    function quoteBaseline(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        view
        returns (uint256)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return IHyperlaneMailbox(mailbox).quoteDispatch(
            remoteDomain,
            remoteAdapter,
            abi.encode(KIND_BASELINE, abi.encode(routeId, message))
        );
    }

    function sendSource(bytes calldata body)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        return _dispatch(abi.encode(KIND_XIR, body));
    }

    function forwardInFlight(bytes calldata body)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        return _dispatch(abi.encode(KIND_XIR, body));
    }

    function sendSourceBundle(ForwardRequest calldata request)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        return _forwardVerified(request);
    }

    function forwardInFlightBundle(ForwardRequest calldata request)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        return _forwardVerified(request);
    }

    function quoteBundle(ForwardRequest calldata request) external view returns (uint256) {
        _checkBundle(request);
        return IHyperlaneMailbox(mailbox).quoteDispatch(
            remoteDomain, remoteAdapter, _bundleBody(request)
        );
    }

    function _forwardVerified(ForwardRequest calldata request) private returns (bytes32) {
        _checkBundle(request);
        for (uint256 i = 0; i < request.verifiers.length; i++) {
            if (
                request.verifiers[i] == address(0)
                    || !IXIRCarrierAdapter(request.verifiers[i])
                        .verify(
                            request.profileHashes[i],
                            request.evidenceHashes[i],
                            request.transitionHashes[i]
                        )
            ) revert UnverifiedPriorEvidence(i);
        }
        return _dispatch(_bundleBody(request));
    }

    function sendBaselineSource(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata options
    )
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return _dispatch(abi.encode(KIND_BASELINE, abi.encode(routeId, message)));
    }

    function forwardBaseline(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata options
    )
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return _dispatch(abi.encode(KIND_BASELINE, abi.encode(routeId, message)));
    }

    function _dispatch(bytes memory body) private returns (bytes32) {
        bytes32 messageId =
            IHyperlaneMailbox(mailbox).dispatch{value: msg.value}(remoteDomain, remoteAdapter, body);
        emit HyperlaneDispatched(messageId, remoteDomain, remoteAdapter, msg.value);
        return messageId;
    }

    function handle(uint32 origin, bytes32 sender, bytes calldata body) external payable {
        if (msg.sender != mailbox) revert OnlyMailbox();
        if (remoteAdapter == bytes32(0) || origin != remoteDomain || sender != remoteAdapter) {
            revert OnlyRemote();
        }
        (uint8 kind, bytes memory message) = abi.decode(body, (uint8, bytes));
        if (kind == KIND_BASELINE) {
            (bytes32 routeId, bytes memory payload) = abi.decode(message, (bytes32, bytes));
            address receiver = baselineReceivers[routeId];
            if (receiver == address(0)) revert UnknownBaselineRoute();
            bytes32 messageId = keccak256(abi.encode(origin, sender, body));
            IBaselineCarrierReceiver(receiver).baselineCarrierReceive(messageId, payload);
            return;
        }
        if (kind == KIND_XIR_BUNDLE) {
            DeliveryBundle memory bundle = abi.decode(message, (DeliveryBundle));
            if (
                bundle.priorProfiles.length != bundle.priorEvidence.length
                    || bundle.priorProfiles.length != bundle.priorTransitions.length
            ) revert InvalidBundle();
            bytes32 messageId = keccak256(abi.encode(origin, sender, body));
            acceptedEvidence[
                keccak256(
                    abi.encode(
                        bundle.profileHash,
                        messageId,
                        bundle.transitionHash
                    )
                )
            ] = true;
            emit HyperlaneEvidence(
                messageId,
                bundle.profileHash,
                bundle.transitionHash,
                origin,
                sender
            );
            for (uint256 i = 0; i < bundle.priorProfiles.length; i++) {
                acceptedEvidence[
                    keccak256(
                        abi.encode(
                            bundle.priorProfiles[i],
                            bundle.priorEvidence[i],
                            bundle.priorTransitions[i]
                        )
                    )
                ] = true;
                emit PriorEvidenceCarried(
                    messageId,
                    bundle.priorProfiles[i],
                    bundle.priorEvidence[i],
                    bundle.priorTransitions[i]
                );
            }
            return;
        }
        if (kind != KIND_XIR) revert UnknownMessageKind();
        (bytes32 profileHash, bytes32 transitionHash, bytes32 evidenceHash) =
            abi.decode(message, (bytes32, bytes32, bytes32));
        if (evidenceHash == bytes32(0)) revert InvalidEvidence();
        acceptedEvidence[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))] = true;
        emit HyperlaneEvidence(evidenceHash, profileHash, transitionHash, origin, sender);
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash)
        external
        view
        returns (bool)
    {
        return acceptedEvidence[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))];
    }

    function _checkBundle(ForwardRequest calldata request) private pure {
        if (
            request.verifiers.length != request.profileHashes.length
                || request.verifiers.length != request.evidenceHashes.length
                || request.verifiers.length != request.transitionHashes.length
        ) revert InvalidBundle();
    }

    function _bundleBody(ForwardRequest calldata request)
        private
        pure
        returns (bytes memory)
    {
        return abi.encode(
            KIND_XIR_BUNDLE,
            abi.encode(
                DeliveryBundle({
                    profileHash: request.currentProfileHash,
                    transitionHash: request.currentTransitionHash,
                    priorProfiles: request.profileHashes,
                    priorEvidence: request.evidenceHashes,
                    priorTransitions: request.transitionHashes
                })
            )
        );
    }
}
