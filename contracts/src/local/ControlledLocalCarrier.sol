// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrier, IBaselineCarrierReceiver} from "../IBaselineCarrier.sol";
import {IXIRCarrierAdapter} from "../IXIRCarrierAdapter.sol";

/// @notice Controlled local delivery fixture. It is outside every public route.
contract ControlledLocalCarrier is IBaselineCarrier, IXIRCarrierAdapter {
    error WrongChain();
    error OnlyAdministrator();
    error OnlyOutbound();
    error OnlyRelayer();
    error WrongPeer();
    error Unavailable();
    error DuplicateDelivery();
    error ConfigurationAlreadySet();
    error UnknownRoute();

    enum Protocol {
        Hyperlane,
        LayerZeroV2
    }

    uint256 public immutable localChainId;
    uint256 public immutable remoteChainId;
    Protocol public immutable protocol;
    address public immutable administrator;
    address public immutable relayer;
    address public peer;
    address public outbound;
    bool public available = true;
    uint64 public dispatchCount;

    mapping(bytes32 => address) public baselineReceiver;
    mapping(bytes32 => bool) public delivered;
    mapping(bytes32 => bool) private acceptedEvidence;

    event LocalDispatch(
        bytes32 indexed messageId,
        Protocol indexed protocol,
        uint256 indexed remoteChainId,
        bytes32 routeOrProfile,
        bytes32 payloadOrTransitionHash
    );
    event LocalDelivery(
        bytes32 indexed messageId,
        Protocol indexed protocol,
        address indexed sourceCarrier,
        bytes32 evidenceHash
    );
    event AvailabilityChanged(bool available);

    constructor(
        uint256 localChainId_,
        uint256 remoteChainId_,
        Protocol protocol_,
        address administrator_,
        address relayer_
    ) {
        localChainId = localChainId_;
        remoteChainId = remoteChainId_;
        protocol = protocol_;
        administrator = administrator_;
        relayer = relayer_;
    }

    modifier onLocalChain() {
        if (block.chainid != localChainId) revert WrongChain();
        _;
    }

    modifier onlyAdministrator() {
        if (msg.sender != administrator) revert OnlyAdministrator();
        _;
    }

    modifier whenAvailable() {
        if (!available) revert Unavailable();
        _;
    }

    function setPeer(address peer_) external onlyAdministrator {
        if (peer != address(0) || peer_ == address(0)) revert ConfigurationAlreadySet();
        peer = peer_;
    }

    function setOutbound(address outbound_) external onlyAdministrator {
        if (outbound != address(0) || outbound_ == address(0)) {
            revert ConfigurationAlreadySet();
        }
        outbound = outbound_;
    }

    function setBaselineReceiver(bytes32 routeId, address receiver)
        external
        onlyAdministrator
    {
        if (baselineReceiver[routeId] != address(0) || receiver == address(0)) {
            revert ConfigurationAlreadySet();
        }
        baselineReceiver[routeId] = receiver;
    }

    function setAvailable(bool available_) external onlyAdministrator {
        available = available_;
        emit AvailabilityChanged(available_);
    }

    function quoteBaseline(bytes32, bytes calldata, bytes calldata)
        external
        pure
        returns (uint256 nativeFee)
    {
        return 0;
    }

    function sendBaselineSource(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata
    ) external payable returns (bytes32 protocolMessageId) {
        return _dispatch(routeId, keccak256(message));
    }

    function forwardBaseline(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata
    ) external payable returns (bytes32 protocolMessageId) {
        return _dispatch(routeId, keccak256(message));
    }

    function dispatchEvidence(
        bytes32 profileHash,
        bytes32 evidenceHash,
        bytes32 transitionHash
    ) external returns (bytes32 protocolMessageId) {
        protocolMessageId = _dispatch(profileHash, transitionHash);
        emit LocalDelivery(protocolMessageId, protocol, address(this), evidenceHash);
    }

    function receiveBaseline(
        address sourceCarrier,
        bytes32 messageId,
        bytes32 routeId,
        bytes calldata payload
    ) external onLocalChain whenAvailable {
        _authenticateDelivery(sourceCarrier, messageId);
        address receiver = baselineReceiver[routeId];
        if (receiver == address(0)) revert UnknownRoute();
        IBaselineCarrierReceiver(receiver).baselineCarrierReceive(messageId, payload);
        emit LocalDelivery(messageId, protocol, sourceCarrier, bytes32(0));
    }

    function receiveEvidence(
        address sourceCarrier,
        bytes32 messageId,
        bytes32 profileHash,
        bytes32 evidenceHash,
        bytes32 transitionHash
    ) external onLocalChain whenAvailable {
        _authenticateDelivery(sourceCarrier, messageId);
        acceptedEvidence[
            keccak256(abi.encode(profileHash, evidenceHash, transitionHash))
        ] = true;
        emit LocalDelivery(messageId, protocol, sourceCarrier, evidenceHash);
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash)
        external
        view
        returns (bool)
    {
        return acceptedEvidence[
            keccak256(abi.encode(profileHash, evidenceHash, transitionHash))
        ];
    }

    function _dispatch(bytes32 routeOrProfile, bytes32 payloadOrTransitionHash)
        private
        onLocalChain
        whenAvailable
        returns (bytes32 messageId)
    {
        if (msg.sender != outbound) revert OnlyOutbound();
        dispatchCount++;
        messageId = keccak256(
            abi.encode(
                protocol,
                localChainId,
                remoteChainId,
                dispatchCount,
                routeOrProfile,
                payloadOrTransitionHash
            )
        );
        emit LocalDispatch(
            messageId,
            protocol,
            remoteChainId,
            routeOrProfile,
            payloadOrTransitionHash
        );
    }

    function _authenticateDelivery(address sourceCarrier, bytes32 messageId) private {
        if (msg.sender != relayer) revert OnlyRelayer();
        if (sourceCarrier != peer) revert WrongPeer();
        if (delivered[messageId]) revert DuplicateDelivery();
        delivered[messageId] = true;
    }
}
