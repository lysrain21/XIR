// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrier} from "./IBaselineCarrier.sol";
import {IBaselineCarrierReceiver} from "./IBaselineCarrier.sol";
import {OutboundControl} from "./OutboundControl.sol";

interface IBaselineEffectReceiver {
    function baselineReceive(bytes32 messageId, bytes calldata payload) external;
}

contract BaselineRouteControl is OutboundControl, IBaselineCarrierReceiver {
    error OnlyFirstInboundCarrier();
    error OnlySecondInboundCarrier();
    error CarrierSequenceMismatch();

    enum Carrier {
        Hyperlane,
        LayerZeroV2
    }

    Carrier public immutable firstCarrier;
    Carrier public immutable secondCarrier;
    IBaselineCarrier public immutable firstOutbound;
    IBaselineCarrier public immutable secondOutbound;
    address public immutable firstInbound;
    address public immutable secondInbound;
    IBaselineEffectReceiver public immutable receiver;
    bytes32 public immutable routeId;

    event BaselineSourceDispatched(
        bytes32 indexed protocolMessageId, Carrier indexed carrier, bytes32 payloadHash
    );
    event BaselineIntermediateForwarded(
        bytes32 indexed inboundMessageId,
        bytes32 indexed outboundMessageId,
        Carrier indexed carrier,
        bytes32 payloadHash
    );
    event BaselineDestinationApplied(bytes32 indexed messageId, bytes32 indexed payloadHash);

    constructor(
        bytes32 routeId_,
        Carrier firstCarrier_,
        Carrier secondCarrier_,
        IBaselineCarrier firstOutbound_,
        IBaselineCarrier secondOutbound_,
        address firstInbound_,
        address secondInbound_,
        IBaselineEffectReceiver receiver_,
        address administrator_,
        address runner_
    ) OutboundControl(administrator_, runner_) {
        if (
            routeId_ == bytes32(0) || address(firstOutbound_) == address(0)
                || address(secondOutbound_) == address(0)
                || firstInbound_ == address(0) || secondInbound_ == address(0)
                || address(receiver_) == address(0)
        ) revert CarrierSequenceMismatch();
        routeId = routeId_;
        firstCarrier = firstCarrier_;
        secondCarrier = secondCarrier_;
        firstOutbound = firstOutbound_;
        secondOutbound = secondOutbound_;
        firstInbound = firstInbound_;
        secondInbound = secondInbound_;
        receiver = receiver_;
    }

    function dispatchSource(bytes calldata payload, bytes calldata options)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32 protocolMessageId)
    {
        protocolMessageId =
            firstOutbound.sendBaselineSource{value: msg.value}(routeId, payload, options);
        emit BaselineSourceDispatched(protocolMessageId, firstCarrier, keccak256(payload));
    }

    function receiveFirstLegAndForward(
        bytes32 inboundMessageId,
        bytes calldata payload,
        bytes calldata options
    ) external payable whenOutboundActive returns (bytes32 outboundMessageId) {
        if (msg.sender != firstInbound) revert OnlyFirstInboundCarrier();
        outboundMessageId =
            secondOutbound.forwardBaseline{value: msg.value}(routeId, payload, options);
        emit BaselineIntermediateForwarded(
            inboundMessageId, outboundMessageId, secondCarrier, keccak256(payload)
        );
    }

    function receiveSecondLegAndApply(bytes32 messageId, bytes calldata payload) external {
        if (msg.sender != secondInbound) revert OnlySecondInboundCarrier();
        receiver.baselineReceive(messageId, payload);
        emit BaselineDestinationApplied(messageId, keccak256(payload));
    }

    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external {
        if (msg.sender == firstInbound) {
            bytes32 outboundMessageId =
                secondOutbound.forwardBaseline(routeId, payload, bytes(""));
            emit BaselineIntermediateForwarded(
                messageId, outboundMessageId, secondCarrier, keccak256(payload)
            );
            return;
        }
        if (msg.sender == secondInbound) {
            receiver.baselineReceive(messageId, payload);
            emit BaselineDestinationApplied(messageId, keccak256(payload));
            return;
        }
        revert CarrierSequenceMismatch();
    }
}
