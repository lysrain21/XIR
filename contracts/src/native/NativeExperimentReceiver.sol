// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrierReceiver} from "../IBaselineCarrier.sol";
import {IXIRReceiver} from "../IXIRReceiver.sol";
import {NativeRoutePayload} from "./NativeRoutePayload.sol";

contract NativeExperimentReceiver is IBaselineCarrierReceiver, IXIRReceiver {
    error InvalidAuthority();
    error WrongDeliveryMode();
    error DuplicateAttempt(bytes32 attemptId);
    error DuplicateMessage(bytes32 messageId);

    address public immutable hyperlaneCarrier;
    address public immutable layerZeroCarrier;
    address public immutable xirGateway;
    bytes32 public effectStateHash;
    uint256 public deliveryCount;
    mapping(bytes32 => bool) public consumedAttempts;
    mapping(bytes32 => bool) public consumedMessages;
    mapping(bytes32 => bytes32) public effectClassForAttempt;

    event NativeEffectApplied(
        bytes32 indexed attemptId,
        bytes2 indexed route,
        uint64 indexed routeSequence,
        bytes32 messageId,
        bytes32 payloadHash,
        bytes32 effectClassHash,
        bytes32 beforeStateHash,
        bytes32 afterStateHash,
        uint256 deliveryCount,
        bool viaXIR
    );

    constructor(
        address hyperlaneCarrier_,
        address layerZeroCarrier_,
        address xirGateway_,
        bytes32 initialStateHash_
    ) {
        if (
            hyperlaneCarrier_ == address(0) || layerZeroCarrier_ == address(0)
                || xirGateway_ == address(0)
        ) revert InvalidAuthority();
        hyperlaneCarrier = hyperlaneCarrier_;
        layerZeroCarrier = layerZeroCarrier_;
        xirGateway = xirGateway_;
        effectStateHash = initialStateHash_;
    }

    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external {
        NativeRoutePayload.Data memory data = NativeRoutePayload.decode(payload);
        if (NativeRoutePayload.isHeterogeneous(data.route)) revert WrongDeliveryMode();
        address expected = NativeRoutePayload.secondIsHyperlane(data.route)
            ? hyperlaneCarrier
            : layerZeroCarrier;
        if (msg.sender != expected) revert InvalidAuthority();
        _apply(messageId, data, false);
    }

    function xirReceive(bytes32 messageId, bytes calldata payload) external {
        if (msg.sender != xirGateway) revert InvalidAuthority();
        NativeRoutePayload.Data memory data = NativeRoutePayload.decode(payload);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) revert WrongDeliveryMode();
        _apply(messageId, data, true);
    }

    function _apply(
        bytes32 messageId,
        NativeRoutePayload.Data memory data,
        bool viaXIR
    ) private {
        if (consumedAttempts[data.attemptId]) revert DuplicateAttempt(data.attemptId);
        if (consumedMessages[messageId]) revert DuplicateMessage(messageId);
        bytes32 beforeStateHash = effectStateHash;
        bytes32 payloadHash = keccak256(data.applicationPayload);
        bytes32 effectClass = NativeRoutePayload.effectClassHash(data);
        consumedAttempts[data.attemptId] = true;
        consumedMessages[messageId] = true;
        effectClassForAttempt[data.attemptId] = effectClass;
        deliveryCount++;
        effectStateHash = keccak256(
            abi.encode(
                beforeStateHash,
                data.attemptId,
                effectClass,
                messageId,
                deliveryCount
            )
        );
        emit NativeEffectApplied(
            data.attemptId,
            data.route,
            data.routeSequence,
            messageId,
            payloadHash,
            effectClass,
            beforeStateHash,
            effectStateHash,
            deliveryCount,
            viaXIR
        );
    }
}
