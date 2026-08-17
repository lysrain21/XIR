// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRReceiver} from "../IXIRReceiver.sol";
import {NativeMultihopPayload} from "./NativeMultihopPayload.sol";

contract NativeMultihopReceiver is IXIRReceiver {
    error InvalidAuthority();
    error DuplicateAttempt(bytes32 attemptId);
    error DuplicateMessage(bytes32 messageId);

    address public immutable xirGateway;
    bytes32 public effectStateHash;
    uint256 public deliveryCount;
    mapping(bytes32 => bool) public consumedAttempts;
    mapping(bytes32 => bool) public consumedMessages;
    mapping(bytes32 => bytes32) public effectClassForAttempt;

    event NativeMultihopEffectApplied(
        bytes32 indexed attemptId,
        bytes32 indexed messageId,
        uint64 indexed routeSequence,
        bytes route,
        bytes32 payloadHash,
        bytes32 effectClassHash,
        bytes32 beforeStateHash,
        bytes32 afterStateHash,
        uint256 deliveryCount
    );

    constructor(address xirGateway_, bytes32 initialStateHash_) {
        if (xirGateway_ == address(0)) revert InvalidAuthority();
        xirGateway = xirGateway_;
        effectStateHash = initialStateHash_;
    }

    function xirReceive(bytes32 messageId, bytes calldata payload) external {
        if (msg.sender != xirGateway) revert InvalidAuthority();
        NativeMultihopPayload.Data memory data = NativeMultihopPayload.decode(payload);
        if (consumedAttempts[data.attemptId]) revert DuplicateAttempt(data.attemptId);
        if (consumedMessages[messageId]) revert DuplicateMessage(messageId);
        bytes32 beforeStateHash = effectStateHash;
        bytes32 effectClass = NativeMultihopPayload.effectClassHash(data);
        consumedAttempts[data.attemptId] = true;
        consumedMessages[messageId] = true;
        effectClassForAttempt[data.attemptId] = effectClass;
        deliveryCount++;
        effectStateHash = keccak256(abi.encode(beforeStateHash, data.attemptId, effectClass, messageId, deliveryCount));
        emit NativeMultihopEffectApplied(
            data.attemptId,
            messageId,
            data.routeSequence,
            data.route,
            keccak256(data.applicationPayload),
            effectClass,
            beforeStateHash,
            effectStateHash,
            deliveryCount
        );
    }
}
