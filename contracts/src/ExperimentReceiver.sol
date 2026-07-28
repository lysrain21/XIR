// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRReceiver} from "./IXIRReceiver.sol";

contract ExperimentReceiver is IXIRReceiver {
    error UnauthorizedCaller();
    error WrongReceiverMode();
    error PayloadMismatch();
    error DuplicateMessage();

    enum ReceiverMode {
        Baseline,
        XIR
    }

    address public immutable authority;
    bytes32 public immutable namespaceId;
    bytes32 public immutable expectedPayloadHash;
    bytes32 public immutable initialStateHash;
    ReceiverMode public immutable mode;

    uint256 public deliveryCount;
    bytes32 public lastPayloadHash;
    bytes32 public lastMessageId;
    mapping(bytes32 => bool) public consumed;

    event EffectApplied(
        bytes32 indexed namespaceId,
        bytes32 indexed messageId,
        bytes32 indexed payloadHash,
        bytes32 beforeStateHash,
        bytes32 afterStateHash,
        uint256 deliveryCount
    );

    constructor(
        address authority_,
        bytes32 namespaceId_,
        bytes32 expectedPayloadHash_,
        bytes32 initialStateHash_,
        ReceiverMode mode_
    ) {
        if (authority_ == address(0)) revert UnauthorizedCaller();
        authority = authority_;
        namespaceId = namespaceId_;
        expectedPayloadHash = expectedPayloadHash_;
        initialStateHash = initialStateHash_;
        mode = mode_;
    }

    function baselineReceive(bytes32 messageId, bytes calldata payload) external {
        if (mode != ReceiverMode.Baseline) revert WrongReceiverMode();
        _receiveEffect(messageId, payload);
    }

    function xirReceive(bytes32 messageId, bytes calldata payload) external {
        if (mode != ReceiverMode.XIR) revert WrongReceiverMode();
        _receiveEffect(messageId, payload);
    }

    function effectStateHash() public view returns (bytes32) {
        return keccak256(abi.encode(initialStateHash, deliveryCount, lastPayloadHash));
    }

    function effectSatisfied(uint256 expectedDeliveryCount) external view returns (bool) {
        return deliveryCount == expectedDeliveryCount
            && (expectedDeliveryCount == 0 || lastPayloadHash == expectedPayloadHash);
    }

    function _receiveEffect(bytes32 messageId, bytes calldata payload) private {
        if (msg.sender != authority) revert UnauthorizedCaller();
        bytes32 payloadHash = keccak256(payload);
        if (payloadHash != expectedPayloadHash) revert PayloadMismatch();
        if (consumed[messageId]) revert DuplicateMessage();
        bytes32 beforeStateHash = effectStateHash();
        consumed[messageId] = true;
        deliveryCount++;
        lastPayloadHash = payloadHash;
        lastMessageId = messageId;
        emit EffectApplied(
            namespaceId,
            messageId,
            payloadHash,
            beforeStateHash,
            effectStateHash(),
            deliveryCount
        );
    }
}
