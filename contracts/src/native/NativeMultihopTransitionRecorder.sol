// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {XIRGateway} from "../XIRGateway.sol";
import {XIRTypes} from "../XIRTypes.sol";
import {NativeMultihopPayload} from "./NativeMultihopPayload.sol";

contract NativeMultihopTransitionRecorder {
    error Unauthorized();
    error PayloadMismatch();
    error WrongInboundReceiptCount();
    error TransitionAlreadyRecorded(bytes32 key);
    error NotCarrierSwitch();
    error InvalidOutboundProfile();

    XIRGateway public immutable intermediateGateway;
    address public immutable runner;
    mapping(bytes32 => bytes32) public transitionForAttemptHop;

    event NativeMultihopTransitionRecorded(
        bytes32 indexed attemptId,
        uint8 indexed hopIndex,
        uint64 indexed routeSequence,
        bytes route,
        bytes32 inboundProfileHash,
        bytes32 outboundProfileHash,
        bytes32 protocolTransitionHash,
        bytes32 rid,
        bytes32 mid,
        bytes32 verifiedPrefix,
        uint256 verifiedReceiptCount
    );

    constructor(XIRGateway intermediateGateway_, address runner_) {
        if (address(intermediateGateway_) == address(0) || runner_ == address(0)) {
            revert Unauthorized();
        }
        intermediateGateway = intermediateGateway_;
        runner = runner_;
    }

    function record(
        bytes calldata encodedPayload,
        XIRTypes.Envelope calldata inboundEnvelope,
        uint8 hopIndex,
        bytes32 outboundProfileHash
    ) external returns (bytes32 protocolTransitionHash) {
        if (msg.sender != runner) revert Unauthorized();
        if (outboundProfileHash == bytes32(0)) revert InvalidOutboundProfile();
        NativeMultihopPayload.Data memory data = NativeMultihopPayload.decode(encodedPayload);
        if (!NativeMultihopPayload.switchAt(data.route, hopIndex)) revert NotCarrierSwitch();
        if (keccak256(encodedPayload) != inboundEnvelope.record.payloadHash) {
            revert PayloadMismatch();
        }
        if (inboundEnvelope.receipts.length != hopIndex) {
            revert WrongInboundReceiptCount();
        }
        bytes32 key = keccak256(abi.encode(data.attemptId, hopIndex));
        if (transitionForAttemptHop[key] != bytes32(0)) {
            revert TransitionAlreadyRecorded(key);
        }
        (bytes32 rid, bytes32 mid, bytes32 prefix) = intermediateGateway.verifyTrace(inboundEnvelope);
        XIRTypes.Receipt calldata inbound = inboundEnvelope.receipts[hopIndex - 1];
        protocolTransitionHash = keccak256(
            abi.encode(
                keccak256("XIR_NATIVE_MULTIHOP_PROTOCOL_TRANSITION_V1"),
                data.attemptId,
                data.route,
                data.routeSequence,
                hopIndex,
                inboundEnvelope.record.payloadHash,
                inbound.profileHash,
                inbound.evidenceHash,
                inbound.transitionHash,
                outboundProfileHash,
                rid,
                mid,
                prefix
            )
        );
        transitionForAttemptHop[key] = protocolTransitionHash;
        emit NativeMultihopTransitionRecorded(
            data.attemptId,
            hopIndex,
            data.routeSequence,
            data.route,
            inbound.profileHash,
            outboundProfileHash,
            protocolTransitionHash,
            rid,
            mid,
            prefix,
            inboundEnvelope.receipts.length
        );
    }
}
