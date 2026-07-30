// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {XIRGateway} from "../XIRGateway.sol";
import {XIRTypes} from "../XIRTypes.sol";
import {NativeRoutePayload} from "./NativeRoutePayload.sol";

contract NativeXIRTransitionRecorder {
    error Unauthorized();
    error HomogeneousRouteCannotTransition();
    error PayloadMismatch();
    error WrongInboundReceiptCount();
    error TransitionAlreadyRecorded(bytes32 attemptId);
    error InvalidOutboundProfile();

    XIRGateway public immutable intermediateGateway;
    address public immutable runner;
    mapping(bytes32 => bytes32) public transitionForAttempt;

    event NativeXIRTransitionRecorded(
        bytes32 indexed attemptId,
        bytes2 indexed route,
        uint64 indexed routeSequence,
        bytes32 inboundProfileHash,
        bytes32 inboundEvidenceHash,
        bytes32 inboundTransitionHash,
        bytes32 outboundProfileHash,
        bytes32 protocolTransitionHash,
        bytes32 rid,
        bytes32 mid,
        bytes32 verifiedPrefix
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
        bytes32 outboundProfileHash
    ) external returns (bytes32 protocolTransitionHash) {
        if (msg.sender != runner) revert Unauthorized();
        if (outboundProfileHash == bytes32(0)) revert InvalidOutboundProfile();
        NativeRoutePayload.Data memory data = NativeRoutePayload.decode(encodedPayload);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) {
            revert HomogeneousRouteCannotTransition();
        }
        if (keccak256(encodedPayload) != inboundEnvelope.record.payloadHash) {
            revert PayloadMismatch();
        }
        if (inboundEnvelope.receipts.length != 1) revert WrongInboundReceiptCount();
        if (transitionForAttempt[data.attemptId] != bytes32(0)) {
            revert TransitionAlreadyRecorded(data.attemptId);
        }

        (bytes32 rid, bytes32 mid, bytes32 prefix) =
            intermediateGateway.verifyTrace(inboundEnvelope);
        XIRTypes.Receipt calldata inbound = inboundEnvelope.receipts[0];
        protocolTransitionHash = keccak256(
            abi.encode(
                keccak256("XIR_NATIVE_PROTOCOL_TRANSITION_V1"),
                data.attemptId,
                data.route,
                data.routeSequence,
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
        transitionForAttempt[data.attemptId] = protocolTransitionHash;
        emit NativeXIRTransitionRecorded(
            data.attemptId,
            data.route,
            data.routeSequence,
            inbound.profileHash,
            inbound.evidenceHash,
            inbound.transitionHash,
            outboundProfileHash,
            protocolTransitionHash,
            rid,
            mid,
            prefix
        );
    }
}
