// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrierReceiver} from "../IBaselineCarrier.sol";
import {IXIRCarrierAdapter} from "../IXIRCarrierAdapter.sol";
import {IXIRReceiver} from "../IXIRReceiver.sol";
import {XIREncoding} from "../XIREncoding.sol";
import {XIRTypes} from "../XIRTypes.sol";
import {NativeRoutePayload} from "./NativeRoutePayload.sol";

/// @notice Records a native-authenticated first hop without forwarding it.
/// The experiment runner waits for this state before submitting the second
/// carrier transaction, so B0 and B1 retain authentication on both hops.
contract NativeAblationIngressV1 is IBaselineCarrierReceiver {
    error InvalidAuthority();
    error DuplicatePayload(bytes32 payloadHash);

    address public immutable hyperlaneCarrier;
    address public immutable layerZeroCarrier;
    mapping(bytes32 => bytes32) public firstMessageForPayload;

    event FirstHopAccepted(bytes32 indexed payloadHash, bytes32 indexed nativeMessageId, address indexed carrier);

    constructor(address hyperlaneCarrier_, address layerZeroCarrier_) {
        if (hyperlaneCarrier_ == address(0) || layerZeroCarrier_ == address(0)) {
            revert InvalidAuthority();
        }
        hyperlaneCarrier = hyperlaneCarrier_;
        layerZeroCarrier = layerZeroCarrier_;
    }

    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external {
        if (msg.sender != hyperlaneCarrier && msg.sender != layerZeroCarrier) {
            revert InvalidAuthority();
        }
        bytes32 payloadHash = keccak256(payload);
        if (firstMessageForPayload[payloadHash] != bytes32(0)) {
            revert DuplicatePayload(payloadHash);
        }
        firstMessageForPayload[payloadHash] = messageId;
        emit FirstHopAccepted(payloadHash, messageId, msg.sender);
    }
}

/// @notice Materializes the exact executable Record/rid/mid objects used by
/// B1 and B2 without adding root signatures, registry lookup, or policy.
contract NativeAblationRootV1 {
    error InvalidDestination();
    error DuplicateRoot(bytes32 rid);

    XIRTypes.TypedId private sourceGateway;
    mapping(bytes32 => bool) public created;

    event LogicalRecordCreated(
        bytes32 indexed rid, bytes32 indexed mid, address indexed sender, uint64 nonce, bytes32 payloadHash
    );

    constructor(XIRTypes.TypedId memory sourceGateway_) {
        XIREncoding.typedIdHash(sourceGateway_);
        sourceGateway = sourceGateway_;
    }

    function create(
        uint64 nonce,
        XIRTypes.TypedId calldata destinationApp,
        bytes calldata payload,
        XIRTypes.VerifiedContext calldata context,
        uint32 registryVersion
    ) external returns (XIRTypes.Record memory record, bytes32 rid, bytes32 mid) {
        if (destinationApp.kind != XIRTypes.EVM || destinationApp.value.length != 20) {
            revert InvalidDestination();
        }
        record = XIRTypes.Record({
            sourceGateway: sourceGateway,
            sourceApp: XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(msg.sender)),
            destinationApp: destinationApp,
            nonce: nonce,
            payloadHash: keccak256(payload)
        });
        rid = XIREncoding.rootId(
            sourceGateway, XIREncoding.recordHash(record), XIREncoding.contextHash(context), registryVersion
        );
        if (created[rid]) revert DuplicateRoot(rid);
        created[rid] = true;
        mid = XIREncoding.messageId(rid, destinationApp);
        emit LogicalRecordCreated(rid, mid, msg.sender, nonce, record.payloadHash);
    }
}

/// @notice B2's intermediate transition stage. It verifies the first native
/// evidence tuple through a statically configured adapter and prefix binding,
/// while intentionally omitting registry resolution and policy evaluation.
contract NativeAblationTransitionV1 {
    error InvalidAuthority();
    error InvalidRoute();
    error InvalidRecord();
    error InvalidReceipt();
    error EvidenceRejected();
    error DuplicateAttempt(bytes32 attemptId);

    address public immutable runner;
    IXIRCarrierAdapter public immutable hyperlaneInbound;
    IXIRCarrierAdapter public immutable layerZeroInbound;
    bytes32 public immutable sourceGatewayHash;
    bytes32 public immutable intermediateGatewayHash;
    bytes32 public immutable hyperlaneProfile;
    bytes32 public immutable layerZeroProfile;
    mapping(bytes32 => bool) public recordedAttempts;

    event B2TransitionRecorded(
        bytes32 indexed attemptId, bytes2 indexed route, bytes32 indexed rid, bytes32 mid, bytes32 verifiedPrefix
    );

    constructor(
        address runner_,
        IXIRCarrierAdapter hyperlaneInbound_,
        IXIRCarrierAdapter layerZeroInbound_,
        bytes32 sourceGatewayHash_,
        bytes32 intermediateGatewayHash_,
        bytes32 hyperlaneProfile_,
        bytes32 layerZeroProfile_
    ) {
        if (
            runner_ == address(0) || address(hyperlaneInbound_) == address(0)
                || address(layerZeroInbound_) == address(0)
        ) revert InvalidAuthority();
        runner = runner_;
        hyperlaneInbound = hyperlaneInbound_;
        layerZeroInbound = layerZeroInbound_;
        sourceGatewayHash = sourceGatewayHash_;
        intermediateGatewayHash = intermediateGatewayHash_;
        hyperlaneProfile = hyperlaneProfile_;
        layerZeroProfile = layerZeroProfile_;
    }

    function record(
        bytes calldata payload,
        XIRTypes.Record calldata logicalRecord,
        XIRTypes.VerifiedContext calldata context,
        XIRTypes.Receipt calldata receipt,
        uint32 registryVersion
    ) external returns (bytes32 rid, bytes32 mid, bytes32 prefix) {
        if (msg.sender != runner) revert InvalidAuthority();
        NativeRoutePayload.Data memory data = abi.decode(payload, (NativeRoutePayload.Data));
        NativeRoutePayload.validate(data);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) revert InvalidRoute();
        if (recordedAttempts[data.attemptId]) revert DuplicateAttempt(data.attemptId);
        if (logicalRecord.payloadHash != keccak256(payload)) revert InvalidRecord();

        bytes32 recordDigest = XIREncoding.recordHash(logicalRecord);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        rid = XIREncoding.rootId(logicalRecord.sourceGateway, recordDigest, contextDigest, registryVersion);
        mid = XIREncoding.messageId(rid, logicalRecord.destinationApp);
        if (
            XIREncoding.typedIdHash(logicalRecord.sourceGateway) != sourceGatewayHash
                || XIREncoding.typedIdHash(receipt.srcGateway) != sourceGatewayHash
                || XIREncoding.typedIdHash(receipt.dstGateway) != intermediateGatewayHash
                || receipt.priorPrefix != XIREncoding.rootPrefix(rid)
        ) revert InvalidReceipt();
        bytes32 expectedProfile = NativeRoutePayload.firstIsHyperlane(data.route) ? hyperlaneProfile : layerZeroProfile;
        IXIRCarrierAdapter adapter =
            NativeRoutePayload.firstIsHyperlane(data.route) ? hyperlaneInbound : layerZeroInbound;
        bytes32 transition =
            XIREncoding.transitionHash(recordDigest, contextDigest, receipt.srcGateway, receipt.dstGateway);
        if (receipt.profileHash != expectedProfile || receipt.transitionHash != transition) {
            revert InvalidReceipt();
        }
        if (!adapter.verify(receipt.profileHash, receipt.evidenceHash, transition)) {
            revert EvidenceRejected();
        }
        prefix = XIREncoding.nextPrefix(receipt.priorPrefix, XIREncoding.receiptHash(receipt));
        recordedAttempts[data.attemptId] = true;
        emit B2TransitionRecorded(data.attemptId, data.route, rid, mid, prefix);
    }
}

/// @notice One effect contract shared by B0--B3. B0 and B1 enter from a
/// native final-hop adapter, B2 enters through static evidence verification,
/// and B3 enters through XIRGateway.
contract NativeAblationReceiverV1 is IBaselineCarrierReceiver, IXIRReceiver {
    error InvalidAuthority();
    error InvalidLayer();
    error InvalidRecord();
    error InvalidReceipt(uint256 index);
    error EvidenceRejected(uint256 index);
    error BundleRejected();
    error DuplicateAttempt(bytes32 attemptId);
    error DuplicateMessage(bytes32 messageId);

    uint8 public constant B0 = 0;
    uint8 public constant B1 = 1;
    uint8 public constant B2 = 2;
    uint8 public constant B3 = 3;

    address public immutable runner;
    address public immutable hyperlaneBaselineCarrier;
    address public immutable layerZeroBaselineCarrier;
    address public immutable xirGateway;
    IXIRCarrierAdapter public immutable hyperlaneXirAdapter;
    IXIRCarrierAdapter public immutable layerZeroXirAdapter;
    bytes32 public immutable sourceGatewayHash;
    bytes32 public immutable intermediateGatewayHash;
    bytes32 public immutable destinationGatewayHash;
    bytes32 public immutable hyperlaneABProfile;
    bytes32 public immutable layerZeroABProfile;
    bytes32 public immutable hyperlaneBCProfile;
    bytes32 public immutable layerZeroBCProfile;

    bytes32 public effectStateHash;
    uint256 public deliveryCount;
    mapping(bytes32 => bool) public consumedAttempts;
    mapping(bytes32 => bool) public consumedMessages;

    event AblationEffectApplied(
        bytes32 indexed attemptId,
        bytes2 indexed route,
        uint8 indexed layer,
        uint64 routeSequence,
        bytes32 messageId,
        bytes32 payloadHash,
        bytes32 beforeStateHash,
        bytes32 afterStateHash,
        uint256 deliveryCount
    );
    event AblationReplayRejected(
        bytes32 indexed attemptId, bytes32 indexed messageId, uint8 indexed layer, address carrier
    );

    constructor(
        address runner_,
        address hyperlaneBaselineCarrier_,
        address layerZeroBaselineCarrier_,
        address xirGateway_,
        IXIRCarrierAdapter hyperlaneXirAdapter_,
        IXIRCarrierAdapter layerZeroXirAdapter_,
        bytes32[3] memory gatewayHashes_,
        bytes32[4] memory profileHashes_
    ) {
        if (
            runner_ == address(0) || hyperlaneBaselineCarrier_ == address(0) || layerZeroBaselineCarrier_ == address(0)
                || xirGateway_ == address(0) || address(hyperlaneXirAdapter_) == address(0)
                || address(layerZeroXirAdapter_) == address(0)
        ) revert InvalidAuthority();
        runner = runner_;
        hyperlaneBaselineCarrier = hyperlaneBaselineCarrier_;
        layerZeroBaselineCarrier = layerZeroBaselineCarrier_;
        xirGateway = xirGateway_;
        hyperlaneXirAdapter = hyperlaneXirAdapter_;
        layerZeroXirAdapter = layerZeroXirAdapter_;
        sourceGatewayHash = gatewayHashes_[0];
        intermediateGatewayHash = gatewayHashes_[1];
        destinationGatewayHash = gatewayHashes_[2];
        hyperlaneABProfile = profileHashes_[0];
        layerZeroABProfile = profileHashes_[1];
        hyperlaneBCProfile = profileHashes_[2];
        layerZeroBCProfile = profileHashes_[3];
        effectStateHash = keccak256("XIR_NATIVE_ABLATION_EFFECT_V1");
    }

    /// @dev B0 encoding: (uint8 layer, bytes routePayload).
    /// B1 uses fixed-width EVM identifiers on the wire and reconstructs the
    /// exact typed Record and Context before checking rid and mid.  The compact
    /// representation stays within the native LayerZero message-size limit.
    function baselineCarrierReceive(bytes32 nativeMessageId, bytes calldata encoded) external {
        if (msg.sender != hyperlaneBaselineCarrier && msg.sender != layerZeroBaselineCarrier) {
            revert InvalidAuthority();
        }
        uint8 layer = abi.decode(encoded, (uint8));
        if (layer == B0) {
            (, bytes memory b0Payload) = abi.decode(encoded, (uint8, bytes));
            NativeRoutePayload.Data memory b0Data = _routePayload(b0Payload);
            _applyBaseline(b0Data, B0, nativeMessageId);
            return;
        }
        if (layer != B1) revert InvalidLayer();
        (
            ,
            bytes memory payload,
            address encodedSourceGateway,
            address encodedSourceApp,
            address encodedDestinationApp,
            uint64 encodedNonce,
            bytes32 encodedPayloadHash,
            uint8 encodedRequiredSecurity,
            bytes32 encodedPolicyHash,
            uint32 registryVersion,
            bytes32 rid,
            bytes32 mid
        ) = abi.decode(
            encoded,
            (uint8, bytes, address, address, address, uint64, bytes32, uint8, bytes32, uint32, bytes32, bytes32)
        );
        XIRTypes.Record memory record = XIRTypes.Record({
            sourceGateway: XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(encodedSourceGateway)),
            sourceApp: XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(encodedSourceApp)),
            destinationApp: XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(encodedDestinationApp)),
            nonce: encodedNonce,
            payloadHash: encodedPayloadHash
        });
        XIRTypes.VerifiedContext memory context =
            XIRTypes.VerifiedContext({requiredSecurity: encodedRequiredSecurity, policyHash: encodedPolicyHash});
        NativeRoutePayload.Data memory data = _routePayload(payload);
        if (
            record.payloadHash != keccak256(payload)
                || XIREncoding.typedIdHash(record.sourceGateway) != sourceGatewayHash
                || _evmAddress(record.destinationApp) != address(this)
        ) revert InvalidRecord();
        bytes32 expectedRid = XIREncoding.rootId(
            record.sourceGateway, XIREncoding.recordHash(record), XIREncoding.contextHash(context), registryVersion
        );
        if (rid != expectedRid || mid != XIREncoding.messageId(expectedRid, record.destinationApp)) {
            revert InvalidRecord();
        }
        _applyBaseline(data, B1, mid);
    }

    function deliverB2(
        bytes calldata payload,
        XIRTypes.Record calldata record,
        XIRTypes.VerifiedContext calldata context,
        uint32 registryVersion,
        XIRTypes.Receipt[] calldata receipts
    ) external returns (bytes32 mid) {
        if (msg.sender != runner) revert InvalidAuthority();
        if (
            receipts.length != 2 || record.payloadHash != keccak256(payload)
                || XIREncoding.typedIdHash(record.sourceGateway) != sourceGatewayHash
                || _evmAddress(record.destinationApp) != address(this)
        ) revert InvalidRecord();
        NativeRoutePayload.Data memory data = abi.decode(payload, (NativeRoutePayload.Data));
        NativeRoutePayload.validate(data);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) revert InvalidRecord();

        bytes32 recordDigest = XIREncoding.recordHash(record);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        bytes32 rid = XIREncoding.rootId(record.sourceGateway, recordDigest, contextDigest, registryVersion);
        mid = XIREncoding.messageId(rid, record.destinationApp);
        bytes32 prefix = XIREncoding.rootPrefix(rid);
        bytes32 bundle = XIREncoding.bundleStart(2);
        IXIRCarrierAdapter adapter =
            NativeRoutePayload.secondIsHyperlane(data.route) ? hyperlaneXirAdapter : layerZeroXirAdapter;
        bytes32[2] memory expectedSrc = [sourceGatewayHash, intermediateGatewayHash];
        bytes32[2] memory expectedDst = [intermediateGatewayHash, destinationGatewayHash];
        bytes32[2] memory expectedProfiles;
        if (data.route == bytes2("HL")) {
            expectedProfiles = [hyperlaneABProfile, layerZeroBCProfile];
        } else {
            expectedProfiles = [layerZeroABProfile, hyperlaneBCProfile];
        }
        for (uint256 i = 0; i < 2; i++) {
            XIRTypes.Receipt calldata receipt = receipts[i];
            bytes32 transition =
                XIREncoding.transitionHash(recordDigest, contextDigest, receipt.srcGateway, receipt.dstGateway);
            if (
                receipt.priorPrefix != prefix || XIREncoding.typedIdHash(receipt.srcGateway) != expectedSrc[i]
                    || XIREncoding.typedIdHash(receipt.dstGateway) != expectedDst[i]
                    || receipt.profileHash != expectedProfiles[i] || receipt.transitionHash != transition
            ) revert InvalidReceipt(i);
            if (!adapter.verify(receipt.profileHash, receipt.evidenceHash, transition)) {
                revert EvidenceRejected(i);
            }
            bundle = XIREncoding.bundleStep(bundle, i, receipt.profileHash, receipt.evidenceHash, transition);
            prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(receipt));
        }
        if (!adapter.verifyBundle(bundle)) revert BundleRejected();
        _apply(data, B2, mid);
    }

    function xirReceive(bytes32 mid, bytes calldata payload) external {
        if (msg.sender != xirGateway) revert InvalidAuthority();
        NativeRoutePayload.Data memory data = abi.decode(payload, (NativeRoutePayload.Data));
        NativeRoutePayload.validate(data);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) revert InvalidRecord();
        _apply(data, B3, mid);
    }

    function _routePayload(bytes memory payload) private pure returns (NativeRoutePayload.Data memory data) {
        data = abi.decode(payload, (NativeRoutePayload.Data));
        NativeRoutePayload.validate(data);
        if (!NativeRoutePayload.isHeterogeneous(data.route)) revert InvalidRecord();
    }

    function _apply(NativeRoutePayload.Data memory data, uint8 layer, bytes32 messageId) private {
        if (consumedAttempts[data.attemptId]) revert DuplicateAttempt(data.attemptId);
        if (consumedMessages[messageId]) revert DuplicateMessage(messageId);
        _commitEffect(data, layer, messageId);
    }

    function _applyBaseline(NativeRoutePayload.Data memory data, uint8 layer, bytes32 messageId) private {
        if (consumedAttempts[data.attemptId] || consumedMessages[messageId]) {
            emit AblationReplayRejected(data.attemptId, messageId, layer, msg.sender);
            return;
        }
        _commitEffect(data, layer, messageId);
    }

    function _commitEffect(NativeRoutePayload.Data memory data, uint8 layer, bytes32 messageId) private {
        bytes32 beforeState = effectStateHash;
        consumedAttempts[data.attemptId] = true;
        consumedMessages[messageId] = true;
        deliveryCount++;
        effectStateHash = keccak256(
            abi.encode(beforeState, data.attemptId, layer, messageId, keccak256(data.applicationPayload), deliveryCount)
        );
        emit AblationEffectApplied(
            data.attemptId,
            data.route,
            layer,
            data.routeSequence,
            messageId,
            keccak256(data.applicationPayload),
            beforeState,
            effectStateHash,
            deliveryCount
        );
    }

    function _evmAddress(XIRTypes.TypedId memory id) private pure returns (address result) {
        if (id.kind != XIRTypes.EVM || id.value.length != 20) revert InvalidRecord();
        bytes memory value = id.value;
        assembly ("memory-safe") {
            result := shr(96, mload(add(value, 32)))
        }
    }
}
