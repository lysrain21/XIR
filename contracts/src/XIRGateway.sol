// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "./IXIRCarrierAdapter.sol";
import {IXIRReceiver} from "./IXIRReceiver.sol";
import {XIREncoding} from "./XIREncoding.sol";
import {XIRRegistry} from "./XIRRegistry.sol";
import {XIRTypes} from "./XIRTypes.sol";

contract XIRGateway {
    error RootMismatch();
    error RootInactive();
    error InvalidRootSignature();
    error InvalidTrace(uint256 index);
    error ProfileInactive(uint256 index);
    error PolicyRefused(uint256 index);
    error EvidenceRejected(uint256 index);
    error WrongDestination();
    error PayloadMismatch();
    error AlreadyConsumed(bytes32 mid);
    error ReceiverCallFailed();
    error ReceiverMismatch();

    XIRRegistry public immutable registry;
    bytes32 public immutable gatewayHash;
    XIRTypes.TypedId private gatewayId;
    mapping(address => uint64) public nextNonce;
    mapping(bytes32 => bool) public consumed;

    event RootCreated(
        bytes32 indexed rid, bytes32 indexed mid, address indexed sender, uint64 nonce
    );
    event Delivered(bytes32 indexed mid, address indexed receiver, uint256 receiptCount);

    constructor(XIRRegistry registry_, XIRTypes.TypedId memory gatewayId_) {
        registry = registry_;
        gatewayHash = XIREncoding.typedIdHash(gatewayId_);
        gatewayId = gatewayId_;
    }

    function selfId() external view returns (XIRTypes.TypedId memory) {
        return gatewayId;
    }

    function createRecord(
        XIRTypes.TypedId calldata destinationApp,
        bytes calldata payload,
        XIRTypes.VerifiedContext calldata context,
        uint32 registryVersion
    ) external returns (XIRTypes.Record memory record, bytes32 rid, bytes32 mid) {
        uint64 nonce = nextNonce[msg.sender]++;
        record = XIRTypes.Record({
            sourceGateway: gatewayId,
            sourceApp: XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(msg.sender)),
            destinationApp: destinationApp,
            nonce: nonce,
            payloadHash: keccak256(payload)
        });
        bytes32 recordDigest = XIREncoding.recordHash(record);
        rid = XIREncoding.rootId(
            gatewayId, recordDigest, XIREncoding.contextHash(context), registryVersion
        );
        mid = XIREncoding.messageId(rid, destinationApp);
        emit RootCreated(rid, mid, msg.sender, nonce);
    }

    function verifyRoot(XIRTypes.Envelope calldata envelope)
        public
        view
        returns (bytes32 rid, bytes32 mid, bytes32 prefix)
    {
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        rid = XIREncoding.rootId(
            envelope.record.sourceGateway,
            recordDigest,
            contextDigest,
            envelope.certificate.registryVersion
        );
        XIRRegistry.RootSnapshot memory root = registry.rootAt(envelope.certificate.registryVersion);
        if (root.gatewayHash != XIREncoding.typedIdHash(envelope.record.sourceGateway)) {
            revert RootMismatch();
        }
        if (!_active(root.enabled, root.validAfter, root.validUntil)) revert RootInactive();
        if (_recover(_ethSigned(rid), envelope.certificate.signature) != root.signer) {
            revert InvalidRootSignature();
        }
        mid = XIREncoding.messageId(rid, envelope.record.destinationApp);
        prefix = XIREncoding.rootPrefix(rid);
    }

    function verifyTrace(XIRTypes.Envelope calldata envelope)
        public
        view
        returns (bytes32 rid, bytes32 mid, bytes32 prefix)
    {
        (rid, mid, prefix) = verifyRoot(envelope);
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 expectedSrc = XIREncoding.typedIdHash(envelope.record.sourceGateway);
        for (uint256 i = 0; i < envelope.receipts.length; i++) {
            XIRTypes.Receipt calldata receipt = envelope.receipts[i];
            bytes32 srcHash = XIREncoding.typedIdHash(receipt.srcGateway);
            bytes32 dstHash = XIREncoding.typedIdHash(receipt.dstGateway);
            if (receipt.priorPrefix != prefix || srcHash != expectedSrc) revert InvalidTrace(i);
            XIRRegistry.ProfileSnapshot memory profile = registry.profileAt(receipt.profileHash);
            if (
                profile.srcHash != srcHash || profile.dstHash != dstHash
                    || !_active(profile.enabled, profile.validAfter, profile.validUntil)
            ) revert ProfileInactive(i);
            if (profile.securityLevel < envelope.context.requiredSecurity) revert PolicyRefused(i);
            bytes32 transition = XIREncoding.transitionHash(
                recordDigest, contextDigest, receipt.srcGateway, receipt.dstGateway
            );
            if (receipt.transitionHash != transition) revert InvalidTrace(i);
            if (
                receipt.evidenceHash == bytes32(0) || profile.adapter == address(0)
                    || !IXIRCarrierAdapter(profile.adapter)
                        .verify(receipt.profileHash, receipt.evidenceHash, transition)
            ) revert EvidenceRejected(i);
            prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(receipt));
            expectedSrc = dstHash;
        }
        if (expectedSrc != gatewayHash) revert WrongDestination();
    }

    function deliver(XIRTypes.Envelope calldata envelope, bytes calldata payload, address receiver)
        external
        returns (bytes32 mid)
    {
        if (keccak256(payload) != envelope.record.payloadHash) revert PayloadMismatch();
        if (receiver == address(0) || _evmAddress(envelope.record.destinationApp) != receiver) {
            revert ReceiverMismatch();
        }
        (, mid,) = verifyTrace(envelope);
        if (consumed[mid]) revert AlreadyConsumed(mid);
        consumed[mid] = true;
        (bool ok,) = receiver.call(abi.encodeCall(IXIRReceiver.xirReceive, (mid, payload)));
        if (!ok) revert ReceiverCallFailed();
        emit Delivered(mid, receiver, envelope.receipts.length);
    }

    function _active(bool enabled, uint64 validAfter, uint64 validUntil)
        private
        view
        returns (bool)
    {
        return enabled && block.timestamp >= validAfter
            && (validUntil == 0 || block.timestamp < validUntil);
    }

    function _ethSigned(bytes32 digest) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }

    function _evmAddress(XIRTypes.TypedId calldata id) private pure returns (address result) {
        if (id.kind != XIRTypes.EVM || id.value.length != 20) revert ReceiverMismatch();
        bytes calldata value = id.value;
        assembly ("memory-safe") {
            result := shr(96, calldataload(value.offset))
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
