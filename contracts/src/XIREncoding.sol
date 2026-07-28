// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {XIRTypes} from "./XIRTypes.sol";

library XIREncoding {
    error InvalidIdentifier(uint8 kind, uint256 length);

    bytes internal constant RECORD_TAG = "XIR_RECORD_V1";
    bytes internal constant CONTEXT_TAG = "XIR_CONTEXT_V1";
    bytes internal constant RID_TAG = "XIR_RID_V1";
    bytes internal constant MID_TAG = "XIR_MID_V1";
    bytes internal constant ROOT_TAG = "XIR_ROOT_V1";
    bytes internal constant TRANSITION_TAG = "XIR_TRANSITION_V1";
    bytes internal constant HOP_TAG = "XIR_HOP_V1";
    bytes internal constant PREFIX_TAG = "XIR_PREFIX_V1";

    function encodeTypedId(XIRTypes.TypedId memory id) internal pure returns (bytes memory) {
        uint256 expected = id.kind == XIRTypes.EVM ? 20 : id.kind == XIRTypes.SOLANA ? 32 : 0;
        if (expected == 0 || id.value.length != expected) {
            revert InvalidIdentifier(id.kind, id.value.length);
        }
        return abi.encodePacked(id.kind, uint8(id.value.length), id.value);
    }

    function typedIdHash(XIRTypes.TypedId memory id) internal pure returns (bytes32) {
        return keccak256(encodeTypedId(id));
    }

    function recordHash(XIRTypes.Record memory record) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                RECORD_TAG,
                encodeTypedId(record.sourceGateway),
                encodeTypedId(record.sourceApp),
                encodeTypedId(record.destinationApp),
                record.nonce,
                record.payloadHash
            )
        );
    }

    function contextHash(XIRTypes.VerifiedContext memory context) internal pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(CONTEXT_TAG, context.requiredSecurity, context.policyHash));
    }

    function rootId(
        XIRTypes.TypedId memory rootGateway,
        bytes32 recordDigest,
        bytes32 contextDigest,
        uint32 registryVersion
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                RID_TAG, encodeTypedId(rootGateway), recordDigest, contextDigest, registryVersion
            )
        );
    }

    function messageId(bytes32 rid, XIRTypes.TypedId memory destinationApp)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(MID_TAG, rid, encodeTypedId(destinationApp)));
    }

    function rootPrefix(bytes32 rid) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ROOT_TAG, rid));
    }

    function transitionHash(
        bytes32 recordDigest,
        bytes32 contextDigest,
        XIRTypes.TypedId memory src,
        XIRTypes.TypedId memory dst
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                TRANSITION_TAG, recordDigest, contextDigest, encodeTypedId(src), encodeTypedId(dst)
            )
        );
    }

    function receiptHash(XIRTypes.Receipt memory receipt) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                HOP_TAG,
                receipt.priorPrefix,
                encodeTypedId(receipt.srcGateway),
                encodeTypedId(receipt.dstGateway),
                receipt.profileHash,
                receipt.evidenceHash,
                receipt.transitionHash
            )
        );
    }

    function nextPrefix(bytes32 priorPrefix, bytes32 receiptDigest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(PREFIX_TAG, priorPrefix, receiptDigest));
    }
}
