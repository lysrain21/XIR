// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRTypes} from "../src/XIRTypes.sol";

contract XIRGoldenTest {
    function testGoldenEncodingVector() public pure {
        XIRTypes.TypedId memory sourceGateway =
            XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        XIRTypes.TypedId memory sourceApp =
            XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        XIRTypes.TypedId memory destinationApp = XIRTypes.TypedId(
            2, hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        XIRTypes.Record memory record = XIRTypes.Record({
            sourceGateway: sourceGateway,
            sourceApp: sourceApp,
            destinationApp: destinationApp,
            nonce: 7,
            payloadHash: keccak256("hello XIR")
        });
        XIRTypes.VerifiedContext memory context = XIRTypes.VerifiedContext({
            requiredSecurity: 2, policyHash: keccak256("minimum-security-two")
        });
        bytes32 recordDigest = XIREncoding.recordHash(record);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        bytes32 rid = XIREncoding.rootId(sourceGateway, recordDigest, contextDigest, 1);

        require(
            recordDigest == 0xbc491f471441339ac5373f625feafae9a51aeb4b27912232611e5a919ec237d1,
            "record digest drift"
        );
        require(
            contextDigest == 0x5b70ae95445a0881fc7f2ad32d627c9a765c1b0f2f70b13bd7f44836e5ad4062,
            "context digest drift"
        );
        require(
            rid == 0x03b1cac384ad9ad8718cfb179b228d36e5ed4298622c25c4abe088eaaaaf0023,
            "RID drift"
        );
        require(
            XIREncoding.messageId(rid, destinationApp)
                == 0xd27fdef9e985c22f7f433219f9aa3ed453a1ed3ef295f07bb6fd72b7fc783f56,
            "MID drift"
        );
    }

    function testGoldenReceiptVector() public pure {
        XIRTypes.TypedId memory sourceGateway =
            XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        XIRTypes.TypedId memory intermediateGateway =
            XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        XIRTypes.TypedId memory sourceApp =
            XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        XIRTypes.TypedId memory destinationApp = XIRTypes.TypedId(
            2, hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        XIRTypes.Record memory record = XIRTypes.Record({
            sourceGateway: sourceGateway,
            sourceApp: sourceApp,
            destinationApp: destinationApp,
            nonce: 7,
            payloadHash: keccak256("hello XIR")
        });
        XIRTypes.VerifiedContext memory context = XIRTypes.VerifiedContext({
            requiredSecurity: 2, policyHash: keccak256("minimum-security-two")
        });
        bytes32 recordDigest = XIREncoding.recordHash(record);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        bytes32 rid = XIREncoding.rootId(sourceGateway, recordDigest, contextDigest, 1);
        XIRTypes.Receipt memory receipt = XIRTypes.Receipt({
            srcGateway: sourceGateway,
            dstGateway: intermediateGateway,
            profileHash: keccak256("hyperlane-op-arb-v1"),
            evidenceHash: keccak256("hyperlane-message-id"),
            transitionHash: XIREncoding.transitionHash(
                recordDigest, contextDigest, sourceGateway, intermediateGateway
            ),
            priorPrefix: XIREncoding.rootPrefix(rid)
        });
        require(
            XIREncoding.receiptHash(receipt)
                == 0xc12fb3bfe7ad396ded8e315e2ebd4f4372e066a691b09d290dccd4c92deada56,
            "receipt digest drift"
        );
    }
}
