// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";
import {IXIRReceiver} from "../src/IXIRReceiver.sol";
import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRGateway} from "../src/XIRGateway.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {XIRTypes} from "../src/XIRTypes.sol";

interface SpliceVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
}

contract IndependentTupleEvidence is IXIRCarrierAdapter {
    mapping(bytes32 => bool) internal accepted;

    function accept(bytes32 profile, bytes32 evidence, bytes32 transition) external {
        accepted[keccak256(abi.encode(profile, evidence, transition))] = true;
    }

    function verify(bytes32 profile, bytes32 evidence, bytes32 transition)
        external
        view
        returns (bool)
    {
        return accepted[keccak256(abi.encode(profile, evidence, transition))];
    }
}

contract SpliceReceiver is IXIRReceiver {
    uint256 public count;

    function xirReceive(bytes32, bytes calldata) external {
        count++;
    }
}

/// @notice Regression fixture for two accepted tuples originating in distinct bundles.
contract SecuritySpliceRegressionTest {
    SpliceVm internal constant VM =
        SpliceVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNER_KEY = 0x51A1CE;
    bytes32 internal constant PROFILE_AB = keccak256("splice-profile-ab");
    bytes32 internal constant PROFILE_BC = keccak256("splice-profile-bc");
    bytes32 internal constant EVIDENCE_EXECUTION_A = keccak256("execution-a-first");
    bytes32 internal constant EVIDENCE_EXECUTION_B = keccak256("execution-b-second");

    XIRTypes.TypedId internal idA;
    XIRTypes.TypedId internal idB;
    XIRTypes.TypedId internal idC;
    XIRRegistry internal registry;
    IndependentTupleEvidence internal evidence;
    XIRGateway internal gateway;
    SpliceReceiver internal receiver;

    function setUp() public {
        idA = XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        idB = XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        idC = XIRTypes.TypedId(1, hex"3333333333333333333333333333333333333333");
        registry = new XIRRegistry(address(this));
        evidence = new IndependentTupleEvidence();
        gateway = new XIRGateway(registry, idC);
        receiver = new SpliceReceiver();
        registry.setRoot(
            1,
            XIRRegistry.RootSnapshot({
                gatewayHash: XIREncoding.typedIdHash(idA),
                signer: VM.addr(SIGNER_KEY),
                validAfter: 0,
                validUntil: 0,
                enabled: true
            })
        );
        _profile(PROFILE_AB, idA, idB);
        _profile(PROFILE_BC, idB, idC);
    }

    /// Pre-fix evidence: independent tuple membership did not bind adjacent receipts
    /// to the same native delivery bundle, so this recomputed-prefix splice succeeded.
    function testPreFixCrossExecutionSpliceIsAccepted() public {
        XIRTypes.Envelope memory envelope = _splicedEnvelope();
        gateway.deliver(envelope, bytes("splice-payload"), address(receiver));
        require(receiver.count() == 1, "pre-fix splice was not reproduced");
    }

    function _splicedEnvelope() private returns (XIRTypes.Envelope memory envelope) {
        envelope.record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            destinationApp: XIRTypes.TypedId(1, abi.encodePacked(address(receiver))),
            nonce: 9,
            payloadHash: keccak256("splice-payload")
        });
        envelope.context = XIRTypes.VerifiedContext(1, keccak256("splice-policy"));
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 rid = XIREncoding.rootId(idA, recordDigest, contextDigest, 1);
        envelope.certificate = XIRTypes.RootCertificate(1, _sign(rid));
        bytes32 transitionAB =
            XIREncoding.transitionHash(recordDigest, contextDigest, idA, idB);
        bytes32 transitionBC =
            XIREncoding.transitionHash(recordDigest, contextDigest, idB, idC);
        evidence.accept(PROFILE_AB, EVIDENCE_EXECUTION_A, transitionAB);
        evidence.accept(PROFILE_BC, EVIDENCE_EXECUTION_B, transitionBC);
        envelope.receipts = new XIRTypes.Receipt[](2);
        envelope.receipts[0] = XIRTypes.Receipt(
            idA,
            idB,
            PROFILE_AB,
            EVIDENCE_EXECUTION_A,
            transitionAB,
            XIREncoding.rootPrefix(rid)
        );
        envelope.receipts[1] = XIRTypes.Receipt(
            idB,
            idC,
            PROFILE_BC,
            EVIDENCE_EXECUTION_B,
            transitionBC,
            XIREncoding.nextPrefix(
                envelope.receipts[0].priorPrefix,
                XIREncoding.receiptHash(envelope.receipts[0])
            )
        );
    }

    function _profile(
        bytes32 profile,
        XIRTypes.TypedId memory source,
        XIRTypes.TypedId memory destination
    ) private {
        registry.setProfile(
            profile,
            XIRRegistry.ProfileSnapshot({
                srcHash: XIREncoding.typedIdHash(source),
                dstHash: XIREncoding.typedIdHash(destination),
                adapter: address(evidence),
                securityLevel: 1,
                validAfter: 0,
                validUntil: 0,
                enabled: true
            })
        );
    }

    function _sign(bytes32 rid) private returns (bytes memory) {
        bytes32 digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rid));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }
}
