// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrierReceiver} from "../src/IBaselineCarrier.sol";
import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";
import {IXIRReceiver} from "../src/IXIRReceiver.sol";
import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRTypes} from "../src/XIRTypes.sol";
import {
    NativeAblationIngressV1,
    NativeAblationReceiverV1,
    NativeAblationRootV1,
    NativeAblationTransitionV1
} from "../src/native/NativeAblationV1.sol";
import {NativeRoutePayload} from "../src/native/NativeRoutePayload.sol";

contract AblationCaller {
    function baseline(IBaselineCarrierReceiver receiver, bytes32 id, bytes calldata payload) external {
        receiver.baselineCarrierReceive(id, payload);
    }

    function xir(IXIRReceiver receiver, bytes32 id, bytes calldata payload) external {
        receiver.xirReceive(id, payload);
    }
}

contract AblationEvidenceMock is IXIRCarrierAdapter {
    mapping(bytes32 => bool) internal accepted;
    mapping(bytes32 => bool) internal bundles;

    function set(bytes32 profile, bytes32 evidence, bytes32 transition) external {
        accepted[keccak256(abi.encode(profile, evidence, transition))] = true;
    }

    function setBundle(bytes32 bundle) external {
        bundles[bundle] = true;
    }

    function verify(bytes32 profile, bytes32 evidence, bytes32 transition) external view returns (bool) {
        return accepted[keccak256(abi.encode(profile, evidence, transition))];
    }

    function verifyBundle(bytes32 bundle) external view returns (bool) {
        return bundles[bundle];
    }
}

contract NativeAblationV1Test {
    bytes32 internal constant H_AB = keccak256("H_AB");
    bytes32 internal constant L_AB = keccak256("L_AB");
    bytes32 internal constant H_BC = keccak256("H_BC");
    bytes32 internal constant L_BC = keccak256("L_BC");
    XIRTypes.TypedId internal idA;
    XIRTypes.TypedId internal idB;
    XIRTypes.TypedId internal idC;
    AblationCaller internal hyperlaneBaseline;
    AblationCaller internal layerZeroBaseline;
    AblationCaller internal gateway;
    AblationEvidenceMock internal hyperlaneEvidence;
    AblationEvidenceMock internal layerZeroEvidence;
    NativeAblationReceiverV1 internal receiver;
    NativeAblationRootV1 internal root;

    function setUp() public {
        idA = XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        idB = XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        idC = XIRTypes.TypedId(1, hex"3333333333333333333333333333333333333333");
        hyperlaneBaseline = new AblationCaller();
        layerZeroBaseline = new AblationCaller();
        gateway = new AblationCaller();
        hyperlaneEvidence = new AblationEvidenceMock();
        layerZeroEvidence = new AblationEvidenceMock();
        bytes32[3] memory gatewayHashes =
            [XIREncoding.typedIdHash(idA), XIREncoding.typedIdHash(idB), XIREncoding.typedIdHash(idC)];
        bytes32[4] memory profiles = [H_AB, L_AB, H_BC, L_BC];
        receiver = new NativeAblationReceiverV1(
            address(this),
            address(hyperlaneBaseline),
            address(layerZeroBaseline),
            address(gateway),
            hyperlaneEvidence,
            layerZeroEvidence,
            gatewayHashes,
            profiles
        );
        root = new NativeAblationRootV1(idA);
    }

    function testB0UsesNativeFinalHopAndApplicationReplay() public {
        bytes32 attempt = keccak256("b0-attempt");
        bytes memory payload = _payload(attempt, 0x484c, 1);
        bytes memory encoded = abi.encode(uint8(0), payload);
        hyperlaneBaseline.baseline(receiver, keccak256("native-final"), encoded);
        require(receiver.consumedAttempts(attempt), "B0 effect missing");
        hyperlaneBaseline.baseline(receiver, keccak256("native-replay"), encoded);
        require(receiver.deliveryCount() == 1, "B0 replay produced an effect");
    }

    function testB1AddsExactRecordRidAndMid() public {
        bytes32 attempt = keccak256("b1-attempt");
        bytes memory payload = _payload(attempt, 0x4c48, 2);
        XIRTypes.VerifiedContext memory context = XIRTypes.VerifiedContext(1, keccak256("policy"));
        XIRTypes.TypedId memory destination = XIRTypes.TypedId(1, abi.encodePacked(address(receiver)));
        (XIRTypes.Record memory record, bytes32 rid, bytes32 mid) = root.create(9, destination, payload, context, 1);
        bytes memory encoded = abi.encode(
            uint8(1),
            payload,
            address(0x1111111111111111111111111111111111111111),
            address(this),
            address(receiver),
            record.nonce,
            record.payloadHash,
            context.requiredSecurity,
            context.policyHash,
            uint32(1),
            rid,
            mid
        );
        require(encoded.length <= 840, "B1 payload exceeds LayerZero envelope budget");
        layerZeroBaseline.baseline(receiver, keccak256("native-final-b1"), encoded);
        require(receiver.consumedAttempts(attempt), "B1 effect missing");
        require(receiver.consumedMessages(mid), "B1 mid missing");
    }

    function testB2VerifiesOrderedEvidenceBundle() public {
        bytes32 attempt = keccak256("b2-attempt");
        bytes memory payload = _payload(attempt, 0x484c, 3);
        XIRTypes.VerifiedContext memory context = XIRTypes.VerifiedContext(1, keccak256("policy"));
        XIRTypes.TypedId memory destination = XIRTypes.TypedId(1, abi.encodePacked(address(receiver)));
        (XIRTypes.Record memory record, bytes32 rid,) = root.create(10, destination, payload, context, 1);
        bytes32 recordDigest = XIREncoding.recordHash(record);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        XIRTypes.Receipt[] memory receipts = new XIRTypes.Receipt[](2);
        receipts[0] = XIRTypes.Receipt({
            srcGateway: idA,
            dstGateway: idB,
            profileHash: H_AB,
            evidenceHash: keccak256("H evidence"),
            transitionHash: XIREncoding.transitionHash(recordDigest, contextDigest, idA, idB),
            priorPrefix: XIREncoding.rootPrefix(rid)
        });
        receipts[1] = XIRTypes.Receipt({
            srcGateway: idB,
            dstGateway: idC,
            profileHash: L_BC,
            evidenceHash: keccak256("L evidence"),
            transitionHash: XIREncoding.transitionHash(recordDigest, contextDigest, idB, idC),
            priorPrefix: XIREncoding.nextPrefix(receipts[0].priorPrefix, XIREncoding.receiptHash(receipts[0]))
        });
        bytes32 bundle = XIREncoding.bundleStart(2);
        for (uint256 i = 0; i < receipts.length; i++) {
            layerZeroEvidence.set(receipts[i].profileHash, receipts[i].evidenceHash, receipts[i].transitionHash);
            bundle = XIREncoding.bundleStep(
                bundle, i, receipts[i].profileHash, receipts[i].evidenceHash, receipts[i].transitionHash
            );
        }
        layerZeroEvidence.setBundle(bundle);
        receiver.deliverB2(payload, record, context, 1, receipts);
        require(receiver.consumedAttempts(attempt), "B2 effect missing");

        XIRTypes.Receipt memory swap = receipts[0];
        receipts[0] = receipts[1];
        receipts[1] = swap;
        try receiver.deliverB2(payload, record, context, 1, receipts) {
            revert("reordered B2 trace succeeded");
        } catch {}
    }

    function testB3EntryIsRestrictedToGateway() public {
        bytes32 attempt = keccak256("b3-attempt");
        bytes memory payload = _payload(attempt, 0x4c48, 4);
        bytes32 mid = keccak256("b3-mid");
        gateway.xir(receiver, mid, payload);
        require(receiver.consumedAttempts(attempt), "B3 effect missing");
        try receiver.xirReceive(keccak256("forged"), payload) {
            revert("unauthorized B3 entry succeeded");
        } catch {}
    }

    function testIngressAndB2TransitionRequireNativeEvidence() public {
        NativeAblationIngressV1 ingress =
            new NativeAblationIngressV1(address(hyperlaneBaseline), address(layerZeroBaseline));
        bytes32 attempt = keccak256("transition-attempt");
        bytes memory payload = _payload(attempt, 0x484c, 5);
        hyperlaneBaseline.baseline(ingress, keccak256("first-hop"), payload);
        require(ingress.firstMessageForPayload(keccak256(payload)) != bytes32(0), "ingress missing");

        NativeAblationTransitionV1 transition = new NativeAblationTransitionV1(
            address(this),
            hyperlaneEvidence,
            layerZeroEvidence,
            XIREncoding.typedIdHash(idA),
            XIREncoding.typedIdHash(idB),
            H_AB,
            L_AB
        );
        XIRTypes.VerifiedContext memory context = XIRTypes.VerifiedContext(1, keccak256("policy"));
        XIRTypes.TypedId memory destination = XIRTypes.TypedId(1, abi.encodePacked(address(receiver)));
        (XIRTypes.Record memory record, bytes32 rid,) = root.create(11, destination, payload, context, 1);
        bytes32 digest = XIREncoding.recordHash(record);
        bytes32 contextDigest = XIREncoding.contextHash(context);
        XIRTypes.Receipt memory receipt = XIRTypes.Receipt({
            srcGateway: idA,
            dstGateway: idB,
            profileHash: H_AB,
            evidenceHash: keccak256("accepted-first"),
            transitionHash: XIREncoding.transitionHash(digest, contextDigest, idA, idB),
            priorPrefix: XIREncoding.rootPrefix(rid)
        });
        hyperlaneEvidence.set(receipt.profileHash, receipt.evidenceHash, receipt.transitionHash);
        transition.record(payload, record, context, receipt, 1);
        require(transition.recordedAttempts(attempt), "B2 transition missing");
    }

    function _payload(bytes32 attempt, bytes2 route, uint64 sequence) private pure returns (bytes memory) {
        return abi.encode(
            NativeRoutePayload.Data({
                attemptId: attempt,
                route: route,
                routeSequence: sequence,
                applicationPayload: bytes("matched-application-payload")
            })
        );
    }
}
