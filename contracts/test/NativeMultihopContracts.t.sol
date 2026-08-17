// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";
import {NativeMultihopPayload} from "../src/native/NativeMultihopPayload.sol";
import {NativeMultihopReceiver} from "../src/native/NativeMultihopReceiver.sol";
import {NativeMultihopTransitionRecorder} from "../src/native/NativeMultihopTransitionRecorder.sol";
import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRGateway} from "../src/XIRGateway.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {XIRTypes} from "../src/XIRTypes.sol";

interface MultihopVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract MultihopEvidenceMock is IXIRCarrierAdapter {
    mapping(bytes32 => bool) internal accepted;
    mapping(bytes32 => bool) internal bundles;

    function set(bytes32 profile, bytes32 evidence, bytes32 transition) external {
        accepted[keccak256(abi.encode(profile, evidence, transition))] = true;
    }

    function acceptBundle(bytes32 commitment) external {
        bundles[commitment] = true;
    }

    function verify(bytes32 profile, bytes32 evidence, bytes32 transition) external view returns (bool) {
        return accepted[keccak256(abi.encode(profile, evidence, transition))];
    }

    function verifyBundle(bytes32 commitment) external view returns (bool) {
        return bundles[commitment];
    }
}

contract NativeMultihopContractsTest {
    MultihopVm internal constant VM = MultihopVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNER_KEY = 0xA11CE;
    uint32 internal constant VERSION = 1;

    struct FourHopFixture {
        bytes encoded;
        XIRTypes.Envelope envelope;
        NativeMultihopTransitionRecorder recorder;
    }

    function testDynamicPayloadAndReceiverApplyOneEffect() public {
        NativeMultihopPayload.Data memory data = NativeMultihopPayload.Data({
            attemptId: keccak256("attempt"),
            route: bytes("HLHL"),
            routeSequence: 77,
            applicationPayload: bytes("payload")
        });
        bytes memory encoded = abi.encode(data);
        NativeMultihopReceiver receiver = new NativeMultihopReceiver(address(this), keccak256("initial"));
        receiver.xirReceive(keccak256("mid"), encoded);
        require(receiver.deliveryCount() == 1, "effect missing");
        require(receiver.consumedAttempts(data.attemptId), "attempt not consumed");
        try receiver.xirReceive(keccak256("mid-2"), encoded) {
            revert("duplicate accepted");
        } catch {}
    }

    function testTransitionRequiresRealSwitchAndExactPrefixLength() public {
        XIRTypes.TypedId memory idA = XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        XIRTypes.TypedId memory idB = XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        bytes32 profile = keccak256("route-HL-hop-1");
        XIRRegistry registry = new XIRRegistry(address(this));
        XIRGateway gateway = new XIRGateway(registry, idB);
        MultihopEvidenceMock evidence = new MultihopEvidenceMock();
        NativeMultihopTransitionRecorder recorder = new NativeMultihopTransitionRecorder(gateway, address(this));
        registry.setRoot(
            VERSION,
            XIRRegistry.RootSnapshot({
                gatewayHash: XIREncoding.typedIdHash(idA),
                signer: VM.addr(SIGNER_KEY),
                validAfter: 0,
                validUntil: 0,
                enabled: true
            })
        );
        registry.setProfile(
            profile,
            XIRRegistry.ProfileSnapshot({
                srcHash: XIREncoding.typedIdHash(idA),
                dstHash: XIREncoding.typedIdHash(idB),
                adapter: address(evidence),
                securityLevel: 2,
                validAfter: 0,
                validUntil: 0,
                enabled: true
            })
        );
        bytes memory encoded = abi.encode(
            NativeMultihopPayload.Data({
                attemptId: keccak256("hl"), route: bytes("HL"), routeSequence: 3, applicationPayload: bytes("payload")
            })
        );
        XIRTypes.Envelope memory envelope = _envelope(encoded, idA, idB, profile, evidence);
        bytes32 transition = recorder.record(encoded, envelope, 1, keccak256("route-HL-hop-2"));
        require(transition != bytes32(0), "transition missing");
        try recorder.record(encoded, envelope, 1, keccak256("route-HL-hop-2")) {
            revert("duplicate accepted");
        } catch {}
        bytes memory homogeneous = abi.encode(
            NativeMultihopPayload.Data({
                attemptId: keccak256("hh"), route: bytes("HH"), routeSequence: 3, applicationPayload: bytes("payload")
            })
        );
        XIRTypes.Envelope memory homogeneousEnvelope = _envelope(homogeneous, idA, idB, profile, evidence);
        try recorder.record(homogeneous, homogeneousEnvelope, 1, keccak256("next")) {
            revert("non-switch accepted");
        } catch {}
    }

    function testFourHopTransitionVerifiesThreeReceiptPrefix() public {
        FourHopFixture memory fixture = _fourHopFixture();
        bytes32 validSecondPrefix = fixture.envelope.receipts[1].priorPrefix;
        fixture.envelope.receipts[1].priorPrefix = keccak256("wrong-prefix");
        try fixture.recorder.record(fixture.encoded, fixture.envelope, 3, keccak256("hhhl-hop-4")) {
            revert("broken prefix accepted");
        } catch {}
        fixture.envelope.receipts[1].priorPrefix = validSecondPrefix;
        bytes32 protocolTransition =
            fixture.recorder.record(fixture.encoded, fixture.envelope, 3, keccak256("hhhl-hop-4"));
        require(protocolTransition != bytes32(0), "four-hop transition missing");
    }

    function _fourHopFixture() private returns (FourHopFixture memory fixture) {
        XIRTypes.TypedId[4] memory ids = [
            XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111"),
            XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222"),
            XIRTypes.TypedId(1, hex"3333333333333333333333333333333333333333"),
            XIRTypes.TypedId(1, hex"4444444444444444444444444444444444444444")
        ];
        XIRRegistry registry = new XIRRegistry(address(this));
        XIRGateway gateway = new XIRGateway(registry, ids[3]);
        MultihopEvidenceMock evidence = new MultihopEvidenceMock();
        fixture.recorder = new NativeMultihopTransitionRecorder(gateway, address(this));
        registry.setRoot(
            VERSION,
            XIRRegistry.RootSnapshot({
                gatewayHash: XIREncoding.typedIdHash(ids[0]),
                signer: VM.addr(SIGNER_KEY),
                validAfter: 0,
                validUntil: 0,
                enabled: true
            })
        );
        fixture.encoded = abi.encode(
            NativeMultihopPayload.Data({
                attemptId: keccak256("hhhl"),
                route: bytes("HHHL"),
                routeSequence: 9,
                applicationPayload: bytes("payload")
            })
        );
        fixture.envelope.record = XIRTypes.Record({
            sourceGateway: ids[0],
            sourceApp: XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            destinationApp: XIRTypes.TypedId(1, hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            nonce: 9,
            payloadHash: keccak256(fixture.encoded)
        });
        fixture.envelope.context = XIRTypes.VerifiedContext({requiredSecurity: 2, policyHash: keccak256("policy")});
        bytes32 recordDigest = XIREncoding.recordHash(fixture.envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(fixture.envelope.context);
        bytes32 rid = XIREncoding.rootId(ids[0], recordDigest, contextDigest, VERSION);
        fixture.envelope.certificate = XIRTypes.RootCertificate({registryVersion: VERSION, signature: _sign(rid)});
        bytes32 bundle;
        (fixture.envelope.receipts, bundle) =
            _fourHopReceipts(registry, evidence, ids, recordDigest, contextDigest, rid);
        evidence.acceptBundle(bundle);
    }

    function _fourHopReceipts(
        XIRRegistry registry,
        MultihopEvidenceMock evidence,
        XIRTypes.TypedId[4] memory ids,
        bytes32 recordDigest,
        bytes32 contextDigest,
        bytes32 rid
    ) private returns (XIRTypes.Receipt[] memory receipts, bytes32 bundle) {
        receipts = new XIRTypes.Receipt[](3);
        bytes32 prefix = XIREncoding.rootPrefix(rid);
        bundle = XIREncoding.bundleStart(3);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 profile = keccak256(abi.encode("hhhl-profile", i));
            bytes32 evidenceHash = keccak256(abi.encode("hhhl-evidence", i));
            bytes32 transition = XIREncoding.transitionHash(recordDigest, contextDigest, ids[i], ids[i + 1]);
            receipts[i] = XIRTypes.Receipt({
                srcGateway: ids[i],
                dstGateway: ids[i + 1],
                profileHash: profile,
                evidenceHash: evidenceHash,
                transitionHash: transition,
                priorPrefix: prefix
            });
            registry.setProfile(
                profile,
                XIRRegistry.ProfileSnapshot({
                    srcHash: XIREncoding.typedIdHash(ids[i]),
                    dstHash: XIREncoding.typedIdHash(ids[i + 1]),
                    adapter: address(evidence),
                    securityLevel: 2,
                    validAfter: 0,
                    validUntil: 0,
                    enabled: true
                })
            );
            evidence.set(profile, evidenceHash, transition);
            bundle = XIREncoding.bundleStep(bundle, i, profile, evidenceHash, transition);
            prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(receipts[i]));
        }
    }

    function _envelope(
        bytes memory payload,
        XIRTypes.TypedId memory idA,
        XIRTypes.TypedId memory idB,
        bytes32 profile,
        MultihopEvidenceMock evidence
    ) private returns (XIRTypes.Envelope memory envelope) {
        envelope.record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            destinationApp: XIRTypes.TypedId(1, hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            nonce: 3,
            payloadHash: keccak256(payload)
        });
        envelope.context = XIRTypes.VerifiedContext({requiredSecurity: 2, policyHash: keccak256("policy")});
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 rid = XIREncoding.rootId(idA, recordDigest, contextDigest, VERSION);
        envelope.certificate = XIRTypes.RootCertificate({registryVersion: VERSION, signature: _sign(rid)});
        envelope.receipts = new XIRTypes.Receipt[](1);
        bytes32 evidenceHash = keccak256("evidence");
        bytes32 transition = XIREncoding.transitionHash(recordDigest, contextDigest, idA, idB);
        envelope.receipts[0] = XIRTypes.Receipt({
            srcGateway: idA,
            dstGateway: idB,
            profileHash: profile,
            evidenceHash: evidenceHash,
            transitionHash: transition,
            priorPrefix: XIREncoding.rootPrefix(rid)
        });
        evidence.set(profile, evidenceHash, transition);
        evidence.acceptBundle(XIREncoding.bundleStep(XIREncoding.bundleStart(1), 0, profile, evidenceHash, transition));
    }

    function _sign(bytes32 rid) private returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rid));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }
}
