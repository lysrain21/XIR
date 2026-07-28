// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";
import {IXIRReceiver} from "../src/IXIRReceiver.sol";
import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRGateway} from "../src/XIRGateway.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {XIRTypes} from "../src/XIRTypes.sol";

interface TestVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract SafetyEvidence is IXIRCarrierAdapter {
    mapping(bytes32 => bool) public accepted;

    function set(
        bytes32 profileHash,
        bytes32 evidenceHash,
        bytes32 transitionHash,
        bool value
    ) external {
        accepted[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))] = value;
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash)
        external
        view
        returns (bool)
    {
        return accepted[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))];
    }
}

contract SafetyReceiver is IXIRReceiver {
    uint256 public count;
    bytes32 public lastMid;

    function xirReceive(bytes32 mid, bytes calldata) external {
        count++;
        lastMid = mid;
    }
}

contract ArbitraryTarget is IXIRReceiver {
    uint256 public callCount;

    function xirReceive(bytes32, bytes calldata) external {
        callCount++;
    }
}

contract EncodingHarness {
    function encode(XIRTypes.TypedId calldata id) external pure returns (bytes memory) {
        return XIREncoding.encodeTypedId(id);
    }
}

contract XIRGatewaySafetyTest {
    TestVm internal constant VM =
        TestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNER_KEY = 0xA11CE;
    uint32 internal constant VERSION = 1;
    bytes32 internal constant PROFILE_AB = keccak256("hyperlane-op-arb-v1");
    bytes32 internal constant PROFILE_BC = keccak256("layerzero-arb-base-v1");
    bytes32 internal constant EVIDENCE_AB = keccak256("hyperlane-message-id");
    bytes32 internal constant EVIDENCE_BC = keccak256("layerzero-guid");

    XIRTypes.TypedId internal idA;
    XIRTypes.TypedId internal idB;
    XIRTypes.TypedId internal idC;
    XIRRegistry internal registry;
    SafetyEvidence internal firstEvidence;
    SafetyEvidence internal secondEvidence;
    XIRGateway internal gatewayC;
    SafetyReceiver internal receiver;

    function setUp() public {
        idA = XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        idB = XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        idC = XIRTypes.TypedId(1, hex"3333333333333333333333333333333333333333");
        registry = new XIRRegistry(address(this));
        firstEvidence = new SafetyEvidence();
        secondEvidence = new SafetyEvidence();
        gatewayC = new XIRGateway(registry, idC);
        receiver = new SafetyReceiver();
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
        _setProfile(PROFILE_AB, idA, idB, address(firstEvidence), 2, 0);
        _setProfile(PROFILE_BC, idB, idC, address(secondEvidence), 2, 0);
    }

    function testTwoHopDeliveryAndReplayRejection() public {
        XIRTypes.Envelope memory envelope = _envelope();
        gatewayC.deliver(envelope, bytes("fixed-payload"), address(receiver));
        require(receiver.count() == 1, "delivery missing");
        try gatewayC.deliver(envelope, bytes("fixed-payload"), address(receiver)) {
            revert("replay succeeded");
        } catch {}
        require(receiver.count() == 1, "replay changed receiver");
    }

    function testPayloadAndEvidenceTamperingAreRejected() public {
        XIRTypes.Envelope memory envelope = _envelope();
        try gatewayC.deliver(envelope, bytes("changed"), address(receiver)) {
            revert("payload tampering succeeded");
        } catch {}
        envelope.receipts[1].evidenceHash = keccak256("forged-evidence");
        try gatewayC.deliver(envelope, bytes("fixed-payload"), address(receiver)) {
            revert("evidence tampering succeeded");
        } catch {}
    }

    function testExpiredProfileIsRejected() public {
        _setProfile(PROFILE_BC, idB, idC, address(secondEvidence), 2, 2);
        VM.warp(2);
        try gatewayC.verifyTrace(_envelope()) {
            revert("expired profile succeeded");
        } catch {}
    }

    function testDestinationBindingRejectsArbitraryTarget() public {
        XIRTypes.Envelope memory envelope = _envelope();
        ArbitraryTarget target = new ArbitraryTarget();
        try gatewayC.deliver(envelope, bytes("fixed-payload"), address(target)) {
            revert("arbitrary target call succeeded");
        } catch {}
        require(target.callCount() == 0, "arbitrary target was called");
    }

    function testFuzzTypedIdLengthIsStrict(uint8 rawLength) public {
        uint256 length = uint256(rawLength) % 41;
        XIRTypes.TypedId memory id = XIRTypes.TypedId(1, new bytes(length));
        EncodingHarness harness = new EncodingHarness();
        if (length == 20) {
            require(harness.encode(id).length == 22, "valid EVM identifier rejected");
        } else {
            try harness.encode(id) {
                revert("invalid EVM identifier accepted");
            } catch {}
        }
    }

    function _envelope() private returns (XIRTypes.Envelope memory envelope) {
        envelope.record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(
                1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            destinationApp: XIRTypes.TypedId(1, abi.encodePacked(address(receiver))),
            nonce: 7,
            payloadHash: keccak256("fixed-payload")
        });
        envelope.context = XIRTypes.VerifiedContext({
            requiredSecurity: 2, policyHash: keccak256("policy")
        });
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 rid = XIREncoding.rootId(idA, recordDigest, contextDigest, VERSION);
        envelope.certificate = XIRTypes.RootCertificate(VERSION, _sign(rid));
        envelope.receipts = new XIRTypes.Receipt[](2);
        bytes32 prefix = XIREncoding.rootPrefix(rid);
        envelope.receipts[0] =
            _receipt(idA, idB, PROFILE_AB, EVIDENCE_AB, prefix, firstEvidence);
        prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(envelope.receipts[0]));
        envelope.receipts[1] =
            _receipt(idB, idC, PROFILE_BC, EVIDENCE_BC, prefix, secondEvidence);
    }

    function _receipt(
        XIRTypes.TypedId memory src,
        XIRTypes.TypedId memory dst,
        bytes32 profile,
        bytes32 evidence,
        bytes32 prefix,
        SafetyEvidence adapter
    ) private returns (XIRTypes.Receipt memory receipt) {
        XIRTypes.Record memory record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(
                1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            destinationApp: XIRTypes.TypedId(1, abi.encodePacked(address(receiver))),
            nonce: 7,
            payloadHash: keccak256("fixed-payload")
        });
        XIRTypes.VerifiedContext memory context =
            XIRTypes.VerifiedContext(2, keccak256("policy"));
        bytes32 transition = XIREncoding.transitionHash(
            XIREncoding.recordHash(record), XIREncoding.contextHash(context), src, dst
        );
        receipt = XIRTypes.Receipt(src, dst, profile, evidence, transition, prefix);
        adapter.set(profile, evidence, transition, true);
    }

    function _setProfile(
        bytes32 profile,
        XIRTypes.TypedId memory src,
        XIRTypes.TypedId memory dst,
        address adapter,
        uint8 security,
        uint64 validUntil
    ) private {
        registry.setProfile(
            profile,
            XIRRegistry.ProfileSnapshot({
                srcHash: XIREncoding.typedIdHash(src),
                dstHash: XIREncoding.typedIdHash(dst),
                adapter: adapter,
                securityLevel: security,
                validAfter: 0,
                validUntil: validUntil,
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
