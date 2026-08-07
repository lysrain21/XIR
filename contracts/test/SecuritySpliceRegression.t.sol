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
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract BundleEvidence is IXIRCarrierAdapter {
    mapping(bytes32 => bool) internal accepted;
    mapping(bytes32 => bool) internal bundles;

    function accept(bytes32 profile, bytes32 evidence, bytes32 transition) external {
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

contract SpliceReceiver is IXIRReceiver {
    uint256 public count;

    function xirReceive(bytes32, bytes calldata) external {
        count++;
    }
}

/// @notice Post-fix regression fixture for ordered, final-delivery bundle binding.
contract SecuritySpliceRegressionTest {
    SpliceVm internal constant VM = SpliceVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNER_KEY = 0x51A1CE;
    bytes32 internal constant PAYLOAD_HASH = keccak256("splice-payload");

    XIRTypes.TypedId internal idA;
    XIRTypes.TypedId internal idB;
    XIRTypes.TypedId internal idC;
    XIRTypes.TypedId internal idD;
    XIRRegistry internal registry;
    BundleEvidence internal evidence;
    XIRGateway internal gateway;
    SpliceReceiver internal receiver;

    function setUp() public {
        idA = _id(0x11);
        idB = _id(0x22);
        idC = _id(0x33);
        idD = _id(0x44);
        registry = new XIRRegistry(address(this));
        evidence = new BundleEvidence();
        gateway = new XIRGateway(registry, idD);
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
    }

    function testOneReceiptBundleAccepted() public {
        XIRTypes.TypedId[] memory path = new XIRTypes.TypedId[](2);
        path[0] = idA;
        path[1] = idD;
        XIRTypes.Envelope memory envelope = _envelope(path, 1);
        _acceptExactBundle(envelope);
        gateway.deliver(envelope, bytes("splice-payload"), address(receiver));
        require(receiver.count() == 1, "one-receipt bundle rejected");
    }

    function testTwoReceiptBundleAccepted() public {
        XIRTypes.TypedId[] memory path = new XIRTypes.TypedId[](3);
        path[0] = idA;
        path[1] = idB;
        path[2] = idD;
        XIRTypes.Envelope memory envelope = _envelope(path, 2);
        _acceptExactBundle(envelope);
        gateway.deliver(envelope, bytes("splice-payload"), address(receiver));
        require(receiver.count() == 1, "two-receipt bundle rejected");
    }

    function testThreeReceiptBundleAccepted() public {
        XIRTypes.TypedId[] memory path = new XIRTypes.TypedId[](4);
        path[0] = idA;
        path[1] = idB;
        path[2] = idC;
        path[3] = idD;
        XIRTypes.Envelope memory envelope = _envelope(path, 3);
        _acceptExactBundle(envelope);
        gateway.deliver(envelope, bytes("splice-payload"), address(receiver));
        require(receiver.count() == 1, "three-receipt bundle rejected");
    }

    /// Independent tuple membership from two accepted executions is insufficient.
    function testCrossExecutionSpliceRejectedWithoutExactBundle() public {
        XIRTypes.TypedId[] memory path = new XIRTypes.TypedId[](3);
        path[0] = idA;
        path[1] = idB;
        path[2] = idD;
        XIRTypes.Envelope memory envelope = _envelope(path, 40);
        _acceptTuples(envelope);
        // Each tuple can belong to another real one-receipt bundle.  The ordered
        // two-receipt sequence itself was never authenticated by a native delivery.
        for (uint256 i = 0; i < envelope.receipts.length; i++) {
            XIRTypes.Receipt memory receipt = envelope.receipts[i];
            bytes32 singleton = XIREncoding.bundleStep(
                XIREncoding.bundleStart(1), 0, receipt.profileHash, receipt.evidenceHash, receipt.transitionHash
            );
            evidence.acceptBundle(singleton);
        }
        try gateway.deliver(envelope, bytes("splice-payload"), address(receiver)) {
            revert("cross-execution splice delivered");
        } catch (bytes memory reason) {
            require(_selector(reason) == XIRGateway.BundleRejected.selector, "wrong rejection");
        }
        require(receiver.count() == 0, "splice changed application state");
    }

    function testDeletedReceiptRejected() public {
        XIRTypes.Envelope memory original = _threeHopEnvelope(50);
        _acceptExactBundle(original);
        XIRTypes.Receipt memory first = original.receipts[0];
        XIRTypes.Receipt memory last = original.receipts[2];
        XIRTypes.Envelope memory mutated = original;
        mutated.receipts = new XIRTypes.Receipt[](2);
        mutated.receipts[0] = first;
        mutated.receipts[1] = last;
        try gateway.deliver(mutated, bytes("splice-payload"), address(receiver)) {
            revert("deleted receipt delivered");
        } catch {}
        require(receiver.count() == 0, "deletion changed application state");
    }

    function testReorderedReceiptsRejected() public {
        XIRTypes.Envelope memory original = _threeHopEnvelope(60);
        _acceptExactBundle(original);
        XIRTypes.Envelope memory mutated = original;
        XIRTypes.Receipt memory first = mutated.receipts[0];
        mutated.receipts[0] = mutated.receipts[1];
        mutated.receipts[1] = first;
        _recomputePrefixes(mutated);
        try gateway.deliver(mutated, bytes("splice-payload"), address(receiver)) {
            revert("reordered receipts delivered");
        } catch {}
        require(receiver.count() == 0, "reordering changed application state");
    }

    function testDuplicatedReceiptRejected() public {
        XIRTypes.Envelope memory original = _threeHopEnvelope(70);
        _acceptExactBundle(original);
        XIRTypes.Envelope memory mutated = original;
        mutated.receipts[1] = mutated.receipts[0];
        _recomputePrefixes(mutated);
        try gateway.deliver(mutated, bytes("splice-payload"), address(receiver)) {
            revert("duplicated receipt delivered");
        } catch {}
        require(receiver.count() == 0, "duplication changed application state");
    }

    function _threeHopEnvelope(uint64 nonce) private returns (XIRTypes.Envelope memory) {
        XIRTypes.TypedId[] memory path = new XIRTypes.TypedId[](4);
        path[0] = idA;
        path[1] = idB;
        path[2] = idC;
        path[3] = idD;
        return _envelope(path, nonce);
    }

    function _envelope(XIRTypes.TypedId[] memory path, uint64 nonce)
        private
        returns (XIRTypes.Envelope memory envelope)
    {
        envelope.record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            destinationApp: XIRTypes.TypedId(1, abi.encodePacked(address(receiver))),
            nonce: nonce,
            payloadHash: PAYLOAD_HASH
        });
        envelope.context = XIRTypes.VerifiedContext(1, keccak256("splice-policy"));
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 rid = XIREncoding.rootId(idA, recordDigest, contextDigest, 1);
        envelope.certificate = XIRTypes.RootCertificate(1, _sign(rid));
        envelope.receipts = new XIRTypes.Receipt[](path.length - 1);
        bytes32 prefix = XIREncoding.rootPrefix(rid);
        for (uint256 i = 0; i + 1 < path.length; i++) {
            bytes32 profile = keccak256(abi.encode("profile", nonce, i));
            bytes32 nativeEvidence = keccak256(abi.encode("evidence", nonce, i));
            bytes32 transition = XIREncoding.transitionHash(recordDigest, contextDigest, path[i], path[i + 1]);
            envelope.receipts[i] = XIRTypes.Receipt(path[i], path[i + 1], profile, nativeEvidence, transition, prefix);
            _profile(profile, path[i], path[i + 1]);
            prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(envelope.receipts[i]));
        }
    }

    function _acceptTuples(XIRTypes.Envelope memory envelope) private {
        for (uint256 i = 0; i < envelope.receipts.length; i++) {
            XIRTypes.Receipt memory receipt = envelope.receipts[i];
            evidence.accept(receipt.profileHash, receipt.evidenceHash, receipt.transitionHash);
        }
    }

    function _acceptExactBundle(XIRTypes.Envelope memory envelope) private {
        _acceptTuples(envelope);
        bytes32 commitment = XIREncoding.bundleStart(envelope.receipts.length);
        for (uint256 i = 0; i < envelope.receipts.length; i++) {
            XIRTypes.Receipt memory receipt = envelope.receipts[i];
            commitment = XIREncoding.bundleStep(
                commitment, i, receipt.profileHash, receipt.evidenceHash, receipt.transitionHash
            );
        }
        evidence.acceptBundle(commitment);
    }

    function _recomputePrefixes(XIRTypes.Envelope memory envelope) private pure {
        bytes32 rid = XIREncoding.rootId(
            envelope.record.sourceGateway,
            XIREncoding.recordHash(envelope.record),
            XIREncoding.contextHash(envelope.context),
            envelope.certificate.registryVersion
        );
        bytes32 prefix = XIREncoding.rootPrefix(rid);
        for (uint256 i = 0; i < envelope.receipts.length; i++) {
            envelope.receipts[i].priorPrefix = prefix;
            prefix = XIREncoding.nextPrefix(prefix, XIREncoding.receiptHash(envelope.receipts[i]));
        }
    }

    function _profile(bytes32 profile, XIRTypes.TypedId memory source, XIRTypes.TypedId memory destination) private {
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

    function _id(uint8 fill) private pure returns (XIRTypes.TypedId memory) {
        bytes memory value = new bytes(20);
        for (uint256 i = 0; i < value.length; i++) {
            value[i] = bytes1(fill);
        }
        return XIRTypes.TypedId(1, value);
    }

    function _selector(bytes memory reason) private pure returns (bytes4 selector) {
        if (reason.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(reason, 32))
        }
    }

    function _sign(bytes32 rid) private returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rid));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }
}
