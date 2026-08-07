// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter} from "../src/HyperlaneAdapter.sol";
import {IBaselineCarrier, IBaselineCarrierReceiver} from "../src/IBaselineCarrier.sol";
import {IXIRCarrierAdapter} from "../src/IXIRCarrierAdapter.sol";
import {XIREncoding} from "../src/XIREncoding.sol";
import {XIRGateway} from "../src/XIRGateway.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {XIRTypes} from "../src/XIRTypes.sol";
import {NativeExperimentReceiver} from "../src/native/NativeExperimentReceiver.sol";
import {NativeHomogeneousForwarder} from "../src/native/NativeHomogeneousForwarder.sol";
import {NativeRoutePayload} from "../src/native/NativeRoutePayload.sol";
import {NativeXIRTransitionRecorder} from "../src/native/NativeXIRTransitionRecorder.sol";

interface NativeVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract NativeCarrierMock is IBaselineCarrier {
    IBaselineCarrierReceiver public destination;
    uint256 public fee;
    uint256 public dispatchCount;
    bytes32 public lastRouteId;
    bytes32 public lastPayloadHash;

    function setDestination(IBaselineCarrierReceiver destination_) external {
        destination = destination_;
    }

    function setFee(uint256 fee_) external {
        fee = fee_;
    }

    function quoteBaseline(bytes32, bytes calldata, bytes calldata) external view returns (uint256) {
        return fee;
    }

    function sendBaselineSource(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        payable
        returns (bytes32)
    {
        return _dispatch(routeId, message, options);
    }

    function forwardBaseline(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        payable
        returns (bytes32)
    {
        return _dispatch(routeId, message, options);
    }

    function deliver(IBaselineCarrierReceiver receiver, bytes32 messageId, bytes calldata payload) external {
        receiver.baselineCarrierReceive(messageId, payload);
    }

    function _dispatch(bytes32 routeId, bytes calldata message, bytes calldata) private returns (bytes32 messageId) {
        require(msg.value == fee, "wrong fee");
        dispatchCount++;
        lastRouteId = routeId;
        lastPayloadHash = keccak256(message);
        messageId = keccak256(abi.encode(address(this), dispatchCount, message));
        if (address(destination) != address(0)) {
            destination.baselineCarrierReceive(messageId, message);
        }
    }
}

contract NativeMailboxMock {
    uint256 public dispatchCount;

    function dispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        payable
        returns (bytes32 messageId)
    {
        dispatchCount++;
        messageId = keccak256(abi.encode(destination, recipient, body, dispatchCount));
    }

    function quoteDispatch(uint32, bytes32, bytes calldata) external pure returns (uint256) {
        return 0;
    }

    function deliver(HyperlaneAdapter adapter, uint32 origin, bytes32 sender, bytes calldata body) external {
        adapter.handle(origin, sender, body);
    }
}

contract NativeEvidenceMock is IXIRCarrierAdapter {
    mapping(bytes32 => bool) public accepted;
    mapping(bytes32 => bool) public acceptedBundles;

    function set(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash) external {
        accepted[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))] = true;
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash) external view returns (bool) {
        return accepted[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))];
    }

    function acceptBundle(bytes32 bundleCommitment) external {
        acceptedBundles[bundleCommitment] = true;
    }

    function verifyBundle(bytes32 bundleCommitment) external view returns (bool) {
        return acceptedBundles[bundleCommitment];
    }
}

contract NativeRouteExecutionTest {
    NativeVm internal constant VM = NativeVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNER_KEY = 0xB0B;
    uint32 internal constant VERSION = 1;
    bytes32 internal constant PROFILE_AB = keccak256("native-hyperlane-ab-v1");
    bytes32 internal constant PROFILE_BC = keccak256("native-layerzero-bc-v1");

    NativeCarrierMock internal hyperlane;
    NativeCarrierMock internal layerZero;
    NativeHomogeneousForwarder internal forwarder;
    NativeExperimentReceiver internal receiver;

    function setUp() public {
        hyperlane = new NativeCarrierMock();
        layerZero = new NativeCarrierMock();
        forwarder =
            new NativeHomogeneousForwarder(address(this), hyperlane, hyperlane, layerZero, layerZero, hex"010203");
        receiver =
            new NativeExperimentReceiver(address(hyperlane), address(layerZero), address(this), keccak256("initial"));
        hyperlane.setDestination(receiver);
        layerZero.setDestination(receiver);
    }

    function testHomogeneousRoutesForwardAndApplyEqualMatchedEffects() public {
        bytes memory applicationPayload = bytes("same-matched-application-payload");
        bytes32 hhAttempt = keccak256("hh-attempt");
        bytes32 llAttempt = keccak256("ll-attempt");
        bytes memory hh = _payload(hhAttempt, 0x4848, 7, applicationPayload);
        bytes memory ll = _payload(llAttempt, 0x4c4c, 7, applicationPayload);

        hyperlane.deliver(forwarder, keccak256("hh-inbound"), hh);
        layerZero.deliver(forwarder, keccak256("ll-inbound"), ll);

        require(receiver.deliveryCount() == 2, "effects missing");
        require(forwarder.forwardedAttempts(hhAttempt), "HH not forwarded");
        require(forwarder.forwardedAttempts(llAttempt), "LL not forwarded");
        require(
            receiver.effectClassForAttempt(hhAttempt) == receiver.effectClassForAttempt(llAttempt),
            "matched effect classes differ"
        );
    }

    function testRouteOrderPeerAndReplayRejection() public {
        bytes32 attempt = keccak256("fixed-attempt");
        bytes memory hh = _payload(attempt, 0x4848, 0, bytes("payload"));
        try layerZero.deliver(forwarder, keccak256("wrong-peer"), hh) {
            revert("wrong carrier accepted");
        } catch {}
        hyperlane.deliver(forwarder, keccak256("first"), hh);
        try hyperlane.deliver(forwarder, keccak256("replay"), hh) {
            revert("replay accepted");
        } catch {}
        bytes memory hl = _payload(keccak256("heterogeneous"), 0x484c, 0, bytes("payload"));
        try hyperlane.deliver(forwarder, keccak256("hl"), hl) {
            revert("heterogeneous route bypassed XIR");
        } catch {}
    }

    function testOfficialHyperlaneAdapterInterfaceDrivesNativeForwarder() public {
        NativeMailboxMock mailbox = new NativeMailboxMock();
        bytes32 remote = bytes32(uint256(uint160(address(0x1234))));
        HyperlaneAdapter adapter = new HyperlaneAdapter(address(mailbox), 3133701, remote, address(this), address(this));
        NativeHomogeneousForwarder adapterForwarder =
            new NativeHomogeneousForwarder(address(this), adapter, adapter, layerZero, layerZero, bytes(""));
        adapter.setRunner(address(adapterForwarder));
        adapter.setBaselineReceiver(NativeRoutePayload.routeId(0x4848), address(adapterForwarder));
        bytes memory hh = _payload(keccak256("official-interface"), 0x4848, 1, bytes("payload"));
        mailbox.deliver(
            adapter, 3133701, remote, abi.encode(uint8(2), abi.encode(NativeRoutePayload.routeId(0x4848), hh))
        );
        require(mailbox.dispatchCount() == 1, "official adapter did not dispatch");
    }

    function testHeterogeneousTransitionUsesVerifiedXIRTraceExactlyOnce() public {
        XIRTypes.TypedId memory idA = XIRTypes.TypedId(1, hex"1111111111111111111111111111111111111111");
        XIRTypes.TypedId memory idB = XIRTypes.TypedId(1, hex"2222222222222222222222222222222222222222");
        XIRRegistry registry = new XIRRegistry(address(this));
        NativeEvidenceMock evidence = new NativeEvidenceMock();
        XIRGateway gatewayB = new XIRGateway(registry, idB);
        NativeXIRTransitionRecorder recorder = new NativeXIRTransitionRecorder(gatewayB, address(this));
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
            PROFILE_AB,
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

        bytes32 attempt = keccak256("hl-xir-attempt");
        bytes memory encoded = _payload(attempt, 0x484c, 9, bytes("payload"));
        XIRTypes.Envelope memory envelope = _oneHopEnvelope(encoded, idA, idB, evidence);
        bytes32 transition = recorder.record(encoded, envelope, PROFILE_BC);
        require(transition != bytes32(0), "transition missing");
        require(recorder.transitionForAttempt(attempt) == transition, "transition not bound");
        try recorder.record(encoded, envelope, PROFILE_BC) {
            revert("duplicate transition accepted");
        } catch {}

        bytes memory homogeneous = _payload(keccak256("hh-no-xir"), 0x4848, 9, bytes("payload"));
        try recorder.record(homogeneous, envelope, PROFILE_BC) {
            revert("homogeneous transition accepted");
        } catch {}
    }

    function _oneHopEnvelope(
        bytes memory encoded,
        XIRTypes.TypedId memory idA,
        XIRTypes.TypedId memory idB,
        NativeEvidenceMock evidence
    ) private returns (XIRTypes.Envelope memory envelope) {
        envelope.record = XIRTypes.Record({
            sourceGateway: idA,
            sourceApp: XIRTypes.TypedId(1, hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            destinationApp: XIRTypes.TypedId(1, hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            nonce: 9,
            payloadHash: keccak256(encoded)
        });
        envelope.context = XIRTypes.VerifiedContext({requiredSecurity: 2, policyHash: keccak256("native-policy")});
        bytes32 recordDigest = XIREncoding.recordHash(envelope.record);
        bytes32 contextDigest = XIREncoding.contextHash(envelope.context);
        bytes32 rid = XIREncoding.rootId(idA, recordDigest, contextDigest, VERSION);
        envelope.certificate = XIRTypes.RootCertificate({registryVersion: VERSION, signature: _sign(rid)});
        envelope.receipts = new XIRTypes.Receipt[](1);
        bytes32 evidenceHash = keccak256("official-hyperlane-message-id");
        bytes32 transition = XIREncoding.transitionHash(recordDigest, contextDigest, idA, idB);
        envelope.receipts[0] = XIRTypes.Receipt({
            srcGateway: idA,
            dstGateway: idB,
            profileHash: PROFILE_AB,
            evidenceHash: evidenceHash,
            transitionHash: transition,
            priorPrefix: XIREncoding.rootPrefix(rid)
        });
        evidence.set(PROFILE_AB, evidenceHash, transition);
        bytes32 bundleCommitment =
            XIREncoding.bundleStep(XIREncoding.bundleStart(1), 0, PROFILE_AB, evidenceHash, transition);
        evidence.acceptBundle(bundleCommitment);
    }

    function _payload(bytes32 attemptId, bytes2 route, uint64 routeSequence, bytes memory applicationPayload)
        private
        pure
        returns (bytes memory)
    {
        return abi.encode(
            NativeRoutePayload.Data({
                attemptId: attemptId, route: route, routeSequence: routeSequence, applicationPayload: applicationPayload
            })
        );
    }

    function _sign(bytes32 rid) private returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rid));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }
}
