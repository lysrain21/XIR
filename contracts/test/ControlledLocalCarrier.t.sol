// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrierReceiver} from "../src/IBaselineCarrier.sol";
import {ControlledLocalCarrier} from "../src/local/ControlledLocalCarrier.sol";

interface LocalCarrierVm {
    function chainId(uint256 newChainId) external;
}

contract ControlledReceiver is IBaselineCarrierReceiver {
    bytes32 public lastMessageId;
    bytes32 public lastPayloadHash;
    uint256 public deliveries;

    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external {
        lastMessageId = messageId;
        lastPayloadHash = keccak256(payload);
        deliveries++;
    }
}

contract ControlledLocalCarrierTest {
    LocalCarrierVm internal constant VM =
        LocalCarrierVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SOURCE = 3133701;
    uint256 internal constant DESTINATION = 3133702;

    ControlledLocalCarrier internal sourceH;
    ControlledLocalCarrier internal destinationH;
    ControlledLocalCarrier internal sourceL;
    ControlledLocalCarrier internal destinationL;
    ControlledReceiver internal receiver;
    bytes32 internal routeId = keccak256("local-route");

    function setUp() public {
        sourceH = _carrier(SOURCE, DESTINATION, ControlledLocalCarrier.Protocol.Hyperlane);
        destinationH =
            _carrier(DESTINATION, SOURCE, ControlledLocalCarrier.Protocol.Hyperlane);
        sourceL =
            _carrier(SOURCE, DESTINATION, ControlledLocalCarrier.Protocol.LayerZeroV2);
        destinationL =
            _carrier(DESTINATION, SOURCE, ControlledLocalCarrier.Protocol.LayerZeroV2);
        sourceH.setPeer(address(destinationH));
        destinationH.setPeer(address(sourceH));
        sourceL.setPeer(address(destinationL));
        destinationL.setPeer(address(sourceL));
        sourceH.setOutbound(address(this));
        destinationH.setOutbound(address(this));
        sourceL.setOutbound(address(this));
        destinationL.setOutbound(address(this));
        receiver = new ControlledReceiver();
        destinationH.setBaselineReceiver(routeId, address(receiver));
        destinationL.setBaselineReceiver(routeId, address(receiver));
    }

    function testOrderedBaselineDeliveryAndReplayRejection() public {
        bytes memory payload = bytes("matched-local-payload");
        VM.chainId(SOURCE);
        bytes32 messageId = sourceH.sendBaselineSource(routeId, payload, bytes(""));
        VM.chainId(DESTINATION);
        destinationH.receiveBaseline(address(sourceH), messageId, routeId, payload);
        require(receiver.deliveries() == 1, "delivery missing");
        require(receiver.lastPayloadHash() == keccak256(payload), "payload changed");
        try destinationH.receiveBaseline(address(sourceH), messageId, routeId, payload) {
            revert("duplicate delivery succeeded");
        } catch {}
        try destinationL.receiveBaseline(address(sourceH), messageId, routeId, payload) {
            revert("carrier order substitution succeeded");
        } catch {}
    }

    function testOutageRecoveryAndEvidenceAttribution() public {
        bytes32 profile = keccak256("profile");
        bytes32 evidence = keccak256("evidence");
        bytes32 transition = keccak256("transition");
        VM.chainId(SOURCE);
        bytes32 messageId = sourceL.dispatchEvidence(profile, evidence, transition);
        VM.chainId(DESTINATION);
        destinationL.setAvailable(false);
        try destinationL.receiveEvidence(
            address(sourceL), messageId, profile, evidence, transition
        ) {
            revert("unavailable carrier delivered");
        } catch {}
        destinationL.setAvailable(true);
        destinationL.receiveEvidence(
            address(sourceL), messageId, profile, evidence, transition
        );
        require(destinationL.verify(profile, evidence, transition), "evidence missing");
    }

    function testWrongChainAndPeerAreRejected() public {
        VM.chainId(DESTINATION);
        try sourceH.sendBaselineSource(routeId, bytes("payload"), bytes("")) {
            revert("wrong-chain dispatch succeeded");
        } catch {}
        VM.chainId(SOURCE);
        bytes32 messageId =
            sourceH.sendBaselineSource(routeId, bytes("payload"), bytes(""));
        VM.chainId(DESTINATION);
        try destinationH.receiveBaseline(
            address(sourceL), messageId, routeId, bytes("payload")
        ) {
            revert("wrong peer delivered");
        } catch {}
    }

    function _carrier(
        uint256 localChainId,
        uint256 remoteChainId,
        ControlledLocalCarrier.Protocol protocol
    ) private returns (ControlledLocalCarrier) {
        return new ControlledLocalCarrier(
            localChainId,
            remoteChainId,
            protocol,
            address(this),
            address(this)
        );
    }
}
