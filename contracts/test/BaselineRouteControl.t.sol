// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    BaselineRouteControl,
    IBaselineEffectReceiver
} from "../src/BaselineRouteControl.sol";
import {IBaselineCarrier} from "../src/IBaselineCarrier.sol";

contract MockBaselineCarrier is IBaselineCarrier {
    uint256 public sourceCount;
    uint256 public forwardCount;
    bytes32 public lastPayloadHash;

    function quoteBaseline(bytes32, bytes calldata, bytes calldata)
        external
        pure
        returns (uint256)
    {
        return 1;
    }

    function sendBaselineSource(bytes32, bytes calldata message, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        sourceCount++;
        lastPayloadHash = keccak256(message);
        return keccak256(abi.encode("source", sourceCount, message));
    }

    function forwardBaseline(bytes32, bytes calldata message, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        forwardCount++;
        lastPayloadHash = keccak256(message);
        return keccak256(abi.encode("forward", forwardCount, message));
    }
}

contract MockBaselineReceiver is IBaselineEffectReceiver {
    uint256 public count;
    bytes32 public lastMessageId;
    bytes32 public lastPayloadHash;

    function baselineReceive(bytes32 messageId, bytes calldata payload) external {
        count++;
        lastMessageId = messageId;
        lastPayloadHash = keccak256(payload);
    }
}

contract BaselineInbound {
    function forward(
        BaselineRouteControl route,
        bytes32 messageId,
        bytes calldata payload
    ) external returns (bytes32) {
        return route.receiveFirstLegAndForward(messageId, payload, bytes(""));
    }

    function deliver(BaselineRouteControl route, bytes32 messageId, bytes calldata payload)
        external
    {
        route.receiveSecondLegAndApply(messageId, payload);
    }
}

contract BaselineRunner {
    function dispatch(BaselineRouteControl route, bytes calldata payload)
        external
        returns (bytes32)
    {
        return route.dispatchSource(payload, bytes(""));
    }
}

contract BaselineRouteControlTest {
    function testAllFourCarrierSequencesUseExactlyTwoCarrierOnlyLegs() public {
        _assertSequence(
            BaselineRouteControl.Carrier.Hyperlane,
            BaselineRouteControl.Carrier.Hyperlane
        );
        _assertSequence(
            BaselineRouteControl.Carrier.Hyperlane,
            BaselineRouteControl.Carrier.LayerZeroV2
        );
        _assertSequence(
            BaselineRouteControl.Carrier.LayerZeroV2,
            BaselineRouteControl.Carrier.Hyperlane
        );
        _assertSequence(
            BaselineRouteControl.Carrier.LayerZeroV2,
            BaselineRouteControl.Carrier.LayerZeroV2
        );
    }

    function _assertSequence(
        BaselineRouteControl.Carrier first,
        BaselineRouteControl.Carrier second
    ) private {
        MockBaselineCarrier firstPort = new MockBaselineCarrier();
        MockBaselineCarrier secondPort = new MockBaselineCarrier();
        MockBaselineReceiver receiver = new MockBaselineReceiver();
        BaselineInbound firstInbound = new BaselineInbound();
        BaselineInbound secondInbound = new BaselineInbound();
        BaselineRunner runner = new BaselineRunner();
        BaselineRouteControl route = new BaselineRouteControl(
            keccak256(abi.encode("route", first, second)),
            first,
            second,
            firstPort,
            secondPort,
            address(firstInbound),
            address(secondInbound),
            receiver,
            address(this),
            address(runner)
        );
        bytes memory payload = bytes("fixed-payload");
        bytes32 firstMessage = runner.dispatch(route, payload);
        bytes32 secondMessage = firstInbound.forward(route, firstMessage, payload);
        secondInbound.deliver(route, secondMessage, payload);
        require(firstPort.sourceCount() == 1, "source leg count");
        require(secondPort.forwardCount() == 1, "second leg count");
        require(receiver.count() == 1, "destination effect count");
        require(receiver.lastPayloadHash() == keccak256(payload), "payload changed");
    }
}
