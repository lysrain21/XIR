// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LocalScaleWorkload} from "../src/local/LocalScaleWorkload.sol";

interface PaperVm {
    function chainId(uint256 newChainId) external;
}

contract LocalPaperScaleWorkloadTest {
    PaperVm internal constant VM =
        PaperVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant CHAIN = 910001;
    bytes32 internal constant PAYLOAD = keccak256("balanced-payload");

    function testAllFourRoutesApplyXirOnlyAcrossProtocols() public {
        for (uint8 route = 0; route < 4; route++) {
            bytes32 attempt = keccak256(abi.encode("attempt", route));
            (
                LocalScaleWorkload.Protocol first,
                LocalScaleWorkload.Protocol second,
                bool xir
            ) = _definition(route);

            VM.chainId(CHAIN);
            LocalScaleWorkload source = new LocalScaleWorkload(CHAIN, 0, address(this));
            LocalScaleWorkload intermediate =
                new LocalScaleWorkload(CHAIN, 1, address(this));
            LocalScaleWorkload destination =
                new LocalScaleWorkload(CHAIN, 2, address(this));

            bytes32 firstEnvelope = source.recordRouteStage(
                attempt, route, first, second, xir, PAYLOAD, 64, bytes32(0)
            );
            bytes32 secondEnvelope = intermediate.recordRouteStage(
                attempt, route, first, second, xir, PAYLOAD, 64, firstEnvelope
            );
            destination.recordRouteStage(
                attempt, route, first, second, xir, PAYLOAD, 64, secondEnvelope
            );

            require(
                (intermediate.xirTransition(attempt) != bytes32(0)) == xir,
                "wrong XIR attribution"
            );
            require(
                destination.applicationEffect(attempt) != bytes32(0),
                "missing application effect"
            );
        }
    }

    function testReplayWrongProtocolOrderPriorAndXirAreRejected() public {
        VM.chainId(CHAIN);
        LocalScaleWorkload source = new LocalScaleWorkload(CHAIN, 0, address(this));
        bytes32 attempt = keccak256("negative");
        source.recordRouteStage(
            attempt,
            0,
            LocalScaleWorkload.Protocol.Hyperlane,
            LocalScaleWorkload.Protocol.Hyperlane,
            false,
            PAYLOAD,
            32,
            bytes32(0)
        );
        try source.recordRouteStage(
            attempt,
            0,
            LocalScaleWorkload.Protocol.Hyperlane,
            LocalScaleWorkload.Protocol.Hyperlane,
            false,
            PAYLOAD,
            32,
            bytes32(0)
        ) {
            revert("replay accepted");
        } catch {}
        try source.recordRouteStage(
            keccak256("wrong-order"),
            0,
            LocalScaleWorkload.Protocol.LayerZeroV2,
            LocalScaleWorkload.Protocol.Hyperlane,
            false,
            PAYLOAD,
            32,
            bytes32(0)
        ) {
            revert("wrong carrier accepted");
        } catch {}
        try source.recordRouteStage(
            keccak256("wrong-xir"),
            0,
            LocalScaleWorkload.Protocol.Hyperlane,
            LocalScaleWorkload.Protocol.Hyperlane,
            true,
            PAYLOAD,
            32,
            bytes32(0)
        ) {
            revert("wrong XIR accepted");
        } catch {}
        try source.recordRouteStage(
            keccak256("wrong-prior"),
            0,
            LocalScaleWorkload.Protocol.Hyperlane,
            LocalScaleWorkload.Protocol.Hyperlane,
            false,
            PAYLOAD,
            32,
            keccak256("unexpected")
        ) {
            revert("wrong prior accepted");
        } catch {}
    }

    function _definition(uint8 route)
        private
        pure
        returns (
            LocalScaleWorkload.Protocol first,
            LocalScaleWorkload.Protocol second,
            bool xir
        )
    {
        first = route < 2
            ? LocalScaleWorkload.Protocol.Hyperlane
            : LocalScaleWorkload.Protocol.LayerZeroV2;
        second = route % 2 == 0
            ? LocalScaleWorkload.Protocol.Hyperlane
            : LocalScaleWorkload.Protocol.LayerZeroV2;
        xir = first != second;
    }
}
