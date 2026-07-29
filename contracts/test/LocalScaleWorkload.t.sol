// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LocalScaleWorkload} from "../src/local/LocalScaleWorkload.sol";

interface LocalScaleVm {
    function chainId(uint256 newChainId) external;
}

contract LocalScaleWorkloadTest {
    LocalScaleVm internal constant VM =
        LocalScaleVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SOURCE_CHAIN = 3133701;
    uint256 internal constant INTERMEDIATE_CHAIN = 3133702;
    uint256 internal constant DESTINATION_CHAIN = 3133703;

    LocalScaleWorkload internal source;
    LocalScaleWorkload internal intermediate;
    LocalScaleWorkload internal destination;

    function setUp() public {
        source = new LocalScaleWorkload(SOURCE_CHAIN, 0, address(this));
        intermediate = new LocalScaleWorkload(INTERMEDIATE_CHAIN, 1, address(this));
        destination = new LocalScaleWorkload(DESTINATION_CHAIN, 2, address(this));
    }

    function testBaselineAndXirPreserveMatchedEffectAcrossThreeStages() public {
        bytes32 pairId = keccak256("pair");
        bytes32 payloadHash = keccak256("payload");
        bytes32 baselineAttempt = keccak256("baseline");
        bytes32 xirAttempt = keccak256("xir");
        _run(baselineAttempt, pairId, payloadHash, false);
        _run(xirAttempt, pairId, payloadHash, true);
        require(
            destination.applicationEffect(baselineAttempt)
                == destination.applicationEffect(xirAttempt),
            "matched effect differs"
        );
        require(source.xirTrace(baselineAttempt) == bytes32(0), "baseline has XIR trace");
        require(source.xirTrace(xirAttempt) != bytes32(0), "XIR trace missing");
    }

    function testWrongPriorWrongChainAndReplayAreRejected() public {
        bytes32 attemptId = keccak256("negative");
        bytes32 pairId = keccak256("pair");
        bytes32 payloadHash = keccak256("payload");
        VM.chainId(INTERMEDIATE_CHAIN);
        try intermediate.recordStage(
            attemptId, pairId, 0, true, payloadHash, bytes32(0)
        ) {
            revert("wrong prior succeeded");
        } catch {}
        VM.chainId(SOURCE_CHAIN);
        source.recordStage(attemptId, pairId, 0, true, payloadHash, bytes32(0));
        try source.recordStage(
            attemptId, pairId, 0, true, payloadHash, bytes32(0)
        ) {
            revert("replay succeeded");
        } catch {}
        VM.chainId(DESTINATION_CHAIN);
        try source.recordStage(
            keccak256("wrong-chain"), pairId, 0, false, payloadHash, bytes32(0)
        ) {
            revert("wrong chain succeeded");
        } catch {}
    }

    function _run(
        bytes32 attemptId,
        bytes32 pairId,
        bytes32 payloadHash,
        bool xir
    ) private {
        VM.chainId(SOURCE_CHAIN);
        bytes32 first =
            source.recordStage(attemptId, pairId, 0, xir, payloadHash, bytes32(0));
        VM.chainId(INTERMEDIATE_CHAIN);
        bytes32 second =
            intermediate.recordStage(attemptId, pairId, 0, xir, payloadHash, first);
        VM.chainId(DESTINATION_CHAIN);
        destination.recordStage(attemptId, pairId, 0, xir, payloadHash, second);
    }
}
