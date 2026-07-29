// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Three-stage controlled workload used only on isolated local QBFT chains.
contract LocalScaleWorkload {
    error WrongChain();
    error OnlyRunner();
    error InvalidStage();
    error InvalidPriorDigest();
    error DuplicateStage();

    uint8 public constant SOURCE = 0;
    uint8 public constant INTERMEDIATE = 1;
    uint8 public constant DESTINATION = 2;

    uint256 public immutable localChainId;
    uint8 public immutable stage;
    address public immutable runner;

    mapping(bytes32 => bool) public recorded;
    mapping(bytes32 => bytes32) public applicationEffect;
    mapping(bytes32 => bytes32) public xirTrace;

    event LocalStageRecorded(
        bytes32 indexed attemptId,
        bytes32 indexed pairId,
        uint8 indexed stage,
        uint8 condition,
        bool xir,
        bytes32 priorDigest,
        bytes32 stageDigest,
        bytes32 payloadHash
    );

    constructor(uint256 localChainId_, uint8 stage_, address runner_) {
        if (stage_ > DESTINATION) revert InvalidStage();
        localChainId = localChainId_;
        stage = stage_;
        runner = runner_;
    }

    function recordStage(
        bytes32 attemptId,
        bytes32 pairId,
        uint8 condition,
        bool xir,
        bytes32 payloadHash,
        bytes32 priorDigest
    ) external returns (bytes32 stageDigest) {
        if (block.chainid != localChainId) revert WrongChain();
        if (msg.sender != runner) revert OnlyRunner();
        if (condition > 3) revert InvalidStage();
        if (recorded[attemptId]) revert DuplicateStage();
        bytes32 expected = stage == SOURCE
            ? bytes32(0)
            : digestFor(
                attemptId,
                pairId,
                condition,
                xir,
                payloadHash,
                stage - 1
            );
        if (priorDigest != expected) revert InvalidPriorDigest();
        stageDigest =
            digestFor(attemptId, pairId, condition, xir, payloadHash, stage);
        recorded[attemptId] = true;
        if (xir) {
            bytes32 trace = keccak256(
                abi.encodePacked(
                    "XIR_LOCAL_RECORD_V1",
                    attemptId,
                    pairId,
                    condition,
                    payloadHash
                )
            );
            trace = keccak256(
                abi.encodePacked("XIR_LOCAL_HOP_V1", trace, stage, stageDigest)
            );
            xirTrace[attemptId] = trace;
        }
        if (stage == DESTINATION) {
            applicationEffect[attemptId] = payloadHash;
        }
        emit LocalStageRecorded(
            attemptId,
            pairId,
            stage,
            condition,
            xir,
            priorDigest,
            stageDigest,
            payloadHash
        );
    }

    function digestFor(
        bytes32 attemptId,
        bytes32 pairId,
        uint8 condition,
        bool xir,
        bytes32 payloadHash,
        uint8 stage_
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "XIR_LOCAL_STAGE_V1",
                attemptId,
                pairId,
                condition,
                xir,
                payloadHash,
                stage_
            )
        );
    }
}
