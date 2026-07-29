// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Protocol-distinct workload for the isolated three-chain paper experiment.
/// @dev Hyperlane and LayerZero are controlled adapters, not vendor deployments.
contract LocalScaleWorkload {
    error WrongChain();
    error OnlyRunner();
    error InvalidStage();
    error InvalidRoute();
    error InvalidCarrierOrder();
    error InvalidXIRAssignment();
    error InvalidPriorEnvelope();
    error DuplicateStage();

    enum Protocol {
        Hyperlane,
        LayerZeroV2
    }

    uint8 public constant SOURCE = 0;
    uint8 public constant INTERMEDIATE = 1;
    uint8 public constant DESTINATION = 2;
    bytes32 public constant XIR_VERSION = keccak256("XIR_LOCAL_TRANSITION_V2");

    uint256 public immutable localChainId;
    uint8 public immutable stage;
    address public immutable runner;

    mapping(bytes32 => bool) public recorded;
    mapping(bytes32 => bytes32) public applicationEffect;
    mapping(bytes32 => bytes32) public xirTransition;

    event RouteStageRecorded(
        bytes32 indexed attemptId,
        uint8 indexed route,
        uint8 indexed stage,
        Protocol firstCarrier,
        Protocol secondCarrier,
        bool xir,
        bytes32 payloadHash,
        uint32 payloadBytes,
        bytes32 priorEnvelope,
        bytes32 stageEnvelope
    );

    event XIRTransitionRecorded(
        bytes32 indexed attemptId,
        uint8 indexed route,
        Protocol indexed inboundCarrier,
        Protocol outboundCarrier,
        bytes32 inboundEnvelope,
        bytes32 outboundEnvelope,
        bytes32 transitionDigest,
        bytes32 version
    );

    event ApplicationEffectRecorded(
        bytes32 indexed attemptId,
        uint8 indexed route,
        bytes32 indexed payloadHash,
        bytes32 effectDigest
    );

    constructor(uint256 localChainId_, uint8 stage_, address runner_) {
        if (stage_ > DESTINATION) revert InvalidStage();
        localChainId = localChainId_;
        stage = stage_;
        runner = runner_;
    }

    function recordRouteStage(
        bytes32 attemptId,
        uint8 route,
        Protocol firstCarrier,
        Protocol secondCarrier,
        bool xir,
        bytes32 payloadHash,
        uint32 payloadBytes,
        bytes32 priorEnvelope
    ) external returns (bytes32 stageEnvelope) {
        if (block.chainid != localChainId) revert WrongChain();
        if (msg.sender != runner) revert OnlyRunner();
        if (route > 3) revert InvalidRoute();
        if (recorded[attemptId]) revert DuplicateStage();

        (Protocol expectedFirst, Protocol expectedSecond, bool expectedXir) =
            routeDefinition(route);
        if (firstCarrier != expectedFirst || secondCarrier != expectedSecond) {
            revert InvalidCarrierOrder();
        }
        if (xir != expectedXir) revert InvalidXIRAssignment();

        if (stage == SOURCE) {
            if (priorEnvelope != bytes32(0)) revert InvalidPriorEnvelope();
            stageEnvelope =
                envelopeFor(firstCarrier, attemptId, route, payloadHash, payloadBytes, 0);
        } else if (stage == INTERMEDIATE) {
            bytes32 expectedInbound =
                envelopeFor(firstCarrier, attemptId, route, payloadHash, payloadBytes, 0);
            if (priorEnvelope != expectedInbound) revert InvalidPriorEnvelope();
            stageEnvelope =
                envelopeFor(secondCarrier, attemptId, route, payloadHash, payloadBytes, 1);
            if (xir) {
                bytes32 transitionDigest = transitionFor(
                    attemptId,
                    route,
                    firstCarrier,
                    secondCarrier,
                    payloadHash,
                    expectedInbound,
                    stageEnvelope
                );
                xirTransition[attemptId] = transitionDigest;
                emit XIRTransitionRecorded(
                    attemptId,
                    route,
                    firstCarrier,
                    secondCarrier,
                    expectedInbound,
                    stageEnvelope,
                    transitionDigest,
                    XIR_VERSION
                );
            }
        } else {
            bytes32 expectedSecondEnvelope =
                envelopeFor(secondCarrier, attemptId, route, payloadHash, payloadBytes, 1);
            if (priorEnvelope != expectedSecondEnvelope) revert InvalidPriorEnvelope();
            stageEnvelope =
                envelopeFor(secondCarrier, attemptId, route, payloadHash, payloadBytes, 2);
            bytes32 effectDigest = keccak256(
                abi.encode(
                    "XIR_LOCAL_APPLICATION_EFFECT_V2",
                    attemptId,
                    route,
                    payloadHash,
                    payloadBytes
                )
            );
            applicationEffect[attemptId] = effectDigest;
            emit ApplicationEffectRecorded(
                attemptId, route, payloadHash, effectDigest
            );
        }

        recorded[attemptId] = true;
        emit RouteStageRecorded(
            attemptId,
            route,
            stage,
            firstCarrier,
            secondCarrier,
            xir,
            payloadHash,
            payloadBytes,
            priorEnvelope,
            stageEnvelope
        );
    }

    function routeDefinition(uint8 route)
        public
        pure
        returns (Protocol firstCarrier, Protocol secondCarrier, bool xir)
    {
        if (route > 3) revert InvalidRoute();
        firstCarrier = route < 2 ? Protocol.Hyperlane : Protocol.LayerZeroV2;
        secondCarrier =
            route % 2 == 0 ? Protocol.Hyperlane : Protocol.LayerZeroV2;
        xir = firstCarrier != secondCarrier;
    }

    function envelopeFor(
        Protocol protocol,
        bytes32 attemptId,
        uint8 route,
        bytes32 payloadHash,
        uint32 payloadBytes,
        uint8 hop
    ) public pure returns (bytes32) {
        bytes32 domain = protocol == Protocol.Hyperlane
            ? keccak256("CONTROLLED_HYPERLANE_ENVELOPE_V2")
            : keccak256("CONTROLLED_LAYERZERO_V2_ENVELOPE_V2");
        return keccak256(
            abi.encode(domain, attemptId, route, payloadHash, payloadBytes, hop)
        );
    }

    function transitionFor(
        bytes32 attemptId,
        uint8 route,
        Protocol inboundCarrier,
        Protocol outboundCarrier,
        bytes32 payloadHash,
        bytes32 inboundEnvelope,
        bytes32 outboundEnvelope
    ) public pure returns (bytes32) {
        if (inboundCarrier == outboundCarrier) revert InvalidXIRAssignment();
        return keccak256(
            abi.encode(
                XIR_VERSION,
                attemptId,
                route,
                inboundCarrier,
                outboundCarrier,
                payloadHash,
                inboundEnvelope,
                outboundEnvelope
            )
        );
    }
}
