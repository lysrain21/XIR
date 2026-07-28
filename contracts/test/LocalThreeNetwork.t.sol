// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface LocalVm {
    function chainId(uint256 newChainId) external;
    function roll(uint256 newHeight) external;
}

contract LocalEndpoint {
    error WrongChain();
    error OnlyPeer();
    error Unavailable();
    error DuplicateDelivery();
    error DeliveryDelayed();
    error PeerAlreadySet();

    enum Protocol {
        Hyperlane,
        LayerZeroV2
    }

    uint256 public immutable localChainId;
    uint256 public immutable remoteChainId;
    Protocol public immutable protocol;
    address public immutable administrator;
    address public peer;
    bool public available = true;
    bool public batchMode;
    uint256 public minimumDeliveryBlock;
    bool public lastAttributionAvailable = true;
    mapping(bytes32 => bool) public delivered;

    constructor(uint256 localChainId_, uint256 remoteChainId_, Protocol protocol_) {
        localChainId = localChainId_;
        remoteChainId = remoteChainId_;
        protocol = protocol_;
        administrator = msg.sender;
    }

    function setPeer(address peer_) external {
        if (msg.sender != administrator) revert OnlyPeer();
        if (peer != address(0)) revert PeerAlreadySet();
        peer = peer_;
    }

    function setAvailable(bool available_) external {
        if (msg.sender != administrator) revert OnlyPeer();
        available = available_;
    }

    function setBatchMode(bool batchMode_) external {
        if (msg.sender != administrator) revert OnlyPeer();
        batchMode = batchMode_;
    }

    function setMinimumDeliveryBlock(uint256 blockNumber) external {
        if (msg.sender != administrator) revert OnlyPeer();
        minimumDeliveryBlock = blockNumber;
    }

    function dispatch(bytes32 attemptId, bytes calldata payload)
        external
        view
        returns (bytes32 messageId)
    {
        if (block.chainid != localChainId) revert WrongChain();
        if (!available) revert Unavailable();
        return keccak256(
            abi.encode(protocol, localChainId, remoteChainId, attemptId, keccak256(payload))
        );
    }

    function deliver(
        LocalEndpoint target,
        bytes32 messageId,
        bytes32 attemptId,
        bytes calldata payload
    ) external {
        target.receiveMessage(messageId, attemptId, payload);
    }

    function receiveMessage(bytes32 messageId, bytes32, bytes calldata) external {
        if (block.chainid != localChainId) revert WrongChain();
        if (!available) revert Unavailable();
        if (msg.sender != peer) revert OnlyPeer();
        if (block.number < minimumDeliveryBlock) revert DeliveryDelayed();
        if (delivered[messageId]) revert DuplicateDelivery();
        delivered[messageId] = true;
        lastAttributionAvailable = !batchMode;
    }
}

contract LocalReceiver {
    error WrongChain();
    error NotWarm();
    error PayloadMismatch();
    error DuplicateEffect();

    uint256 public constant BASE_CHAIN_ID = 84532;
    bytes32 public immutable initialStateHash;
    bytes32 public immutable expectedPayloadHash;
    bool public warmed;
    uint256 public deliveryCount;
    bytes32 public lastPayloadHash;
    mapping(bytes32 => bool) public consumed;

    constructor(bytes32 initialStateHash_, bytes32 expectedPayloadHash_) {
        initialStateHash = initialStateHash_;
        expectedPayloadHash = expectedPayloadHash_;
    }

    function warm() external {
        if (block.chainid != BASE_CHAIN_ID) revert WrongChain();
        warmed = true;
    }

    function applyEffect(bytes32 messageId, bytes calldata payload) external {
        if (block.chainid != BASE_CHAIN_ID) revert WrongChain();
        if (!warmed) revert NotWarm();
        if (keccak256(payload) != expectedPayloadHash) revert PayloadMismatch();
        if (consumed[messageId]) revert DuplicateEffect();
        consumed[messageId] = true;
        deliveryCount++;
        lastPayloadHash = keccak256(payload);
    }

    function stateHash() external view returns (bytes32) {
        return keccak256(abi.encode(initialStateHash, deliveryCount, lastPayloadHash));
    }
}

contract LocalXIRWork {
    error XIRRejected();

    bool public reject;
    mapping(bytes32 => uint256) public workCount;

    function setReject(bool reject_) external {
        reject = reject_;
    }

    function record(bytes32 attemptId) external {
        if (reject) revert XIRRejected();
        workCount[attemptId]++;
    }
}

contract LocalThreeNetworkTest {
    LocalVm internal constant VM =
        LocalVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant OP = 11155420;
    uint256 internal constant ARB = 421614;
    uint256 internal constant BASE = 84532;
    bytes32 internal constant INITIAL = keccak256("equivalent-initial-state-v1");
    bytes32 internal constant PAYLOAD_HASH = keccak256("fixed-payload");

    struct Leg {
        LocalEndpoint outbound;
        LocalEndpoint inbound;
    }

    struct Result {
        LocalEndpoint.Protocol first;
        LocalEndpoint.Protocol second;
        bytes32 effectStateHash;
        uint256 physicalTransactions;
        uint256 accountingBuckets;
        uint256 logicalLabels;
        uint256 xirWorkCount;
    }

    Leg internal opArbH;
    Leg internal opArbL;
    Leg internal arbBaseH;
    Leg internal arbBaseL;
    LocalXIRWork internal xirWork;

    function setUp() public {
        opArbH = _leg(OP, ARB, LocalEndpoint.Protocol.Hyperlane);
        opArbL = _leg(OP, ARB, LocalEndpoint.Protocol.LayerZeroV2);
        arbBaseH = _leg(ARB, BASE, LocalEndpoint.Protocol.Hyperlane);
        arbBaseL = _leg(ARB, BASE, LocalEndpoint.Protocol.LayerZeroV2);
        xirWork = new LocalXIRWork();
    }

    function testAllEightPathsPreserveOrderEffectAndAccounting() public {
        for (uint256 condition = 0; condition < 4; condition++) {
            (LocalEndpoint.Protocol first, LocalEndpoint.Protocol second) =
                _protocols(condition);
            Result memory baseline = _run(condition, false);
            Result memory xir = _run(condition, true);
            require(baseline.first == first && baseline.second == second, "baseline order");
            require(xir.first == first && xir.second == second, "XIR order");
            require(baseline.effectStateHash == xir.effectStateHash, "effect mismatch");
            require(
                baseline.physicalTransactions == 3 && xir.physicalTransactions == 3,
                "physical transaction count"
            );
            require(
                baseline.accountingBuckets == 3 && xir.accountingBuckets == 3,
                "accounting bucket count"
            );
            require(baseline.logicalLabels == 7, "baseline label count");
            require(xir.logicalLabels == 10, "XIR label count");
            require(baseline.xirWorkCount == 0, "baseline performed XIR work");
            require(xir.xirWorkCount == 3, "XIR work missing");
        }
    }

    function testUnavailableLegWrongChainPeerAndReorderedProtocolAreRejected() public {
        opArbH.outbound.setAvailable(false);
        VM.chainId(OP);
        try opArbH.outbound.dispatch(keccak256("unavailable"), bytes("fixed-payload")) {
            revert("unavailable leg dispatched");
        } catch {}
        opArbH.outbound.setAvailable(true);
        VM.chainId(ARB);
        try opArbH.outbound.dispatch(keccak256("wrong-chain"), bytes("fixed-payload")) {
            revert("wrong-chain dispatch succeeded");
        } catch {}
        try opArbH.inbound.receiveMessage(
            keccak256("message"), keccak256("attempt"), bytes("fixed-payload")
        ) {
            revert("wrong peer delivery succeeded");
        } catch {}
        bytes32 messageId = keccak256("reordered");
        try opArbH.outbound.deliver(
            opArbL.inbound, messageId, keccak256("attempt"), bytes("fixed-payload")
        ) {
            revert("reordered protocol delivery succeeded");
        } catch {}
    }

    function testDuplicateDelayedBatchAndXirRejectionAreExplicit() public {
        bytes32 attemptId = keccak256("negative-attempt");
        VM.chainId(OP);
        bytes32 messageId = opArbH.outbound.dispatch(attemptId, bytes("fixed-payload"));
        VM.chainId(ARB);
        opArbH.outbound.deliver(
            opArbH.inbound, messageId, attemptId, bytes("fixed-payload")
        );
        try opArbH.outbound.deliver(
            opArbH.inbound, messageId, attemptId, bytes("fixed-payload")
        ) {
            revert("duplicate delivery succeeded");
        } catch {}

        opArbL.inbound.setMinimumDeliveryBlock(block.number + 5);
        VM.chainId(OP);
        bytes32 delayed = opArbL.outbound.dispatch(attemptId, bytes("fixed-payload"));
        VM.chainId(ARB);
        try opArbL.outbound.deliver(
            opArbL.inbound, delayed, attemptId, bytes("fixed-payload")
        ) {
            revert("early delayed delivery succeeded");
        } catch {}
        VM.roll(block.number + 5);
        opArbL.outbound.deliver(
            opArbL.inbound, delayed, attemptId, bytes("fixed-payload")
        );

        arbBaseH.inbound.setBatchMode(true);
        VM.chainId(ARB);
        bytes32 batched = arbBaseH.outbound.dispatch(attemptId, bytes("fixed-payload"));
        VM.chainId(BASE);
        arbBaseH.outbound.deliver(
            arbBaseH.inbound, batched, attemptId, bytes("fixed-payload")
        );
        require(!arbBaseH.inbound.lastAttributionAvailable(), "batch attribution fabricated");

        xirWork.setReject(true);
        try xirWork.record(attemptId) {
            revert("XIR rejection ignored");
        } catch {}
    }

    function _run(uint256 condition, bool xir) private returns (Result memory result) {
        (Leg storage first, Leg storage second) = _legs(condition);
        bytes32 attemptId = keccak256(abi.encode("attempt", condition, xir));
        bytes memory payload = bytes("fixed-payload");
        LocalReceiver receiver = new LocalReceiver(INITIAL, PAYLOAD_HASH);

        VM.chainId(BASE);
        receiver.warm();
        VM.chainId(OP);
        if (xir) xirWork.record(attemptId);
        bytes32 firstMessage = first.outbound.dispatch(attemptId, payload);
        VM.chainId(ARB);
        first.outbound.deliver(first.inbound, firstMessage, attemptId, payload);
        if (xir) xirWork.record(attemptId);
        bytes32 secondMessage = second.outbound.dispatch(attemptId, payload);
        VM.chainId(BASE);
        second.outbound.deliver(second.inbound, secondMessage, attemptId, payload);
        if (xir) xirWork.record(attemptId);
        receiver.applyEffect(secondMessage, payload);

        result = Result({
            first: first.outbound.protocol(),
            second: second.outbound.protocol(),
            effectStateHash: receiver.stateHash(),
            physicalTransactions: 3,
            accountingBuckets: 3,
            logicalLabels: xir ? 10 : 7,
            xirWorkCount: xirWork.workCount(attemptId)
        });
    }

    function _leg(uint256 source, uint256 destination, LocalEndpoint.Protocol protocol)
        private
        returns (Leg memory leg)
    {
        VM.chainId(source);
        LocalEndpoint outbound = new LocalEndpoint(source, destination, protocol);
        VM.chainId(destination);
        LocalEndpoint inbound = new LocalEndpoint(destination, source, protocol);
        outbound.setPeer(address(inbound));
        inbound.setPeer(address(outbound));
        return Leg(outbound, inbound);
    }

    function _legs(uint256 condition)
        private
        view
        returns (Leg storage first, Leg storage second)
    {
        first = condition < 2 ? opArbH : opArbL;
        second = condition % 2 == 0 ? arbBaseH : arbBaseL;
    }

    function _protocols(uint256 condition)
        private
        pure
        returns (LocalEndpoint.Protocol first, LocalEndpoint.Protocol second)
    {
        first = condition < 2
            ? LocalEndpoint.Protocol.Hyperlane
            : LocalEndpoint.Protocol.LayerZeroV2;
        second = condition % 2 == 0
            ? LocalEndpoint.Protocol.Hyperlane
            : LocalEndpoint.Protocol.LayerZeroV2;
    }
}
