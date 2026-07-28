// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    ILayerZeroEndpointV2,
    LayerZeroAdapter,
    MessagingFee,
    MessagingParams,
    MessagingReceipt
} from "../src/LayerZeroAdapter.sol";

contract MockLayerZeroEndpoint is ILayerZeroEndpointV2 {
    address public delegate;
    uint32 public lastDstEid;
    bytes32 public lastReceiver;
    address public lastRefundAddress;
    uint64 public sendCount;

    function setDelegate(address delegate_) external {
        delegate = delegate_;
    }

    function quote(MessagingParams calldata, address)
        external
        pure
        returns (MessagingFee memory)
    {
        return MessagingFee({nativeFee: 7, lzTokenFee: 0});
    }

    function send(MessagingParams calldata params, address refundAddress)
        external
        payable
        returns (MessagingReceipt memory)
    {
        sendCount++;
        lastDstEid = params.dstEid;
        lastReceiver = params.receiver;
        lastRefundAddress = refundAddress;
        return MessagingReceipt({
            guid: keccak256(abi.encode(params.dstEid, params.receiver, sendCount)),
            nonce: sendCount,
            fee: MessagingFee({nativeFee: msg.value, lzTokenFee: 0})
        });
    }

    function deliver(
        LayerZeroAdapter adapter,
        LayerZeroAdapter.Origin calldata origin,
        bytes32 guid,
        bytes calldata message
    ) external {
        adapter.lzReceive(origin, guid, message, address(this), bytes(""));
    }
}

contract LayerZeroRunner {
    function sendSource(LayerZeroAdapter adapter, LayerZeroAdapter.ForwardRequest calldata request)
        external
        returns (MessagingReceipt memory)
    {
        return adapter.sendSource(request);
    }

    function forwardInFlight(
        LayerZeroAdapter adapter,
        LayerZeroAdapter.ForwardRequest calldata request
    ) external returns (MessagingReceipt memory) {
        return adapter.forwardInFlight(request);
    }
}

contract CarrierAdaptersTest {
    uint32 internal constant REMOTE_EID = 40232;
    bytes32 internal constant REMOTE_PEER = bytes32(uint256(0xBEEF));

    MockLayerZeroEndpoint internal endpoint;
    LayerZeroRunner internal runner;
    LayerZeroAdapter internal adapter;

    function setUp() public {
        endpoint = new MockLayerZeroEndpoint();
        runner = new LayerZeroRunner();
        adapter = new LayerZeroAdapter(
            address(endpoint), REMOTE_EID, REMOTE_PEER, address(this), address(runner)
        );
    }

    function testQuoteAndSendUseConfiguredEidPeerAndRunnerRefund() public {
        LayerZeroAdapter.ForwardRequest memory request = _request();
        MessagingFee memory fee = adapter.quoteForward(request);
        require(fee.nativeFee == 7, "quote not forwarded");
        MessagingReceipt memory receipt = runner.sendSource(adapter, request);
        require(receipt.nonce == 1, "receipt nonce missing");
        require(endpoint.lastDstEid() == REMOTE_EID, "EID substitution");
        require(endpoint.lastReceiver() == REMOTE_PEER, "peer substitution");
        require(endpoint.lastRefundAddress() == address(runner), "refund not bound to runner");
    }

    function testEndpointAndRemotePeerAuthenticationRemainEnforced() public {
        bytes32 profile = keccak256("profile");
        bytes32 transition = keccak256("transition");
        bytes32 guid = keccak256("guid");
        bytes32[] memory empty = new bytes32[](0);
        bytes memory message = abi.encode(
            LayerZeroAdapter.DeliveryBundle({
                profileHash: profile,
                transitionHash: transition,
                priorProfiles: empty,
                priorEvidence: empty,
                priorTransitions: empty
            })
        );
        LayerZeroAdapter.Origin memory origin =
            LayerZeroAdapter.Origin({srcEid: REMOTE_EID, sender: REMOTE_PEER, nonce: 1});
        try adapter.lzReceive(origin, guid, message, address(this), bytes("")) {
            revert("non-endpoint delivery succeeded");
        } catch {}
        origin.sender = bytes32(uint256(1));
        try endpoint.deliver(adapter, origin, guid, message) {
            revert("wrong peer delivery succeeded");
        } catch {}
        origin.sender = REMOTE_PEER;
        endpoint.deliver(adapter, origin, guid, message);
        require(adapter.verify(profile, guid, transition), "authenticated GUID missing");
    }

    function _request() private pure returns (LayerZeroAdapter.ForwardRequest memory request) {
        request.verifiers = new address[](0);
        request.profileHashes = new bytes32[](0);
        request.evidenceHashes = new bytes32[](0);
        request.transitionHashes = new bytes32[](0);
        request.currentProfileHash = keccak256("current-profile");
        request.currentTransitionHash = keccak256("current-transition");
        request.options = bytes("options");
    }
}
