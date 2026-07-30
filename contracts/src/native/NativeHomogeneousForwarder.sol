// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBaselineCarrier, IBaselineCarrierReceiver} from "../IBaselineCarrier.sol";
import {NativeRoutePayload} from "./NativeRoutePayload.sol";

contract NativeHomogeneousForwarder is IBaselineCarrierReceiver {
    error Unauthorized();
    error HeterogeneousRouteRequiresXIR();
    error WrongInboundCarrier();
    error AlreadyForwarded(bytes32 attemptId);
    error InsufficientForwardingBalance(uint256 required, uint256 available);

    address public immutable administrator;
    IBaselineCarrier public immutable hyperlaneInboundCarrier;
    IBaselineCarrier public immutable hyperlaneOutboundCarrier;
    IBaselineCarrier public immutable layerZeroInboundCarrier;
    IBaselineCarrier public immutable layerZeroOutboundCarrier;
    bytes public layerZeroOptions;
    mapping(bytes32 => bool) public forwardedAttempts;

    event LayerZeroOptionsSet(bytes32 indexed optionsHash);
    event HomogeneousHopForwarded(
        bytes32 indexed attemptId,
        bytes2 indexed route,
        uint64 indexed routeSequence,
        bytes32 inboundMessageId,
        bytes32 outboundMessageId,
        uint256 nativeFee
    );

    constructor(
        address administrator_,
        IBaselineCarrier hyperlaneInboundCarrier_,
        IBaselineCarrier hyperlaneOutboundCarrier_,
        IBaselineCarrier layerZeroInboundCarrier_,
        IBaselineCarrier layerZeroOutboundCarrier_,
        bytes memory layerZeroOptions_
    ) {
        if (
            administrator_ == address(0)
                || address(hyperlaneInboundCarrier_) == address(0)
                || address(hyperlaneOutboundCarrier_) == address(0)
                || address(layerZeroInboundCarrier_) == address(0)
                || address(layerZeroOutboundCarrier_) == address(0)
        ) revert Unauthorized();
        administrator = administrator_;
        hyperlaneInboundCarrier = hyperlaneInboundCarrier_;
        hyperlaneOutboundCarrier = hyperlaneOutboundCarrier_;
        layerZeroInboundCarrier = layerZeroInboundCarrier_;
        layerZeroOutboundCarrier = layerZeroOutboundCarrier_;
        layerZeroOptions = layerZeroOptions_;
    }

    receive() external payable {}

    function setLayerZeroOptions(bytes calldata options) external {
        if (msg.sender != administrator) revert Unauthorized();
        layerZeroOptions = options;
        emit LayerZeroOptionsSet(keccak256(options));
    }

    function routeId(bytes2 route) external pure returns (bytes32) {
        return NativeRoutePayload.routeId(route);
    }

    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external {
        NativeRoutePayload.Data memory data = NativeRoutePayload.decode(payload);
        if (NativeRoutePayload.isHeterogeneous(data.route)) {
            revert HeterogeneousRouteRequiresXIR();
        }
        bool hyperlane = NativeRoutePayload.firstIsHyperlane(data.route);
        IBaselineCarrier inboundCarrier =
            hyperlane ? hyperlaneInboundCarrier : layerZeroInboundCarrier;
        IBaselineCarrier outboundCarrier =
            hyperlane ? hyperlaneOutboundCarrier : layerZeroOutboundCarrier;
        if (msg.sender != address(inboundCarrier)) revert WrongInboundCarrier();
        if (forwardedAttempts[data.attemptId]) revert AlreadyForwarded(data.attemptId);
        forwardedAttempts[data.attemptId] = true;

        bytes memory options = hyperlane ? bytes("") : layerZeroOptions;
        bytes32 route = NativeRoutePayload.routeId(data.route);
        uint256 fee = outboundCarrier.quoteBaseline(route, payload, options);
        if (address(this).balance < fee) {
            revert InsufficientForwardingBalance(fee, address(this).balance);
        }
        bytes32 outboundMessageId =
            outboundCarrier.forwardBaseline{value: fee}(route, payload, options);
        emit HomogeneousHopForwarded(
            data.attemptId,
            data.route,
            data.routeSequence,
            messageId,
            outboundMessageId,
            fee
        );
    }
}
