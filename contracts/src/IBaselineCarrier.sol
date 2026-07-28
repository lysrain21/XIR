// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IBaselineCarrier {
    function quoteBaseline(bytes32 routeId, bytes calldata message, bytes calldata options)
        external
        view
        returns (uint256 nativeFee);

    function sendBaselineSource(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata options
    )
        external
        payable
        returns (bytes32 protocolMessageId);

    function forwardBaseline(
        bytes32 routeId,
        bytes calldata message,
        bytes calldata options
    )
        external
        payable
        returns (bytes32 protocolMessageId);
}

interface IBaselineCarrierReceiver {
    function baselineCarrierReceive(bytes32 messageId, bytes calldata payload) external;
}
