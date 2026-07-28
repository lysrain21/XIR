// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IBaselineCarrier {
    function quoteBaseline(bytes calldata message, bytes calldata options)
        external
        view
        returns (uint256 nativeFee);

    function sendBaselineSource(bytes calldata message, bytes calldata options)
        external
        payable
        returns (bytes32 protocolMessageId);

    function forwardBaseline(bytes calldata message, bytes calldata options)
        external
        payable
        returns (bytes32 protocolMessageId);
}
