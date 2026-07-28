// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IXIRReceiver {
    function xirReceive(bytes32 mid, bytes calldata payload) external;
}
