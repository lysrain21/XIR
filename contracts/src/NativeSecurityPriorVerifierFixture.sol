// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "./IXIRCarrierAdapter.sol";

/// @notice Isolated native-security-v2 fixture that accepts every prior tuple.
/// @dev The production deployer includes this contract only when explicitly
///      requested for the negative-input campaign.
contract NativeSecurityPriorVerifierFixture is IXIRCarrierAdapter {
    function verify(bytes32, bytes32, bytes32) external pure returns (bool) {
        return true;
    }

    function verifyBundle(bytes32) external pure returns (bool) {
        return true;
    }
}
