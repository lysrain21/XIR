// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Live runner rotation must use a separate closeout approval and external signer.
contract RotateRunner {
    error ExternalSignerServiceRequired();

    function run() external pure {
        revert ExternalSignerServiceRequired();
    }
}
