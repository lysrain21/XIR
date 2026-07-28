// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Live closeout must use a separate closeout approval and external signer.
contract PauseOutbound {
    error ExternalSignerServiceRequired();

    function run() external pure {
        revert ExternalSignerServiceRequired();
    }
}
