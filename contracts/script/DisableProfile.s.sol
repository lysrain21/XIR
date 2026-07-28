// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Live profile disablement must use a separate closeout approval.
contract DisableProfile {
    error ExternalSignerServiceRequired();

    function run() external pure {
        revert ExternalSignerServiceRequired();
    }
}
