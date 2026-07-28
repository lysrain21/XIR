// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Live configuration must use the guarded external-signer dispatcher.
contract ConfigureLab {
    error ExternalSignerServiceRequired();

    function run() external pure {
        revert ExternalSignerServiceRequired();
    }
}
