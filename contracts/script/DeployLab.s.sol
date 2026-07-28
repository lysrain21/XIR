// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Public-testnet deployment is planned as unsigned EIP-1559
/// transactions and signed only by the repository-external signer service.
contract DeployLab {
    error ExternalSignerServiceRequired();

    function run() external pure {
        revert ExternalSignerServiceRequired();
    }
}
