// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IXIRCarrierAdapter {
    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash) external view returns (bool);

    /// @notice Returns true only when the adapter authenticated this exact,
    /// ordered receipt-tuple sequence in one native delivery bundle.
    function verifyBundle(bytes32 bundleCommitment) external view returns (bool);
}
