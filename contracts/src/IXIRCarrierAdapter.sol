// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IXIRCarrierAdapter {
    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash)
        external
        view
        returns (bool);
}
