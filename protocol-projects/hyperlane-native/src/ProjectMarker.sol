// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract HyperlaneNativeProjectMarker {
    function componentClass() external pure returns (bytes32) {
        return keccak256("PINNED_OFFICIAL_HYPERLANE_SOURCE");
    }
}
