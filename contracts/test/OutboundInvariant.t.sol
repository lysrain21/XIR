// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter, IHyperlaneMailbox} from "../src/HyperlaneAdapter.sol";

contract InvariantMailbox is IHyperlaneMailbox {
    function dispatch(uint32, bytes32, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        return keccak256("message");
    }

    function quoteDispatch(uint32, bytes32, bytes calldata)
        external
        pure
        returns (uint256)
    {
        return 0;
    }
}

contract OutboundInvariantTest {
    HyperlaneAdapter internal adapter;

    function setUp() public {
        adapter = new HyperlaneAdapter(
            address(new InvariantMailbox()),
            421614,
            bytes32(uint256(1)),
            address(this),
            address(this)
        );
    }

    function invariantControlIdentitiesRemainNonzero() public view {
        require(adapter.administrator() != address(0), "zero administrator");
        require(adapter.runner() != address(0), "zero runner");
    }

    function invariantConfiguredRemoteRemainsNonzero() public view {
        require(adapter.remoteDomain() != 0, "zero domain");
        require(adapter.remoteAdapter() != bytes32(0), "zero peer");
    }
}
