// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DeployLayerZeroNative} from "../script/DeployLayerZeroNative.s.sol";

contract DeployLayerZeroNativeTest {
    DeployLayerZeroNative private immutable deployer = new DeployLayerZeroNative();

    function testEveryFiveChainLocalEidConfiguresAllFourRemoteEids() public view {
        uint32[5] memory all = [uint32(49001), uint32(49002), uint32(49003), uint32(49004), uint32(49005)];
        for (uint256 localIndex = 0; localIndex < all.length; localIndex++) {
            uint32[] memory remotes = deployer.remoteEidsFor(all[localIndex], all);
            require(remotes.length == 4, "remote count");
            uint256 cursor;
            for (uint256 candidateIndex = 0; candidateIndex < all.length; candidateIndex++) {
                if (candidateIndex == localIndex) continue;
                require(remotes[cursor] == all[candidateIndex], "remote ordering/content");
                cursor++;
            }
            require(cursor == 4, "remote coverage");
        }
    }

    function testUnsupportedLocalEidReverts() public {
        uint32[5] memory all = [uint32(49001), uint32(49002), uint32(49003), uint32(49004), uint32(49005)];
        (bool success,) =
            address(deployer).call(abi.encodeCall(DeployLayerZeroNative.remoteEidsFor, (uint32(49999), all)));
        require(!success, "unsupported local accepted");
    }

    function testDuplicateProfileEidReverts() public {
        uint32[5] memory all = [uint32(49001), uint32(49002), uint32(49003), uint32(49004), uint32(49004)];
        (bool success,) =
            address(deployer).call(abi.encodeCall(DeployLayerZeroNative.remoteEidsFor, (uint32(49001), all)));
        require(!success, "duplicate eid accepted");
    }
}
