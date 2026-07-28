// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {XIRRegistry} from "../src/XIRRegistry.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract DisableProfile is LabScriptBase {
    function run() external {
        uint256 administratorKey = vm.envUint("XIR_ADMINISTRATOR_PRIVATE_KEY");
        XIRRegistry registry = XIRRegistry(vm.envAddress("XIR_REGISTRY"));
        bytes32 profileHash = vm.envBytes32("XIR_PROFILE_HASH");
        XIRRegistry.ProfileSnapshot memory snapshot = registry.profileAt(profileHash);
        snapshot.enabled = false;
        vm.startBroadcast(administratorKey);
        registry.setProfile(profileHash, snapshot);
        vm.stopBroadcast();
    }
}
