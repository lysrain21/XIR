// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {OutboundControl} from "../src/OutboundControl.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract RotateRunner is LabScriptBase {
    function run() external {
        uint256 administratorKey = vm.envUint("XIR_ADMINISTRATOR_PRIVATE_KEY");
        OutboundControl target = OutboundControl(vm.envAddress("XIR_CONTROL_TARGET"));
        address nextRunner = vm.envAddress("XIR_NEXT_RUNNER");
        vm.startBroadcast(administratorKey);
        target.setRunner(nextRunner);
        vm.stopBroadcast();
    }
}
