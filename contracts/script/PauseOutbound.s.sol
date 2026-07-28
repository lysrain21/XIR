// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {OutboundControl} from "../src/OutboundControl.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract PauseOutbound is LabScriptBase {
    function run() external {
        uint256 administratorKey = vm.envUint("XIR_ADMINISTRATOR_PRIVATE_KEY");
        OutboundControl target = OutboundControl(vm.envAddress("XIR_CONTROL_TARGET"));
        bool paused = vm.envUint("XIR_PAUSED") == 1;
        vm.startBroadcast(administratorKey);
        target.setOutboundPaused(paused);
        vm.stopBroadcast();
    }
}
