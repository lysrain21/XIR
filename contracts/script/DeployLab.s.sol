// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter} from "../src/HyperlaneAdapter.sol";
import {LayerZeroAdapter} from "../src/LayerZeroAdapter.sol";
import {XIRGateway} from "../src/XIRGateway.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {XIRTypes} from "../src/XIRTypes.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract DeployLab is LabScriptBase {
    function run()
        external
        returns (
            XIRRegistry registry,
            XIRGateway gateway,
            HyperlaneAdapter hyperlane,
            LayerZeroAdapter layerZero
        )
    {
        uint256 deployerKey = vm.envUint("XIR_DEPLOYER_PRIVATE_KEY");
        address administrator = vm.envAddress("XIR_ADMINISTRATOR");
        address runner = vm.envAddress("XIR_RUNNER");
        address gatewayIdentity = vm.envAddress("XIR_GATEWAY_ID_ADDRESS");
        vm.startBroadcast(deployerKey);
        registry = new XIRRegistry(administrator);
        gateway = new XIRGateway(
            registry, XIRTypes.TypedId(XIRTypes.EVM, abi.encodePacked(gatewayIdentity))
        );
        hyperlane = new HyperlaneAdapter(
            vm.envAddress("XIR_HYPERLANE_MAILBOX"),
            uint32(vm.envUint("XIR_HYPERLANE_REMOTE_DOMAIN")),
            vm.envBytes32("XIR_HYPERLANE_REMOTE_PEER"),
            administrator,
            runner
        );
        layerZero = new LayerZeroAdapter(
            vm.envAddress("XIR_LAYERZERO_ENDPOINT"),
            uint32(vm.envUint("XIR_LAYERZERO_REMOTE_EID")),
            vm.envBytes32("XIR_LAYERZERO_REMOTE_PEER"),
            administrator,
            runner
        );
        vm.stopBroadcast();
        _writeFourContractManifest(
            vm.envString("XIR_MANIFEST_PATH"),
            "deployment",
            address(registry),
            address(gateway),
            address(hyperlane),
            address(layerZero)
        );
    }
}
