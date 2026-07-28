// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter} from "../src/HyperlaneAdapter.sol";
import {LayerZeroAdapter} from "../src/LayerZeroAdapter.sol";
import {XIRRegistry} from "../src/XIRRegistry.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract ConfigureLab is LabScriptBase {
    function run() external {
        uint256 administratorKey = vm.envUint("XIR_ADMINISTRATOR_PRIVATE_KEY");
        XIRRegistry registry = XIRRegistry(vm.envAddress("XIR_REGISTRY"));
        HyperlaneAdapter hyperlane =
            HyperlaneAdapter(payable(vm.envAddress("XIR_HYPERLANE_ADAPTER")));
        LayerZeroAdapter layerZero =
            LayerZeroAdapter(payable(vm.envAddress("XIR_LAYERZERO_ADAPTER")));

        vm.startBroadcast(administratorKey);
        hyperlane.setRemoteAdapter(vm.envBytes32("XIR_HYPERLANE_REMOTE_PEER"));
        layerZero.setRemotePeer(vm.envBytes32("XIR_LAYERZERO_REMOTE_PEER"));
        registry.setRoot(
            uint32(vm.envUint("XIR_REGISTRY_VERSION")),
            XIRRegistry.RootSnapshot({
                gatewayHash: vm.envBytes32("XIR_ROOT_GATEWAY_HASH"),
                signer: vm.envAddress("XIR_ROOT_SIGNER"),
                validAfter: uint64(vm.envUint("XIR_ROOT_VALID_AFTER")),
                validUntil: uint64(vm.envUint("XIR_ROOT_VALID_UNTIL")),
                enabled: true
            })
        );
        vm.stopBroadcast();
        _writeFourContractManifest(
            vm.envString("XIR_MANIFEST_PATH"),
            "configuration",
            address(registry),
            vm.envAddress("XIR_GATEWAY"),
            address(hyperlane),
            address(layerZero)
        );
    }
}
