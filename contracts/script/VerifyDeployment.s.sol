// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LabScriptBase} from "./LabScriptBase.sol";

contract VerifyDeployment is LabScriptBase {
    /// @notice Read-only: performs no startBroadcast and writes only a local manifest.
    function run() external {
        address registry = vm.envAddress("XIR_REGISTRY");
        address gateway = vm.envAddress("XIR_GATEWAY");
        address hyperlane = vm.envAddress("XIR_HYPERLANE_ADAPTER");
        address layerZero = vm.envAddress("XIR_LAYERZERO_ADAPTER");
        _requireCodeHash("registry", registry, vm.envBytes32("XIR_REGISTRY_CODE_HASH"));
        _requireCodeHash("gateway", gateway, vm.envBytes32("XIR_GATEWAY_CODE_HASH"));
        _requireCodeHash(
            "hyperlane-adapter",
            hyperlane,
            vm.envBytes32("XIR_HYPERLANE_CODE_HASH")
        );
        _requireCodeHash(
            "layerzero-v2-adapter",
            layerZero,
            vm.envBytes32("XIR_LAYERZERO_CODE_HASH")
        );
        _writeFourContractManifest(
            vm.envString("XIR_MANIFEST_PATH"),
            "read-only-verification",
            registry,
            gateway,
            hyperlane,
            layerZero
        );
    }
}
