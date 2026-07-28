// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter} from "../src/HyperlaneAdapter.sol";
import {LayerZeroAdapter} from "../src/LayerZeroAdapter.sol";
import {LabScriptBase} from "./LabScriptBase.sol";

contract DryRun is LabScriptBase {
    /// @notice Read-only: resolves current quotes and code hashes without broadcasting.
    function run() external view returns (uint256 hyperlaneFee, uint256 layerZeroFee) {
        HyperlaneAdapter hyperlane =
            HyperlaneAdapter(payable(vm.envAddress("XIR_HYPERLANE_ADAPTER")));
        LayerZeroAdapter layerZero =
            LayerZeroAdapter(payable(vm.envAddress("XIR_LAYERZERO_ADAPTER")));
        _requireCode("hyperlane-adapter", address(hyperlane));
        _requireCode("layerzero-v2-adapter", address(layerZero));
        bytes memory payload = abi.encodePacked(vm.envBytes32("XIR_DRY_RUN_PAYLOAD_HASH"));
        bytes32 routeId = vm.envBytes32("XIR_DRY_RUN_ROUTE_ID");
        hyperlaneFee = hyperlane.quoteBaseline(routeId, payload, bytes(""));
        layerZeroFee = layerZero.quoteBaseline(routeId, payload, bytes(""));
    }
}
