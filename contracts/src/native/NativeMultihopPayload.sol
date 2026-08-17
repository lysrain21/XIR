// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library NativeMultihopPayload {
    error InvalidRoute();

    struct Data {
        bytes32 attemptId;
        bytes route;
        uint64 routeSequence;
        bytes applicationPayload;
    }

    function decode(bytes calldata encoded) internal pure returns (Data memory data) {
        data = abi.decode(encoded, (Data));
        validateRoute(data.route);
    }

    function validateRoute(bytes memory route) internal pure {
        if (route.length == 0 || route.length > 4) revert InvalidRoute();
        for (uint256 i = 0; i < route.length; i++) {
            if (route[i] != bytes1("H") && route[i] != bytes1("L")) {
                revert InvalidRoute();
            }
        }
    }

    function switchAt(bytes memory route, uint8 hopIndex) internal pure returns (bool) {
        validateRoute(route);
        if (hopIndex == 0 || hopIndex >= route.length) revert InvalidRoute();
        return route[hopIndex - 1] != route[hopIndex];
    }

    function effectClassHash(Data memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(data.routeSequence, keccak256(data.applicationPayload)));
    }
}
