// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library NativeRoutePayload {
    error InvalidAttempt();
    error InvalidRoute(bytes2 route);
    error EmptyApplicationPayload();

    bytes2 internal constant HH = 0x4848;
    bytes2 internal constant HL = 0x484c;
    bytes2 internal constant LH = 0x4c48;
    bytes2 internal constant LL = 0x4c4c;

    struct Data {
        bytes32 attemptId;
        bytes2 route;
        uint64 routeSequence;
        bytes applicationPayload;
    }

    function decode(bytes calldata encoded) internal pure returns (Data memory data) {
        data = abi.decode(encoded, (Data));
        validate(data);
    }

    function validate(Data memory data) internal pure {
        if (data.attemptId == bytes32(0)) revert InvalidAttempt();
        if (data.applicationPayload.length == 0) revert EmptyApplicationPayload();
        if (data.route != HH && data.route != HL && data.route != LH && data.route != LL) {
            revert InvalidRoute(data.route);
        }
    }

    function isHeterogeneous(bytes2 route) internal pure returns (bool) {
        if (route == HL || route == LH) return true;
        if (route == HH || route == LL) return false;
        revert InvalidRoute(route);
    }

    function firstIsHyperlane(bytes2 route) internal pure returns (bool) {
        if (route == HH || route == HL) return true;
        if (route == LH || route == LL) return false;
        revert InvalidRoute(route);
    }

    function secondIsHyperlane(bytes2 route) internal pure returns (bool) {
        if (route == HH || route == LH) return true;
        if (route == HL || route == LL) return false;
        revert InvalidRoute(route);
    }

    function routeId(bytes2 route) internal pure returns (bytes32) {
        if (route == HH) return keccak256("XIR_NATIVE_ROUTE_HH_V1");
        if (route == HL) return keccak256("XIR_NATIVE_ROUTE_HL_V1");
        if (route == LH) return keccak256("XIR_NATIVE_ROUTE_LH_V1");
        if (route == LL) return keccak256("XIR_NATIVE_ROUTE_LL_V1");
        revert InvalidRoute(route);
    }

    function effectClassHash(Data memory data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("XIR_NATIVE_COMMON_EFFECT_V1"),
                data.routeSequence,
                keccak256(data.applicationPayload)
            )
        );
    }
}
