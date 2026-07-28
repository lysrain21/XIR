// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface Vm {
    function envAddress(string calldata name) external view returns (address value);
    function envUint(string calldata name) external view returns (uint256 value);
    function envBytes32(string calldata name) external view returns (bytes32 value);
    function envString(string calldata name) external view returns (string memory value);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
    function writeJson(string calldata json, string calldata path) external;
    function toString(address value) external pure returns (string memory);
    function toString(bytes32 value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
}

abstract contract LabScriptBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error MissingRuntimeCode(string role, address target);
    error RuntimeCodeMismatch(string role, address target, bytes32 expected, bytes32 observed);

    function _requireCode(string memory role, address target) internal view returns (bytes32 hash) {
        if (target.code.length == 0) revert MissingRuntimeCode(role, target);
        return target.codehash;
    }

    function _requireCodeHash(
        string memory role,
        address target,
        bytes32 expected
    ) internal view returns (bytes32 observed) {
        observed = _requireCode(role, target);
        if (observed != expected) {
            revert RuntimeCodeMismatch(role, target, expected, observed);
        }
    }

    function _entry(string memory role, address target)
        internal
        view
        returns (string memory)
    {
        return string.concat(
            '{"role":"',
            role,
            '","address":"',
            vm.toString(target),
            '","runtime_code_hash":"',
            vm.toString(target.codehash),
            '"}'
        );
    }

    function _writeFourContractManifest(
        string memory path,
        string memory operation,
        address registry,
        address gateway,
        address hyperlane,
        address layerZero
    ) internal {
        string memory document = string.concat(
            '{"schema_version":"xir-lab-runtime-code-manifest-v1","operation":"',
            operation,
            '","chain_id":',
            vm.toString(block.chainid),
            ',"contracts":[',
            _entry("registry", registry),
            ",",
            _entry("gateway", gateway),
            ",",
            _entry("hyperlane-adapter", hyperlane),
            ",",
            _entry("layerzero-v2-adapter", layerZero),
            "]}"
        );
        vm.writeJson(document, path);
    }
}
