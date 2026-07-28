// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract XIRRegistry {
    error Unauthorized();
    error InvalidWindow();

    struct RootSnapshot {
        bytes32 gatewayHash;
        address signer;
        uint64 validAfter;
        uint64 validUntil;
        bool enabled;
    }

    struct ProfileSnapshot {
        bytes32 srcHash;
        bytes32 dstHash;
        address adapter;
        uint8 securityLevel;
        uint64 validAfter;
        uint64 validUntil;
        bool enabled;
    }

    address public immutable owner;
    mapping(uint32 => RootSnapshot) public roots;
    mapping(bytes32 => ProfileSnapshot) public profiles;

    event RootSet(uint32 indexed version, bytes32 gatewayHash, address signer);
    event ProfileSet(bytes32 indexed profileHash, bytes32 srcHash, bytes32 dstHash);

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function setRoot(uint32 version, RootSnapshot calldata snapshot) external onlyOwner {
        _checkWindow(snapshot.validAfter, snapshot.validUntil);
        roots[version] = snapshot;
        emit RootSet(version, snapshot.gatewayHash, snapshot.signer);
    }

    function setProfile(bytes32 profileHash, ProfileSnapshot calldata snapshot) external onlyOwner {
        _checkWindow(snapshot.validAfter, snapshot.validUntil);
        profiles[profileHash] = snapshot;
        emit ProfileSet(profileHash, snapshot.srcHash, snapshot.dstHash);
    }

    function rootAt(uint32 version) external view returns (RootSnapshot memory snapshot) {
        snapshot = roots[version];
    }

    function profileAt(bytes32 profileHash)
        external
        view
        returns (ProfileSnapshot memory snapshot)
    {
        snapshot = profiles[profileHash];
    }

    function _checkWindow(uint64 validAfter, uint64 validUntil) private pure {
        if (validUntil != 0 && validUntil <= validAfter) revert InvalidWindow();
    }
}
