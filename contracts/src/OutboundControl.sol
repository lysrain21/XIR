// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract OutboundControl {
    error OnlyAdministrator();
    error OnlyPendingAdministrator();
    error OnlyRunner();
    error OutboundPaused();
    error SourceDraining();
    error InvalidControlAddress();

    address public administrator;
    address public pendingAdministrator;
    address public runner;
    bool public outboundPaused;
    bool public draining;

    event AdministratorTransferStarted(
        address indexed administrator, address indexed pendingAdministrator
    );
    event AdministratorTransferred(
        address indexed previousAdministrator, address indexed newAdministrator
    );
    event RunnerUpdated(address indexed previousRunner, address indexed newRunner);
    event OutboundPauseUpdated(bool paused);
    event DrainUpdated(bool draining);

    constructor(address administrator_, address runner_) {
        if (administrator_ == address(0) || runner_ == address(0)) {
            revert InvalidControlAddress();
        }
        administrator = administrator_;
        runner = runner_;
    }

    modifier onlyAdministrator() {
        if (msg.sender != administrator) revert OnlyAdministrator();
        _;
    }

    modifier onlyRunner() {
        if (msg.sender != runner) revert OnlyRunner();
        _;
    }

    modifier whenOutboundActive() {
        if (outboundPaused) revert OutboundPaused();
        _;
    }

    modifier whenSourceStartAllowed() {
        if (outboundPaused) revert OutboundPaused();
        if (draining) revert SourceDraining();
        _;
    }

    function proposeAdministrator(address pendingAdministrator_) external onlyAdministrator {
        if (pendingAdministrator_ == address(0)) revert InvalidControlAddress();
        pendingAdministrator = pendingAdministrator_;
        emit AdministratorTransferStarted(administrator, pendingAdministrator_);
    }

    function acceptAdministrator() external {
        if (msg.sender != pendingAdministrator) revert OnlyPendingAdministrator();
        address previous = administrator;
        administrator = msg.sender;
        pendingAdministrator = address(0);
        emit AdministratorTransferred(previous, msg.sender);
    }

    function setRunner(address runner_) external onlyAdministrator {
        if (runner_ == address(0)) revert InvalidControlAddress();
        address previous = runner;
        runner = runner_;
        emit RunnerUpdated(previous, runner_);
    }

    function setOutboundPaused(bool paused) external onlyAdministrator {
        outboundPaused = paused;
        emit OutboundPauseUpdated(paused);
    }

    /// @notice Drain blocks new source attempts but does not recall or block
    /// already in-flight carrier work. Emergency pause blocks every new send.
    function setDrain(bool draining_) external onlyAdministrator {
        draining = draining_;
        emit DrainUpdated(draining_);
    }
}
