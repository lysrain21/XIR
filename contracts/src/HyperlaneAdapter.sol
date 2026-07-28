// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IXIRCarrierAdapter} from "./IXIRCarrierAdapter.sol";
import {IBaselineCarrier} from "./IBaselineCarrier.sol";
import {OutboundControl} from "./OutboundControl.sol";

interface IHyperlaneMailbox {
    function dispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        payable
        returns (bytes32 messageId);

    function quoteDispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        view
        returns (uint256 fee);
}

contract HyperlaneAdapter is IXIRCarrierAdapter, IBaselineCarrier, OutboundControl {
    error OnlyMailbox();
    error OnlyRemote();
    error InvalidEvidence();
    error InvalidPeer();
    error UnsupportedOptions();

    address public immutable mailbox;
    uint32 public immutable remoteDomain;
    bytes32 public remoteAdapter;
    mapping(bytes32 => bool) public acceptedEvidence;

    event HyperlaneEvidence(
        bytes32 indexed evidenceHash,
        bytes32 indexed profileHash,
        bytes32 indexed transitionHash,
        uint32 origin,
        bytes32 sender
    );
    event RemoteAdapterSet(bytes32 indexed remoteAdapter);
    event HyperlaneDispatched(
        bytes32 indexed messageId,
        uint32 indexed destination,
        bytes32 indexed recipient,
        uint256 fee
    );

    constructor(
        address mailbox_,
        uint32 remoteDomain_,
        bytes32 remoteAdapter_,
        address administrator_,
        address runner_
    ) OutboundControl(administrator_, runner_) {
        if (mailbox_ == address(0) || remoteAdapter_ == bytes32(0)) revert InvalidPeer();
        mailbox = mailbox_;
        remoteDomain = remoteDomain_;
        remoteAdapter = remoteAdapter_;
    }

    function setRemoteAdapter(bytes32 remoteAdapter_) external onlyAdministrator {
        if (remoteAdapter_ == bytes32(0)) revert InvalidPeer();
        remoteAdapter = remoteAdapter_;
        emit RemoteAdapterSet(remoteAdapter_);
    }

    function quote(bytes calldata body) external view returns (uint256) {
        return IHyperlaneMailbox(mailbox).quoteDispatch(remoteDomain, remoteAdapter, body);
    }

    function quoteBaseline(bytes calldata message, bytes calldata options)
        external
        view
        returns (uint256)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return IHyperlaneMailbox(mailbox).quoteDispatch(remoteDomain, remoteAdapter, message);
    }

    function sendSource(bytes calldata body)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        return _dispatch(body);
    }

    function forwardInFlight(bytes calldata body)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        return _dispatch(body);
    }

    function sendBaselineSource(bytes calldata message, bytes calldata options)
        external
        payable
        onlyRunner
        whenSourceStartAllowed
        returns (bytes32)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return _dispatch(message);
    }

    function forwardBaseline(bytes calldata message, bytes calldata options)
        external
        payable
        onlyRunner
        whenOutboundActive
        returns (bytes32)
    {
        if (options.length != 0) revert UnsupportedOptions();
        return _dispatch(message);
    }

    function _dispatch(bytes calldata body) private returns (bytes32) {
        bytes32 messageId =
            IHyperlaneMailbox(mailbox).dispatch{value: msg.value}(remoteDomain, remoteAdapter, body);
        emit HyperlaneDispatched(messageId, remoteDomain, remoteAdapter, msg.value);
        return messageId;
    }

    function handle(uint32 origin, bytes32 sender, bytes calldata body) external payable {
        if (msg.sender != mailbox) revert OnlyMailbox();
        if (remoteAdapter == bytes32(0) || origin != remoteDomain || sender != remoteAdapter) {
            revert OnlyRemote();
        }
        (bytes32 profileHash, bytes32 transitionHash, bytes32 evidenceHash) =
            abi.decode(body, (bytes32, bytes32, bytes32));
        if (evidenceHash == bytes32(0)) revert InvalidEvidence();
        acceptedEvidence[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))] = true;
        emit HyperlaneEvidence(evidenceHash, profileHash, transitionHash, origin, sender);
    }

    function verify(bytes32 profileHash, bytes32 evidenceHash, bytes32 transitionHash)
        external
        view
        returns (bool)
    {
        return acceptedEvidence[keccak256(abi.encode(profileHash, evidenceHash, transitionHash))];
    }
}
