// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HyperlaneAdapter, IHyperlaneMailbox} from "../src/HyperlaneAdapter.sol";
import {IBaselineCarrierReceiver} from "../src/IBaselineCarrier.sol";

contract HyperlaneBaselineReceiver is IBaselineCarrierReceiver {
    bytes32 public lastPayloadHash;

    function baselineCarrierReceive(bytes32, bytes calldata payload) external {
        lastPayloadHash = keccak256(payload);
    }
}

contract MockMailbox is IHyperlaneMailbox {
    uint256 public dispatchCount;

    function dispatch(uint32 destination, bytes32 recipient, bytes calldata body)
        external
        payable
        returns (bytes32 messageId)
    {
        dispatchCount++;
        messageId = keccak256(abi.encode(destination, recipient, body, dispatchCount));
    }

    function quoteDispatch(uint32, bytes32, bytes calldata)
        external
        pure
        returns (uint256 fee)
    {
        return 1;
    }

    function deliver(
        HyperlaneAdapter adapter,
        uint32 origin,
        bytes32 sender,
        bytes calldata body
    ) external {
        adapter.handle(origin, sender, body);
    }
}

contract ControlActor {
    function sendSource(
        HyperlaneAdapter adapter,
        bytes calldata body
    ) external returns (bytes32) {
        return adapter.sendSource(body);
    }

    function forwardInFlight(
        HyperlaneAdapter adapter,
        bytes calldata body
    ) external returns (bytes32) {
        return adapter.forwardInFlight(body);
    }

    function pause(HyperlaneAdapter adapter, bool paused) external {
        adapter.setOutboundPaused(paused);
    }

    function drain(HyperlaneAdapter adapter, bool draining) external {
        adapter.setDrain(draining);
    }

    function setRunner(HyperlaneAdapter adapter, address runner) external {
        adapter.setRunner(runner);
    }

    function setBaselineReceiver(
        HyperlaneAdapter adapter,
        bytes32 routeId,
        address receiver
    ) external {
        adapter.setBaselineReceiver(routeId, receiver);
    }

    function proposeAdministrator(HyperlaneAdapter adapter, address pending) external {
        adapter.proposeAdministrator(pending);
    }

    function acceptAdministrator(HyperlaneAdapter adapter) external {
        adapter.acceptAdministrator();
    }
}

contract OutboundControlTest {
    uint32 internal constant REMOTE_DOMAIN = 421614;
    bytes32 internal constant REMOTE_ADAPTER = bytes32(uint256(0x1234));
    MockMailbox internal mailbox;
    HyperlaneAdapter internal adapter;
    ControlActor internal administrator;
    ControlActor internal runner;
    ControlActor internal nextRunner;
    ControlActor internal nextAdministrator;

    function setUp() public {
        mailbox = new MockMailbox();
        administrator = new ControlActor();
        runner = new ControlActor();
        nextRunner = new ControlActor();
        nextAdministrator = new ControlActor();
        adapter = new HyperlaneAdapter(
            address(mailbox),
            REMOTE_DOMAIN,
            REMOTE_ADAPTER,
            address(administrator),
            address(runner)
        );
    }

    function testRunnerCanSendAndUnprivilegedCallerCannot() public {
        runner.sendSource(adapter, bytes("payload"));
        require(mailbox.dispatchCount() == 1, "runner did not dispatch");
        try adapter.sendSource(bytes("payload")) {
            revert("unprivileged send succeeded");
        } catch {}
    }

    function testPauseAndRunnerRotationTakeEffectImmediately() public {
        administrator.pause(adapter, true);
        try runner.sendSource(adapter, bytes("payload")) {
            revert("paused send succeeded");
        } catch {}
        administrator.setRunner(adapter, address(nextRunner));
        administrator.pause(adapter, false);
        try runner.sendSource(adapter, bytes("payload")) {
            revert("old runner retained authority");
        } catch {}
        nextRunner.sendSource(adapter, bytes("payload"));
        require(mailbox.dispatchCount() == 1, "new runner did not dispatch");
    }

    function testAdministratorTransferRequiresAcceptance() public {
        administrator.proposeAdministrator(adapter, address(nextAdministrator));
        require(adapter.administrator() == address(administrator), "transferred too early");
        nextAdministrator.acceptAdministrator(adapter);
        require(
            adapter.administrator() == address(nextAdministrator), "acceptance did not transfer"
        );
        try administrator.pause(adapter, true) {
            revert("old administrator retained authority");
        } catch {}
    }

    function testInboundMailboxAndRemoteAuthenticationRemainEnforced() public {
        bytes32 profile = keccak256("profile");
        bytes32 transition = keccak256("transition");
        bytes32 evidence = keccak256("evidence");
        bytes memory body =
            abi.encode(uint8(1), abi.encode(profile, transition, evidence));
        try adapter.handle(REMOTE_DOMAIN, REMOTE_ADAPTER, body) {
            revert("non-mailbox inbound succeeded");
        } catch {}
        try mailbox.deliver(adapter, REMOTE_DOMAIN, bytes32(uint256(9)), body) {
            revert("wrong remote inbound succeeded");
        } catch {}
        mailbox.deliver(adapter, REMOTE_DOMAIN, REMOTE_ADAPTER, body);
        require(adapter.verify(profile, evidence, transition), "authenticated evidence missing");
    }

    function testAuthenticatedBaselineEnvelopeUsesConfiguredRoute() public {
        bytes32 routeId = keccak256("route");
        bytes memory payload = bytes("baseline-payload");
        HyperlaneBaselineReceiver receiver = new HyperlaneBaselineReceiver();
        administrator.setBaselineReceiver(adapter, routeId, address(receiver));
        mailbox.deliver(
            adapter,
            REMOTE_DOMAIN,
            REMOTE_ADAPTER,
            abi.encode(uint8(2), abi.encode(routeId, payload))
        );
        require(receiver.lastPayloadHash() == keccak256(payload), "baseline payload changed");
    }

    function testDrainBlocksNewSourceButAllowsInFlightForward() public {
        administrator.drain(adapter, true);
        try runner.sendSource(adapter, bytes("source")) {
            revert("draining source send succeeded");
        } catch {}
        runner.forwardInFlight(adapter, bytes("forward"));
        require(mailbox.dispatchCount() == 1, "in-flight forward was blocked by drain");
    }

    function testEmergencyPauseBlocksSourceAndInFlightForward() public {
        administrator.pause(adapter, true);
        try runner.sendSource(adapter, bytes("source")) {
            revert("halted source send succeeded");
        } catch {}
        try runner.forwardInFlight(adapter, bytes("forward")) {
            revert("halted in-flight forward succeeded");
        } catch {}
        require(mailbox.dispatchCount() == 0, "halt allowed a dispatch");
    }
}
