// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ExperimentReceiver} from "../src/ExperimentReceiver.sol";

contract ReceiverAuthority {
    function baseline(ExperimentReceiver receiver, bytes32 messageId, bytes calldata payload)
        external
    {
        receiver.baselineReceive(messageId, payload);
    }

    function xir(ExperimentReceiver receiver, bytes32 messageId, bytes calldata payload) external {
        receiver.xirReceive(messageId, payload);
    }
}

contract ExperimentReceiverTest {
    bytes32 internal constant INITIAL_STATE = keccak256("equivalent-initial-state-v1");
    bytes32 internal constant PAYLOAD_HASH = keccak256("fixed-payload");
    ReceiverAuthority internal baselineAuthority;
    ReceiverAuthority internal xirAuthority;
    ExperimentReceiver internal baseline;
    ExperimentReceiver internal xir;

    function setUp() public {
        baselineAuthority = new ReceiverAuthority();
        xirAuthority = new ReceiverAuthority();
        baseline = new ExperimentReceiver(
            address(baselineAuthority),
            keccak256("baseline-namespace"),
            PAYLOAD_HASH,
            INITIAL_STATE,
            ExperimentReceiver.ReceiverMode.Baseline
        );
        xir = new ExperimentReceiver(
            address(xirAuthority),
            keccak256("xir-namespace"),
            PAYLOAD_HASH,
            INITIAL_STATE,
            ExperimentReceiver.ReceiverMode.XIR
        );
    }

    function testEquivalentPayloadProducesEquivalentEffectInIsolatedState() public {
        require(baseline.effectStateHash() == xir.effectStateHash(), "initial states differ");
        baselineAuthority.baseline(baseline, keccak256("baseline-message"), bytes("fixed-payload"));
        require(baseline.deliveryCount() == 1, "baseline effect missing");
        require(xir.deliveryCount() == 0, "baseline warmed XIR namespace");
        xirAuthority.xir(xir, keccak256("xir-message"), bytes("fixed-payload"));
        require(baseline.effectStateHash() == xir.effectStateHash(), "effects differ");
        require(baseline.effectSatisfied(1), "baseline predicate failed");
        require(xir.effectSatisfied(1), "XIR predicate failed");
    }

    function testModesAndAuthoritiesCannotCrossNamespaces() public {
        try baselineAuthority.xir(baseline, keccak256("message"), bytes("fixed-payload")) {
            revert("XIR entry accepted by baseline");
        } catch {}
        try xirAuthority.baseline(xir, keccak256("message"), bytes("fixed-payload")) {
            revert("baseline entry accepted by XIR");
        } catch {}
        try baseline.baselineReceive(keccak256("message"), bytes("fixed-payload")) {
            revert("untrusted caller accepted");
        } catch {}
    }

    function testPayloadAndReplayAreRejected() public {
        bytes32 messageId = keccak256("message");
        try baselineAuthority.baseline(baseline, messageId, bytes("changed")) {
            revert("wrong payload accepted");
        } catch {}
        baselineAuthority.baseline(baseline, messageId, bytes("fixed-payload"));
        try baselineAuthority.baseline(baseline, messageId, bytes("fixed-payload")) {
            revert("duplicate message accepted");
        } catch {}
    }
}
