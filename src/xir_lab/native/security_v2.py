"""Final-revision native security campaign with runner-authority cases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, cast

from eth_utils import keccak  # type: ignore[attr-defined]
from web3 import Web3

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.deployer import gateway_typed_id
from xir_lab.native.runner import NativeExperimentRunner
from xir_lab.native.security_v1 import (
    EXPECTED_ERROR,
    NativeSecurityCampaign,
    case_payload,
    error_from_revert_data,
    extract_revert_data,
)
from xir_lab.native.xir_trace import XIRContext, XIRRecord, message_id, root_id

AUTHORITY_CASES = frozenset({"fake_verifier", "wrong_endpoint"})


@dataclass(frozen=True)
class ExpectedPriorVerifierRejection(Exception):
    """A deliberately invalid second-hop transaction reverted as configured."""

    case_name: str
    selector: str
    error_name: str


class NativeSecurityV2Runner(NativeExperimentRunner):
    """Select invalid prior verifiers only for named v2 negative cases."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        fixture = cast(dict[str, Any], self.deployment.get("security_v2_fixtures", {}))
        if not fixture.get("always_true_prior_verifier"):
            raise LocalTopologyError(
                "native-security-v2 deployment lacks the always-true prior-verifier fixture"
            )

    @staticmethod
    def _authority_case(attempt: NativeAttempt) -> str | None:
        case_name = attempt.execution_class.rsplit(":", 1)[-1]
        return case_name if case_name in AUTHORITY_CASES else None

    def _prior_verifier_for_second_dispatch(self, attempt: NativeAttempt) -> str:
        case_name = self._authority_case(attempt)
        if case_name == "fake_verifier":
            fixture = cast(dict[str, str], self.deployment["security_v2_fixtures"])
            return Web3.to_checksum_address(fixture["always_true_prior_verifier"])
        if case_name == "wrong_endpoint":
            wrong_protocol = "l" if attempt.route[0] == "H" else "h"
            return Web3.to_checksum_address(self.contracts["intermediate"][f"{wrong_protocol}_in"])
        return super()._prior_verifier_for_second_dispatch(attempt)

    def _dispatch_second_xir(
        self,
        attempt: NativeAttempt,
        protocol: str,
        prior_profile: bytes,
        prior_evidence: bytes,
        prior_transition: bytes,
        current_profile: bytes,
        current_transition: bytes,
    ) -> bytes:
        case_name = self._authority_case(attempt)
        if case_name is None:
            return super()._dispatch_second_xir(
                attempt,
                protocol,
                prior_profile,
                prior_evidence,
                prior_transition,
                current_profile,
                current_transition,
            )
        verifier = self._prior_verifier_for_second_dispatch(attempt)
        _adapter, function, _quote, _evidence = self._second_xir_dispatch_components(
            attempt=attempt,
            protocol=protocol,
            verifier=verifier,
            prior_profile=prior_profile,
            prior_evidence=prior_evidence,
            prior_transition=prior_transition,
            current_profile=current_profile,
            current_transition=current_transition,
        )
        try:
            function.call({"from": self.account.address, "gas": 8_000_000})
        except Exception as exc:  # Web3 wraps custom errors by provider.
            selector, error_name = error_from_revert_data(extract_revert_data(exc))
        else:
            selector, error_name = None, None
        expected = EXPECTED_ERROR[case_name]
        if selector is None or error_name != expected:
            raise LocalTopologyError(
                f"{case_name} preflight rejected at {error_name or selector}, expected {expected}"
            )
        try:
            self._transact(
                attempt_id=attempt.attempt_id,
                stage="second_protocol_dispatch",
                role="intermediate",
                function=function,
                value=0,
                detail={
                    "security_case": case_name,
                    "submitted_prior_verifier": verifier.lower(),
                    "expected_rejection": expected,
                    "revert_selector": selector,
                },
            )
        except LocalTopologyError:
            stage = self.state.stage(attempt.attempt_id, "second_protocol_dispatch")
            if stage is None or str(stage["state"]) != "failed":
                raise
            raise ExpectedPriorVerifierRejection(case_name, selector, error_name)
        raise LocalTopologyError(f"{case_name} unexpectedly dispatched the second protocol")


class NativeSecurityV2Campaign(NativeSecurityCampaign):
    """Add two final-revision authority cases to the v1 conformance matrix."""

    runner: NativeSecurityV2Runner

    def _run_one(
        self,
        attempt: NativeAttempt,
        case_name: str,
        repetition: int,
        fixed_seed: str,
    ) -> None:
        if case_name not in AUTHORITY_CASES:
            super()._run_one(attempt, case_name, repetition, fixed_seed)
            return
        if not self.state.begin(attempt, case_name, repetition):
            return
        self.runner.state.begin(attempt)
        payload = case_payload(attempt, fixed_seed)
        before = self._receiver_snapshot()
        rejection: ExpectedPriorVerifierRejection | None = None
        try:
            self.runner.prepare_heterogeneous(attempt, payload)
        except ExpectedPriorVerifierRejection as exc:
            rejection = exc
        after = self._receiver_snapshot()
        stage = self.runner.state.stage(attempt.attempt_id, "second_protocol_dispatch")
        stage_detail = (
            cast(dict[str, Any], json.loads(stage["detail_json"])) if stage is not None else {}
        )
        consumed = self._derived_mid_consumed(attempt, payload)
        expected_error = EXPECTED_ERROR[case_name]
        effect_delta = int(after["receiver_delivery_count"]) - int(
            before["receiver_delivery_count"]
        )
        valid = (
            rejection is not None
            and rejection.error_name == expected_error
            and stage is not None
            and str(stage["state"]) == "failed"
            and bool(stage["transaction_hash"])
            and effect_delta == 0
            and before["receiver_state_hash"] == after["receiver_state_hash"]
            and not consumed
        )
        result = {
            "schema_version": self.case_schema_version,
            "case": case_name,
            "route": attempt.route,
            "repetition": repetition,
            "attempt_id": attempt.attempt_id,
            "expected_rejection": expected_error,
            "actual_rejections": ([rejection.error_name] if rejection is not None else []),
            "expected_application_effects": 0,
            "application_effect_delta": effect_delta,
            "rejection_application_effect_delta": effect_delta,
            "effect_attempt_ids": [],
            "before": before,
            "after": {**after, "gateway_consumed": consumed},
            "transactions": [
                {
                    "stage": "second_protocol_dispatch",
                    "transaction_hash": (
                        str(stage["transaction_hash"]) if stage is not None else None
                    ),
                    "status": 0,
                    "revert_selector": (rejection.selector if rejection is not None else None),
                    "revert_error": (rejection.error_name if rejection is not None else None),
                    "receipt": stage_detail.get("receipt"),
                    "receipt_sha256": stage_detail.get("receipt_sha256"),
                    "submitted_prior_verifier": stage_detail.get("submitted_prior_verifier"),
                    "native_effect_attempt_ids": [],
                }
            ],
            "root_signer_separated": (
                str(self.runner.deployment.get("root_signer", "")).lower()
                != self.runner.account.address.lower()
            ),
            "valid": valid,
        }
        self.runner.state.finish(attempt.attempt_id)
        self.state.finish(attempt, case_name, repetition, result)
        if not valid:
            raise LocalTopologyError(
                f"security case failed: {attempt.route}/{case_name}/{repetition}"
            )

    def _receiver_snapshot(self) -> dict[str, Any]:
        return {
            "receiver_delivery_count": int(self.receiver.functions.deliveryCount().call()),
            "receiver_state_hash": Web3.to_hex(self.receiver.functions.effectStateHash().call()),
        }

    def _derived_mid_consumed(self, attempt: NativeAttempt, payload: bytes) -> bool:
        root_stage = self.runner.state.stage(attempt.attempt_id, "xir_root_record")
        if root_stage is None:
            raise LocalTopologyError("authority case lacks its source-root stage")
        detail = cast(dict[str, Any], json.loads(root_stage["detail_json"]))
        receiver_address = self.runner.contracts["destination"]["receiver"]
        record = XIRRecord(
            source_gateway=gateway_typed_id(int(self.runner.chain_by_role["source"]["chain_id"])),
            source_app=(1, bytes.fromhex(self.runner.account.address[2:])),
            destination_app=(1, bytes.fromhex(receiver_address[2:])),
            nonce=int(detail["record_nonce"]),
            payload_hash=keccak(payload),
        )
        context = XIRContext(1, keccak(text="XIR_NATIVE_POLICY_V1"))
        mid = message_id(root_id(record, context, 1), record.destination_app)
        return bool(self.gateway.functions.consumed(mid).call())
