from pathlib import Path

from web3 import Web3

from xir_lab.localnet.native_profile import NativeAttempt
from xir_lab.native.security_v1 import load_security_config
from xir_lab.native.security_v2 import NativeSecurityV2Runner


def _attempt(route: str, case_name: str) -> NativeAttempt:
    return NativeAttempt(
        attempt_id=f"security-v2-{route}-{case_name}",
        phase="smoke",
        route=route,
        route_sequence=0,
        first_protocol="hyperlane" if route[0] == "H" else "layerzero-v2",
        second_protocol="hyperlane" if route[1] == "H" else "layerzero-v2",
        execution_class=f"native-security-v2:{case_name}",
        xir=True,
        payload_bytes=64,
        payload_sha256="00" * 32,
    )


def _runner() -> NativeSecurityV2Runner:
    runner = object.__new__(NativeSecurityV2Runner)
    runner.contracts = {
        "intermediate": {
            "h_in": "0x0000000000000000000000000000000000000001",
            "l_in": "0x0000000000000000000000000000000000000002",
        }
    }
    runner.deployment = {
        "security_v2_fixtures": {
            "always_true_prior_verifier": "0x0000000000000000000000000000000000000003"
        }
    }
    return runner


def test_security_v2_config_freezes_thirteen_cases_by_two_routes_by_thirty() -> None:
    root = Path(__file__).resolve().parents[2]
    config, digest = load_security_config(root / "configs/native/native-security-v2.json")
    assert len(digest) == 64
    assert config["campaign_id"] == "native-security-v2"
    assert len(config["cases"]) == 13
    assert (
        len(config["routes"]) * len(config["cases"]) * int(config["repetitions_per_route_case"])
        == 780
    )


def test_security_v2_fake_verifier_hook_is_route_independent() -> None:
    runner = _runner()
    expected = Web3.to_checksum_address(
        runner.deployment["security_v2_fixtures"]["always_true_prior_verifier"]
    )
    assert runner._prior_verifier_for_second_dispatch(_attempt("HL", "fake_verifier")) == expected
    assert runner._prior_verifier_for_second_dispatch(_attempt("LH", "fake_verifier")) == expected


def test_security_v2_wrong_endpoint_hook_selects_opposite_ingress() -> None:
    runner = _runner()
    assert runner._prior_verifier_for_second_dispatch(
        _attempt("HL", "wrong_endpoint")
    ) == Web3.to_checksum_address(runner.contracts["intermediate"]["l_in"])
    assert runner._prior_verifier_for_second_dispatch(
        _attempt("LH", "wrong_endpoint")
    ) == Web3.to_checksum_address(runner.contracts["intermediate"]["h_in"])


def test_security_v2_normal_case_keeps_profile_matched_ingress() -> None:
    runner = _runner()
    assert (
        runner._prior_verifier_for_second_dispatch(_attempt("HL", "payload_tamper"))
        == runner.contracts["intermediate"]["h_in"]
    )
    assert (
        runner._prior_verifier_for_second_dispatch(_attempt("LH", "payload_tamper"))
        == runner.contracts["intermediate"]["l_in"]
    )
