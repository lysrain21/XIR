import json
from pathlib import Path

import pytest

from xir_lab.localnet.topology import LocalTopologyError
from xir_lab.native.security_v1 import (
    SELECTOR_TO_ERROR,
    SecurityState,
    case_attempt,
    error_from_revert_data,
    extract_revert_data,
    load_security_config,
)


def test_frozen_security_config_has_thirty_repetitions_per_route_case() -> None:
    root = Path(__file__).resolve().parents[2]
    config, digest = load_security_config(root / "configs/native/native-security-v1.json")
    assert len(digest) == 64
    assert config["routes"] == ["HL", "LH"]
    assert config["repetitions_per_route_case"] == 30
    assert len(config["cases"]) == 11


def test_config_rejects_underpowered_campaign(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    document = json.loads((root / "configs/native/native-security-v1.json").read_text())
    document["repetitions_per_route_case"] = 29
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document))
    with pytest.raises(LocalTopologyError, match="minimum of 30"):
        load_security_config(path)


def test_revert_extraction_decodes_nested_besu_shape() -> None:
    selector = next(value for value, name in SELECTOR_TO_ERROR.items() if name == "InvalidTrace")
    response = {
        "error": {
            "message": "execution reverted",
            "data": {"0xtransaction": {"returnValue": selector + "00" * 32}},
        }
    }
    data = extract_revert_data(response)
    observed_selector, error = error_from_revert_data(data)
    assert observed_selector == selector
    assert error == "InvalidTrace"


def test_revert_extraction_prefers_known_selector_over_address_prefix() -> None:
    selector = next(
        value for value, name in SELECTOR_TO_ERROR.items() if name == "UnapprovedPriorVerifier"
    )
    fixture = "0x0f7124308b3d36ac6f2ed3e1fc817a7e84c4dfd2"
    data = extract_revert_data(
        f"execution reverted while calling {fixture}: data={selector + '00' * 32}"
    )
    observed_selector, error = error_from_revert_data(data)
    assert observed_selector == selector
    assert error == "UnapprovedPriorVerifier"


def test_case_identity_is_route_case_repetition_stable() -> None:
    first = case_attempt(
        campaign_id="native-security-v1",
        route="HL",
        case="payload_tamper",
        repetition=3,
    )
    second = case_attempt(
        campaign_id="native-security-v1",
        route="HL",
        case="payload_tamper",
        repetition=3,
    )
    other = case_attempt(
        campaign_id="native-security-v1",
        route="LH",
        case="payload_tamper",
        repetition=3,
    )
    assert first == second
    assert first.attempt_id != other.attempt_id


def test_security_state_is_resume_safe(tmp_path: Path) -> None:
    attempt = case_attempt(
        campaign_id="native-security-v1",
        route="HL",
        case="payload_tamper",
        repetition=0,
    )
    state = SecurityState(tmp_path / "campaign.sqlite")
    assert state.begin(attempt, "payload_tamper", 0)
    assert state.begin(attempt, "payload_tamper", 0)
    result = {"valid": True, "actual_rejections": ["PayloadMismatch"]}
    state.finish(attempt, "payload_tamper", 0, result)
    assert not state.begin(attempt, "payload_tamper", 0)
    rows = state.rows()
    assert rows[0]["status"] == "validated"
    assert rows[0]["result"] == result
