from __future__ import annotations

import pytest

from xir_lab.live import (
    LIVE_DISABLE_ENV,
    LIVE_FEATURE_ENV,
    LIVE_FEATURE_VERSION,
    LiveFeatureError,
    construct_live_dependency,
    live_feature_status,
)


def test_feature_defaults_off() -> None:
    status = live_feature_status({})
    assert not status.enabled
    assert status.reason_code == "live_feature_not_enabled"


def test_hard_disable_has_priority_over_feature_enable() -> None:
    status = live_feature_status(
        {
            LIVE_DISABLE_ENV: "1",
            LIVE_FEATURE_ENV: LIVE_FEATURE_VERSION,
        }
    )
    assert not status.enabled
    assert status.reason_code == "live_writes_hard_disabled"


@pytest.mark.parametrize("kind", ("signer", "write_rpc"))
def test_disabled_gate_never_constructs_live_dependency(kind: str) -> None:
    calls = 0

    def factory() -> object:
        nonlocal calls
        calls += 1
        return object()

    with pytest.raises(LiveFeatureError, match="live_writes_hard_disabled"):
        construct_live_dependency(
            kind,
            factory,
            environ={
                LIVE_DISABLE_ENV: "true",
                LIVE_FEATURE_ENV: LIVE_FEATURE_VERSION,
            },
        )
    assert calls == 0


def test_exact_feature_version_is_required() -> None:
    assert not live_feature_status({LIVE_FEATURE_ENV: "1"}).enabled
    dependency = object()
    assert (
        construct_live_dependency(
            "fixture",
            lambda: dependency,
            environ={LIVE_FEATURE_ENV: LIVE_FEATURE_VERSION},
        )
        is dependency
    )
