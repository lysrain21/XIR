"""Hard, side-effect-free gates in front of every future live dependency."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar

LIVE_DISABLE_ENV = "XIR_LIVE_WRITES_DISABLED"
LIVE_FEATURE_ENV = "XIR_LIVE_FEATURE"
LIVE_FEATURE_VERSION = "approved-pilot-v1"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

T = TypeVar("T")


class LiveFeatureError(RuntimeError):
    """Raised before a live signer or write-RPC dependency can be built."""


@dataclass(frozen=True)
class LiveFeatureStatus:
    enabled: bool
    reason_code: str


def live_feature_status(
    environ: Mapping[str, str] | None = None,
) -> LiveFeatureStatus:
    """Resolve the feature gate without constructing any external dependency."""

    values = os.environ if environ is None else environ
    disabled = values.get(LIVE_DISABLE_ENV, "").strip().lower()
    if disabled in _TRUTHY:
        return LiveFeatureStatus(False, "live_writes_hard_disabled")
    if values.get(LIVE_FEATURE_ENV) != LIVE_FEATURE_VERSION:
        return LiveFeatureStatus(False, "live_feature_not_enabled")
    return LiveFeatureStatus(True, "live_feature_enabled")


def construct_live_dependency(
    kind: str,
    factory: Callable[[], T],
    *,
    environ: Mapping[str, str] | None = None,
) -> T:
    """Construct one dependency only after the hard feature gate passes."""

    status = live_feature_status(environ)
    if not status.enabled:
        raise LiveFeatureError(f"{kind} construction blocked: {status.reason_code}")
    return factory()
