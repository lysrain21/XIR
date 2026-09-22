#!/usr/bin/env bash
# Fail on missing fixtures, skipped tests, or an accidentally empty test selection.
set -euo pipefail
[[ $# -eq 1 && "$1" = /* ]] || { echo "usage: $0 <absolute-json-log>" >&2; exit 2; }
log=$1
repository_root=$(cd "$(dirname "$0")/.." && pwd)
command -v jq >/dev/null
mkdir -p "$(dirname "$log")"
cd "$repository_root/go-runtime"
XIR_REQUIRE_E2E=1 go test -count=1 -timeout=20m -json ./internal/runner -run '^(TestAnvil|TestReview)' | tee "$log"
jq -se '
  ([.[] | select(.Action == "skip" or .Action == "fail")] | length == 0) and
  ([.[] | select(.Action == "pass") | .Test] as $passed |
    ["TestAnvilRouteDeliversAndAppliesEffect",
     "TestAnvilRestartResumesWithoutDuplicateDispatch",
     "TestReviewLayerZeroDurations", "TestReviewRootFinalityRetry",
     "TestReviewLayerZeroLateRestart", "TestReviewHyperlaneRetryAfterLaterDispatch",
     "TestReviewLegacyRootRecovery", "TestReviewRootNonceReservation",
     "TestReviewLayerZeroStageRestarts", "TestReviewLayerZeroExternalPolling",
     "TestReviewHyperlaneSameBlockCheckpoint"] |
    all(.[]; . as $test | $passed | index($test) != null))
' "$log" >/dev/null || { echo "required Go E2E tests did not all run and pass (skip is failure)" >&2; exit 1; }
