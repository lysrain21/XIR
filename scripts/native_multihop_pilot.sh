#!/usr/bin/env bash
set -Eeuo pipefail

script_root="$(cd "$(dirname "$0")" && pwd)"
export XIR_MULTIHOP_CAMPAIGN_KIND=pilot
exec "$script_root/native_multihop_campaign.sh" "$@"
