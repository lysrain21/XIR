#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 && "$1" = /* ]] || {
  echo "usage: $0 <absolute-native-runtime-root>" >&2
  exit 2
}
runtime_root=$1
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
scale_pid=$(<"$runtime_root/pids/scale-phase.pid")
[[ "$scale_pid" =~ ^[0-9]+$ ]]
while kill -0 "$scale_pid" 2>/dev/null; do
  sleep 30
done
jq -e '.valid == true' "$runtime_root/runs/scale/reconciliation.json" >/dev/null
"$repository_root/scripts/close_native_experiment.sh" "$runtime_root"
