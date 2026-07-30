#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 2 && $# -le 4 ]] || {
  echo "usage: $0 <smoke|rehearsal|scale> <runtime-root> [concurrency] [batch-attempts]" >&2
  exit 2
}
phase=$1
runtime_root=$2
concurrency=${3:-16}
batch_attempts=${4:-256}
[[ "$phase" =~ ^(smoke|rehearsal|scale)$ && "$runtime_root" = /* ]] || {
  echo "phase or runtime root is invalid" >&2
  exit 2
}
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
profile="$runtime_root/profile.json"
deployment="$runtime_root/native-application/deployment.json"
key_file="$runtime_root/private/accounts/runner.key"
phase_root="$runtime_root/runs/$phase"
mkdir -p "$phase_root/raw-receipts" "$runtime_root/pids"

if [[ "$phase" = rehearsal ]]; then
  jq -e '.valid == true' "$runtime_root/runs/smoke/reconciliation.json" >/dev/null
elif [[ "$phase" = scale ]]; then
  jq -e '.valid == true' "$runtime_root/runs/smoke/reconciliation.json" >/dev/null
  jq -e '.valid == true' "$runtime_root/runs/rehearsal/reconciliation.json" >/dev/null
  jq -e '.eligible == true' "$runtime_root/runs/rehearsal/measured-limits.json" >/dev/null
fi

"$repository_root/scripts/native_stack_processes.sh" start-monitor \
  "$runtime_root" "$phase"
set +e
"$python" "$repository_root/scripts/run_native_experiment.py" "$phase" \
  --runtime-root "$runtime_root" \
  --profile "$profile" \
  --deployment "$deployment" \
  --key-file "$key_file" \
  --state "$phase_root/runner.sqlite" \
  --raw-root "$phase_root/raw-receipts" \
  --concurrency "$concurrency" \
  --batch-attempts "$batch_attempts" \
  >"$phase_root/runner.log" 2>&1 &
runner_pid=$!
echo "$runner_pid" >"$runtime_root/pids/native-runner.pid"
wait "$runner_pid"
runner_status=$?
set -e
touch "$phase_root/monitor.stop"
monitor_pid=$(cat "$runtime_root/pids/native-monitor.pid")
for _ in $(seq 1 50); do
  kill -0 "$monitor_pid" 2>/dev/null || break
  sleep 0.1
done
if [[ "$runner_status" -ne 0 ]]; then
  exit "$runner_status"
fi

"$python" "$repository_root/scripts/reconcile_native_experiment.py" "$phase" \
  --profile "$profile" \
  --deployment "$deployment" \
  --runner-state "$phase_root/runner.sqlite" \
  --layerzero-state "$runtime_root/layerzero/worker.sqlite" \
  --output "$phase_root/reconciliation.json"
"$python" "$repository_root/scripts/analyze_native_experiment.py" "$phase" \
  --runner-state "$phase_root/runner.sqlite" \
  --reconciliation "$phase_root/reconciliation.json" \
  --resources "$phase_root/resources.ndjson" \
  --output-json "$phase_root/analysis.json" \
  --output-csv "$phase_root/per-route.csv"

if [[ "$phase" = rehearsal ]]; then
  "$python" "$repository_root/scripts/freeze_native_limits.py" \
    --analysis "$phase_root/analysis.json" \
    --resources "$phase_root/resources.ndjson" \
    --concurrency "$concurrency" \
    --batch-attempts "$batch_attempts" \
    --output "$phase_root/measured-limits.json"
fi
