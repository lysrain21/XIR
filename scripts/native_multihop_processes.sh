#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 2 ]] || {
  echo "usage: $0 <start-agents|start-worker|status|stop> <runtime-root> [workspace prereg review-gate lease token]" >&2
  exit 2
}
action=$1
runtime_root=$2
shift 2
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
identity_cli="$repository_root/scripts/native_multihop_process_identity.py"
pid_root="$runtime_root/pids"
log_root="$runtime_root/logs"

authority_args=()
if [[ $action == start-agents || $action == start-worker ]]; then
  [[ $# -eq 5 ]] || {
    echo "multihop service start requires workspace, preregistration, review gate, lease, and token" >&2
    exit 2
  }
  workspace_root=$1
  preregistration=$2
  review_gate=$3
  lease=$4
  lease_token=$5
  "$python" "$repository_root/scripts/verify_native_multihop_execution_authority.py" \
    --workspace-root "$workspace_root" --repository-root "$repository_root" \
    --runtime-root "$runtime_root" --preregistration "$preregistration" \
    --review-gate "$review_gate" --lease "$lease" --lease-token "$lease_token" \
    >/dev/null
  authority_args=("$workspace_root" "$preregistration" "$review_gate" "$lease" "$lease_token")
elif [[ $# -ne 0 ]]; then
  echo "status/stop do not accept write-authority arguments" >&2
  exit 2
fi

mkdir -p "$pid_root" "$log_root"

alive() {
  [[ -f "$1" ]] || return 1
  local pid
  pid=$(<"$1")
  kill -0 "$pid" 2>/dev/null || return 1
  "$python" "$identity_cli" verify --identity "${1%.pid}.identity.json" \
    >/dev/null 2>&1
}

record_identity() {
  local pid_file=$1
  local pid=$2
  echo "$pid" >"$pid_file"
  "$python" "$identity_cli" record --identity "${pid_file%.pid}.identity.json" \
    --pid "$pid" --runtime-root "$runtime_root" --expected-token "$runtime_root" \
    >/dev/null
}

signal_identity() {
  local pid_file=$1
  local signal_name=$2
  "$python" "$identity_cli" signal --identity "${pid_file%.pid}.identity.json" \
    --signal "$signal_name" >/dev/null
}

wait_stopped() {
  local pid_file=$1
  local label=$2
  local attempts=0
  while alive "$pid_file" && [[ $attempts -lt 100 ]]; do
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if alive "$pid_file"; then
    echo "$label did not stop cleanly" >&2
    return 1
  fi
  local pid
  pid=$(<"$pid_file")
  # Reaching this point means the recorded identity is no longer alive.  A
  # concurrently reused numeric PID belongs to another process and must be
  # left untouched; it is evidence that our original service has exited, not
  # a cleanup failure.
  if kill -0 "$pid" 2>/dev/null; then
    echo "$label exited; reused PID left untouched" >&2
  fi
}

case "$action" in
  start-agents)
    "$repository_root/scripts/multihop_hyperlane_agents.sh" start "$runtime_root" \
      "$runtime_root/private/accounts/hyperlane-validator.key" \
      "$runtime_root/private/accounts/hyperlane-relayer.key" \
      "${authority_args[@]}"
    ;;
  start-worker)
    if [[ -f $pid_root/layerzero-worker.pid ]]; then
      pid=$(<"$pid_root/layerzero-worker.pid")
      if kill -0 "$pid" 2>/dev/null; then
        if alive "$pid_root/layerzero-worker.pid"; then
          echo "layerzero worker already running" >&2
        else
          echo "layerzero worker PID identity mismatch; refusing replacement" >&2
        fi
        exit 1
      fi
      rm -f "$pid_root/layerzero-worker.pid" \
        "$pid_root/layerzero-worker.identity.json"
    fi
    nohup "$repository_root/.venv/bin/python" \
      "$repository_root/scripts/layerzero_worker.py" run \
      --config "$runtime_root/layerzero/worker-config.json" \
      --key-file "$runtime_root/private/accounts/layerzero-worker.key" \
      --state "$runtime_root/layerzero/worker.sqlite" \
      --raw-root "$runtime_root/layerzero/worker-receipts" \
      --runtime-root "$runtime_root" \
      --workspace-root "${authority_args[0]}" \
      --repository-root "$repository_root" \
      --preregistration "${authority_args[1]}" \
      --review-gate "${authority_args[2]}" \
      --lease "${authority_args[3]}" --lease-token "${authority_args[4]}" \
      --batch-packets 100 >"$log_root/layerzero-worker.log" 2>&1 </dev/null &
    record_identity "$pid_root/layerzero-worker.pid" "$!"
    ;;
  status)
    result=0
    alive "$pid_root/layerzero-worker.pid" || result=1
    "$repository_root/scripts/multihop_hyperlane_agents.sh" status "$runtime_root" \
      "$runtime_root/private/accounts/hyperlane-validator.key" \
      "$runtime_root/private/accounts/hyperlane-relayer.key" || result=1
    exit "$result"
    ;;
  stop)
    if alive "$pid_root/layerzero-worker.pid"; then
      if ! signal_identity "$pid_root/layerzero-worker.pid" SIGTERM; then
        pid=$(<"$pid_root/layerzero-worker.pid")
        if kill -0 "$pid" 2>/dev/null; then
          echo "layerzero worker PID identity mismatch; refusing signal" >&2
          exit 1
        fi
      fi
      wait_stopped "$pid_root/layerzero-worker.pid" "layerzero worker"
      rm -f "$pid_root/layerzero-worker.pid" \
        "$pid_root/layerzero-worker.identity.json"
    elif [[ -f $pid_root/layerzero-worker.pid ]]; then
      pid=$(<"$pid_root/layerzero-worker.pid")
      if kill -0 "$pid" 2>/dev/null; then
        echo "layerzero worker PID identity mismatch; refusing signal" >&2
        exit 1
      fi
      rm -f "$pid_root/layerzero-worker.pid" \
        "$pid_root/layerzero-worker.identity.json"
    fi
    "$repository_root/scripts/multihop_hyperlane_agents.sh" stop "$runtime_root" \
      "$runtime_root/private/accounts/hyperlane-validator.key" \
      "$runtime_root/private/accounts/hyperlane-relayer.key"
    ;;
  *) echo "unknown action: $action" >&2; exit 2 ;;
esac
