#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 2 ]] || {
  echo "usage: $0 <start-agents|start-worker|start-monitor|status|stop> <runtime-root> [phase]" >&2
  exit 2
}
action=$1
runtime_root=$2
phase=${3:-}
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
pid_root="$runtime_root/pids"
log_root="$runtime_root/logs"
layerzero_key_file="$runtime_root/private/accounts/layerzero-worker.key"
validator_key_file="$runtime_root/private/accounts/hyperlane-validator.key"
relayer_key_file="$runtime_root/private/accounts/hyperlane-relayer.key"
mkdir -p "$pid_root" "$log_root"

alive() {
  local file=$1
  [[ -f "$file" ]] || return 1
  local pid
  pid=$(<"$file")
  kill -0 "$pid" 2>/dev/null
}

start_process() {
  local name=$1
  shift
  local pid_file="$pid_root/$name.pid"
  if alive "$pid_file"; then
    echo "$name already running" >&2
    return 1
  fi
  nohup "$@" >"$log_root/$name.log" 2>&1 </dev/null &
  echo "$!" >"$pid_file"
}

case "$action" in
  start-agents)
    "$repository_root/scripts/hyperlane_agents.sh" \
      start "$runtime_root" "$validator_key_file" "$relayer_key_file"
    ;;
  start-worker)
    start_process layerzero-worker \
      "$repository_root/.venv/bin/python" \
      "$repository_root/scripts/layerzero_worker.py" run \
      --config "$runtime_root/layerzero/worker-config.json" \
      --key-file "$layerzero_key_file" \
      --state "$runtime_root/layerzero/worker.sqlite" \
      --raw-root "$runtime_root/layerzero/worker-receipts" \
      --batch-packets 100
    ;;
  start-monitor)
    [[ "$phase" =~ ^(smoke|rehearsal|scale|recovery)$ ]] || {
      echo "monitor phase is required" >&2
      exit 2
    }
    stop_file="$runtime_root/runs/$phase/monitor.stop"
    rm -f "$stop_file"
    mkdir -p "$runtime_root/runs/$phase"
    start_process native-monitor \
      "$repository_root/.venv/bin/python" \
      "$repository_root/scripts/monitor_native_resources.py" \
      --runtime-root "$runtime_root" \
      --phase "$phase" \
      --output "$runtime_root/runs/$phase/resources.ndjson" \
      --stop-file "$stop_file" \
      --submission-stop-file "$runtime_root/runs/$phase/submissions.stop" \
      --minimum-docker-free-bytes $((8 * 1024 * 1024 * 1024)) \
      --minimum-gpfs-free-bytes $((40 * 1024 * 1024 * 1024)) \
      --interval 5
    ;;
  status)
    result=0
    for name in layerzero-worker native-monitor native-runner; do
      if alive "$pid_root/$name.pid"; then
        echo "$name running pid=$(<"$pid_root/$name.pid")"
      else
        echo "$name stopped"
        result=1
      fi
    done
    "$repository_root/scripts/hyperlane_agents.sh" \
      status "$runtime_root" "$validator_key_file" "$relayer_key_file" || result=1
    exit "$result"
    ;;
  stop)
    for stop in "$runtime_root"/runs/*/monitor.stop; do
      [[ -e "$stop" ]] && touch "$stop"
    done
    for name in layerzero-worker native-monitor native-runner; do
      pid_file="$pid_root/$name.pid"
      if alive "$pid_file"; then
        kill "$(<"$pid_file")"
      fi
    done
    "$repository_root/scripts/hyperlane_agents.sh" \
      stop "$runtime_root" "$validator_key_file" "$relayer_key_file"
    echo "dedicated native-stack processes stopped; validators, volumes, and evidence retained"
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
