#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 4 ]] || {
  echo "usage: $0 <start|status|stop> <runtime-root> <validator-key-file> <relayer-key-file> [workspace prereg review-gate lease token]" >&2
  exit 2
}
action=$1
runtime_root=$2
validator_key_file=$3
relayer_key_file=$4
shift 4
agent_root="$runtime_root/hyperlane/agents"
binary_root="$runtime_root/protocols/hyperlane/rust/main/target/release"
binary_working_directory="$runtime_root/protocols/hyperlane/rust/main"
pid_root="$agent_root/pids"
log_root="$agent_root/logs"
chains=(xirlocalchaina xirlocalchainb xirlocalchainc xirlocalchaind xirlocalchaine)
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
identity_cli="$repository_root/scripts/native_multihop_process_identity.py"

if [[ $action == start ]]; then
  [[ $# -eq 5 ]] || {
    echo "Hyperlane multihop start requires review closure and live lease authority" >&2
    exit 2
  }
  "$python" "$repository_root/scripts/verify_native_multihop_execution_authority.py" \
    --workspace-root "$1" --repository-root "$repository_root" \
    --runtime-root "$runtime_root" --preregistration "$2" \
    --review-gate "$3" --lease "$4" --lease-token "$5" >/dev/null
elif [[ $# -ne 0 ]]; then
  echo "Hyperlane status/stop do not accept write-authority arguments" >&2
  exit 2
fi

check_key() {
  local path=$1
  [[ -f "$path" ]] || { echo "agent key file not found: $path" >&2; exit 2; }
  local value
  value=$(tr -d '\r\n' <"$path")
  [[ "$value" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] || {
    echo "invalid agent key file: $path" >&2
    exit 2
  }
}

process_status() {
  local name=$1
  local pid_file="$pid_root/$name.pid"
  [[ -f "$pid_file" ]] || { echo "$name stopped"; return 1; }
  local pid
  pid=$(<"$pid_file")
  kill -0 "$pid" 2>/dev/null || { echo "$name stale pid=$pid"; return 1; }
  "$python" "$identity_cli" verify \
    --identity "${pid_file%.pid}.identity.json" >/dev/null 2>&1 || {
      echo "$name identity mismatch pid=$pid"
      return 1
    }
  echo "$name running pid=$pid"
}

record_identity() {
  local pid_file=$1
  local pid=$2
  echo "$pid" >"$pid_file"
  "$python" "$identity_cli" record --identity "${pid_file%.pid}.identity.json" \
    --pid "$pid" --runtime-root "$runtime_root" --expected-token "$runtime_root" \
    >/dev/null
}

require_startable() {
  local name=$1
  local pid_file="$pid_root/$name.pid"
  [[ -f $pid_file ]] || return 0
  local pid
  pid=$(<"$pid_file")
  if kill -0 "$pid" 2>/dev/null; then
    if "$python" "$identity_cli" verify \
      --identity "${pid_file%.pid}.identity.json" >/dev/null 2>&1; then
      echo "$name already running" >&2
    else
      echo "$name PID identity mismatch; refusing replacement" >&2
    fi
    return 1
  fi
  rm -f "$pid_file" "${pid_file%.pid}.identity.json"
}

case "$action" in
  start)
    check_key "$validator_key_file"
    check_key "$relayer_key_file"
    [[ -x "$binary_root/validator" && -x "$binary_root/relayer" ]] || {
      echo "pinned Hyperlane agent binaries are missing" >&2
      exit 1
    }
    mkdir -p "$pid_root" "$log_root" "$agent_root/db"
    for chain in "${chains[@]}"; do
      require_startable "validator-$chain"
    done
    require_startable relayer
    validator_key=$(tr -d '\r\n' <"$validator_key_file")
    [[ "$validator_key" = 0x* ]] || validator_key="0x$validator_key"
    for chain in "${chains[@]}"; do
      name="validator-$chain"
      (
        cd "$binary_working_directory"
        exec nohup env CONFIG_FILES="$agent_root/config/$name.json" \
          HYP_VALIDATOR_TYPE=hexKey HYP_VALIDATOR_KEY="$validator_key" \
          RUST_LOG=info "$binary_root/validator"
      ) >"$log_root/$name.log" 2>&1 </dev/null &
      record_identity "$pid_root/$name.pid" "$!"
    done
    unset validator_key
    relayer_key=$(tr -d '\r\n' <"$relayer_key_file")
    [[ "$relayer_key" = 0x* ]] || relayer_key="0x$relayer_key"
    (
      cd "$binary_working_directory"
      exec nohup env CONFIG_FILES="$agent_root/config/relayer.json" \
        HYP_DEFAULTSIGNER_TYPE=hexKey HYP_DEFAULTSIGNER_KEY="$relayer_key" \
        RUST_LOG=info "$binary_root/relayer"
    ) >"$log_root/relayer.log" 2>&1 </dev/null &
    record_identity "$pid_root/relayer.pid" "$!"
    unset relayer_key
    ;;
  status)
    result=0
    for chain in "${chains[@]}"; do
      process_status "validator-$chain" || result=1
    done
    process_status relayer || result=1
    exit "$result"
    ;;
  stop)
    names=(relayer)
    for chain in "${chains[@]}"; do names+=("validator-$chain"); done
    for name in "${names[@]}"; do
      pid_file="$pid_root/$name.pid"
      if [[ -f "$pid_file" ]]; then
        pid=$(<"$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
          if ! "$python" "$identity_cli" signal \
            --identity "${pid_file%.pid}.identity.json" --signal SIGTERM \
            >/dev/null 2>&1; then
            if kill -0 "$pid" 2>/dev/null; then
              echo "$name PID identity mismatch; refusing signal" >&2
              exit 1
            fi
          fi
        fi
      fi
    done
    for name in "${names[@]}"; do
      pid_file="$pid_root/$name.pid"
      [[ -f "$pid_file" ]] || continue
      pid=$(<"$pid_file")
      attempts=0
      while kill -0 "$pid" 2>/dev/null && [[ $attempts -lt 100 ]]; do
        sleep 0.1
        attempts=$((attempts + 1))
      done
      if kill -0 "$pid" 2>/dev/null; then
        echo "$name did not stop cleanly" >&2
        exit 1
      fi
      rm -f "$pid_file" "${pid_file%.pid}.identity.json"
    done
    ;;
  *) echo "unknown action: $action" >&2; exit 2 ;;
esac
