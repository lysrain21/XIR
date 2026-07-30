#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 4 ]] || {
  echo "usage: $0 <start|status|stop> <runtime-root> <validator-key-file> <relayer-key-file>" >&2
  exit 2
}
action=$1
runtime_root=$2
validator_key_file=$3
relayer_key_file=$4
agent_root="$runtime_root/hyperlane/agents"
binary_root="$runtime_root/protocols/hyperlane/rust/main/target/release"
binary_working_directory="$runtime_root/protocols/hyperlane/rust/main"
pid_root="$agent_root/pids"
log_root="$agent_root/logs"

check_key() {
  local path=$1
  [[ -f "$path" ]] || {
    echo "agent key file not found: $path" >&2
    exit 2
  }
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
  if [[ ! -f "$pid_file" ]]; then
    echo "$name stopped"
    return 1
  fi
  local pid
  pid=$(<"$pid_file")
  if kill -0 "$pid" 2>/dev/null; then
    echo "$name running pid=$pid"
    return 0
  fi
  echo "$name stale pid=$pid"
  return 1
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
    validator_key=$(tr -d '\r\n' <"$validator_key_file")
    [[ "$validator_key" = 0x* ]] || validator_key="0x$validator_key"
    for chain in xirlocalsource xirlocalintermediate xirlocaldestination; do
      name="validator-$chain"
      if process_status "$name" >/dev/null 2>&1; then
        echo "$name already running" >&2
        exit 1
      fi
      (
        cd "$binary_working_directory"
        exec nohup env \
          CONFIG_FILES="$agent_root/config/$name.json" \
          HYP_VALIDATOR_TYPE=hexKey \
          HYP_VALIDATOR_KEY="$validator_key" \
          RUST_LOG=info \
          "$binary_root/validator"
      ) >"$log_root/$name.log" 2>&1 </dev/null &
      echo "$!" >"$pid_root/$name.pid"
    done
    validator_key=
    relayer_key=$(tr -d '\r\n' <"$relayer_key_file")
    [[ "$relayer_key" = 0x* ]] || relayer_key="0x$relayer_key"
    (
      cd "$binary_working_directory"
      exec nohup env \
        CONFIG_FILES="$agent_root/config/relayer.json" \
        HYP_DEFAULTSIGNER_TYPE=hexKey \
        HYP_DEFAULTSIGNER_KEY="$relayer_key" \
        RUST_LOG=info \
        "$binary_root/relayer"
    ) >"$log_root/relayer.log" 2>&1 </dev/null &
    echo "$!" >"$pid_root/relayer.pid"
    relayer_key=
    ;;
  status)
    result=0
    for name in validator-xirlocalsource validator-xirlocalintermediate \
      validator-xirlocaldestination relayer; do
      process_status "$name" || result=1
    done
    exit "$result"
    ;;
  stop)
    for name in validator-xirlocalsource validator-xirlocalintermediate \
      validator-xirlocaldestination relayer; do
      pid_file="$pid_root/$name.pid"
      if [[ -f "$pid_file" ]]; then
        pid=$(<"$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
          kill "$pid"
        fi
      fi
    done
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
