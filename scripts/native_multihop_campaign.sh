#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 <workspace-root> <runtime-root> [--resume | --fault-injection-dry-run <boundary>]" >&2
  exit 2
}

[[ $# -eq 2 || $# -eq 3 || $# -eq 4 ]] || usage
WORKSPACE=$1
RUNTIME=$2
MODE=production
FAIL_AT=
RESUME=0
RESUME_REQUIRED=0
if [[ $# -eq 3 ]]; then
  [[ $3 == --resume ]] || usage
  RESUME=1
elif [[ $# -eq 4 ]]; then
  [[ $3 == --fault-injection-dry-run ]] || usage
  MODE=dry-run
  FAIL_AT=$4
fi
[[ $WORKSPACE = /* && $RUNTIME = /* ]] || usage
if [[ $MODE == production ]]; then
  CANONICAL_WORKSPACE=$(realpath -e "$WORKSPACE") || usage
else
  CANONICAL_WORKSPACE=$(realpath -m "$WORKSPACE") || usage
fi
CANONICAL_RUNTIME=$(realpath -m "$RUNTIME") || usage
[[ ! -L $WORKSPACE && ! -L $RUNTIME \
  && $CANONICAL_WORKSPACE == "$WORKSPACE" \
  && $CANONICAL_RUNTIME == "$RUNTIME" ]] || {
  echo "workspace and runtime must be canonical, non-symlink absolute paths" >&2
  exit 2
}
RUN_ID=$(basename "$RUNTIME")
if [[ $MODE == production && ! $RUN_ID =~ ^run-[0-9]{3}$ ]]; then
  echo "production runtime basename must be run-NNN" >&2
  exit 2
fi

REPO="$WORKSPACE/xir-testnet-lab"
SCRIPT_REPO="$(cd "$(dirname "$0")/.." && pwd)"
CHANGE="$WORKSPACE/openspec/changes/measure-multihop-switching-scalability"
TOPOLOGY="$REPO/configs/local/topology-multihop-remote-v1.json"
CAMPAIGN_KIND=${XIR_MULTIHOP_CAMPAIGN_KIND:-formal}
case "$CAMPAIGN_KIND" in
  formal)
    CONFIG="$REPO/configs/native/native-multihop-switching-v1.json"
    PREREG="$CHANGE/artifacts/preregistration-v1.json"
    EVIDENCE_NAMESPACE=native-multihop-switching-v1
    PUBLICATION_NAMESPACE=native-multihop-switching-v1
    ;;
  pilot)
    CONFIG="$REPO/configs/native/native-multihop-switching-pilot-v1.json"
    PREREG="$CHANGE/artifacts/pilot-preregistration-v1.json"
    EVIDENCE_NAMESPACE=native-multihop-switching-pilot-v1
    PUBLICATION_NAMESPACE=native-multihop-switching-pilot-v1
    ;;
  *)
    echo "unsupported XIR_MULTIHOP_CAMPAIGN_KIND: $CAMPAIGN_KIND" >&2
    exit 2
    ;;
esac
TRACE_CONCURRENCY=8
TRACE_SETTLE_SECONDS=0
if [[ $CAMPAIGN_KIND == pilot ]]; then
  TRACE_CONCURRENCY=1
  TRACE_SETTLE_SECONDS=30
fi
PROFILE_SOURCE="$REPO/configs/profiles/native-multihop-five-chain-v1.json"
DEPLOYMENT_RELATIVE=native-multihop-switching-v1/deployment/deployment.json
if [[ $MODE == production ]]; then
  COMPOSE_PROJECT=$(jq -er \
    '.project_name | select(type == "string" and test("^[a-z0-9][a-z0-9-]*$"))' \
    "$TOPOLOGY")
  [[ $COMPOSE_PROJECT == xir-native-multihop-v1 ]] || {
    echo "multihop topology compose project is not the frozen project identity" >&2
    exit 2
  }
else
  COMPOSE_PROJECT=xir-native-multihop-v1
fi
if [[ $MODE == production ]]; then
  REVIEW_REL=$(jq -er '.review_gate.closure_audit_path | select(type == "string")' "$PREREG")
  [[ $REVIEW_REL =~ ^openspec/changes/measure-multihop-switching-scalability/artifacts/(pilot-)?independent-readonly-closure-v[0-9]+\.json$ ]] || {
    echo "preregistration review closure path is invalid" >&2
    exit 2
  }
  REVIEW=$(realpath -e "$WORKSPACE/$REVIEW_REL") || {
    echo "preregistration review closure is absent" >&2
    exit 2
  }
  [[ ! -L $REVIEW && $REVIEW == "$CHANGE/artifacts/"* ]] || {
    echo "preregistration review closure must be canonical below change artifacts" >&2
    exit 2
  }
else
  REVIEW="$CHANGE/artifacts/dry-run-review-placeholder.json"
fi
PY="$REPO/.venv/bin/python"
if [[ $MODE == dry-run ]]; then
  REPO=$SCRIPT_REPO
  PY="$REPO/.venv/bin/python"
fi
# Bind every Python child to the reviewed source tree.  Formal execution must
# not depend on an editable install or an inherited interactive-shell setting.
export PYTHONPATH="$REPO/src"
LEASE="$RUNTIME/provenance/exclusive-writer-lease/lease.json"
LEASE_TOKEN="$RUNTIME/private/writer-lease.token"
if [[ $MODE == dry-run ]]; then
  HOST_LEASE_BASE=${XIR_MULTIHOP_HOST_LEASE_BASE:-"/run/lock/xir-lab-runtime-leases"}
else
  [[ -z ${XIR_MULTIHOP_HOST_LEASE_BASE+x} ]] || {
    echo "production host-global lease base cannot be overridden" >&2
    exit 2
  }
  HOST_LEASE_BASE="/run/lock/xir-lab-runtime-leases"
fi
[[ $HOST_LEASE_BASE = /* && ! -L $HOST_LEASE_BASE ]] || {
  echo "host-global lease base must be an absolute, non-symlink path" >&2
  exit 2
}
# Pilot and formal executions share one host-global writer lock because both
# own the same five-chain Compose project and protocol service ports.
GLOBAL_LEASE_ROOT="$HOST_LEASE_BASE/native-multihop-switching-v1"
REVIEW_GATE="$RUNTIME/provenance/predeployment-review-gate.json"
LEASE_SUPERVISOR_STOP="$RUNTIME/provenance/lease-supervisor.stop"
LEASE_SUPERVISOR_PID=
LEASE_ACQUIRED=0
CLEANUP_COMPLETE=0
CURRENT_RUN=
export XIR_LOCAL_RUNTIME_ROOT="$RUNTIME"

FAILPOINTS=(review_gate lease preflight runner_launch runner_sigstop freeze rebuild handoff service_stop sync)

record() {
  mkdir -p "$RUNTIME/provenance"
  printf '%s\n' "$1" >>"$RUNTIME/provenance/campaign-lifecycle.log"
}

failpoint() {
  local boundary=$1
  record "boundary:$boundary"
  if [[ $FAIL_AT == "$boundary" ]]; then
    echo "injected failure at $boundary" >&2
    return 97
  fi
}

valid_pid() {
  [[ ${1:-} =~ ^[0-9]+$ ]] && (( $1 > 1 ))
}

alive() {
  valid_pid "${1:-}" && kill -0 "$1" 2>/dev/null
}

identity_path_for_pidfile() {
  printf '%s.identity.json\n' "${1%.pid}"
}

record_pid_identity() {
  local pidfile=$1
  local pid=$2
  printf '%s\n' "$pid" >"$pidfile"
  "$PY" "$REPO/scripts/native_multihop_process_identity.py" record \
    --identity "$(identity_path_for_pidfile "$pidfile")" --pid "$pid" \
    --runtime-root "$RUNTIME" --expected-token "$RUNTIME" >/dev/null
}

owned_process_alive() {
  local pidfile=$1
  [[ -f $pidfile ]] || return 1
  local pid
  pid=$(tr -d '\r\n' <"$pidfile")
  alive "$pid" || return 1
  "$PY" "$REPO/scripts/native_multihop_process_identity.py" verify \
    --identity "$(identity_path_for_pidfile "$pidfile")" >/dev/null 2>&1
}

complete_pidfile() {
  local pidfile=$1
  rm -f "$pidfile" "$(identity_path_for_pidfile "$pidfile")"
}

bounded_wait() {
  local pid=$1
  local seconds=${2:-30}
  local deadline=$((SECONDS + seconds))
  while alive "$pid" && (( SECONDS < deadline )); do
    sleep 0.1
  done
  ! alive "$pid"
}

wait_for_durable_ready() {
  local ready=$1
  local pidfile=$2
  local schema=$3
  local pid_key=$4
  local deadline=$((SECONDS + 45))
  local pid
  pid=$(<"$pidfile")
  while (( SECONDS < deadline )); do
    owned_process_alive "$pidfile" || {
      echo "process exited before durable readiness: $pidfile" >&2
      return 1
    }
    if [[ -s $ready ]] && jq -e --arg schema "$schema" --argjson pid "$pid" \
      --arg pid_key "$pid_key" \
      '.schema_version == $schema and .valid == true and .[$pid_key] == $pid' \
      "$ready" >/dev/null; then
      record "durable-ready:$schema:$pid"
      return 0
    fi
    sleep 0.1
  done
  echo "durable readiness timed out: $ready" >&2
  return 1
}

write_sidecar_failure_stop() {
  local path=$1
  local reason=$2
  "$PY" - "$path" "$reason" <<'PY'
import json
import os
import sys
import time
from pathlib import Path
path = Path(sys.argv[1])
reason = sys.argv[2]
temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
with temporary.open("x", encoding="utf-8") as stream:
    stream.write(json.dumps({
        "schema_version": "xir-lab-submission-stop-v1",
        "reason": reason,
        "utc_ns": time.time_ns(),
    }, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, path)
directory_fd = os.open(path.parent, os.O_RDONLY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

stop_pidfile() {
  local pidfile=$1
  local resume_first=${2:-0}
  [[ -f $pidfile ]] || return 0
  local pid
  pid=$(tr -d '\r\n' <"$pidfile")
  valid_pid "$pid" || {
    echo "invalid PID file: $pidfile" >&2
    return 1
  }
  if ! alive "$pid"; then
    complete_pidfile "$pidfile"
    return 0
  fi
  owned_process_alive "$pidfile" || {
    if ! alive "$pid"; then
      complete_pidfile "$pidfile"
      return 0
    fi
    echo "refusing to signal process with mismatched identity: $pidfile" >&2
    return 1
  }
  if [[ $resume_first -eq 1 ]]; then
    if ! "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
      --identity "$(identity_path_for_pidfile "$pidfile")" --signal SIGCONT \
      >/dev/null 2>&1; then
      if ! alive "$pid"; then
        complete_pidfile "$pidfile"
        return 0
      fi
      return 1
    fi
  fi
  if bounded_wait "$pid" 3; then
    complete_pidfile "$pidfile"
    return 0
  fi
  if ! "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
    --identity "$(identity_path_for_pidfile "$pidfile")" --signal SIGTERM \
    >/dev/null 2>&1; then
    if ! alive "$pid"; then
      complete_pidfile "$pidfile"
      return 0
    fi
    return 1
  fi
  if bounded_wait "$pid" 10; then
    complete_pidfile "$pidfile"
    return 0
  fi
  if ! "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
    --identity "$(identity_path_for_pidfile "$pidfile")" --signal SIGKILL \
    >/dev/null 2>&1; then
    if ! alive "$pid"; then
      complete_pidfile "$pidfile"
      return 0
    fi
    return 1
  fi
  bounded_wait "$pid" 5 || return 1
  complete_pidfile "$pidfile"
}

stop_resource_monitor_pidfile() {
  local run=$1
  local pidfile=$run/resource-monitor.pid
  [[ -f $pidfile ]] || return 0
  touch "$run/monitor.stop"
  # One in-flight sample can include 15 RPC calls (5 chains x 3 methods)
  # plus two bounded Docker probes.  Let that sample finish and fsync its
  # completion rather than terminating the monitor mid-record.
  local deadline=$((SECONDS + 150))
  local pid
  pid=$(<"$pidfile")
  owned_process_alive "$pidfile" || {
    alive "$pid" && return 1
    complete_pidfile "$pidfile"
    shopt -s nullglob
    local existing_segments=("$run"/resource-samples.segment-*.jsonl)
    shopt -u nullglob
    if (( ${#existing_segments[@]} > 0 )); then
      local existing_last=${existing_segments[$((${#existing_segments[@]} - 1))]}
      if ! resource_completion_covers_runner_tail \
        "$run" "${existing_last%.jsonl}.completion.json"; then
        RESUME_REQUIRED=1
        record "resource-monitor-dead-tail-requires-resume:$run"
        quarantine_resource_segment "$run" "$existing_last"
        return 1
      fi
    fi
    quarantine_incomplete_resource_tail "$run"
    return 0
  }
  while alive "$pid" && (( SECONDS < deadline )); do sleep 0.2; done
  if alive "$pid"; then
    echo "resource monitor did not write a graceful completion within 150s" >&2
    return 1
  fi
  complete_pidfile "$pidfile"
  shopt -s nullglob
  local segments=("$run"/resource-samples.segment-*.jsonl)
  shopt -u nullglob
  (( ${#segments[@]} > 0 )) || return 1
  local last=${segments[$((${#segments[@]} - 1))]}
  if ! resource_completion_covers_runner_tail \
    "$run" "${last%.jsonl}.completion.json"; then
    quarantine_resource_segment "$run" "$last"
    quarantine_incomplete_resource_tail "$run"
    RESUME_REQUIRED=1
    record "resource-monitor-stop-tail-quarantined:$run"
    return 1
  fi
}

resource_completion_covers_runner_tail() {
  local run=$1
  local completion=$2
  [[ -f $completion ]] || return 1
  local runner_utc=0
  if [[ -f $run/runner.sqlite ]]; then
    runner_utc=$("$PY" - "$run/runner.sqlite" <<'PY'
import sqlite3
import sys
with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    row = connection.execute("SELECT COALESCE(MAX(utc_ns),0) FROM events").fetchone()
if row is None:
    raise RuntimeError("runner event tail query returned no row")
print(int(row[0]))
PY
) || return 1
  fi
  jq -e --argjson runner_utc "$runner_utc" \
    '.valid == true and .last_utc_ns >= $runner_utc' "$completion" \
    >/dev/null 2>&1
}

quarantine_resource_segment() {
  local run=$1
  local segment=$2
  local completion=${segment%.jsonl}.completion.json
  local quarantine=$run/resume-quarantine/resource-tail-$(date --utc +%Y%m%dT%H%M%S.%NZ)
  mkdir -p "$quarantine"
  [[ ! -e $segment ]] || mv "$segment" "$quarantine/"
  [[ ! -e $completion ]] || mv "$completion" "$quarantine/"
  record "resource-monitor-tail-quarantined:$quarantine"
}

quarantine_incomplete_resource_tail() {
  local run=$1
  shopt -s nullglob
  local segments=("$run"/resource-samples.segment-*.jsonl)
  shopt -u nullglob
  (( ${#segments[@]} > 0 )) || return 0
  local index segment completion quarantine
  for ((index = 0; index < ${#segments[@]}; index++)); do
    segment=${segments[$index]}
    completion=${segment%.jsonl}.completion.json
    if [[ -f $completion ]] && jq -e --arg path "$(basename "$segment")" \
      '.schema_version == "xir-lab-native-multihop-resource-segment-completion-v1" and .valid == true and .path == $path' \
      "$completion" >/dev/null 2>&1; then
      continue
    fi
    (( index == ${#segments[@]} - 1 )) || {
      echo "non-tail resource monitor segment lacks completion" >&2
      return 1
    }
    quarantine=$run/resume-quarantine/resource-monitor-$(date --utc +%Y%m%dT%H%M%S.%NZ)
    mkdir -p "$quarantine"
    mv "$segment" "$quarantine/"
    [[ ! -e $completion ]] || mv "$completion" "$quarantine/"
    record "partial-resource-monitor-segment-quarantined:$segment:$quarantine"
  done
}

wait_for_stopped_process() {
  local pid=$1
  local attempts=${2:-200}
  local state
  local iteration
  for ((iteration = 0; iteration < attempts; iteration++)); do
    if [[ ! -r /proc/$pid/status ]]; then
      record "runner-stop-handshake-failed:$pid:exited"
      return 1
    fi
    state=$(awk '/^State:/ {print $2}' "/proc/$pid/status")
    if [[ $state == T || $state == t ]]; then
      record "runner-stop-handshake-complete:$pid"
      return 0
    fi
    sleep 0.05
  done
  record "runner-stop-handshake-failed:$pid:timeout"
  return 1
}

phase_writers_dead() {
  local pidfile pid
  shopt -s nullglob
  for pidfile in "$RUNTIME"/runs/*/{runner,resource-monitor,hyperlane-observer}.pid; do
    pid=$(tr -d '\r\n' <"$pidfile")
    if alive "$pid"; then
      owned_process_alive "$pidfile" || {
        shopt -u nullglob
        return 1
      }
      shopt -u nullglob
      return 1
    fi
    complete_pidfile "$pidfile"
  done
  shopt -u nullglob
  return 0
}

release_lease_after_writers_dead() {
  if [[ $LEASE_ACQUIRED -eq 0 ]]; then
    record "no-lease-acquired"
    return 0
  fi
  phase_writers_dead || {
    echo "refusing to release writer lease while a phase process is alive" >&2
    return 1
  }
  if [[ $MODE == dry-run ]]; then
    rm -f "$LEASE" "$LEASE_TOKEN"
    if [[ -d $GLOBAL_LEASE_ROOT ]]; then
      rm -f "$GLOBAL_LEASE_ROOT/owner.json"
      rmdir "$GLOBAL_LEASE_ROOT"
    fi
  elif [[ $LEASE_ACQUIRED -eq 1 && -L $LEASE && -f $LEASE_TOKEN ]]; then
    "$PY" "$REPO/scripts/native_multihop_lease.py" release \
      --runtime-root "$RUNTIME" --preregistration "$PREREG" \
      --lease "$LEASE" --token "$LEASE_TOKEN"
  fi
  LEASE_ACQUIRED=0
  record "lease-released-after-writers-dead"
}

validator_volume_command() {
  "$PY" "$REPO/scripts/stage_native_multihop_validator_volumes.py" "$1" \
    --workspace-root "$WORKSPACE" --repository-root "$REPO" \
    --runtime-root "$RUNTIME" --topology "$TOPOLOGY" \
    --identity-manifest "$RUNTIME/identity-manifest.json" \
    --compose "$RUNTIME/compose.yaml" --preregistration "$PREREG" \
    --review-gate "$REVIEW_GATE" --lease "$LEASE" --lease-token "$LEASE_TOKEN" \
    --attestation "$RUNTIME/provenance/validator-volume-bootstrap.json" \
    --journal "$RUNTIME/provenance/validator-volume-transaction.json" \
    --recovery-output "$RUNTIME/provenance/validator-volume-recovery.json" \
    "${@:2}"
}

validator_containers_absent() {
  [[ -z $(docker compose --project-name "$COMPOSE_PROJECT" \
    -f "$RUNTIME/compose.yaml" ps --all --quiet) ]]
}

cleanup_multihop_runtime() {
  local status=${1:-$?}
  [[ $CLEANUP_COMPLETE -eq 0 ]] || return "$status"
  CLEANUP_COMPLETE=1
  trap - EXIT ERR INT TERM
  local cleanup_failed=0
  local run_root
  shopt -s nullglob
  for run_root in "$RUNTIME"/runs/*; do
    [[ -d $run_root ]] || continue
    touch "$run_root/submission.stop" "$run_root/hyperlane-observer.stop"
    stop_pidfile "$run_root/runner.pid" 1 || cleanup_failed=1
    stop_resource_monitor_pidfile "$run_root" || cleanup_failed=1
    stop_pidfile "$run_root/hyperlane-observer.pid" || cleanup_failed=1
  done
  shopt -u nullglob
  if [[ $MODE == production && -x $REPO/scripts/native_multihop_processes.sh ]]; then
    if ! timeout 60 "$REPO/scripts/native_multihop_processes.sh" stop "$RUNTIME"; then
      cleanup_failed=1
    fi
  fi
  if [[ $MODE == production && -f $RUNTIME/compose.yaml ]]; then
    if ! timeout 120 docker compose --project-name "$COMPOSE_PROJECT" \
      -f "$RUNTIME/compose.yaml" down --remove-orphans; then
      cleanup_failed=1
    fi
  fi
  if ! phase_writers_dead; then
    cleanup_failed=1
  else
    record "all-phase-writers-dead"
  fi
  if [[ $MODE == production ]]; then
    if pgrep -af '[r]un_native_multihop|[a]nalyze_native_multihop|[r]ebuild_native_multihop|[r]ender_native_multihop|[m]onitor_native_multihop|[o]bserve_native_multihop' \
      | grep -F -- "$RUNTIME" >"$RUNTIME/provenance/remaining-processes.txt"; then
      cleanup_failed=1
    fi
    if [[ -f $RUNTIME/compose.yaml ]] && ! validator_containers_absent; then
      cleanup_failed=1
    fi
  fi
  if [[ $MODE == dry-run && ${XIR_TEST_FORCE_CLEANUP_FAILURE:-0} == 1 ]]; then
    cleanup_failed=1
  fi
  if [[ $RESUME_REQUIRED -eq 1 && $cleanup_failed -eq 0 ]]; then
    if [[ $LEASE_ACQUIRED -ne 1 ]] || \
      ! owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
      cleanup_failed=1
    elif [[ $MODE == production ]]; then
      if ! "$PY" "$REPO/scripts/native_multihop_lease.py" mark-resume-pending \
        --runtime-root "$RUNTIME" --preregistration "$PREREG" \
        --lease "$LEASE" --token "$LEASE_TOKEN" >/dev/null; then
        cleanup_failed=1
      fi
    fi
    if [[ $cleanup_failed -eq 0 ]]; then
      record "resume-required-clean-shutdown-lease-retained"
      record "cleanup-complete-resume-pending"
      return "$status"
    fi
  fi
  if [[ $MODE == production && $cleanup_failed -eq 0 ]]; then
    if [[ -f $RUNTIME/provenance/validator-volume-bootstrap.json ]]; then
      if ! validator_volume_command remove-existing; then
        cleanup_failed=1
      else
        record "validator-volumes-removed-after-writers-dead"
      fi
    elif [[ -f $RUNTIME/provenance/validator-volume-transaction.json ]]; then
      if ! validator_volume_command recover-incomplete; then
        cleanup_failed=1
      else
        record "incomplete-validator-volume-transaction-recovered"
      fi
    elif [[ -f $RUNTIME/provenance/validator-volume-bootstrap-failure.json ]]; then
      cleanup_failed=1
    fi
  fi
  if [[ $cleanup_failed -eq 0 ]]; then
    if [[ -n $LEASE_SUPERVISOR_STOP ]]; then
      touch "$LEASE_SUPERVISOR_STOP"
    fi
    if [[ -n $LEASE_SUPERVISOR_PID ]] && \
      owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
      if ! bounded_wait "$LEASE_SUPERVISOR_PID" 5; then
        "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
          --identity "$RUNTIME/provenance/lease-supervisor.identity.json" \
          --signal SIGTERM >/dev/null || cleanup_failed=1
        bounded_wait "$LEASE_SUPERVISOR_PID" 5 || cleanup_failed=1
      fi
      if ! alive "$LEASE_SUPERVISOR_PID"; then
        complete_pidfile "$RUNTIME/provenance/lease-supervisor.pid"
      fi
    fi
  fi
  if [[ $cleanup_failed -eq 0 ]]; then
    if ! release_lease_after_writers_dead; then
      cleanup_failed=1
    fi
  fi
  if [[ $cleanup_failed -ne 0 ]]; then
    if [[ $LEASE_ACQUIRED -eq 1 ]]; then
      if [[ $MODE == production && -L $LEASE && -f $LEASE_TOKEN ]]; then
        local retain_pid=$LEASE_SUPERVISOR_PID
        if ! owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
          retain_pid=$$
        fi
        if ! "$PY" "$REPO/scripts/native_multihop_lease.py" retain \
          --runtime-root "$RUNTIME" --preregistration "$PREREG" \
          --lease "$LEASE" --token "$LEASE_TOKEN" \
          --supervisor-pid "$retain_pid"; then
          record "cleanup-incomplete-lease-retain-marker-failed"
          echo "cleanup incomplete and durable recovery block failed" >&2
          return 1
        fi
        record "cleanup-incomplete-recovery-blocked"
      fi
      if ! owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
        start_lease_supervisor
        if [[ $MODE == production ]]; then
          "$PY" "$REPO/scripts/native_multihop_lease.py" retain \
            --runtime-root "$RUNTIME" --preregistration "$PREREG" \
            --lease "$LEASE" --token "$LEASE_TOKEN" \
            --supervisor-pid "$LEASE_SUPERVISOR_PID" >/dev/null
        fi
      fi
      if ! owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
        record "cleanup-incomplete-lease-supervisor-unavailable"
        echo "cleanup incomplete and lease supervisor unavailable" >&2
        return 1
      fi
      record "cleanup-incomplete-lease-supervisor-active:$LEASE_SUPERVISOR_PID"
    fi
    record "cleanup-incomplete-lease-retained"
    echo "cleanup incomplete; canonical writer lease retained" >&2
    return 1
  fi
  record "cleanup-complete"
  return "$status"
}

on_exit() {
  local status=$?
  cleanup_multihop_runtime "$status"
}
trap on_exit EXIT
trap 'RESUME_REQUIRED=1; record "campaign-signal-resume-required"; exit 130' INT TERM
trap 'exit $?' ERR

start_lease_supervisor() {
  rm -f "$LEASE_SUPERVISOR_STOP"
  (
    while [[ ! -f $LEASE_SUPERVISOR_STOP ]]; do
      date +%s%N >"$RUNTIME/provenance/lease-supervisor-heartbeat-ns"
      if [[ $MODE == production && -f $RUNTIME/provenance/lease-supervisor.ready \
        && -L $LEASE && -f $LEASE_TOKEN ]]; then
        "$PY" "$REPO/scripts/native_multihop_lease.py" heartbeat \
          --runtime-root "$RUNTIME" --preregistration "$PREREG" \
          --lease "$LEASE" --token "$LEASE_TOKEN"
      fi
      sleep 1
    done
  ) >"$RUNTIME/logs/lease-supervisor.log" 2>&1 &
  LEASE_SUPERVISOR_PID=$!
  disown "$LEASE_SUPERVISOR_PID" 2>/dev/null || true
  record_pid_identity "$RUNTIME/provenance/lease-supervisor.pid" \
    "$LEASE_SUPERVISOR_PID"
}

prepare_environment() {
  mkdir -p "$RUNTIME" "$RUNTIME/provenance" "$RUNTIME/runs" "$RUNTIME/private" \
    "$RUNTIME/logs" "$(dirname "$GLOBAL_LEASE_ROOT")"
  chmod 0700 "$(dirname "$GLOBAL_LEASE_ROOT")"
  [[ $(stat -c '%u:%a' "$(dirname "$GLOBAL_LEASE_ROOT")") == "$(id -u):700" ]] || {
    echo "host-global lease base ownership/mode is invalid" >&2
    return 1
  }
  if [[ $MODE == production ]]; then
    cp "$PROFILE_SOURCE" "$RUNTIME/profile.json"
    {
      date --utc --iso-8601=ns
      uname -a
      cat /proc/sys/kernel/random/boot_id
      df -B1 "$RUNTIME"
      ss -lntup
      docker ps --no-trunc
      pgrep -af 'native|hyperlane|layerzero|besu' || true
      git -C "$REPO" rev-parse HEAD
      git -C "$REPO" status --porcelain=v2
      sha256sum "$PREREG" "$REVIEW" "$CONFIG" "$PROFILE_SOURCE" "$TOPOLOGY"
    } >"$RUNTIME/provenance/pre-lease-host-and-source-inventory.txt"
    "$PY" "$REPO/scripts/verify_native_multihop_review_gate.py" \
      --workspace-root "$WORKSPACE" --repository-root "$REPO" \
      --preregistration "$PREREG" --output "$REVIEW_GATE"
  fi
}

acquire_lease() {
  start_lease_supervisor
  if [[ $MODE == dry-run ]]; then
    mkdir "$GLOBAL_LEASE_ROOT"
    printf '{}\n' >"$GLOBAL_LEASE_ROOT/owner.json"
    mkdir -p "$(dirname "$LEASE")"
    ln -s "$GLOBAL_LEASE_ROOT/owner.json" "$LEASE"
    printf 'dry-run-token\n' >"$LEASE_TOKEN"
  else
    "$PY" "$REPO/scripts/native_multihop_lease.py" acquire \
      --runtime-root "$RUNTIME" --preregistration "$PREREG" \
      --review-closure "$REVIEW" \
      --lease "$LEASE" --token "$LEASE_TOKEN" \
      --global-lock-root "$GLOBAL_LEASE_ROOT" \
      --holder "$EVIDENCE_NAMESPACE" --ttl-seconds 172800 \
      --supervisor-pid "$LEASE_SUPERVISOR_PID"
    touch "$RUNTIME/provenance/lease-supervisor.ready"
  fi
  LEASE_ACQUIRED=1
}

capture_heads() {
  local output=$1
  local role index rpc head temporary
  temporary=$output.tmp
  printf '{}\n' >"$temporary"
  for role in a b c d e; do
    index=$(( $(printf '%d' "'$role") - $(printf '%d' "'a") ))
    rpc=$(jq -er ".chains[$index].rpc_url" "$RUNTIME/profile.json")
    head=$(cast block-number --rpc-url "$rpc")
    jq --arg role "$role" --argjson head "$head" '.[$role]=$head' \
      "$temporary" >"$temporary.next"
    mv "$temporary.next" "$temporary"
  done
  mv "$temporary" "$output"
}

merge_resource_segments() {
  local run=$1
  "$PY" - "$run" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
segments = sorted(root.glob("resource-samples.segment-*.jsonl"))
if not segments:
    raise SystemExit("no resource-monitor segments")
expected = 0
payload = bytearray()
manifest_segments = []
for segment in segments:
    completion_path = segment.with_suffix(".completion.json")
    completion = json.loads(completion_path.read_text(encoding="utf-8"))
    raw = segment.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    sequences = [int(row["sequence"]) for row in rows]
    checks = (
        completion.get("schema_version")
        == "xir-lab-native-multihop-resource-segment-completion-v1"
        and completion.get("valid") is True
        and completion.get("path") == segment.name
        and completion.get("sha256") == hashlib.sha256(raw).hexdigest()
        and int(completion.get("sample_count", -1)) == len(rows)
        and sequences == list(range(expected, expected + len(rows)))
        and int(completion.get("sequence_start", -1)) == expected
        and int(completion.get("sequence_end", -1)) == expected + len(rows) - 1
    )
    if not checks:
        raise SystemExit(f"invalid resource-monitor segment: {segment.name}")
    expected += len(rows)
    payload.extend(raw)
    manifest_segments.append(completion)
temporary = root / f".resource-samples.jsonl.{os.getpid()}.tmp"
with temporary.open("xb") as stream:
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, root / "resource-samples.jsonl")
manifest = {
    "schema_version": "xir-lab-native-multihop-resource-segments-v1",
    "valid": True,
    "segments": manifest_segments,
    "combined_path": "resource-samples.jsonl",
    "combined_sha256": hashlib.sha256(payload).hexdigest(),
    "sample_count": expected,
}
manifest_path = root / "resource-segments.json"
temporary = root / f".resource-segments.json.{os.getpid()}.tmp"
with temporary.open("x", encoding="utf-8") as stream:
    stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, manifest_path)
PY
}

start_dry_phase_processes() {
  local run=$RUNTIME/runs/smoke
  mkdir -p "$run"
  (
    kill -STOP "$BASHPID"
    while [[ ! -f $run/submission.stop ]]; do sleep 0.05; done
  ) &
  record_pid_identity "$run/runner.pid" "$!"
  ( while [[ ! -f $run/monitor.stop ]]; do sleep 0.05; done ) &
  record_pid_identity "$run/resource-monitor.pid" "$!"
  ( while [[ ! -f $run/hyperlane-observer.stop ]]; do sleep 0.05; done ) &
  record_pid_identity "$run/hyperlane-observer.pid" "$!"
}

start_and_admit_validator_containers() {
  docker compose --project-name "$COMPOSE_PROJECT" \
    -f "$RUNTIME/compose.yaml" up --detach --wait --wait-timeout 150
  validator_volume_command verify-existing
  record "validator-volumes-live-mapping-admitted-before-protocol-writers"
}

deploy_and_preflight() {
  "$PY" "$REPO/scripts/prepare_native_multihop_topology.py" \
    --topology "$TOPOLOGY" --runtime-root "$RUNTIME" \
    --repository-root "$REPO" --initialize
  validator_volume_command stage \
    --failure-output "$RUNTIME/provenance/validator-volume-bootstrap-failure.json"
  start_and_admit_validator_containers
  "$REPO/scripts/bootstrap_native_protocols.sh" all "$RUNTIME" \
    "$REPO/toolchain/native-protocol-stack.lock.json"
  "$REPO/scripts/deploy_native_multihop_stack.sh" "$RUNTIME" "$WORKSPACE" "$PREREG"
  "$REPO/scripts/native_multihop_processes.sh" start-agents "$RUNTIME" \
    "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
  "$REPO/scripts/native_multihop_processes.sh" start-worker "$RUNTIME" \
    "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
  "$PY" "$REPO/scripts/preflight_native_multihop.py" \
    --workspace-root "$WORKSPACE" --repository-root "$REPO" \
    --runtime-root "$RUNTIME" --topology "$TOPOLOGY" \
    --identity "$RUNTIME/identity-manifest.json" --config "$CONFIG" \
    --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
    --preregistration "$PREREG" --review-gate "$REVIEW_GATE" \
    --lease "$LEASE" --lease-token "$LEASE_TOKEN" \
    --validator-volume-attestation \
      "$RUNTIME/provenance/validator-volume-bootstrap.json" \
    --validator-volume-journal \
      "$RUNTIME/provenance/validator-volume-transaction.json" \
    --output "$RUNTIME/preflight.json"
  jq -e '.valid == true' "$RUNTIME/preflight.json" >/dev/null
}

phase_runner_complete() {
  local phase=$1
  local database=$RUNTIME/runs/$phase/runner.sqlite
  "$PY" - "$database" "$phase" "$CONFIG" <<'PY'
import json
import sqlite3
import sys

database, phase, config_path = sys.argv[1:]
config = json.loads(open(config_path, encoding="utf-8").read())
expected = int(config["attempts_per_route"][phase]) * len(config["route_order"])
with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
    succeeded = int(connection.execute(
        "SELECT COUNT(*) FROM attempts WHERE status='succeeded'"
    ).fetchone()[0])
    unfinished = int(connection.execute(
        "SELECT COUNT(*) FROM attempts WHERE status!='succeeded'"
    ).fetchone()[0])
    errors = int(connection.execute("SELECT COUNT(*) FROM attempt_errors").fetchone()[0])
raise SystemExit(0 if (succeeded, unfinished, errors) == (expected, 0, 0) else 1)
PY
}

verify_phase_handoff() {
  local phase=$1
  local run=$RUNTIME/runs/$phase
  "$PY" "$REPO/scripts/verify_native_multihop_handoff.py" \
    --frozen-source "$run/frozen-source" \
    --source-publication "$run/source-publication" \
    --rebuild-a "$run/rebuild-a" --rebuild-b "$run/rebuild-b" \
    --review-closure "$REVIEW" --comparison "$run/rebuild-comparison.json" \
    --handoff "$run/final-handoff.json" >/dev/null
}

quarantine_partial_phase_outputs() {
  local run=$1
  local found=0
  local path
  local candidates=(
    hyperlane-processes.json traces.sqlite traces.sqlite-shm traces.sqlite-wal
    effect-audit.json incidents.json frozen-source source-publication
    rebuild-a rebuild-b rebuild-comparison.json final-handoff.json
  )
  for path in "${candidates[@]}"; do
    [[ -e $run/$path ]] && found=1
  done
  [[ $found -eq 1 ]] || return 0
  local quarantine=$run/resume-quarantine/postprocess-$(date --utc +%Y%m%dT%H%M%S.%NZ)
  mkdir -p "$quarantine"
  for path in "${candidates[@]}"; do
    [[ -e $run/$path ]] && mv "$run/$path" "$quarantine/$path"
  done
  record "phase-partial-postprocess-quarantined:$run:$quarantine"
}

postprocess_phase() {
  local phase=$1
  local run=$RUNTIME/runs/$phase
  local prior_handoff_args=()
  if [[ $phase == publication_smoke ]]; then
    prior_handoff_args+=(--smoke-handoff "$RUNTIME/runs/smoke/final-handoff.json")
  elif [[ $phase == scale ]]; then
    prior_handoff_args+=(--smoke-handoff "$RUNTIME/runs/smoke/final-handoff.json")
    prior_handoff_args+=(--publication-smoke-handoff \
      "$RUNTIME/runs/publication_smoke/final-handoff.json")
  fi
  if [[ -f $run/final-handoff.json ]]; then
    verify_phase_handoff "$phase"
    record "phase-handoff-reverified:$phase"
    return 0
  fi
  quarantine_partial_phase_outputs "$run"
  [[ -f $run/end-blocks.json ]] || capture_heads "$run/end-blocks.json"
  merge_resource_segments "$run"
  "$PY" "$REPO/scripts/capture_native_multihop_processes.py" \
    --profile "$RUNTIME/profile.json" --runtime-root "$RUNTIME" \
    --start-blocks "$run/start-blocks.json" --end-blocks "$run/end-blocks.json" \
    --observer "$run/hyperlane-observer.jsonl" \
    --output "$run/hyperlane-processes.json"
  if (( TRACE_SETTLE_SECONDS > 0 )); then
    sleep "$TRACE_SETTLE_SECONDS"
  fi
  "$PY" "$REPO/scripts/capture_native_multihop_traces.py" \
    --repository-root "$REPO" --config "$CONFIG" \
    --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
    --phase "$phase" --runner-state "$run/runner.sqlite" \
    --worker-state "$RUNTIME/layerzero/worker.sqlite" \
    --hyperlane-processes "$run/hyperlane-processes.json" \
    --root-signer-audit "$run/root-signer-audit.jsonl" \
    --trace-state "$run/traces.sqlite" --concurrency "$TRACE_CONCURRENCY"
  "$PY" "$REPO/scripts/capture_native_multihop_effects.py" reconcile \
    --repository-root "$REPO" --profile "$RUNTIME/profile.json" \
    --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
    --config "$CONFIG" --phase "$phase" --baseline "$run/effect-baseline.json" \
    --runner-state "$run/runner.sqlite" --trace-state "$run/traces.sqlite" \
    --output "$run/effect-audit.json"
  jq -e '.valid == true' "$run/effect-audit.json" >/dev/null
  "$PY" "$REPO/scripts/capture_native_multihop_incidents.py" \
    --runner-state "$run/runner.sqlite" \
    --worker-state "$RUNTIME/layerzero/worker.sqlite" \
    --hyperlane-processes "$run/hyperlane-processes.json" --phase "$phase" \
    --output "$run/incidents.json"
  "$PY" "$REPO/scripts/freeze_native_multihop.py" --phase "$phase" \
    --config "$CONFIG" --profile "$RUNTIME/profile.json" \
    --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
    --plan "$run/plan.json" --preflight "$RUNTIME/preflight.json" \
    --runner-state "$run/runner.sqlite" --worker-state "$RUNTIME/layerzero/worker.sqlite" \
    --trace-state "$run/traces.sqlite" \
    --coordinator-signed-root "$run/private-signed-transactions" \
    --hyperlane-processes "$run/hyperlane-processes.json" \
    --hyperlane-observer "$run/hyperlane-observer.jsonl" \
    --hyperlane-observer-completion "$run/hyperlane-observer-completion.json" \
    --incidents "$run/incidents.json" --root-signer-audit "$run/root-signer-audit.jsonl" \
    --resource-monitor "$run/resource-samples.jsonl" \
    --resource-segments "$run/resource-segments.json" \
    --effect-baseline "$run/effect-baseline.json" --effect-audit "$run/effect-audit.json" \
    --phase-authority "$run/phase-authority.json" \
    "${prior_handoff_args[@]}" \
    --preregistration "$PREREG" --review-closure "$REVIEW" --review-gate "$REVIEW_GATE" \
    --topology "$TOPOLOGY" --identity-manifest "$RUNTIME/identity-manifest.json" \
    --validator-volume-attestation \
      "$RUNTIME/provenance/validator-volume-bootstrap.json" \
    --validator-volume-journal \
      "$RUNTIME/provenance/validator-volume-transaction.json" \
    --toolchain-preflight "$RUNTIME/provenance/toolchain-preflight.json" \
    --normalized-stage-schema "$REPO/schemas/normalized-stages-v1.schema.json" \
    --stage-template-schema "$REPO/schemas/stage-template-set-v1.schema.json" \
    --output-root "$run/frozen-source"
  failpoint freeze
  local build
  for build in source-publication rebuild-a rebuild-b; do
    "$PY" "$REPO/scripts/rebuild_native_multihop.py" \
      --source-root "$run/frozen-source" --output-root "$run/$build"
  done
  failpoint rebuild
  "$PY" "$REPO/scripts/finalize_native_multihop.py" \
    --frozen-source "$run/frozen-source" --source-publication "$run/source-publication" \
    --rebuild-a "$run/rebuild-a" --rebuild-b "$run/rebuild-b" \
    --review-closure "$REVIEW" --comparison "$run/rebuild-comparison.json" \
    --handoff "$run/final-handoff.json"
  verify_phase_handoff "$phase"
  failpoint handoff
}

run_phase() {
  local phase=$1
  local resume=${2:-0}
  local run=$RUNTIME/runs/$phase
  local handoff_args=()
  local observer_args=()
  local observer_start_blocks=$run/start-blocks.json
  local monitor_segment_index=0
  local monitor_sequence_start=0
  local monitor_output
  local monitor_completion
  local observer_ready
  local monitor_ready
  CURRENT_RUN=$run
  if [[ $resume -eq 0 ]]; then
    mkdir -p "$run/raw"
    capture_heads "$run/start-blocks.json"
  else
    [[ -d $run/raw && -f $run/start-blocks.json && -f $run/effect-baseline.json \
      && -f $run/plan.json && -f $run/phase-authority.json \
      && -f $run/runner.sqlite ]] || {
      echo "resume phase inputs are incomplete: $phase" >&2
      return 1
    }
    capture_heads "$run/resume-observer-launch-heads.json"
    # Re-scan from the immutable original boundary.  Append mode loads the
    # prior ledger's transaction set and de-duplicates it, so transactions
    # mined between cleanup and observer restart cannot fall into a gap.
    observer_start_blocks=$run/start-blocks.json
    observer_args+=(--append)
    rm -f "$run/submission.stop" "$run/monitor.stop" "$run/hyperlane-observer.stop"
    if [[ -e $run/hyperlane-observer-completion.json ]]; then
      local observer_completion_quarantine=$run/resume-quarantine/observer-completion-$(date --utc +%Y%m%dT%H%M%S.%NZ)
      mkdir -p "$observer_completion_quarantine"
      mv "$run/hyperlane-observer-completion.json" "$observer_completion_quarantine/"
      record "prior-observer-completion-quarantined:$observer_completion_quarantine"
    fi
    quarantine_incomplete_resource_tail "$run"
    if phase_runner_complete "$phase"; then
      # Start the runner under the unchanged DB/plan/authority anyway.  It has
      # zero pending coordinates and exits without submission, while the
      # freshly ready observer and monitor reconstruct the missing evidence
      # tail before postprocessing.
      record "phase-runner-complete-evidence-tail-reconstruction:$phase"
    fi
  fi
  shopt -s nullglob
  local existing_monitor_segments=("$run"/resource-samples.segment-*.jsonl)
  shopt -u nullglob
  monitor_segment_index=${#existing_monitor_segments[@]}
  if (( monitor_segment_index > 0 )); then
    local prior_monitor_segment=${existing_monitor_segments[$((monitor_segment_index - 1))]}
    monitor_sequence_start=$(( $(tail -n 1 "$prior_monitor_segment" | jq -er '.sequence') + 1 ))
  fi
  monitor_output=$(printf '%s/resource-samples.segment-%03d.jsonl' "$run" "$monitor_segment_index")
  monitor_completion=${monitor_output%.jsonl}.completion.json
  observer_ready=$(printf '%s/hyperlane-observer-ready.segment-%03d.json' \
    "$run" "$monitor_segment_index")
  monitor_ready=$(printf '%s/resource-monitor-ready.segment-%03d.json' \
    "$run" "$monitor_segment_index")
  if [[ -e $observer_ready || -e $monitor_ready ]]; then
    [[ $resume -eq 1 ]] || {
      echo "fresh phase readiness artifacts already exist" >&2
      return 1
    }
    local ready_quarantine=$run/resume-quarantine/readiness-$(date --utc +%Y%m%dT%H%M%S.%NZ)
    mkdir -p "$ready_quarantine"
    [[ ! -e $observer_ready ]] || mv "$observer_ready" "$ready_quarantine/"
    [[ ! -e $monitor_ready ]] || mv "$monitor_ready" "$ready_quarantine/"
    record "partial-readiness-artifacts-quarantined:$ready_quarantine"
  fi
  local relayer_address
  relayer_address=$(jq -er '.identities.relayer_address' \
    "$RUNTIME/hyperlane/deployment-inputs.json")
  nohup "$PY" "$REPO/scripts/observe_native_multihop_hyperlane.py" \
    --profile "$RUNTIME/profile.json" --runtime-root "$RUNTIME" \
    --relayer-address "$relayer_address" --start-blocks "$observer_start_blocks" \
    --output "$run/hyperlane-observer.jsonl" \
    --target-blocks "$run/end-blocks.json" \
    --completion "$run/hyperlane-observer-completion.json" \
    --ready "$observer_ready" \
    --stop-file "$run/hyperlane-observer.stop" --poll-seconds 0.25 \
    "${observer_args[@]}" \
    >"$run/hyperlane-observer.log" 2>&1 </dev/null &
  local observer_pid=$!
  record_pid_identity "$run/hyperlane-observer.pid" "$observer_pid"
  if [[ $resume -eq 0 ]]; then
    "$PY" "$REPO/scripts/capture_native_multihop_effects.py" baseline \
      --repository-root "$REPO" --profile "$RUNTIME/profile.json" \
      --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
      --config "$CONFIG" --phase "$phase" --output "$run/effect-baseline.json"
    "$PY" "$REPO/scripts/build_native_multihop_plan.py" \
      --config "$CONFIG" --phase "$phase" --output "$run/plan-a.json"
    "$PY" "$REPO/scripts/build_native_multihop_plan.py" \
      --config "$CONFIG" --phase "$phase" --output "$run/plan-b.json"
    cmp "$run/plan-a.json" "$run/plan-b.json"
    mv "$run/plan-a.json" "$run/plan.json"
    rm "$run/plan-b.json"
  fi
  if [[ $phase == publication_smoke ]]; then
    handoff_args+=(--smoke-handoff "$RUNTIME/runs/smoke/final-handoff.json")
  elif [[ $phase == scale ]]; then
    handoff_args+=(--smoke-handoff "$RUNTIME/runs/smoke/final-handoff.json")
    handoff_args+=(--publication-smoke-handoff \
      "$RUNTIME/runs/publication_smoke/final-handoff.json")
  fi
  nohup bash -c 'kill -STOP $$; exec "$@"' _ \
    "$PY" "$REPO/scripts/run_native_multihop_switching.py" \
    --workspace-root "$WORKSPACE" --repository-root "$REPO" \
    --runtime-root "$RUNTIME" --topology "$TOPOLOGY" \
    --identity "$RUNTIME/identity-manifest.json" --preregistration "$PREREG" \
    --review-gate "$REVIEW_GATE" --lease "$LEASE" --lease-token "$LEASE_TOKEN" \
    --preflight "$RUNTIME/preflight.json" --config "$CONFIG" --plan "$run/plan.json" \
    --phase-authority-output "$run/phase-authority.json" \
    --deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
    --runner-key-file "$RUNTIME/private/accounts/runner.key" \
    --root-signer-key-file "$RUNTIME/private/accounts/root-signer.key" \
    --state "$run/runner.sqlite" --raw-root "$run/raw" --phase "$phase" \
    --submission-stop-file "$run/submission.stop" "${handoff_args[@]}" \
    >"$run/runner.log" 2>&1 </dev/null &
  local runner_pid=$!
  record_pid_identity "$run/runner.pid" "$runner_pid"
  failpoint runner_launch
  wait_for_stopped_process "$runner_pid"
  nohup "$PY" "$REPO/scripts/monitor_native_multihop_resources.py" \
    --runtime-root "$RUNTIME" --profile "$RUNTIME/profile.json" \
    --identity-manifest "$RUNTIME/identity-manifest.json" \
    --runner-state "$run/runner.sqlite" --runner-pid "$run/runner.pid" \
    --output "$monitor_output" --completion "$monitor_completion" \
    --ready "$monitor_ready" \
    --sequence-start "$monitor_sequence_start" --stop-file "$run/monitor.stop" \
    --submission-stop-file "$run/submission.stop" --minimum-runtime-free-bytes 10737418240 \
    --interval 5 >"$run/resource-monitor.log" 2>&1 </dev/null &
  record_pid_identity "$run/resource-monitor.pid" "$!"
  local monitor_pid=$!
  wait_for_durable_ready "$observer_ready" "$run/hyperlane-observer.pid" \
    xir-lab-native-multihop-hyperlane-observer-ready-v1 observer_process_id
  wait_for_durable_ready "$monitor_ready" "$run/resource-monitor.pid" \
    xir-lab-native-multihop-resource-monitor-ready-v1 monitor_process_id
  failpoint runner_sigstop
  "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
    --identity "$(identity_path_for_pidfile "$run/runner.pid")" --signal SIGCONT \
    >/dev/null
  local runner_status=0
  while owned_process_alive "$run/runner.pid"; do
    if ! owned_process_alive "$run/hyperlane-observer.pid"; then
      local observer_status=0
      wait "$observer_pid" || observer_status=$?
      complete_pidfile "$run/hyperlane-observer.pid"
      write_sidecar_failure_stop "$run/submission.stop" \
        hyperlane_observer_process_failed
      record "hyperlane-observer-failed-during-run:$phase:$observer_status"
      local observer_stop_deadline=$((SECONDS + 120))
      while owned_process_alive "$run/runner.pid" \
        && (( SECONDS < observer_stop_deadline )); do sleep 0.2; done
      if owned_process_alive "$run/runner.pid"; then
        "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
          --identity "$(identity_path_for_pidfile "$run/runner.pid")" --signal SIGTERM \
          >/dev/null || true
      fi
      wait "$runner_pid" || true
      complete_pidfile "$run/runner.pid"
      touch "$run/monitor.stop"
      wait "$monitor_pid" || true
      complete_pidfile "$run/resource-monitor.pid"
      quarantine_incomplete_resource_tail "$run"
      RESUME_REQUIRED=1
      return 75
    fi
    if ! owned_process_alive "$run/resource-monitor.pid"; then
      local monitor_status=0
      wait "$monitor_pid" || monitor_status=$?
      complete_pidfile "$run/resource-monitor.pid"
      write_sidecar_failure_stop "$run/submission.stop" \
        resource_monitor_process_failed
      record "resource-monitor-failed-during-run:$phase:$monitor_status"
      local stop_deadline=$((SECONDS + 120))
      while owned_process_alive "$run/runner.pid" \
        && (( SECONDS < stop_deadline )); do sleep 0.2; done
      if owned_process_alive "$run/runner.pid"; then
        "$PY" "$REPO/scripts/native_multihop_process_identity.py" signal \
          --identity "$(identity_path_for_pidfile "$run/runner.pid")" --signal SIGTERM \
          >/dev/null || true
      fi
      wait "$runner_pid" || true
      complete_pidfile "$run/runner.pid"
      quarantine_incomplete_resource_tail "$run"
      RESUME_REQUIRED=1
      return 75
    fi
    sleep 0.2
  done
  if alive "$runner_pid"; then
    echo "runner PID identity changed during supervised execution" >&2
    return 1
  fi
  if wait "$runner_pid"; then runner_status=0; else runner_status=$?; fi
  if [[ $runner_status -ne 0 ]]; then
    complete_pidfile "$run/runner.pid"
    if [[ $runner_status == 75 || $runner_status == 130 || \
      $runner_status == 137 || $runner_status == 143 ]]; then
      RESUME_REQUIRED=1
      record "phase-runner-resumable-interruption:$phase:$runner_status"
      return 75
    fi
    record "phase-runner-terminal-failure:$phase:$runner_status"
    return "$runner_status"
  fi
  complete_pidfile "$run/runner.pid"
  touch "$run/monitor.stop"
  if ! wait "$monitor_pid"; then
    complete_pidfile "$run/resource-monitor.pid"
    echo "resource monitor failed before a valid segment completion" >&2
    quarantine_incomplete_resource_tail "$run"
    RESUME_REQUIRED=1
    record "resource-monitor-failed-at-runner-tail:$phase"
    return 75
  fi
  complete_pidfile "$run/resource-monitor.pid"
  jq -e '.valid == true' "$monitor_completion" >/dev/null
  local last_runner_event_utc
  last_runner_event_utc=$("$PY" - "$run/runner.sqlite" <<'PY'
import sqlite3
import sys
with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    row = connection.execute("SELECT COALESCE(MAX(utc_ns),0) FROM events").fetchone()
print(int(row[0]))
PY
)
  jq -e --argjson runner_utc "$last_runner_event_utc" \
    '.valid == true and .last_utc_ns >= $runner_utc' "$monitor_completion" >/dev/null
  merge_resource_segments "$run"
  [[ -f $run/end-blocks.json ]] || capture_heads "$run/end-blocks.json"
  touch "$run/hyperlane-observer.stop"
  if ! wait "$observer_pid"; then
    complete_pidfile "$run/hyperlane-observer.pid"
    echo "Hyperlane observer failed before clean completion" >&2
    write_sidecar_failure_stop "$run/submission.stop" \
      hyperlane_observer_tail_completion_failed
    RESUME_REQUIRED=1
    record "hyperlane-observer-failed-at-runner-tail:$phase"
    return 75
  fi
  complete_pidfile "$run/hyperlane-observer.pid"
  jq -e '.valid == true and .all_targets_scanned == true' \
    "$run/hyperlane-observer-completion.json" >/dev/null
  # Freeze/rebuild reads worker and relayer SQLite state. Stop only protocol
  # writers here; Besu containers remain alive for the next phase.
  if ! "$REPO/scripts/native_multihop_processes.sh" stop "$RUNTIME"; then
    echo "native protocol writers did not stop before phase postprocess" >&2
    return 1
  fi
  record "native-protocol-writers-stopped-before-postprocess:$phase"
  postprocess_phase "$phase"
  if [[ $phase != scale ]]; then
    "$REPO/scripts/native_multihop_processes.sh" start-agents "$RUNTIME" \
      "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
    "$REPO/scripts/native_multihop_processes.sh" start-worker "$RUNTIME" \
      "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
    record "native-protocol-writers-restarted-after-postprocess:$phase"
  fi
}

publish_gateway_and_figures() {
  local connectivity_v3=$WORKSPACE/experiments/results/connectivity-v3/publishable
  local connectivity_v4=$WORKSPACE/experiments/results/connectivity-v4-robustness/publishable
  local build
  local products=(gateway-a gateway-b gateway-comparison.json figure-a figure-b figure-comparison.json)
  local complete=1
  local product
  for product in "${products[@]}"; do [[ -e $RUNTIME/$product ]] || complete=0; done
  if [[ $complete -eq 1 ]]; then
    local verify_root=$RUNTIME/resume-verification-$(date --utc +%Y%m%dT%H%M%S.%NZ)
    mkdir "$verify_root"
    "$PY" "$REPO/scripts/compare_gateway_deployment_rebuilds.py" \
      --publication-a "$RUNTIME/gateway-a" --publication-b "$RUNTIME/gateway-b" \
      --output "$verify_root/gateway-comparison.json"
    cmp "$verify_root/gateway-comparison.json" "$RUNTIME/gateway-comparison.json"
    "$PY" "$REPO/scripts/compare_native_multihop_figure8.py" \
      --first "$RUNTIME/figure-a" --second "$RUNTIME/figure-b" \
      --output "$verify_root/figure-comparison.json"
    cmp "$verify_root/figure-comparison.json" "$RUNTIME/figure-comparison.json"
    record "gateway-and-figure-products-reverified"
  else
    local partial=0
    for product in "${products[@]}"; do [[ -e $RUNTIME/$product ]] && partial=1; done
    if [[ $partial -eq 1 ]]; then
      local quarantine=$RUNTIME/resume-quarantine/publication-$(date --utc +%Y%m%dT%H%M%S.%NZ)
      mkdir -p "$quarantine"
      for product in "${products[@]}"; do
        [[ -e $RUNTIME/$product ]] && mv "$RUNTIME/$product" "$quarantine/$product"
      done
      record "partial-gateway-figure-products-quarantined:$quarantine"
    fi
  for build in gateway-a gateway-b; do
    "$PY" "$REPO/scripts/publish_gateway_deployment.py" \
      --topology "$connectivity_v3/topology.json" \
      --mainnet "$connectivity_v4/mainnet-only.json" \
      --semantic "$connectivity_v4/semantic-aggregates.json" \
      --multihop-deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
      --hyperlane-evidence "$RUNTIME/hyperlane/deployment-evidence.json" \
      --layerzero-evidence "$RUNTIME/layerzero/deployment-evidence.json" \
      --output-root "$RUNTIME/$build"
  done
  "$PY" "$REPO/scripts/compare_gateway_deployment_rebuilds.py" \
    --publication-a "$RUNTIME/gateway-a" --publication-b "$RUNTIME/gateway-b" \
    --output "$RUNTIME/gateway-comparison.json"
  for build in figure-a figure-b; do
    "$PY" "$REPO/scripts/render_native_multihop_figure8.py" \
      --analysis "$RUNTIME/runs/scale/source-publication/analysis.json" \
      --gateway "$RUNTIME/gateway-a/analysis.json" \
      --multihop-comparison "$RUNTIME/runs/scale/rebuild-comparison.json" \
      --gateway-comparison "$RUNTIME/gateway-comparison.json" \
      --output-root "$RUNTIME/$build"
  done
  "$PY" "$REPO/scripts/compare_native_multihop_figure8.py" \
    --first "$RUNTIME/figure-a" --second "$RUNTIME/figure-b" \
    --output "$RUNTIME/figure-comparison.json"
  jq -e '.valid == true' "$RUNTIME/figure-comparison.json" >/dev/null
  fi
  if [[ ! -f $RUNTIME/figure8-visual-approval.json ]]; then
    RESUME_REQUIRED=1
    record "figure8-human-visual-approval-required"
    echo "inspect real Figure 8 and create the bound visual approval before --resume" >&2
    return 75
  fi
  "$PY" - "$RUNTIME" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
approval = json.loads((root / "figure8-visual-approval.json").read_text(encoding="utf-8"))
checks = (
    approval.get("approved") is True
    and approval.get("figure_a_manifest_sha256") == hashlib.sha256((root / "figure-a/manifest.json").read_bytes()).hexdigest()
    and approval.get("figure_b_manifest_sha256") == hashlib.sha256((root / "figure-b/manifest.json").read_bytes()).hexdigest()
    and approval.get("comparison_sha256") == hashlib.sha256((root / "figure-comparison.json").read_bytes()).hexdigest()
)
raise SystemExit(0 if checks else 1)
PY
}

publish_gateway_only() {
  local connectivity_v3=$WORKSPACE/experiments/results/connectivity-v3/publishable
  local connectivity_v4=$WORKSPACE/experiments/results/connectivity-v4-robustness/publishable
  local build
  if [[ -d $RUNTIME/gateway-a && -d $RUNTIME/gateway-b \
    && -f $RUNTIME/gateway-comparison.json ]]; then
    local verify_root=$RUNTIME/resume-verification-$(date --utc +%Y%m%dT%H%M%S.%NZ)
    mkdir "$verify_root"
    "$PY" "$REPO/scripts/compare_gateway_deployment_rebuilds.py" \
      --publication-a "$RUNTIME/gateway-a" --publication-b "$RUNTIME/gateway-b" \
      --output "$verify_root/gateway-comparison.json"
    cmp "$verify_root/gateway-comparison.json" "$RUNTIME/gateway-comparison.json"
    record "pilot-gateway-products-reverified"
    return 0
  fi
  for build in gateway-a gateway-b; do
    "$PY" "$REPO/scripts/publish_gateway_deployment.py" \
      --topology "$connectivity_v3/topology.json" \
      --mainnet "$connectivity_v4/mainnet-only.json" \
      --semantic "$connectivity_v4/semantic-aggregates.json" \
      --multihop-deployment "$RUNTIME/$DEPLOYMENT_RELATIVE" \
      --hyperlane-evidence "$RUNTIME/hyperlane/deployment-evidence.json" \
      --layerzero-evidence "$RUNTIME/layerzero/deployment-evidence.json" \
      --output-root "$RUNTIME/$build"
  done
  "$PY" "$REPO/scripts/compare_gateway_deployment_rebuilds.py" \
    --publication-a "$RUNTIME/gateway-a" --publication-b "$RUNTIME/gateway-b" \
    --output "$RUNTIME/gateway-comparison.json"
  record "pilot-gateway-products-built"
}

sync_publication() {
  local public_list=$RUNTIME/provenance/public-sync-files.txt
  local local_public=$WORKSPACE/experiment-results/native-multihop-switching-v1/$RUN_ID
  if [[ $CAMPAIGN_KIND == pilot ]]; then
    local_public=$WORKSPACE/experiment-results/native-multihop-switching-pilot-v1/$RUN_ID
  fi
  if [[ $CAMPAIGN_KIND == pilot ]]; then
    (
      cd "$RUNTIME"
      find runs/scale/source-publication runs/scale/rebuild-a runs/scale/rebuild-b \
        runs/smoke/final-handoff.json runs/publication_smoke/final-handoff.json \
        runs/scale/final-handoff.json gateway-a gateway-b gateway-comparison.json \
        -type f ! -name '*.sqlite' ! -name '*.key' ! -name '*.raw' -print0 \
        | sort -z | xargs -0 -r printf '%s\n' >"$public_list"
    )
    "$PY" "$REPO/scripts/build_native_multihop_pilot_handoff.py" \
      --runtime-root "$RUNTIME" --file-list "$public_list" \
      --output "$RUNTIME/final-pilot-publication-handoff.json"
    printf '%s\n' final-pilot-publication-handoff.json >>"$public_list"
    sort -u -o "$public_list" "$public_list"
    "$PY" - "$RUNTIME" "$public_list" "$local_public" <<'PY'
import hashlib
import sys
from pathlib import Path
from xir_lab.native.multihop_sync import sync_exact_publication
runtime = Path(sys.argv[1])
files = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
expected = {name: hashlib.sha256((runtime / name).read_bytes()).hexdigest() for name in files}
sync_exact_publication(runtime_root=runtime, relative_files=files, destination=Path(sys.argv[3]), expected_sha256=expected)
PY
  else
    (
      cd "$RUNTIME"
      find runs/scale/source-publication runs/scale/rebuild-a runs/scale/rebuild-b \
        runs/smoke/final-handoff.json runs/publication_smoke/final-handoff.json \
        runs/scale/final-handoff.json gateway-a gateway-b gateway-comparison.json \
        figure-a figure-b figure-comparison.json \
        figure8-visual-approval.json \
        -type f ! -name '*.sqlite' ! -name '*.key' ! -name '*.raw' -print0 \
        | sort -z | xargs -0 -r printf '%s\n' >"$public_list"
    )
    "$PY" "$REPO/scripts/build_native_multihop_publication_handoff.py" \
      --runtime-root "$RUNTIME" --file-list "$public_list" \
      --visual-approval "$RUNTIME/figure8-visual-approval.json" \
      --output "$RUNTIME/final-publication-handoff.json"
    "$PY" "$REPO/scripts/sync_native_multihop_publication.py" \
      --runtime-root "$RUNTIME" --handoff "$RUNTIME/final-publication-handoff.json" \
      --destination "$local_public"
  fi
}

stop_campaign_services() {
  local failed=0
  local run_root
  shopt -s nullglob
  for run_root in "$RUNTIME"/runs/*; do
    [[ -d $run_root ]] || continue
    touch "$run_root/submission.stop" "$run_root/hyperlane-observer.stop"
    stop_pidfile "$run_root/runner.pid" 1 || failed=1
    stop_resource_monitor_pidfile "$run_root" || failed=1
    stop_pidfile "$run_root/hyperlane-observer.pid" || failed=1
  done
  shopt -u nullglob
  if ! timeout 60 "$REPO/scripts/native_multihop_processes.sh" stop "$RUNTIME"; then
    failed=1
  fi
  if ! timeout 120 docker compose --project-name "$COMPOSE_PROJECT" \
    -f "$RUNTIME/compose.yaml" down --remove-orphans; then
    failed=1
  fi
  phase_writers_dead || failed=1
  if pgrep -af '[r]un_native_multihop|[a]nalyze_native_multihop|[r]ebuild_native_multihop|[r]ender_native_multihop|[m]onitor_native_multihop|[o]bserve_native_multihop' \
    | grep -F -- "$RUNTIME" >"$RUNTIME/provenance/remaining-processes.txt"; then
    failed=1
  fi
  validator_containers_absent || failed=1
  if [[ $failed -eq 0 ]]; then
    validator_volume_command remove-existing || failed=1
  fi
  [[ $failed -eq 0 ]]
}

finalize_stop_and_publish() {
  stop_campaign_services
  record "all-phase-writers-dead"
  record "all-protocol-services-dead"
  failpoint service_stop
  sync_publication
  failpoint sync
  touch "$LEASE_SUPERVISOR_STOP"
  stop_pidfile "$RUNTIME/provenance/lease-supervisor.pid"
  release_lease_after_writers_dead
  CLEANUP_COMPLETE=1
  record "cleanup-complete"
}

production_main() {
  [[ ! -e $RUNTIME ]] || {
    echo "fresh runtime already exists: $RUNTIME" >&2
    return 1
  }
  prepare_environment
  failpoint review_gate
  acquire_lease
  failpoint lease
  deploy_and_preflight
  failpoint preflight
  run_phase smoke
  run_phase publication_smoke
  run_phase scale
  if [[ $CAMPAIGN_KIND == pilot ]]; then
    publish_gateway_only
  else
    publish_gateway_and_figures
  fi
  finalize_stop_and_publish
}

resume_main() {
  [[ -d $RUNTIME && -f $LEASE_TOKEN && -L $LEASE && -f $REVIEW_GATE ]] || {
    echo "authenticated resume runtime is incomplete" >&2
    return 1
  }
  "$PY" "$REPO/scripts/verify_native_multihop_review_gate.py" \
    --workspace-root "$WORKSPACE" --repository-root "$REPO" \
    --preregistration "$PREREG" --output "$RUNTIME/provenance/resume-review-gate.json"
  cmp "$REVIEW_GATE" "$RUNTIME/provenance/resume-review-gate.json"
  if owned_process_alive "$RUNTIME/provenance/lease-supervisor.pid"; then
    LEASE_SUPERVISOR_PID=$(<"$RUNTIME/provenance/lease-supervisor.pid")
  else
    rm -f "$RUNTIME/provenance/lease-supervisor.ready"
    start_lease_supervisor
    "$PY" "$REPO/scripts/native_multihop_lease.py" continue \
      --runtime-root "$RUNTIME" --preregistration "$PREREG" \
      --lease "$LEASE" --token "$LEASE_TOKEN" \
      --supervisor-pid "$LEASE_SUPERVISOR_PID"
    touch "$RUNTIME/provenance/lease-supervisor.ready"
  fi
  LEASE_ACQUIRED=1
  "$PY" "$REPO/scripts/native_multihop_lease.py" activate-resume \
    --runtime-root "$RUNTIME" --preregistration "$PREREG" \
    --lease "$LEASE" --token "$LEASE_TOKEN" >/dev/null
  record "resume-authority-activated"
  validator_volume_command verify-existing
  record "validator-volumes-reverified-before-resume"
  start_and_admit_validator_containers
  "$REPO/scripts/native_multihop_processes.sh" start-agents "$RUNTIME" \
    "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
  "$REPO/scripts/native_multihop_processes.sh" start-worker "$RUNTIME" \
    "$WORKSPACE" "$PREREG" "$REVIEW_GATE" "$LEASE" "$LEASE_TOKEN"
  local phase
  for phase in smoke publication_smoke scale; do
    if [[ -f $RUNTIME/runs/$phase/final-handoff.json ]]; then
      verify_phase_handoff "$phase"
      record "phase-handoff-reverified:$phase"
      continue
    fi
    if [[ -f $RUNTIME/runs/$phase/runner.sqlite ]]; then
      run_phase "$phase" 1
    else
      run_phase "$phase" 0
    fi
  done
  if [[ -f $RUNTIME/runs/scale/final-handoff.json ]]; then
    if [[ $CAMPAIGN_KIND == pilot ]]; then
      publish_gateway_only
    else
      publish_gateway_and_figures
    fi
  fi
  finalize_stop_and_publish
}

dry_run_main() {
  [[ " ${FAILPOINTS[*]} " == *" $FAIL_AT "* ]] || usage
  [[ ! -e $RUNTIME ]] || {
    echo "dry-run runtime already exists: $RUNTIME" >&2
    return 1
  }
  prepare_environment
  failpoint review_gate
  acquire_lease
  failpoint lease
  failpoint preflight
  start_dry_phase_processes
  failpoint runner_launch
  failpoint runner_sigstop
  failpoint freeze
  failpoint rebuild
  failpoint handoff
  failpoint service_stop
  failpoint sync
}

if [[ $MODE == dry-run ]]; then
  dry_run_main
elif [[ $RESUME -eq 1 ]]; then
  resume_main
else
  production_main
fi
