#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
topology_path="${XIR_LOCAL_TOPOLOGY_PATH:-${repository_root}/configs/local/topology-v1.json}"
profile_path="${repository_root}/configs/profiles/local-paper-scale-v2.json"
artifact_path="${repository_root}/contracts/out/LocalScaleWorkload.sol/LocalScaleWorkload.json"
: "${XIR_LOCAL_RUNTIME_ROOT:?set XIR_LOCAL_RUNTIME_ROOT to a dedicated absolute path}"
runtime_root="$(realpath -m -- "${XIR_LOCAL_RUNTIME_ROOT}")"

case "${runtime_root}" in
  /|/home|/home/ubuntu|"${repository_root}")
    echo "refusing broad or repository runtime root: ${runtime_root}" >&2
    exit 2
    ;;
esac
if [[ "${runtime_root}" != /* ]]; then
  echo "runtime root must be absolute" >&2
  exit 2
fi

compose_path="${runtime_root}/compose.yaml"
manifest_path="${runtime_root}/identity-manifest.json"
xir_lab="${repository_root}/.venv/bin/xir-lab"

docker_compose() {
  if [[ -n "${XIR_DOCKER_COMPOSE_BIN:-}" ]]; then
    "${XIR_DOCKER_COMPOSE_BIN}" \
      --project-name xir-local-scale -f "${compose_path}" "$@"
    return
  fi
  if docker info >/dev/null 2>&1; then
    docker compose --project-name xir-local-scale -f "${compose_path}" "$@"
  elif sudo -n docker info >/dev/null 2>&1; then
    sudo -n --preserve-env=XIR_LOCAL_RUNTIME_ROOT docker compose \
      --project-name xir-local-scale -f "${compose_path}" "$@"
  else
    echo "Docker Engine is unavailable to the current user and passwordless sudo" >&2
    return 2
  fi
}

docker_engine() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  elif sudo -n docker info >/dev/null 2>&1; then
    sudo -n --preserve-env=DOCKER_API_VERSION docker "$@"
  else
    echo "Docker Engine is unavailable to the current user and passwordless sudo" >&2
    return 2
  fi
}

require_initialized() {
  if [[ ! -f "${compose_path}" || ! -f "${manifest_path}" ]]; then
    echo "local runtime is not initialized: ${runtime_root}" >&2
    exit 2
  fi
}

stage_docker_volume_bootstrap() {
  if ! docker_compose config --volumes \
    | grep -Fxq "local-source-v1-data"; then
    return
  fi

  local image network validator volume staging_container
  image="$(docker_compose config --images | sort -u)"
  if [[ -z "${image}" || "${image}" == *$'\n'* ]]; then
    echo "expected exactly one validator image for runtime staging" >&2
    return 2
  fi

  for network in local-source local-intermediate local-destination; do
    for validator in v1 v2 v3 v4; do
      volume="xir-local-scale-${network}-${validator}-data"
      staging_container="xir-local-scale-stager-${network}-${validator}-$$"
      docker_engine volume create \
        --label org.xir.environment=controlled-local-qbft \
        --label org.xir.purpose=validator-data \
        "${volume}" >/dev/null
      docker_engine create \
        --name "${staging_container}" \
        --label org.xir.environment=controlled-local-qbft \
        --user 0 \
        --entrypoint /bin/sh \
        --mount "type=volume,source=${volume},target=/stage" \
        "${image}" \
        -c 'set -eu; mkdir -p /stage/bootstrap; mv /stage/genesis.json /stage/bootstrap/genesis.json; mv /stage/key /stage/bootstrap/key; chown -R besu:besu /stage/bootstrap; chmod 700 /stage/bootstrap; chmod 600 /stage/bootstrap/key; chmod 644 /stage/bootstrap/genesis.json' \
        >/dev/null
      docker_engine cp \
        "${runtime_root}/networks/${network}/genesis.json" \
        "${staging_container}:/stage/genesis.json"
      docker_engine cp \
        "${runtime_root}/private/validators/${network}/${validator}/key" \
        "${staging_container}:/stage/key"
      docker_engine start --attach "${staging_container}" >/dev/null
      docker_engine rm "${staging_container}" >/dev/null
    done
  done
}

uses_docker_volume_engine() {
  docker_compose config --volumes | grep -Fxq "local-source-v1-data"
}

host_gate() {
  local output
  set +e
  output="$(
    "${xir_lab}" local-preflight \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --mode "$1"
  )"
  set -e
  python3 -c '
import json
import sys
document = json.load(sys.stdin)
checks = document["details"]["preflight"]["checks"]
host = [item for item in checks if item["check_id"] in {
    "logical_cpus", "memory_bytes", "disk_available_bytes"
}]
failed = [item for item in host if item["status"] != "pass"]
if failed:
    for item in failed:
        check_id = item["check_id"]
        observed = item["observed"]
        required = item["required"]
        print(
            f"{check_id}: observed={observed} required={required}",
            file=sys.stderr,
        )
    raise SystemExit(2)
' <<<"${output}"
}

command="${1:-}"
case "${command}" in
  init)
    "${xir_lab}" local-init \
      --topology "${topology_path}" \
      --runtime-root "${runtime_root}"
    ;;
  render)
    require_initialized
    "${xir_lab}" local-render \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}"
    ;;
  up)
    require_initialized
    host_gate smoke
    docker_compose config --quiet
    if uses_docker_volume_engine; then
      stage_docker_volume_bootstrap
      "${repository_root}/.venv/bin/python" \
        "${repository_root}/scripts/docker_volume_engine.py" \
        up "${compose_path}"
    else
      docker_compose up --detach
    fi
    ;;
  health)
    require_initialized
    "${xir_lab}" local-preflight \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --mode smoke \
      --collect-network-health
    ;;
  scale-preflight)
    require_initialized
    host_gate scale
    "${xir_lab}" local-preflight \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --mode scale \
      --collect-network-health \
      --output "${runtime_root}/scale-preflight.json"
    ;;
  plan)
    require_initialized
    if [[ ! -f "${runtime_root}/evidence/smoke.sqlite" \
      || ! -f "${runtime_root}/evidence/rehearsal.sqlite" \
      || ! -f "${runtime_root}/measured-limits.json" ]]; then
      echo "plan requires reconciled smoke/rehearsal evidence and measured-limits.json" >&2
      exit 2
    fi
    smoke_sha256="$(sha256sum "${runtime_root}/evidence/smoke.sqlite" | cut -d ' ' -f1)"
    rehearsal_sha256="$(sha256sum "${runtime_root}/evidence/rehearsal.sqlite" | cut -d ' ' -f1)"
    measured_limits_sha256="$(sha256sum "${runtime_root}/measured-limits.json" | cut -d ' ' -f1)"
    "${xir_lab}" local-plan \
      --topology "${topology_path}" \
      --profile "${profile_path}" \
      --output "${runtime_root}/scale-plan.json" \
      --smoke-freeze-sha256 "${smoke_sha256}" \
      --rehearsal-freeze-sha256 "${rehearsal_sha256}" \
      --measured-limits-sha256 "${measured_limits_sha256}" \
      "${@:2}"
    ;;
  deploy)
    require_initialized
    if command -v forge >/dev/null 2>&1; then
      forge build --root "${repository_root}/contracts"
    elif [[ ! -f "${artifact_path}" ]]; then
      echo "forge or a prebuilt local workload artifact is required" >&2
      exit 2
    fi
    "${xir_lab}" local-deploy \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --runtime-root "${runtime_root}" \
      --artifact "${artifact_path}"
    ;;
  run-smoke|run-rehearsal)
    require_initialized
    phase="${command#run-}"
    "${xir_lab}" local-run \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --runtime-root "${runtime_root}" \
      --profile "${profile_path}" \
      --deployment "${runtime_root}/deployment.json" \
      --artifact "${artifact_path}" \
      --phase "${phase}" \
      --batch-size "${XIR_LOCAL_BATCH_SIZE:-25}"
    ;;
  run-scale)
    require_initialized
    "${xir_lab}" local-run \
      --topology "${topology_path}" \
      --identity-manifest "${manifest_path}" \
      --runtime-root "${runtime_root}" \
      --profile "${profile_path}" \
      --deployment "${runtime_root}/deployment.json" \
      --artifact "${artifact_path}" \
      --phase scale \
      --batch-size "${XIR_LOCAL_BATCH_SIZE:-25}" \
      --plan "${runtime_root}/scale-plan.json" \
      --preflight "${runtime_root}/scale-preflight.json"
    ;;
  status)
    require_initialized
    if uses_docker_volume_engine; then
      "${repository_root}/.venv/bin/python" \
        "${repository_root}/scripts/docker_volume_engine.py" \
        status "${compose_path}"
    else
      docker_compose ps
    fi
    ;;
  logs)
    require_initialized
    docker_compose logs --tail 200
    ;;
  stop)
    require_initialized
    if uses_docker_volume_engine; then
      "${repository_root}/.venv/bin/python" \
        "${repository_root}/scripts/docker_volume_engine.py" \
        stop "${compose_path}"
    else
      docker_compose stop
    fi
    ;;
  cleanup)
    require_initialized
    if [[ "${2:-}" != "--confirm-remove-local-volumes" ]]; then
      echo "cleanup requires --confirm-remove-local-volumes" >&2
      exit 2
    fi
    docker_compose down --volumes
    echo "removed only xir-local-scale containers and networks"
    echo "runtime-bound validator data, identities, and evidence remain at ${runtime_root}"
    ;;
  *)
    echo "usage: scripts/local_scale.sh {init|render|up|health|scale-preflight|plan|deploy|run-smoke|run-rehearsal|run-scale|status|logs|stop|cleanup}" >&2
    exit 2
    ;;
esac
