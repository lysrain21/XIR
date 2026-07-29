#!/usr/bin/env bash
set -euo pipefail

: "${XIR_REMOTE_HOST:?set XIR_REMOTE_HOST}"
: "${XIR_REMOTE_KEY:?set XIR_REMOTE_KEY}"
remote_port="${XIR_REMOTE_PORT:-22}"
remote_root="${XIR_REMOTE_ROOT:-/vePFS-Mindverse/user/intern/lucian/xir}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
remote_repository="${remote_root}/repo/xir-testnet-lab"
remote_runtime="${remote_root}/runtime/local-scale-run-001"
remote_tools="${remote_root}/tools"
compose_source="${XIR_COMPOSE_SOURCE:-/usr/libexec/docker/cli-plugins/docker-compose}"
uv_source="${XIR_UV_SOURCE:-$(command -v uv)}"
compose_sha256="d87a11e944c990dc9f2186115b1136c1cbffffc870845caff0cbdcce0780f41d"
uv_sha256="2856d1bf7e5bcfba7df20ae6f939340ae1f8022d2d103cada1a6da597df86e32"

ssh_command=(
  ssh
  -i "${XIR_REMOTE_KEY}"
  -p "${remote_port}"
  -o BatchMode=yes
  "${XIR_REMOTE_HOST}"
)
rsync_transport="ssh -i ${XIR_REMOTE_KEY} -p ${remote_port} -o BatchMode=yes"

remote() {
  "${ssh_command[@]}" "$@"
}

require_safe_root() {
  case "${remote_root}" in
    /vePFS-Mindverse/user/intern/lucian/xir)
      ;;
    *)
      echo "refusing unexpected remote root: ${remote_root}" >&2
      exit 2
      ;;
  esac
}

command="${1:-}"
case "${command}" in
  inspect)
    remote "
      set -euo pipefail
      test -d '${remote_root}'
      df -hT '${remote_root}'
      getconf _NPROCESSORS_ONLN
      awk '/MemTotal/ {print}' /proc/meminfo
      DOCKER_API_VERSION=1.43 docker ps --format '{{.ID}} {{.Names}}'
    "
    ;;
  sync)
    require_safe_root
    remote "mkdir -p '${remote_repository}'"
    rsync -a \
      --exclude .git \
      --exclude .venv \
      --exclude .mypy_cache \
      --exclude .pytest_cache \
      --exclude .ruff_cache \
      --exclude 'contracts/cache' \
      --exclude '__pycache__' \
      -e "${rsync_transport}" \
      "${repository_root}/" \
      "${XIR_REMOTE_HOST}:${remote_repository}/"
    remote "
      set -euo pipefail
      cd '${remote_repository}'
      find . -type f -print0 |
        sort -z |
        xargs -0 sha256sum > '${remote_root}/logs/source-manifest.sha256'
    "
    ;;
  bootstrap)
    require_safe_root
    test "$(sha256sum "${compose_source}" | cut -d ' ' -f1)" = "${compose_sha256}"
    test "$(sha256sum "${uv_source}" | cut -d ' ' -f1)" = "${uv_sha256}"
    remote "mkdir -p '${remote_tools}' '${remote_root}/logs'"
    scp -i "${XIR_REMOTE_KEY}" -P "${remote_port}" \
      "${compose_source}" "${uv_source}" \
      "${XIR_REMOTE_HOST}:${remote_tools}/"
    remote "
      set -euo pipefail
      echo '${compose_sha256}  ${remote_tools}/docker-compose' |
        sha256sum --check
      echo '${uv_sha256}  ${remote_tools}/uv' |
        sha256sum --check
      chmod 755 '${remote_tools}/docker-compose' '${remote_tools}/uv'
      export UV_PYTHON_INSTALL_DIR='${remote_tools}/python'
      export UV_CACHE_DIR='${remote_tools}/uv-cache'
      '${remote_tools}/uv' python install 3.13.14
      cd '${remote_repository}'
      '${remote_tools}/uv' sync --frozen --python 3.13.14
      '${remote_tools}/docker-compose' version
      .venv/bin/python --version
    "
    ;;
  probe)
    require_safe_root
    remote "
      set -euo pipefail
      export DOCKER_API_VERSION=1.43
      for port in 18545 28545 38545; do
        if ss -ltn | awk '{print \$4}' | grep -Eq \":\${port}\$\"; then
          echo \"experiment port occupied: \${port}\" >&2
          exit 2
        fi
      done
      probe='${remote_root}/runtime/docker-bind-probe'
      mkdir -p \"\${probe}\"
      '${remote_tools}/docker-compose' version
      docker run --rm --name xir-bind-probe \
        --mount type=bind,src=\"\${probe}\",dst=/probe \
        postgres:15-alpine sh -c 'echo ok >/probe/result'
      if test -f \"\${probe}/result\"; then
        echo daemon_bind_visibility=shared
      else
        echo daemon_bind_visibility=isolated
      fi
      docker run --rm --name xir-bind-probe-cleanup \
        --mount type=bind,src=\"\${probe}\",dst=/probe \
        postgres:15-alpine rm -f /probe/result
      docker volume create xir-explicit-volume-probe >/dev/null
      docker create --name xir-explicit-volume-probe \
        --mount type=volume,source=xir-explicit-volume-probe,target=/probe \
        postgres:15-alpine true >/dev/null
      docker rm xir-explicit-volume-probe >/dev/null
      docker volume rm xir-explicit-volume-probe >/dev/null
      find \"\${probe}\" -depth -delete
      echo remote-probe-ok
    "
    ;;
  *)
    echo "usage: scripts/remote_scale_host.sh {inspect|sync|bootstrap|probe}" >&2
    exit 2
    ;;
esac
