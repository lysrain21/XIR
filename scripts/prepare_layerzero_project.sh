#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: $0 <absolute-native-runtime-root>" >&2
  exit 2
}
runtime_root=$1
[[ "$runtime_root" = /* ]] || {
  echo "runtime root must be absolute" >&2
  exit 2
}
official_root="$runtime_root/protocols/layerzero-v2"
project_root="$(cd "$(dirname "$0")/.." && pwd)/protocol-projects/layerzero-native"
[[ -d "$official_root/.git" ]] || {
  echo "pinned LayerZero V2 checkout is missing" >&2
  exit 1
}
expected_commit=$(jq -r \
  '.components[] | select(.component_id == "layerzero-v2") | .commit' \
  "$(cd "$(dirname "$0")/.." && pwd)/toolchain/native-protocol-stack.lock.json")
[[ "$(git -C "$official_root" rev-parse HEAD)" = "$expected_commit" ]] || {
  echo "LayerZero V2 commit mismatch" >&2
  exit 1
}
[[ -z "$(git -C "$official_root" status --porcelain --untracked-files=all)" ]] || {
  echo "dirty LayerZero V2 checkout rejected" >&2
  exit 1
}
node_modules="$official_root/packages/layerzero-v2/evm/messagelib/node_modules"
[[ -d "$node_modules" ]] || {
  echo "LayerZero message-library node_modules missing; run native bootstrap build first" >&2
  exit 1
}
mkdir -p "$project_root/lib"
ln -sfn "$official_root" "$project_root/lib/layerzero"
ln -sfn "$node_modules" "$project_root/lib/layerzero-node-modules"
forge build --root "$project_root"
