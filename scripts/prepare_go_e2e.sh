#!/usr/bin/env bash
# Build Solidity fixtures only; no Rust validators, deployment or remote RPCs.
set -euo pipefail
[[ $# -eq 1 && "$1" = /* ]] || { echo "usage: $0 <absolute-build-root>" >&2; exit 2; }
runtime_root=$1
repository_root=$(cd "$(dirname "$0")/.." && pwd)
lock="$repository_root/toolchain/native-protocol-stack.lock.json"
for executable in git jq forge anvil node corepack; do command -v "$executable" >/dev/null; done
# Never build through artifacts linked to another worktree.
for path in contracts protocol-projects/hyperlane-native protocol-projects/layerzero-native; do
  for output in out cache lib; do
    [[ ! -L "$repository_root/$path/$output" ]] || {
      echo "refusing linked build directory: $path/$output" >&2; exit 1;
    }
  done
done
mkdir -p "$runtime_root/protocols" "$runtime_root/provenance"
for component in hyperlane layerzero-v2; do
  destination="$runtime_root/protocols/$component"
  repository=$(jq -er --arg id "$component" '.components[] | select(.component_id == $id) | .official_repository' "$lock")
  commit=$(jq -er --arg id "$component" '.components[] | select(.component_id == $id) | .commit' "$lock")
  if [[ ! -d "$destination/.git" ]]; then
    mkdir -p "$destination"
    git -C "$destination" init --quiet
    git -C "$destination" remote add origin "$repository"
  fi
  [[ "$(git -C "$destination" remote get-url origin)" = "$repository" ]]
  [[ -z "$(git -C "$destination" status --porcelain --untracked-files=all)" ]]
  git -C "$destination" fetch --depth 1 origin "$commit"
  git -C "$destination" checkout --detach "$commit"
  [[ "$(git -C "$destination" rev-parse HEAD)" = "$commit" ]]
  printf '%s %s\n' "$component" "$commit"
done
(
  cd "$runtime_root/protocols/layerzero-v2"
  corepack yarn install --immutable
)
forge build --root "$repository_root/contracts"
"$repository_root/scripts/prepare_hyperlane_project.sh" "$runtime_root"
"$repository_root/scripts/prepare_layerzero_project.sh" "$runtime_root"
for component in hyperlane layerzero-v2; do
  [[ -z "$(git -C "$runtime_root/protocols/$component" status --porcelain --untracked-files=all)" ]] || {
    echo "dependency preparation dirtied $component checkout" >&2; exit 1;
  }
done
