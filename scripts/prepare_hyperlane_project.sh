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
official_root="$runtime_root/protocols/hyperlane"
project_root="$(cd "$(dirname "$0")/.." && pwd)/protocol-projects/hyperlane-native"
expected_commit=$(jq -r \
  '.components[] | select(.component_id == "hyperlane") | .commit' \
  "$(cd "$(dirname "$0")/.." && pwd)/toolchain/native-protocol-stack.lock.json")
[[ "$(git -C "$official_root" rev-parse HEAD)" = "$expected_commit" ]] || {
  echo "Hyperlane commit mismatch" >&2
  exit 1
}
[[ -z "$(git -C "$official_root" status --porcelain --untracked-files=all)" ]] || {
  echo "dirty Hyperlane checkout rejected before dependency install" >&2
  exit 1
}
command -v npm >/dev/null || {
  echo "pinned Node npm executable is missing" >&2
  exit 1
}
dependency_root="$runtime_root/tools/hyperlane-solidity-deps"
mkdir -p "$dependency_root"
npm install --prefix "$dependency_root" --ignore-scripts --no-audit --no-fund \
  @openzeppelin/contracts@4.9.6 \
  @openzeppelin/contracts-upgradeable@4.9.6
[[ "$(jq -r '.version' \
  "$dependency_root/node_modules/@openzeppelin/contracts/package.json")" = 4.9.6 ]]
[[ "$(jq -r '.version' \
  "$dependency_root/node_modules/@openzeppelin/contracts-upgradeable/package.json")" = 4.9.6 ]]
mkdir -p "$official_root/solidity/node_modules"
ln -sfn "$dependency_root/node_modules/@openzeppelin" \
  "$official_root/solidity/node_modules/@openzeppelin"
[[ -d "$official_root/solidity/node_modules/@openzeppelin/contracts" ]] || {
  echo "locked Hyperlane OpenZeppelin dependencies are missing" >&2
  exit 1
}
mkdir -p "$project_root/lib"
ln -sfn "$official_root" "$project_root/lib/hyperlane"
forge build --root "$project_root"
git -C "$official_root" status --porcelain --untracked-files=all \
  >"$runtime_root/provenance/hyperlane-post-dependency-status.txt"
[[ ! -s "$runtime_root/provenance/hyperlane-post-dependency-status.txt" ]] || {
  echo "Hyperlane dependency preparation dirtied the official checkout" >&2
  exit 1
}
