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
command -v forge >/dev/null || {
  echo "forge executable is missing" >&2
  exit 1
}

# Materialize Soldeer dependencies in official_root/solidity/dependencies
cd "$official_root/solidity"
forge soldeer install

# Verify all expected dependencies are materialized
expected_deps=(
  "@openzeppelin-contracts-4.9.3"
  "@openzeppelin-contracts-upgradeable-4.9.3"
  "@arbitrum-nitro-contracts-1.2.1"
  "@chainlink-contracts-ccip-1.5.0"
  "@eth-optimism-contracts-0.6.0"
  "@predicate-contracts-2.2.2"
  "forge-std-1.9.2"
  "permit2-1.0.0"
)
for dep in "${expected_deps[@]}"; do
  [[ -d "$official_root/solidity/dependencies/$dep" ]] || {
    echo "Soldeer dependency $dep was not materialized" >&2
    exit 1
  }
done

# Verify OpenZeppelin contracts subdirectory structure
[[ -d "$official_root/solidity/dependencies/@openzeppelin-contracts-4.9.3/contracts" ]] || {
  echo "OpenZeppelin contracts subdirectory missing" >&2
  exit 1
}

mkdir -p "$project_root/lib"
ln -sfn "$official_root" "$project_root/lib/hyperlane"
forge build --root "$project_root" \
  "$project_root/script/DeployHyperlaneNative.s.sol" \
  "$project_root/src/ProjectMarker.sol"
git -C "$official_root" status --porcelain --untracked-files=all \
  >"$runtime_root/provenance/hyperlane-post-dependency-status.txt"
[[ ! -s "$runtime_root/provenance/hyperlane-post-dependency-status.txt" ]] || {
  echo "Hyperlane dependency preparation dirtied the official checkout" >&2
  exit 1
}
