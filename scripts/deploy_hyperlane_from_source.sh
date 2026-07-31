#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || {
  echo "usage: $0 <runtime-root> <deployer-key-file> <validator-key-file>" >&2
  exit 2
}
runtime_root=$1
deployer_key_file=$2
validator_key_file=$3
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
project_root="$repository_root/protocol-projects/hyperlane-native"
deployer_key=$(tr -d '\r\n' <"$deployer_key_file")
[[ "$deployer_key" = 0x* ]] || deployer_key="0x$deployer_key"
owner=$(cast wallet address --private-key "$deployer_key")
validator=$(cast wallet address --private-key \
  "$(tr -d '\r\n' <"$validator_key_file")")
mkdir -p "$runtime_root/hyperlane/native-deployments" \
  "$runtime_root/hyperlane/deployment-logs" "$project_root/deployments"
[[ -f "$runtime_root/hyperlane/start-blocks.json" ]] ||
  jq -n '{}' >"$runtime_root/hyperlane/start-blocks.json"
[[ -f "$runtime_root/hyperlane/end-blocks.json" ]] ||
  jq -n '{}' >"$runtime_root/hyperlane/end-blocks.json"
while IFS=$'\t' read -r chain_id domain rpc_url chain_name; do
  deployment_output="$runtime_root/hyperlane/native-deployments/$chain_id.json"
  if [[ -s "$deployment_output" ]]; then
    last_block=$(cast block-number --rpc-url "$rpc_url")
    jq --arg chain "$chain_name" --argjson last "$last_block" \
      '.[$chain] = $last' "$runtime_root/hyperlane/end-blocks.json" \
      >"$runtime_root/hyperlane/end-blocks.json.tmp"
    mv "$runtime_root/hyperlane/end-blocks.json.tmp" \
      "$runtime_root/hyperlane/end-blocks.json"
    continue
  fi
  start=$(cast block-number --rpc-url "$rpc_url")
  project_output="$project_root/deployments/$chain_id.json"
  printf '{}\n' >"$project_output"
  jq --arg chain "$chain_name" --argjson start "$start" \
    '.[$chain] = $start' "$runtime_root/hyperlane/start-blocks.json" \
    >"$runtime_root/hyperlane/start-blocks.json.tmp"
  mv "$runtime_root/hyperlane/start-blocks.json.tmp" \
    "$runtime_root/hyperlane/start-blocks.json"
  (
    export HYP_DEPLOYER_KEY="$deployer_key"
    export HYP_OWNER_ADDRESS="$owner"
    export HYP_VALIDATOR_ADDRESS="$validator"
    export HYP_LOCAL_DOMAIN="$domain"
    export HYP_DEPLOYMENT_OUTPUT="$project_output"
    cd "$project_root"
    forge script script/DeployHyperlaneNative.s.sol:DeployHyperlaneNative \
      --rpc-url "$rpc_url" --broadcast --slow --non-interactive -vv
  ) >"$runtime_root/hyperlane/deployment-logs/$chain_name.log" 2>&1
  cp -p "$project_output" \
    "$runtime_root/hyperlane/native-deployments/$chain_id.json"
  last_block=$(cast block-number --rpc-url "$rpc_url")
  jq --arg chain "$chain_name" --argjson last "$last_block" \
    '.[$chain] = $last' "$runtime_root/hyperlane/end-blocks.json" \
    >"$runtime_root/hyperlane/end-blocks.json.tmp"
  mv "$runtime_root/hyperlane/end-blocks.json.tmp" \
    "$runtime_root/hyperlane/end-blocks.json"
done < <(
  jq -r '.chains[] |
    [.chain_id, .hyperlane_domain, .rpc_url,
     ("xirlocal" + .route_role)] | @tsv' "$runtime_root/profile.json"
)
unset deployer_key
