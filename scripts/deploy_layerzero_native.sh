#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || {
  echo "usage: $0 <native-runtime-root> <profile-json> <deployer-key-file>" >&2
  exit 2
}
runtime_root=$1
profile_path=$2
key_file=$3
[[ "$runtime_root" = /* && "$profile_path" = /* && "$key_file" = /* ]] || {
  echo "all paths must be absolute" >&2
  exit 2
}
[[ -f "$key_file" ]] || {
  echo "deployer key file missing" >&2
  exit 1
}
project_root="$(cd "$(dirname "$0")/.." && pwd)/protocol-projects/layerzero-native"
deployer_key=$(tr -d '\r\n' <"$key_file")
[[ "$deployer_key" = 0x* ]] || deployer_key="0x$deployer_key"
deployer_address=$(cast wallet address --private-key "$deployer_key")
dvn_signer_address=${LZ_DVN_SIGNER_ADDRESS:-$deployer_address}
mkdir -p "$runtime_root/layerzero/deployments" "$runtime_root/layerzero/logs" \
  "$project_root/deployments"

jq -c '.chains[]' "$profile_path" | while IFS= read -r chain; do
  chain_id=$(jq -r '.chain_id' <<<"$chain")
  rpc_url=$(jq -r '.rpc_url' <<<"$chain")
  local_eid=$(jq -r '.layerzero_eid' <<<"$chain")
  output="$runtime_root/layerzero/deployments/$chain_id.json"
  project_output="$project_root/deployments/$chain_id.json"
  printf '{}\n' >"$project_output"
  start_block=$(cast block-number --rpc-url "$rpc_url")
  printf '%s\n' "$start_block" >"$runtime_root/layerzero/deployments/$chain_id.start-block"
  (
    export LZ_DEPLOYER_KEY="$deployer_key"
    export LZ_DEPLOYER_ADDRESS="$deployer_address"
    export LZ_DVN_SIGNER_ADDRESS="$dvn_signer_address"
    export LZ_LOCAL_EID="$local_eid"
    export LZ_DEPLOYMENT_OUTPUT="$project_output"
    cd "$project_root"
    forge script script/DeployLayerZeroNative.s.sol:DeployLayerZeroNative \
      --rpc-url "$rpc_url" \
      --broadcast \
      --slow \
      --non-interactive \
      -vv
  ) >"$runtime_root/layerzero/logs/deploy-$chain_id.log" 2>&1
  cp -p "$project_output" "$output"
done
unset deployer_key
