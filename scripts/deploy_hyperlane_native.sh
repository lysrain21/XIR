#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || {
  echo "usage: $0 <runtime-root> <deployer-key-file> <start-block-json>" >&2
  exit 2
}
runtime_root=$1
deployer_key_file=$2
start_block_json=$3

[[ "$runtime_root" = /* && -d "$runtime_root/hyperlane/registry" ]] || {
  echo "rendered Hyperlane runtime root is invalid" >&2
  exit 2
}
[[ -f "$deployer_key_file" ]] || {
  echo "deployer key file not found" >&2
  exit 2
}
command -v npx >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null

key=$(tr -d '\r\n' <"$deployer_key_file")
[[ "$key" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] || {
  echo "deployer key file is invalid" >&2
  exit 2
}
export HYP_KEY=$key
trap 'unset HYP_KEY; key=' EXIT

hyperlane_root="$runtime_root/hyperlane"
registry_root="$hyperlane_root/registry"
log_root="$hyperlane_root/deployment-logs"
receipt_root="$hyperlane_root/deployment-receipts"
mkdir -p "$log_root" "$receipt_root"

chains=(xirlocalsource xirlocalintermediate xirlocaldestination)
rpcs=(http://127.0.0.1:18545 http://127.0.0.1:28545 http://127.0.0.1:38545)

jq -n '{}' >"$start_block_json"
for index in "${!chains[@]}"; do
  chain=${chains[$index]}
  rpc=${rpcs[$index]}
  start_hex=$(curl -fsS -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$rpc" | jq -er '.result')
  start=$((16#${start_hex#0x}))
  jq --arg chain "$chain" --argjson start "$start" \
    '.[$chain] = $start' "$start_block_json" >"$start_block_json.tmp"
  mv "$start_block_json.tmp" "$start_block_json"
  npx --yes @hyperlane-xyz/cli@39.0.0 core deploy \
    --registry "$registry_root" \
    --config "$hyperlane_root/core/$chain.yaml" \
    --chain "$chain" \
    --verbosity debug \
    --yes >"$log_root/$chain.log" 2>&1
  npx --yes @hyperlane-xyz/cli@39.0.0 core check \
    --registry "$registry_root" \
    --chain "$chain" \
    --verbosity debug \
    --yes >"$log_root/$chain-check.log" 2>&1
done

unset HYP_KEY
key=
echo "$registry_root"
