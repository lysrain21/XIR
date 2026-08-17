#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 7 ]] || { echo "usage: $0 <runtime-root> <deployer-key> <validator-key> <workspace-root> <preregistration> <review-gate> <lease-token>" >&2; exit 2; }
runtime_root=$1
deployer_key_file=$2
validator_key_file=$3
workspace_root=$4
preregistration=$5
review_gate=$6
lease_token=$7
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
"$repository_root/.venv/bin/python" \
  "$repository_root/scripts/verify_native_multihop_execution_authority.py" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --runtime-root "$runtime_root" --preregistration "$preregistration" \
  --review-gate "$review_gate" \
  --lease "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  --lease-token "$lease_token"
project_root="$repository_root/protocol-projects/hyperlane-native"
profile="$runtime_root/profile.json"
deployer_key=$(tr -d '\r\n' <"$deployer_key_file")
[[ "$deployer_key" = 0x* ]] || deployer_key="0x$deployer_key"
owner=$(cast wallet address --private-key "$deployer_key")
validator=$(cast wallet address --private-key "$(tr -d '\r\n' <"$validator_key_file")")
mkdir -p "$runtime_root/hyperlane/native-deployments" "$runtime_root/hyperlane/deployment-logs" "$project_root/deployments"
[[ -f "$runtime_root/hyperlane/start-blocks.json" ]] || jq -n '{}' >"$runtime_root/hyperlane/start-blocks.json"
[[ -f "$runtime_root/hyperlane/end-blocks.json" ]] || jq -n '{}' >"$runtime_root/hyperlane/end-blocks.json"
while IFS=$'\t' read -r chain_id domain rpc_url label; do
  chain_name="xirlocalchain$(tr '[:upper:]' '[:lower:]' <<<"$label")"
  output="$runtime_root/hyperlane/native-deployments/$chain_id.json"
  project_output="$project_root/deployments/$chain_id.json"
  [[ ! -s "$output" ]] || { echo "existing multihop Hyperlane deployment rejected: $chain_id" >&2; exit 1; }
  start=$(cast block-number --rpc-url "$rpc_url")
  printf '{}\n' >"$project_output"
  jq --arg chain "$chain_name" --argjson value "$start" '.[$chain]=$value' "$runtime_root/hyperlane/start-blocks.json" >"$runtime_root/hyperlane/start-blocks.json.tmp"
  mv "$runtime_root/hyperlane/start-blocks.json.tmp" "$runtime_root/hyperlane/start-blocks.json"
  (
    export HYP_DEPLOYER_KEY="$deployer_key" HYP_OWNER_ADDRESS="$owner" HYP_VALIDATOR_ADDRESS="$validator" HYP_LOCAL_DOMAIN="$domain" HYP_DEPLOYMENT_OUTPUT="$project_output"
    cd "$project_root"
    forge script script/DeployHyperlaneNative.s.sol:DeployHyperlaneNative --rpc-url "$rpc_url" --broadcast --slow --non-interactive -vv
  ) >"$runtime_root/hyperlane/deployment-logs/$chain_name.log" 2>&1
  cp -p "$project_output" "$output"
  end=$(cast block-number --rpc-url "$rpc_url")
  jq --arg chain "$chain_name" --argjson value "$end" '.[$chain]=$value' "$runtime_root/hyperlane/end-blocks.json" >"$runtime_root/hyperlane/end-blocks.json.tmp"
  mv "$runtime_root/hyperlane/end-blocks.json.tmp" "$runtime_root/hyperlane/end-blocks.json"
done < <(jq -r '.chains[] | [.chain_id,.hyperlane_domain,.rpc_url,.label] | @tsv' "$profile")
unset deployer_key
