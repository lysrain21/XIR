#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 8 ]] || {
  echo "usage: $0 <runtime> <profile> <key> <workspace> <prereg> <review-gate> <lease> <token>" >&2
  exit 2
}
runtime_root=$1
profile_path=$2
key_file=$3
workspace_root=$4
preregistration=$5
review_gate=$6
lease=$7
lease_token=$8
[[ "$runtime_root" = /* && "$profile_path" = /* && "$key_file" = /* && \
  "$workspace_root" = /* && "$preregistration" = /* && "$review_gate" = /* && \
  "$lease" = /* && "$lease_token" = /* ]] || {
  echo "all paths must be absolute" >&2
  exit 2
}
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
"$python" "$repository_root/scripts/verify_native_multihop_execution_authority.py" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --runtime-root "$runtime_root" --preregistration "$preregistration" \
  --review-gate "$review_gate" --lease "$lease" --lease-token "$lease_token"
[[ -f "$key_file" ]] || {
  echo "deployer key file missing" >&2
  exit 1
}
project_root="$repository_root/protocol-projects/layerzero-native"
deployer_key=$(tr -d '\r\n' <"$key_file")
[[ "$deployer_key" = 0x* ]] || deployer_key="0x$deployer_key"
deployer_address=$(cast wallet address --private-key "$deployer_key")
dvn_signer_address=${LZ_DVN_SIGNER_ADDRESS:-$deployer_address}
mkdir -p "$runtime_root/layerzero/deployments" "$runtime_root/layerzero/logs" \
  "$project_root/deployments"

mapfile -t lz_eids < <(jq -er '.chains | map(.layerzero_eid) | .[]' "$profile_path")
mapfile -t lz_labels < <(jq -er '.chains | map(.label) | .[]' "$profile_path")
[[ ${#lz_eids[@]} -eq 5 ]] || {
  echo "LayerZero deployment requires exactly five profile EIDs" >&2
  exit 1
}
[[ ${lz_labels[*]} == "A B C D E" ]] || {
  echo "LayerZero profile chains must be ordered A through E" >&2
  exit 1
}
[[ $(printf '%s\n' "${lz_eids[@]}" | sort -u | wc -l) -eq 5 ]] || {
  echo "LayerZero profile EIDs must be unique" >&2
  exit 1
}

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
    export LZ_EID_A="${lz_eids[0]}"
    export LZ_EID_B="${lz_eids[1]}"
    export LZ_EID_C="${lz_eids[2]}"
    export LZ_EID_D="${lz_eids[3]}"
    export LZ_EID_E="${lz_eids[4]}"
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
