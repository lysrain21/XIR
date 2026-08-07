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
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
profile="$runtime_root/profile.json"
key_file="$runtime_root/private/accounts/deployer.key"
python="$repository_root/.venv/bin/python"
[[ -f "$profile" && -f "$key_file" && -x "$python" ]] || {
  echo "profile, deployer key, or project environment is missing" >&2
  exit 1
}
[[ -f "$runtime_root/provenance/component-provenance.json" ]] || {
  echo "native protocol bootstrap has not completed" >&2
  exit 1
}
deployer_address=$(cast wallet address --private-key "$(tr -d '\r\n' <"$key_file")")
"$python" "$repository_root/scripts/provision_native_accounts.py" \
  --runtime-root "$runtime_root" \
  --profile "$profile" \
  --deployer-key-file "$key_file"
validator_address=$(cast wallet address --private-key \
  "$(tr -d '\r\n' <"$runtime_root/private/accounts/hyperlane-validator.key")")
relayer_address=$(cast wallet address --private-key \
  "$(tr -d '\r\n' <"$runtime_root/private/accounts/hyperlane-relayer.key")")
layerzero_worker_address=$(cast wallet address --private-key \
  "$(tr -d '\r\n' <"$runtime_root/private/accounts/layerzero-worker.key")")
export npm_config_cache="$runtime_root/tools/npm-cache"
mkdir -p "$runtime_root/logs" "$runtime_root/tools/npm-cache"

forge build --root "$repository_root/contracts" \
  >"$runtime_root/logs/native-contract-build.log" 2>&1

if [[ ! -f "$runtime_root/hyperlane/registry/chains/xirlocalsource/addresses.yaml" ]]; then
  "$python" "$repository_root/scripts/render_hyperlane_native.py" deployment \
    --profile "$profile" \
    --runtime-root "$runtime_root" \
    --key-file "$key_file" \
    --validator-address "$validator_address" \
    --relayer-address "$relayer_address"
  "$repository_root/scripts/prepare_hyperlane_project.sh" "$runtime_root" \
    >"$runtime_root/logs/hyperlane-project-build.log" 2>&1
  "$repository_root/scripts/deploy_hyperlane_from_source.sh" \
    "$runtime_root" "$key_file" \
    "$runtime_root/private/accounts/hyperlane-validator.key"
  "$python" "$repository_root/scripts/materialize_hyperlane_registry.py" \
    --profile "$profile" --runtime-root "$runtime_root"
fi
"$python" "$repository_root/scripts/capture_hyperlane_deployment.py" \
  --profile "$profile" \
  --runtime-root "$runtime_root" \
  --owner-address "$deployer_address" \
  --start-blocks "$runtime_root/hyperlane/start-blocks.json" \
  --end-blocks "$runtime_root/hyperlane/end-blocks.json" \
  >"$runtime_root/hyperlane/deployment-evidence.stdout.json"

"$repository_root/scripts/prepare_layerzero_project.sh" "$runtime_root" \
  >"$runtime_root/logs/layerzero-project-build.log" 2>&1
if [[ ! -f "$runtime_root/layerzero/deployments/3133701.json" ]]; then
  export LZ_DVN_SIGNER_ADDRESS="$layerzero_worker_address"
  "$repository_root/scripts/deploy_layerzero_native.sh" \
    "$runtime_root" "$profile" "$key_file"
  unset LZ_DVN_SIGNER_ADDRESS
fi
"$python" "$repository_root/scripts/capture_layerzero_deployment.py" \
  --profile "$profile" \
  --runtime-root "$runtime_root" \
  --output "$runtime_root/layerzero/deployment-evidence.json"
"$python" "$repository_root/scripts/verify_layerzero_native.py" \
  --profile "$profile" \
  --runtime-root "$runtime_root" \
  --subject-address "$deployer_address" \
  --output "$runtime_root/layerzero/effective-config.json"
"$python" "$repository_root/scripts/configure_layerzero_worker_roles.py" \
  --runtime-root "$runtime_root" \
  --profile "$profile" \
  --deployer-key-file "$key_file" \
  --worker-key-file "$runtime_root/private/accounts/layerzero-worker.key"

if [[ ! -f "$runtime_root/native-application/deployment.json" ]]; then
  "$python" "$repository_root/scripts/deploy_native_application.py" \
    --runtime-root "$runtime_root" \
    --profile "$profile" \
    --key-file "$key_file" \
    --runner-key-file "$runtime_root/private/accounts/runner.key" \
    --root-signer-key-file "$runtime_root/private/accounts/root-signer.key"
fi
"$python" "$repository_root/scripts/render_hyperlane_native.py" agents \
  --profile "$profile" \
  --runtime-root "$runtime_root"
"$python" "$repository_root/scripts/render_layerzero_worker_config.py" \
  --profile "$profile" \
  --runtime-root "$runtime_root" \
  --output "$runtime_root/layerzero/worker-config.json"

printf '%s\n' "$deployer_address" \
  >"$runtime_root/provenance/deployer-address.txt"
touch "$runtime_root/provenance/native-stack-deployment.complete"
