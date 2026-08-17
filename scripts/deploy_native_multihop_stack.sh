#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 3 ]] || {
  echo "usage: $0 <absolute-runtime-root> <absolute-workspace-root> <absolute-preregistration>" >&2
  exit 2
}
runtime_root=$1
workspace_root=$2
preregistration=$3
[[ "$runtime_root" = /* && "$workspace_root" = /* && "$preregistration" = /* ]] || {
  echo "runtime root, workspace root, and preregistration must be absolute" >&2
  exit 2
}
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
profile="$runtime_root/profile.json"
deployer_key="$runtime_root/private/accounts/deployer.key"
[[ -x "$python" && -f "$profile" && -f "$deployer_key" ]] || {
  echo "multihop profile, deployer key, or Python environment missing" >&2
  exit 1
}
[[ -f "$runtime_root/provenance/component-provenance.json" ]] || {
  echo "native protocol bootstrap has not completed" >&2
  exit 1
}
mkdir -p "$runtime_root/logs" "$runtime_root/tools/npm-cache"
"$python" "$repository_root/scripts/verify_native_multihop_review_gate.py" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --preregistration "$preregistration" \
  --output "$runtime_root/provenance/predeployment-review-gate.json"
"$python" "$repository_root/scripts/verify_native_multihop_execution_authority.py" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --runtime-root "$runtime_root" --preregistration "$preregistration" \
  --review-gate "$runtime_root/provenance/predeployment-review-gate.json" \
  --lease "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  --lease-token "$runtime_root/private/writer-lease.token"
deployment_marker="$runtime_root/provenance/native-multihop-deployment.started"
if ! (set -o noclobber; printf '%s\n' "review-gated fresh deployment" >"$deployment_marker") 2>/dev/null; then
  echo "native multihop deployment was already started in this runtime; use a fresh namespace" >&2
  exit 1
fi
"$python" "$repository_root/scripts/provision_native_accounts.py" \
  --runtime-root "$runtime_root" --profile "$profile" \
  --deployer-key-file "$deployer_key" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --preregistration "$preregistration" \
  --review-gate "$runtime_root/provenance/predeployment-review-gate.json" \
  --lease "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  --lease-token "$runtime_root/private/writer-lease.token"
deployer_address=$(cast wallet address --private-key "$(tr -d '\r\n' <"$deployer_key")")
validator_key="$runtime_root/private/accounts/hyperlane-validator.key"
relayer_key="$runtime_root/private/accounts/hyperlane-relayer.key"
worker_key="$runtime_root/private/accounts/layerzero-worker.key"
runner_key="$runtime_root/private/accounts/runner.key"
root_signer_key="$runtime_root/private/accounts/root-signer.key"
validator_address=$(cast wallet address --private-key "$(tr -d '\r\n' <"$validator_key")")
relayer_address=$(cast wallet address --private-key "$(tr -d '\r\n' <"$relayer_key")")
worker_address=$(cast wallet address --private-key "$(tr -d '\r\n' <"$worker_key")")
export npm_config_cache="$runtime_root/tools/npm-cache"

forge build --root "$repository_root/contracts" \
  >"$runtime_root/logs/native-contract-build.log" 2>&1
"$python" "$repository_root/scripts/render_native_multihop_hyperlane.py" deployment \
  --profile "$profile" --runtime-root "$runtime_root" --key-file "$deployer_key" \
  --validator-address "$validator_address" --relayer-address "$relayer_address"
"$repository_root/scripts/prepare_hyperlane_project.sh" "$runtime_root" \
  >"$runtime_root/logs/hyperlane-project-build.log" 2>&1
"$repository_root/scripts/deploy_native_multihop_hyperlane.sh" \
  "$runtime_root" "$deployer_key" "$validator_key" "$workspace_root" \
  "$preregistration" "$runtime_root/provenance/predeployment-review-gate.json" \
  "$runtime_root/private/writer-lease.token"
"$python" "$repository_root/scripts/render_native_multihop_hyperlane.py" registry \
  --profile "$profile" --runtime-root "$runtime_root"
"$python" "$repository_root/scripts/render_native_multihop_hyperlane.py" evidence \
  --profile "$profile" --runtime-root "$runtime_root" \
  --owner-address "$deployer_address" \
  --start-blocks "$runtime_root/hyperlane/start-blocks.json" \
  --end-blocks "$runtime_root/hyperlane/end-blocks.json"

"$repository_root/scripts/prepare_layerzero_project.sh" "$runtime_root" \
  >"$runtime_root/logs/layerzero-project-build.log" 2>&1
export LZ_DVN_SIGNER_ADDRESS="$worker_address"
"$repository_root/scripts/deploy_layerzero_native.sh" \
  "$runtime_root" "$profile" "$deployer_key" "$workspace_root" \
  "$preregistration" "$runtime_root/provenance/predeployment-review-gate.json" \
  "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  "$runtime_root/private/writer-lease.token"
unset LZ_DVN_SIGNER_ADDRESS
"$python" "$repository_root/scripts/capture_layerzero_deployment.py" \
  --profile "$profile" --runtime-root "$runtime_root" \
  --output "$runtime_root/layerzero/deployment-evidence.json"
"$python" "$repository_root/scripts/verify_layerzero_native.py" \
  --profile "$profile" --runtime-root "$runtime_root" \
  --subject-address "$deployer_address" \
  --output "$runtime_root/layerzero/effective-config.json"
"$python" "$repository_root/scripts/configure_layerzero_worker_roles.py" \
  --runtime-root "$runtime_root" --profile "$profile" \
  --deployer-key-file "$deployer_key" --worker-key-file "$worker_key" \
  --workspace-root "$workspace_root" --repository-root "$repository_root" \
  --preregistration "$preregistration" \
  --review-gate "$runtime_root/provenance/predeployment-review-gate.json" \
  --lease "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  --lease-token "$runtime_root/private/writer-lease.token"

"$python" "$repository_root/scripts/deploy_native_multihop_application.py" \
  --repository-root "$repository_root" --workspace-root "$workspace_root" \
  --runtime-root "$runtime_root" --preregistration "$preregistration" \
  --review-gate "$runtime_root/provenance/predeployment-review-gate.json" \
  --lease "$runtime_root/provenance/exclusive-writer-lease/lease.json" \
  --lease-token "$runtime_root/private/writer-lease.token" \
  --profile "$profile" --deployer-key-file "$deployer_key" \
  --runner-key-file "$runner_key" --root-signer-key-file "$root_signer_key"
"$python" "$repository_root/scripts/render_native_multihop_hyperlane.py" agents \
  --profile "$profile" --runtime-root "$runtime_root"
"$python" "$repository_root/scripts/render_layerzero_worker_config.py" \
  --profile "$profile" --runtime-root "$runtime_root" \
  --output "$runtime_root/layerzero/worker-config.json"
printf '%s\n' "$deployer_address" >"$runtime_root/provenance/deployer-address.txt"
touch "$runtime_root/provenance/native-multihop-deployment.complete"
