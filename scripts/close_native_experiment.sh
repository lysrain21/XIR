#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 && "$1" = /* ]] || {
  echo "usage: $0 <absolute-native-runtime-root>" >&2
  exit 2
}
runtime_root=$1
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
python="$repository_root/.venv/bin/python"
closeout="$runtime_root/closeout"
mkdir -p "$closeout/rebuild-a" "$closeout/rebuild-b"
jq -e '.valid == true' "$runtime_root/runs/scale/reconciliation.json" >/dev/null

"$repository_root/scripts/native_stack_processes.sh" stop "$runtime_root"
sleep 2

for rebuild in rebuild-a rebuild-b; do
  "$python" "$repository_root/scripts/analyze_native_experiment.py" scale \
    --runner-state "$runtime_root/runs/scale/runner.sqlite" \
    --reconciliation "$runtime_root/runs/scale/reconciliation.json" \
    --resources "$runtime_root/runs/scale/resources.ndjson" \
    --output-json "$closeout/$rebuild/analysis.json" \
    --output-csv "$closeout/$rebuild/per-route.csv"
done
digest_a=$(jq -r '.semantic_sha256' "$closeout/rebuild-a/analysis.json")
digest_b=$(jq -r '.semantic_sha256' "$closeout/rebuild-b/analysis.json")
[[ "$digest_a" =~ ^[0-9a-f]{64}$ && "$digest_a" = "$digest_b" ]]
jq -n --arg digest "$digest_a" \
  '{schema_version:"xir-lab-native-offline-rebuild-v1",
    rebuild_a_semantic_sha256:$digest,
    rebuild_b_semantic_sha256:$digest,
    equal:true,network_reads_required:false}' \
  >"$closeout/offline-rebuild-verification.json"

manifest="$closeout/evidence-manifest.json"
verification="$closeout/manifest-verification.json"
report="$closeout/experiment-report.md"
"$python" "$repository_root/scripts/freeze_native_experiment.py" \
  --runtime-root "$runtime_root" \
  --repository-root "$repository_root" \
  --output "$manifest" \
  --exclude "$verification" \
  --exclude "$report" \
  --exclude "$report.sha256" \
  >"$verification"
jq -e '.valid == true' "$verification" >/dev/null
"$python" "$repository_root/scripts/render_native_report.py" \
  --profile "$runtime_root/profile.json" \
  --provenance "$runtime_root/provenance/component-provenance.json" \
  --deployment "$runtime_root/native-application/deployment.json" \
  --reconciliation "$runtime_root/runs/scale/reconciliation.json" \
  --analysis "$closeout/rebuild-a/analysis.json" \
  --manifest "$manifest" \
  --evidence-pointer "$runtime_root" \
  --output "$report"
sha256sum "$report" >"$report.sha256"
touch "$closeout/native-experiment-closeout.complete"
