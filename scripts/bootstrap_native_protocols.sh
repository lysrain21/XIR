#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <fetch|build|all|verify> <runtime-root> [component-lock]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
mode=$1
runtime_root=$2
lock_path=${3:-toolchain/native-protocol-stack.lock.json}
repository_root=$(cd "$(dirname "$0")/.." && pwd)

case "$mode" in
  fetch|build|all|verify) ;;
  *) usage ;;
esac

[[ "$runtime_root" = /* ]] || {
  echo "runtime root must be absolute" >&2
  exit 2
}
[[ -f "$lock_path" ]] || {
  echo "component lock not found: $lock_path" >&2
  exit 2
}
command -v git >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null

protocol_root="$runtime_root/protocols"
evidence_root="$runtime_root/provenance"
log_root="$evidence_root/build-logs"
mkdir -p "$protocol_root" "$log_root"

if [[ "$mode" = fetch || "$mode" = build || "$mode" = all ]]; then
  "$repository_root/.venv/bin/python" \
    "$repository_root/scripts/preflight_native_toolchain.py" \
    --output "$evidence_root/toolchain-preflight.json" >/dev/null
  export LIBCLANG_PATH
  LIBCLANG_PATH=$("$repository_root/.venv/bin/python" - \
    "$evidence_root/toolchain-preflight.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(document["libclang_directory"])
PY
  )
fi

canonical_repo_url() {
  local value=$1
  value=${value%.git}
  printf '%s\n' "${value,,}"
}

fetch_component() {
  local component_id=$1
  local repository=$2
  local commit=$3
  local destination="$protocol_root/$component_id"

  if [[ ! -d "$destination/.git" ]]; then
    mkdir -p "$destination"
    git -C "$destination" init --quiet
    git -C "$destination" remote add origin "$repository"
  fi
  local actual_remote
  actual_remote=$(git -C "$destination" remote get-url origin)
  [[ "$(canonical_repo_url "$actual_remote")" = "$(canonical_repo_url "$repository")" ]] || {
    echo "official repository mismatch for $component_id" >&2
    exit 1
  }
  git -C "$destination" fetch --quiet --depth 1 origin "$commit"
  git -C "$destination" checkout --quiet --detach "$commit"
}

verify_component() {
  local component_id=$1
  local repository=$2
  local commit=$3
  local destination="$protocol_root/$component_id"
  [[ -d "$destination/.git" ]] || {
    echo "missing component checkout: $component_id" >&2
    exit 1
  }
  local actual_remote actual_commit dirty
  actual_remote=$(git -C "$destination" remote get-url origin)
  actual_commit=$(git -C "$destination" rev-parse HEAD)
  dirty=$(git -C "$destination" status --porcelain --untracked-files=all)
  [[ "$(canonical_repo_url "$actual_remote")" = "$(canonical_repo_url "$repository")" ]]
  [[ "$actual_commit" = "$commit" ]]
  [[ -z "$dirty" ]] || {
    echo "dirty protocol checkout rejected: $component_id" >&2
    exit 1
  }
}

build_component() {
  local component_id=$1
  local working_directory=$2
  local destination="$protocol_root/$component_id"
  local log_file="$log_root/$component_id.log"
  : >"$log_file"
  local command_count index command_text
  command_count=$(jq -r \
    --arg id "$component_id" \
    '.components[] | select(.component_id == $id) | .build.commands | length' \
    "$lock_path")
  for ((index = 0; index < command_count; index++)); do
    command_text=$(jq -r \
      --arg id "$component_id" \
      --argjson index "$index" \
      '.components[] | select(.component_id == $id) | .build.commands[$index]' \
      "$lock_path")
    {
      echo "component=$component_id"
      echo "command_index=$index"
      echo "command=$command_text"
      (
        cd "$destination/$working_directory"
        bash -euo pipefail -c "$command_text"
      )
    } >>"$log_file" 2>&1
  done
  if [[ "$component_id" = hyperlane && -n "${CARGO_TARGET_DIR:-}" ]]; then
    mkdir -p "$destination/rust/main/target/release"
    for binary in validator relayer; do
      [[ -x "$CARGO_TARGET_DIR/release/$binary" ]] || {
        echo "missing external Cargo artifact: $CARGO_TARGET_DIR/release/$binary" >&2
        exit 1
      }
      cp -p "$CARGO_TARGET_DIR/release/$binary" \
        "$destination/rust/main/target/release/$binary"
    done
  fi
  if [[ "$component_id" = layerzero-v2 ]]; then
    generated_lock="$destination/packages/layerzero-v2/evm/protocol/foundry.lock"
    if [[ -f "$generated_lock" ]] && \
      git -C "$destination" ls-files --error-unmatch \
        "packages/layerzero-v2/evm/protocol/foundry.lock" >/dev/null 2>&1; then
      :
    elif [[ -f "$generated_lock" ]]; then
      generated_root="$evidence_root/build-generated"
      mkdir -p "$generated_root"
      mv "$generated_lock" \
        "$generated_root/layerzero-v2-protocol-foundry.lock"
    fi
  fi
}

component_count=$(jq '.components | length' "$lock_path")
for ((component_index = 0; component_index < component_count; component_index++)); do
  component_id=$(jq -r ".components[$component_index].component_id" "$lock_path")
  repository=$(jq -r ".components[$component_index].official_repository" "$lock_path")
  commit=$(jq -r ".components[$component_index].commit" "$lock_path")
  working_directory=$(jq -r \
    ".components[$component_index].build.working_directory" "$lock_path")

  if [[ "$mode" = fetch || "$mode" = all ]]; then
    fetch_component "$component_id" "$repository" "$commit"
  fi
  verify_component "$component_id" "$repository" "$commit"
  if [[ "$mode" = build || "$mode" = all ]]; then
    build_component "$component_id" "$working_directory"
    verify_component "$component_id" "$repository" "$commit"
  fi
done

python3 - "$mode" "$lock_path" "$protocol_root" \
  "$evidence_root/component-provenance.json" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

mode = sys.argv[1]
lock_path = pathlib.Path(sys.argv[2])
protocol_root = pathlib.Path(sys.argv[3])
output_path = pathlib.Path(sys.argv[4])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
components = []
for component in lock["components"]:
    root = protocol_root / component["component_id"]
    licenses = []
    for relative in component["license_paths"]:
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"missing license file: {path}")
        licenses.append({
            "relative_path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    outputs = []
    for relative in component["build"]["expected_outputs"]:
        path = root / relative
        if not path.exists():
            if mode in {"build", "all", "verify"}:
                raise SystemExit(f"missing expected build output: {path}")
            continue
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            entries = []
            for child in sorted(item for item in path.rglob("*") if item.is_file()):
                entries.append(
                    f"{child.relative_to(path)}:{hashlib.sha256(child.read_bytes()).hexdigest()}"
                )
            digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
        outputs.append({"relative_path": relative, "sha256": digest})
    components.append({
        "component_id": component["component_id"],
        "official_repository": component["official_repository"],
        "commit": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip(),
        "clean": not subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            text=True,
        ).strip(),
        "licenses": licenses,
        "outputs": outputs,
        "build_complete": (
            len(outputs) == len(component["build"]["expected_outputs"])
        ),
    })
document = {
    "schema_version": "xir-lab-native-component-provenance-v1",
    "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
    "components": components,
}
output_path.write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

find "$evidence_root" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum >"$evidence_root/SHA256SUMS"
echo "$evidence_root/component-provenance.json"
