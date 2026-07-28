#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
expected_python="3.13.14"
expected_foundry_commit="b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required; install it through your trusted package channel" >&2
  exit 1
fi

if ! command -v forge >/dev/null 2>&1; then
  if ! command -v foundryup >/dev/null 2>&1; then
    echo "Foundry is required; install foundryup through your trusted package channel" >&2
    exit 1
  fi
  foundryup --install "${expected_foundry_commit}"
fi

forge_version="$(forge --version)"
if [[ "${forge_version}" != *"${expected_foundry_commit}"* ]]; then
  if ! command -v foundryup >/dev/null 2>&1; then
    echo "forge does not match toolchain.lock.json and foundryup is unavailable" >&2
    exit 1
  fi
  foundryup --install "${expected_foundry_commit}"
  forge_version="$(forge --version)"
fi

if [[ "${forge_version}" != *"${expected_foundry_commit}"* ]]; then
  echo "unable to activate the pinned Foundry commit" >&2
  exit 1
fi

uv python install "${expected_python}"
uv sync \
  --project "${lab_root}" \
  --python "${expected_python}" \
  --all-groups \
  --frozen

(
  cd "${lab_root}/contracts"
  forge build
)

uv run \
  --project "${lab_root}" \
  --python "${expected_python}" \
  python -c "import sys; assert sys.version_info[:3] == (3, 13, 14)"

echo "XIR Testnet Lab toolchain is ready."
