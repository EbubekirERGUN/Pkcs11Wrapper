#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"
fixture_root=""
fixture_env=""
use_existing_env=false
update_docs=false

for arg in "$@"; do
  case "$arg" in
    --use-existing-env)
      use_existing_env=true
      ;;
    --update-docs)
      update_docs=true
      ;;
    *)
      printf 'Unknown argument: %s\n' "$arg" >&2
      exit 1
      ;;
  esac
done

if [[ "${PKCS11_USE_EXISTING_ENV:-0}" == "1" ]]; then
  use_existing_env=true
fi

cleanup() {
  if [[ -n "$fixture_root" ]]; then
    rm -rf "$fixture_root"
  fi
}

trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'Required PKCS#11 environment variable is missing: %s\n' "$name" >&2
    exit 1
  fi
}

require_command dotnet
require_command pkcs11-tool

if [[ "$use_existing_env" == "true" ]]; then
  printf 'Using existing PKCS#11 environment (SoftHSM fixture setup skipped)\n'
else
  fixture_root="$(mktemp -d -t pkcs11wrapper-benchmarks-XXXXXX)"
  fixture_env="$fixture_root/pkcs11-fixture.env"
  "$setup_script" "$fixture_env"
  source "$fixture_env"
fi

require_env PKCS11_MODULE_PATH
require_env PKCS11_TOKEN_LABEL
require_env PKCS11_USER_PIN
require_env PKCS11_FIND_LABEL
require_env PKCS11_SIGN_FIND_LABEL

results_root="$repo_root/artifacts/benchmarks/latest"
mkdir -p "$results_root"

export PKCS11_BENCHMARK_REPO_ROOT="$repo_root"
export PKCS11_BENCHMARK_RESULTS_ROOT="$results_root"
export PKCS11_BENCHMARK_SDK_VERSION="$(dotnet --version)"
export PKCS11_BENCHMARK_RUNTIME_VERSION="$(dotnet --list-runtimes | awk '/Microsoft\.AspNetCore\.App / { version=$2 } END { print version }')"

if [[ "$update_docs" == "true" ]]; then
  export PKCS11_BENCHMARK_CANONICAL_RESULTS_PATH="$repo_root/docs/benchmarks/latest-linux-softhsm.md"
fi

printf 'Running BenchmarkDotNet suite with PKCS#11-backed environment\n'
dotnet run --project "$repo_root/benchmarks/Pkcs11Wrapper.Benchmarks/Pkcs11Wrapper.Benchmarks.csproj" -c Release -- --filter '*'
printf 'Benchmark suite completed successfully\n'
printf 'Summary: %s\n' "$results_root/summary.md"
