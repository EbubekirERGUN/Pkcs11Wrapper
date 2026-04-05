#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"
validator_script="$script_dir/validate-smoke-output.py"
temp_root_default="$repo_root/.tmp-msbuild"
fixture_root=""
fixture_env=""
publish_dir="$repo_root/artifacts/smoke-aot/linux-x64"
smoke_log="$publish_dir/smoke.log"
no_restore=false
no_build=false

for arg in "$@"; do
  case "$arg" in
    --no-restore)
      no_restore=true
      ;;
    --no-build)
      no_build=true
      ;;
    *)
      printf 'Unknown argument: %s\n' "$arg" >&2
      exit 1
      ;;
  esac
done

cleanup() {
  if [[ -n "$fixture_root" && -d "$fixture_root" ]]; then
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

configure_temp_root() {
  local resolved_temp_root="${PKCS11_TEMP_ROOT:-$temp_root_default}"

  export TMPDIR="$resolved_temp_root"
  export TMP="$resolved_temp_root"
  export TEMP="$resolved_temp_root"
  mkdir -p "$resolved_temp_root"
}

append_safe_dotnet_args() {
  local -n args_ref=$1

  args_ref+=(--disable-build-servers -m:1 -nr:false /p:UseSharedCompilation=false /p:BuildInParallel=false)
}

require_command dotnet
require_command file
require_command python3

configure_temp_root

fixture_root="$(mktemp -d -t pkcs11wrapper-smoke-XXXXXX)"
fixture_env="$fixture_root/pkcs11-fixture.env"

"$setup_script" "$fixture_env"
source "$fixture_env"

export CI="${CI:-true}"
export PKCS11_STRICT_REQUIRED=1

rm -rf "$publish_dir"
mkdir -p "$publish_dir"

printf 'Publishing native AOT smoke binary\n'
publish_args=(publish "$repo_root/samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj" -c Release -r linux-x64 /p:PublishAot=true --self-contained true -o "$publish_dir")
append_safe_dotnet_args publish_args

if [[ "$no_build" == "true" ]]; then
  publish_args+=(--no-build)
elif [[ "$no_restore" == "true" ]]; then
  publish_args+=(--no-restore)
fi

dotnet "${publish_args[@]}"

smoke_binary="$publish_dir/Pkcs11Wrapper.Smoke"
if [[ ! -x "$smoke_binary" ]]; then
  printf 'Expected published smoke entrypoint is missing or not executable: %s\n' "$smoke_binary" >&2
  exit 1
fi

printf 'Published binary details:\n'
file "$smoke_binary"

printf 'Running native AOT smoke binary\n'
"$smoke_binary" 2>&1 | tee "$smoke_log"

python3 "$validator_script" "$smoke_log"

printf 'Native AOT smoke completed successfully\n'
