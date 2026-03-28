#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"
fixture_root="$(mktemp -d -t pkcs11wrapper-smoke-XXXXXX)"
fixture_env="$fixture_root/pkcs11-fixture.env"
publish_dir="$repo_root/artifacts/smoke-aot/linux-x64"
smoke_log="$fixture_root/smoke.log"

cleanup() {
  rm -rf "$fixture_root"
}

trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_log_line() {
  local needle="$1"
  if ! grep -Fq "$needle" "$smoke_log"; then
    printf 'Expected smoke output line was not found: %s\n' "$needle" >&2
    exit 1
  fi
}

require_command dotnet
require_command file

"$setup_script" "$fixture_env"
source "$fixture_env"

export CI="${CI:-true}"
export PKCS11_STRICT_REQUIRED=1

rm -rf "$publish_dir"
mkdir -p "$publish_dir"

printf 'Publishing native AOT smoke binary\n'
dotnet publish "$repo_root/samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj" -c Release -r linux-x64 /p:PublishAot=true --self-contained true -o "$publish_dir"

smoke_binary="$publish_dir/Pkcs11Wrapper.Smoke"
if [[ ! -x "$smoke_binary" ]]; then
  printf 'Expected published smoke entrypoint is missing or not executable: %s\n' "$smoke_binary" >&2
  exit 1
fi

printf 'Published binary details:\n'
file "$smoke_binary"

printf 'Running native AOT smoke binary\n'
"$smoke_binary" 2>&1 | tee "$smoke_log"

require_log_line 'Login succeeded.'
require_log_line 'Encrypt/decrypt smoke:'
require_log_line 'roundTrip=True'
require_log_line 'Digest smoke:'
require_log_line 'matchesMultipart=True'
require_log_line 'Random smoke:'
require_log_line 'allZero=False, distinct=True'
require_log_line 'Sign/verify smoke:'
require_log_line 'verified=True, invalidVerified=False'
require_log_line 'Multipart sign/verify smoke:'
require_log_line 'matchesSinglePart=True, verified=True, invalidVerified=False, shortVerified=False'
require_log_line 'Object lifecycle destroy: foundAfterDestroy=False'
require_log_line 'Generate key smoke:'
require_log_line 'Generate key pair smoke:'
require_log_line 'publicMatch=True, privateMatch=True, verified=True'
require_log_line 'Wrap/unwrap smoke:'
require_log_line 'wrapped='
require_log_line 'roundTrip=True'
require_log_line 'Derive key smoke:'
require_log_line 'Logout succeeded.'

printf 'Native AOT smoke completed successfully\n'
