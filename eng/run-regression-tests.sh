#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"
fixture_root="$(mktemp -d -t pkcs11wrapper-regression-XXXXXX)"
fixture_env="$fixture_root/pkcs11-fixture.env"

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

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'Required fixture variable is missing: %s\n' "$name" >&2
    exit 1
  fi
}

require_command dotnet
require_command pkcs11-tool

"$setup_script" "$fixture_env"
source "$fixture_env"

require_env SOFTHSM2_CONF
require_env PKCS11_MODULE_PATH
require_env PKCS11_TOKEN_LABEL
require_env PKCS11_USER_PIN
require_env PKCS11_FIND_LABEL
require_env PKCS11_SIGN_FIND_LABEL

export CI="${CI:-true}"
export PKCS11_STRICT_REQUIRED=1

printf 'Validating SoftHSM fixture objects before regression tests\n'
object_listing="$(pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_USER_PIN" --list-objects)"
printf '%s\n' "$object_listing"

if [[ "$object_listing" != *"label:      $PKCS11_FIND_LABEL"* ]]; then
  printf 'Fixture validation failed: AES key label %s not found.\n' "$PKCS11_FIND_LABEL" >&2
  exit 1
fi

if [[ "$object_listing" != *"label:      $PKCS11_SIGN_FIND_LABEL"* ]]; then
  printf 'Fixture validation failed: RSA key label %s not found.\n' "$PKCS11_SIGN_FIND_LABEL" >&2
  exit 1
fi

printf 'Running regression test suite with fixture-backed environment\n'
dotnet test "$repo_root/Pkcs11Wrapper.sln" -c Release --nologo --logger "console;verbosity=minimal"
printf 'Regression test suite completed successfully\n'
