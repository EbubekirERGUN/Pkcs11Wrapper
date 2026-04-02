#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"
build_v3_shim_script="$script_dir/build-pkcs11-v3-shim.sh"
build_luna_shim_script="$script_dir/build-luna-extension-shim.sh"
fixture_root=""
fixture_env=""
use_existing_env=false

for arg in "$@"; do
  case "$arg" in
    --use-existing-env)
      use_existing_env=true
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

apply_rsa_aes_profile_defaults() {
  export PKCS11_FIND_CLASS="${PKCS11_FIND_CLASS:-secret}"
  export PKCS11_FIND_KEY_TYPE="${PKCS11_FIND_KEY_TYPE:-aes}"
  export PKCS11_REQUIRE_ENCRYPT="${PKCS11_REQUIRE_ENCRYPT:-true}"
  export PKCS11_REQUIRE_DECRYPT="${PKCS11_REQUIRE_DECRYPT:-true}"
  export PKCS11_SIGN_MECHANISM="${PKCS11_SIGN_MECHANISM:-0x00000040}"
  export PKCS11_SIGN_FIND_CLASS="${PKCS11_SIGN_FIND_CLASS:-private}"
  export PKCS11_SIGN_FIND_KEY_TYPE="${PKCS11_SIGN_FIND_KEY_TYPE:-rsa}"
  export PKCS11_SIGN_REQUIRE_SIGN="${PKCS11_SIGN_REQUIRE_SIGN:-true}"
  export PKCS11_VERIFY_FIND_LABEL="${PKCS11_VERIFY_FIND_LABEL:-${PKCS11_SIGN_FIND_LABEL:-}}"
  export PKCS11_VERIFY_FIND_ID_HEX="${PKCS11_VERIFY_FIND_ID_HEX:-${PKCS11_SIGN_FIND_ID_HEX:-}}"
  export PKCS11_VERIFY_FIND_CLASS="${PKCS11_VERIFY_FIND_CLASS:-public}"
  export PKCS11_VERIFY_FIND_KEY_TYPE="${PKCS11_VERIFY_FIND_KEY_TYPE:-rsa}"
  export PKCS11_VERIFY_REQUIRE_VERIFY="${PKCS11_VERIFY_REQUIRE_VERIFY:-true}"
}

apply_existing_env_defaults() {
  export PKCS11_VENDOR_PROFILE="${PKCS11_VENDOR_PROFILE:-baseline-rsa-aes}"

  case "$PKCS11_VENDOR_PROFILE" in
    baseline-rsa-aes)
      apply_rsa_aes_profile_defaults
      ;;
    luna-rsa-aes)
      apply_rsa_aes_profile_defaults
      ;;
    *)
      printf 'Unsupported PKCS#11 vendor profile: %s\n' "$PKCS11_VENDOR_PROFILE" >&2
      printf 'Supported profiles: baseline-rsa-aes, luna-rsa-aes\n' >&2
      exit 1
      ;;
  esac

  export PKCS11_PROVISIONING_REGRESSION="${PKCS11_PROVISIONING_REGRESSION:-0}"
}

print_existing_env_summary() {
  printf 'Vendor compatibility profile: %s\n' "$PKCS11_VENDOR_PROFILE"
  printf '  AES search: label=%s class=%s keyType=%s requireEncrypt=%s requireDecrypt=%s\n' \
    "$PKCS11_FIND_LABEL" "$PKCS11_FIND_CLASS" "$PKCS11_FIND_KEY_TYPE" "$PKCS11_REQUIRE_ENCRYPT" "$PKCS11_REQUIRE_DECRYPT"
  printf '  Sign search: label=%s class=%s keyType=%s mechanism=%s\n' \
    "$PKCS11_SIGN_FIND_LABEL" "$PKCS11_SIGN_FIND_CLASS" "$PKCS11_SIGN_FIND_KEY_TYPE" "$PKCS11_SIGN_MECHANISM"
  printf '  Verify search: label=%s class=%s keyType=%s\n' \
    "$PKCS11_VERIFY_FIND_LABEL" "$PKCS11_VERIFY_FIND_CLASS" "$PKCS11_VERIFY_FIND_KEY_TYPE"

  if [[ "$PKCS11_VENDOR_PROFILE" == "luna-rsa-aes" ]]; then
    printf '  Luna notes: standard C_* partition/keyring validation only; PKCS#11 v3 remains unverified on Luna and CA_* extensions are out of scope\n'
  fi

  if [[ "$PKCS11_PROVISIONING_REGRESSION" == "1" ]]; then
    printf '  Provisioning regression: enabled (SO PIN required)\n'
  else
    printf '  Provisioning regression: disabled\n'
  fi
}

require_command dotnet
require_command pkcs11-tool

if [[ "$(uname -s)" == "Linux" ]]; then
  chmod +x "$build_v3_shim_script" "$build_luna_shim_script"
  export PKCS11_V3_SHIM_PATH="$($build_v3_shim_script)"
  export PKCS11_LUNA_SHIM_PATH="$($build_luna_shim_script)"
  printf 'Built PKCS#11 v3 runtime shim: %s\n' "$PKCS11_V3_SHIM_PATH"
  printf 'Built Luna extension runtime shim: %s\n' "$PKCS11_LUNA_SHIM_PATH"
fi

if [[ "$use_existing_env" == "true" ]]; then
  printf 'Using existing PKCS#11 environment (SoftHSM fixture setup skipped)\n'
  apply_existing_env_defaults
  print_existing_env_summary
else
  fixture_root="$(mktemp -d -t pkcs11wrapper-regression-XXXXXX)"
  fixture_env="$fixture_root/pkcs11-fixture.env"

  "$setup_script" "$fixture_env"
  source "$fixture_env"
fi

if [[ "$use_existing_env" != "true" ]]; then
  require_env SOFTHSM2_CONF
fi
require_env PKCS11_MODULE_PATH
require_env PKCS11_TOKEN_LABEL
require_env PKCS11_USER_PIN
require_env PKCS11_FIND_LABEL
require_env PKCS11_SIGN_FIND_LABEL

export CI="${CI:-true}"
export PKCS11_STRICT_REQUIRED=1

printf 'Validating PKCS#11 test objects before regression tests\n'
object_listing="$(pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_USER_PIN" --list-objects)"
printf '%s\n' "$object_listing"

if [[ "$object_listing" != *"label:      $PKCS11_FIND_LABEL"* ]]; then
  printf 'PKCS#11 environment validation failed: AES key label %s not found.\n' "$PKCS11_FIND_LABEL" >&2
  exit 1
fi

if [[ "$object_listing" != *"label:      $PKCS11_SIGN_FIND_LABEL"* ]]; then
  printf 'PKCS#11 environment validation failed: RSA sign key label %s not found.\n' "$PKCS11_SIGN_FIND_LABEL" >&2
  exit 1
fi

if [[ -n "${PKCS11_VERIFY_FIND_LABEL:-}" && "$PKCS11_VERIFY_FIND_LABEL" != "$PKCS11_SIGN_FIND_LABEL" && "$object_listing" != *"label:      $PKCS11_VERIFY_FIND_LABEL"* ]]; then
  printf 'PKCS#11 environment validation failed: RSA verify key label %s not found.\n' "$PKCS11_VERIFY_FIND_LABEL" >&2
  exit 1
fi

if [[ "$PKCS11_PROVISIONING_REGRESSION" == "1" ]]; then
  require_env PKCS11_SO_PIN
fi

printf 'Running regression test suite with PKCS#11-backed environment\n'
dotnet test "$repo_root/Pkcs11Wrapper.sln" -c Release --nologo --logger "console;verbosity=minimal"
printf 'Regression test suite completed successfully\n'
