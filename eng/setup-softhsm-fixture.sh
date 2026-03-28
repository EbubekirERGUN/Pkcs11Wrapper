#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

env_file_path="${1:-}"

if [[ -z "$env_file_path" ]]; then
  fixture_root="$(mktemp -d -t pkcs11wrapper-softhsm-XXXXXX)"
  env_file_path="$fixture_root/pkcs11-fixture.env"
else
  env_file_path="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$env_file_path")"
  fixture_root="$(dirname "$env_file_path")"
  mkdir -p "$fixture_root"
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

resolve_module_path() {
  local candidates=(
    "${PKCS11_MODULE_PATH:-}"
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    "/usr/lib64/softhsm/libsofthsm2.so"
    "/usr/lib/softhsm/libsofthsm2.so"
    "libsofthsm2.so"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -z "$candidate" ]]; then
      continue
    fi

    if [[ "$candidate" == "libsofthsm2.so" ]]; then
      if ldconfig -p 2>/dev/null | grep -Fq 'libsofthsm2.so'; then
        printf '%s\n' "$candidate"
        return 0
      fi

      continue
    fi

    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  printf 'Unable to resolve SoftHSM module path. Set PKCS11_MODULE_PATH.\n' >&2
  return 1
}

require_command softhsm2-util
require_command pkcs11-tool
require_command python3

module_path="$(resolve_module_path)"

token_label="${PKCS11_TOKEN_LABEL_OVERRIDE:-Pkcs11Wrapper CI Token}"
user_pin="${PKCS11_USER_PIN_OVERRIDE:-123456}"
so_pin="${PKCS11_SO_PIN_OVERRIDE:-12345678}"
aes_label="${PKCS11_AES_LABEL_OVERRIDE:-ci-aes}"
aes_id_hex="${PKCS11_AES_ID_HEX_OVERRIDE:-A1}"
rsa_label="${PKCS11_RSA_LABEL_OVERRIDE:-ci-rsa}"
rsa_id_hex="${PKCS11_RSA_ID_HEX_OVERRIDE:-B2}"
softhsm_conf="$fixture_root/softhsm2.conf"
token_dir="$fixture_root/tokens"

mkdir -p "$token_dir"

cat >"$softhsm_conf" <<EOF
directories.tokendir = $token_dir
objectstore.backend = file
slots.removable = false
EOF

export SOFTHSM2_CONF="$softhsm_conf"

printf 'Creating SoftHSM fixture in %s\n' "$fixture_root"
printf 'Using PKCS#11 module %s\n' "$module_path"

softhsm2-util --init-token --free --label "$token_label" --so-pin "$so_pin" --pin "$user_pin"

pkcs11-tool --module "$module_path" --token-label "$token_label" --login --pin "$user_pin" --keygen --key-type AES:32 --label "$aes_label" --id "$aes_id_hex" --usage-decrypt --usage-wrap >/dev/null
pkcs11-tool --module "$module_path" --token-label "$token_label" --login --pin "$user_pin" --keypairgen --key-type rsa:2048 --label "$rsa_label" --id "$rsa_id_hex" --usage-sign >/dev/null

cat >"$env_file_path" <<EOF
export PKCS11_FIXTURE_ROOT='$fixture_root'
export PKCS11_FIXTURE_ENV_FILE='$env_file_path'
export SOFTHSM2_CONF='$softhsm_conf'
export PKCS11_MODULE_PATH='$module_path'
export PKCS11_TOKEN_LABEL='$token_label'
export PKCS11_USER_PIN='$user_pin'
export PKCS11_SO_PIN='$so_pin'
export PKCS11_FIND_LABEL='$aes_label'
export PKCS11_FIND_ID_HEX='$aes_id_hex'
export PKCS11_FIND_CLASS='secret'
export PKCS11_FIND_KEY_TYPE='aes'
export PKCS11_REQUIRE_ENCRYPT='true'
export PKCS11_REQUIRE_DECRYPT='true'
export PKCS11_MECHANISM='0x1085'
export PKCS11_MECHANISM_PARAM_HEX='00112233445566778899AABBCCDDEEFF'
export PKCS11_MULTIPART='true'
export PKCS11_OPERATION_STATE='true'
export PKCS11_MULTIPART_IV_HEX='00112233445566778899AABBCCDDEEFF'
export PKCS11_MULTIPART_PLAINTEXT_HEX='000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
export PKCS11_MULTIPART_BUFFER_BLOCK_HEX='202122232425262728292A2B2C2D2E2F'
export PKCS11_MULTIPART_PAD_PLAINTEXT_HEX='30313233343536373839414243444546'
export PKCS11_SMOKE_PLAINTEXT='pkcs11-wrapper-smoke'
export PKCS11_DIGEST_MECHANISM='0x250'
export PKCS11_DIGEST_MECHANISM_PARAM_HEX=''
export PKCS11_DIGEST_DATA='pkcs11-wrapper-digest-smoke'
export PKCS11_RANDOM_LENGTH='32'
export PKCS11_SIGN_MECHANISM='0x40'
export PKCS11_SIGN_FIND_LABEL='$rsa_label'
export PKCS11_SIGN_FIND_ID_HEX='$rsa_id_hex'
export PKCS11_SIGN_FIND_CLASS='private'
export PKCS11_SIGN_FIND_KEY_TYPE='rsa'
export PKCS11_SIGN_REQUIRE_SIGN='true'
export PKCS11_VERIFY_FIND_LABEL='$rsa_label'
export PKCS11_VERIFY_FIND_ID_HEX='$rsa_id_hex'
export PKCS11_VERIFY_FIND_CLASS='public'
export PKCS11_VERIFY_FIND_KEY_TYPE='rsa'
export PKCS11_VERIFY_REQUIRE_VERIFY='true'
export PKCS11_SIGN_DATA='pkcs11-wrapper-sign-smoke'
export PKCS11_OBJECT_LIFECYCLE='true'
export PKCS11_OBJECT_APPLICATION='phase8-ci'
export PKCS11_OBJECT_VALUE_HEX='50382D4349'
export PKCS11_PROVISIONING_REGRESSION='1'
export PKCS11_GENERATE_KEYS='true'
export PKCS11_GENERATE_AES_LABEL='phase12-smoke-aes'
export PKCS11_GENERATE_AES_ID_HEX='C1'
export PKCS11_GENERATE_AES_IV_HEX='00112233445566778899AABBCCDDEEFF'
export PKCS11_GENERATE_AES_PLAINTEXT='pkcs11-wrapper-generate-aes-smoke'
export PKCS11_GENERATE_RSA_LABEL='phase12-smoke-rsa'
export PKCS11_GENERATE_RSA_ID_HEX='D2'
export PKCS11_GENERATE_RSA_SIGN_DATA='pkcs11-wrapper-generate-rsa-smoke'
export PKCS11_WRAP_UNWRAP='true'
export PKCS11_WRAP_KEY_LABEL='$aes_label'
export PKCS11_WRAP_KEY_ID_HEX='$aes_id_hex'
export PKCS11_WRAP_UNWRAP_IV_HEX='00112233445566778899AABBCCDDEEFF'
export PKCS11_WRAP_UNWRAP_PLAINTEXT='pkcs11-wrapper-wrap-unwrap-smoke'
export PKCS11_DERIVE_EC='true'
export PKCS11_DERIVE_EC_IV_HEX='00112233445566778899AABBCCDDEEFF'
export PKCS11_DERIVE_EC_PLAINTEXT='pkcs11-wrapper-derive-ecdh-smoke'
EOF

printf 'Fixture objects:\n'
pkcs11-tool --module "$module_path" --token-label "$token_label" --login --pin "$user_pin" --list-objects

printf 'Fixture environment file: %s\n' "$env_file_path"
printf 'Load with: source %s\n' "$env_file_path"
