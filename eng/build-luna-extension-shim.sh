#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
source_file="$repo_root/tests/Pkcs11Wrapper.ThalesLuna.Tests/NativeAssets/luna_extension_shim.c"
output_dir="${1:-$repo_root/artifacts/test-fixtures/luna-extension-shim}"
output_dir="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$output_dir")"
output_file="$output_dir/libpkcs11-luna-extension-shim.so"
unsupported_output_file="$output_dir/libpkcs11-luna-extension-shim-unsupported.so"
null_pointer_output_file="$output_dir/libpkcs11-luna-extension-shim-null-pointer.so"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s
' "$1" >&2
    exit 1
  fi
}

require_command python3
require_command cc

mkdir -p "$output_dir"

build_shim() {
  local output_file="$1"
  shift

  cc     -shared     -fPIC     -O2     -std=c11     -Wall     -Wextra     -Werror     "$@"     "$source_file"     -o "$output_file"
}

build_shim "$output_file"
build_shim "$unsupported_output_file" -DLUNA_SHIM_STATIC_MODE_UNSUPPORTED
build_shim "$null_pointer_output_file" -DLUNA_SHIM_STATIC_MODE_NULL_POINTER

printf '%s
' "$output_file"
