#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
source_file="$repo_root/tests/Pkcs11Wrapper.Native.Tests/NativeAssets/pkcs11_v3_shim.c"
output_dir="${1:-$repo_root/artifacts/test-fixtures/pkcs11-v3-shim}"
output_dir="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$output_dir")"
output_file="$output_dir/libpkcs11-v3-shim.so"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_command python3
require_command cc

mkdir -p "$output_dir"

cc \
  -shared \
  -fPIC \
  -O2 \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  "$source_file" \
  -o "$output_file"

printf '%s\n' "$output_file"
