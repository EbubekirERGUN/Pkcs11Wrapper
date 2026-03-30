#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

version="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$repo_root/artifacts/packages/$version"

cd "$repo_root"
rm -rf "$package_dir"
mkdir -p "$package_dir"

dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
./eng/run-regression-tests.sh
./eng/run-smoke-aot.sh

dotnet pack src/Pkcs11Wrapper.Native/Pkcs11Wrapper.Native.csproj -c Release --no-build -o "$package_dir" /p:PackageVersion="$version"
dotnet pack src/Pkcs11Wrapper/Pkcs11Wrapper.csproj -c Release --no-build -o "$package_dir" /p:PackageVersion="$version"

ls -lh "$package_dir"
