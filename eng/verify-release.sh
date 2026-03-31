#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [version]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_version="$(python3 - "$repo_root/Directory.Build.props" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
value = None
for element in root.iter():
    if element.tag == 'VersionPrefix':
        value = (element.text or '').strip()
        break
if not value:
    raise SystemExit('VersionPrefix was not found in Directory.Build.props')
print(value)
PY
)"

version="${1:-$repo_version}"
if [[ "$version" != "$repo_version" ]]; then
  echo "requested version '$version' does not match repository version '$repo_version' from Directory.Build.props" >&2
  exit 2
fi

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
