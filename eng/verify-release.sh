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
validation_root="$repo_root/artifacts/packages/$version-validation"
consumer_root="$validation_root/consumers"

create_consumer_project() {
  local project_dir="$1"
  local package_id="$2"
  local source_body="$3"

  mkdir -p "$project_dir"

  cat > "$project_dir/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-packages" value="$package_dir" />
  </packageSources>
</configuration>
EOF

  cat > "$project_dir/${package_id}.Consumer.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RestoreConfigFile>NuGet.Config</RestoreConfigFile>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="$package_id" Version="$version" />
  </ItemGroup>
</Project>
EOF

  printf '%b\n' "$source_body" > "$project_dir/Program.cs"
}

validate_consumer_project() {
  local project_dir="$1"
  local project_name="$2"
  local log_path="$validation_root/${project_name}.log"

  printf 'Validating package consumption: %s\n' "$project_name"
  dotnet restore "$project_dir" --configfile "$project_dir/NuGet.Config" 2>&1 | tee "$log_path"
  dotnet build "$project_dir" -c Release --no-restore 2>&1 | tee -a "$log_path"
}

cd "$repo_root"
rm -rf "$package_dir" "$validation_root"
mkdir -p "$package_dir" "$consumer_root"

export CI=true

dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
./eng/run-regression-tests.sh
./eng/run-smoke-aot.sh

dotnet pack src/Pkcs11Wrapper.Native/Pkcs11Wrapper.Native.csproj -c Release --no-build -o "$package_dir" /p:PackageVersion="$version" /p:ContinuousIntegrationBuild=true
dotnet pack src/Pkcs11Wrapper/Pkcs11Wrapper.csproj -c Release --no-build -o "$package_dir" /p:PackageVersion="$version" /p:ContinuousIntegrationBuild=true

dotnet run --project eng/Pkcs11Wrapper.ReleaseValidation/Pkcs11Wrapper.ReleaseValidation.csproj -- "$package_dir" "$version"

create_consumer_project \
  "$consumer_root/Pkcs11Wrapper" \
  "Pkcs11Wrapper" \
  'using Pkcs11Wrapper;\n\nPkcs11InitializeFlags flags = Pkcs11InitializeFlags.UseOperatingSystemLocking;\nConsole.WriteLine($"Managed package OK: {flags}");'

create_consumer_project \
  "$consumer_root/Pkcs11Wrapper.Native" \
  "Pkcs11Wrapper.Native" \
  'using Pkcs11Wrapper.Native;\n\nConsole.WriteLine($"Native package OK: {Pkcs11NativeTypeValidation.IsBlittable<int>()}");'

validate_consumer_project "$consumer_root/Pkcs11Wrapper" managed-package-consumer
validate_consumer_project "$consumer_root/Pkcs11Wrapper.Native" native-package-consumer

ls -lh "$package_dir"
printf 'Release package validation artifacts: %s\n' "$validation_root"
