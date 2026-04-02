#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: release-preflight.sh [--version <version>] [--tag <tag>] [--release-notes <path>]

Validates the repository's effective package/release version, tag naming, and
release-note location for a production release candidate.
USAGE
  exit 2
}

version_arg=""
tag_arg=""
release_notes_arg=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || usage
      version_arg="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || usage
      tag_arg="$2"
      shift 2
      ;;
    --release-notes)
      [[ $# -ge 2 ]] || usage
      release_notes_arg="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_path="$repo_root/src/Pkcs11Wrapper/Pkcs11Wrapper.csproj"

version_json="$(dotnet msbuild "$project_path" -nologo -getProperty:Version -getProperty:VersionPrefix -getProperty:VersionSuffix)"
readarray -t version_parts < <(python3 - <<'PY' "$version_json"
import json
import sys

data = json.loads(sys.argv[1]).get("Properties", {})
print((data.get("Version") or "").strip())
print((data.get("VersionPrefix") or "").strip())
print((data.get("VersionSuffix") or "").strip())
PY
)

repo_version="${version_parts[0]:-}"
version_prefix="${version_parts[1]:-}"
version_suffix="${version_parts[2]:-}"

if [[ -z "$repo_version" ]]; then
  echo "failed to resolve the effective repository version via dotnet msbuild" >&2
  exit 1
fi

version="${version_arg:-$repo_version}"
if [[ "$version" != "$repo_version" ]]; then
  printf "requested version '%s' does not match effective repository version '%s' (VersionPrefix='%s', VersionSuffix='%s')\n" \
    "$version" "$repo_version" "$version_prefix" "$version_suffix" >&2
  exit 2
fi

expected_tag="v$version"
tag="${tag_arg:-$expected_tag}"
if [[ "$tag" != "$expected_tag" ]]; then
  printf "release tag '%s' must match the effective repository version as '%s'\n" "$tag" "$expected_tag" >&2
  exit 2
fi

release_notes_path="${release_notes_arg:-$repo_root/docs/release-notes/$tag.md}"
release_notes_path="$(python3 - <<'PY' "$release_notes_path"
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)"

if [[ ! -f "$release_notes_path" ]]; then
  printf "release notes file is missing: %s\nexpected location: %s\n" "$release_notes_path" "$repo_root/docs/release-notes/$tag.md" >&2
  exit 2
fi

package_dir="$repo_root/artifacts/packages/$version"
validation_root="$repo_root/artifacts/packages/$version-validation"
release_bundle_dir="$repo_root/artifacts/releases/$tag"
release_title="Pkcs11Wrapper $tag"
is_prerelease=false
if [[ "$version" == *-* ]]; then
  is_prerelease=true
fi

cat <<OUT
version=$version
tag=$tag
release_notes_path=$release_notes_path
package_dir=$package_dir
validation_root=$validation_root
release_bundle_dir=$release_bundle_dir
release_title=$release_title
is_prerelease=$is_prerelease
OUT

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'version=%s\n' "$version"
    printf 'tag=%s\n' "$tag"
    printf 'release_notes_path=%s\n' "$release_notes_path"
    printf 'package_dir=%s\n' "$package_dir"
    printf 'validation_root=%s\n' "$validation_root"
    printf 'release_bundle_dir=%s\n' "$release_bundle_dir"
    printf 'release_title=%s\n' "$release_title"
    printf 'is_prerelease=%s\n' "$is_prerelease"
  } >> "$GITHUB_OUTPUT"
fi
