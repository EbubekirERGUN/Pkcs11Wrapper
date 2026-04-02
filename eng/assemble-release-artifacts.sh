#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [release-notes-path]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$1"
release_notes_arg="${2:-}"

preflight_args=(--version "$version")
if [[ -n "$release_notes_arg" ]]; then
  preflight_args+=(--release-notes "$release_notes_arg")
fi

preflight_output="$("$repo_root/eng/release-preflight.sh" "${preflight_args[@]}")"

get_value() {
  local key="$1"
  printf '%s\n' "$preflight_output" | awk -F= -v key="$key" '$1 == key { sub(/^[^=]+=/, ""); print; exit }'
}

tag="$(get_value tag)"
release_notes_path="$(get_value release_notes_path)"
package_dir="$(get_value package_dir)"
validation_root="$(get_value validation_root)"
release_bundle_dir="$(get_value release_bundle_dir)"

linux_smoke_dir="$repo_root/artifacts/smoke-aot/linux-x64"
assets_dir="$release_bundle_dir/assets"

if [[ ! -d "$package_dir" ]]; then
  printf 'package directory is missing: %s\nrun ./eng/verify-release.sh %s first.\n' "$package_dir" "$version" >&2
  exit 2
fi

if [[ ! -d "$validation_root" ]]; then
  printf 'release validation directory is missing: %s\nrun ./eng/verify-release.sh %s first.\n' "$validation_root" "$version" >&2
  exit 2
fi

if [[ ! -d "$linux_smoke_dir" ]]; then
  printf 'linux smoke directory is missing: %s\nrun ./eng/verify-release.sh %s first.\n' "$linux_smoke_dir" "$version" >&2
  exit 2
fi

rm -rf "$release_bundle_dir"
mkdir -p "$assets_dir"

cp "$release_notes_path" "$release_bundle_dir/release-notes.md"
cp "$package_dir"/*.nupkg "$assets_dir/"
cp "$package_dir"/*.snupkg "$assets_dir/"

tar -C "$repo_root/artifacts/smoke-aot" -czf "$assets_dir/Pkcs11Wrapper.Smoke-linux-x64-nativeaot-$tag.tar.gz" linux-x64
tar -C "$repo_root/artifacts/packages" -czf "$assets_dir/Pkcs11Wrapper-release-validation-$tag.tar.gz" "$(basename "$validation_root")"

(
  cd "$assets_dir"
  sha256sum * > SHA256SUMS.txt
)

python3 - <<'PY' "$assets_dir" "$release_bundle_dir/release-manifest.json" "$version" "$tag"
import glob
import hashlib
import json
import os
import sys

assets_dir, manifest_path, version, tag = sys.argv[1:5]

assets = []
for path in sorted(glob.glob(os.path.join(assets_dir, '*'))):
    if not os.path.isfile(path):
        continue

    sha256 = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            sha256.update(chunk)

    assets.append(
        {
            'name': os.path.basename(path),
            'sizeBytes': os.path.getsize(path),
            'sha256': sha256.hexdigest(),
        }
    )

manifest = {
    'version': version,
    'tag': tag,
    'assets': assets,
}

with open(manifest_path, 'w', encoding='utf-8') as handle:
    json.dump(manifest, handle, indent=2)
    handle.write('\n')
PY

printf 'Release bundle created: %s\n' "$release_bundle_dir"
