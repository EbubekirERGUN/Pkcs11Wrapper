#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"

use_existing_env=false
no_restore=false
no_build=false
fixture_root=""
fixture_env=""
admin_data_root=""
server_pid=""
server_running=false

for arg in "$@"; do
  case "$arg" in
    --use-existing-env)
      use_existing_env=true
      ;;
    --no-restore)
      no_restore=true
      ;;
    --no-build)
      no_build=true
      ;;
    *)
      printf 'Unknown argument: %s\n' "$arg" >&2
      exit 1
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-75}"
  local delay="${3:-0.2}"

  for ((i=1; i<=attempts; i++)); do
    if curl -fsS -o /dev/null "$url"; then
      return 0
    fi

    if [[ -n "$server_pid" ]] && ! kill -0 "$server_pid" 2>/dev/null; then
      printf 'Admin web process exited before readiness check completed.\n' >&2
      return 1
    fi

    sleep "$delay"
  done

  return 1
}

select_free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
}

cleanup() {
  if [[ "$server_running" == "true" && -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi

  if [[ -n "$admin_data_root" && -d "$admin_data_root" ]]; then
    rm -rf "$admin_data_root"
  fi

  if [[ -n "$fixture_root" && -d "$fixture_root" ]]; then
    rm -rf "$fixture_root"
  fi
}

trap cleanup EXIT

require_command dotnet
require_command curl
require_command pkcs11-tool
require_command python3

export CI="${CI:-true}"
export DOTNET_CLI_TELEMETRY_OPTOUT="${DOTNET_CLI_TELEMETRY_OPTOUT:-true}"
export DOTNET_NOLOGO="${DOTNET_NOLOGO:-true}"

artifact_root="${CI_ARTIFACT_ROOT:-$repo_root/artifacts/ci/admin-e2e}"
mkdir -p "$artifact_root"

if [[ "$use_existing_env" == "true" || "${PKCS11_USE_EXISTING_ENV:-0}" == "1" ]]; then
  printf 'Using existing PKCS#11 environment (SoftHSM fixture setup skipped)\n'
else
  fixture_root="$(mktemp -d -t pkcs11wrapper-admin-e2e-XXXXXX)"
  fixture_env="$fixture_root/pkcs11-fixture.env"
  "$setup_script" "$fixture_env" 2>&1 | tee "$artifact_root/fixture-setup.log"
  # shellcheck disable=SC1090
  source "$fixture_env"
fi

: "${PKCS11_MODULE_PATH:?PKCS11_MODULE_PATH must be set}"
: "${PKCS11_TOKEN_LABEL:?PKCS11_TOKEN_LABEL must be set}"
: "${PKCS11_USER_PIN:?PKCS11_USER_PIN must be set}"
: "${PKCS11_FIND_LABEL:?PKCS11_FIND_LABEL must be set}"

pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_USER_PIN" --list-objects > "$artifact_root/fixture-objects.log"

if [[ "$no_restore" != "true" ]]; then
  dotnet restore "$repo_root/Pkcs11Wrapper.sln"
fi

if [[ "$no_build" != "true" ]]; then
  build_args=(build "$repo_root/Pkcs11Wrapper.sln" -c Release)
  if [[ "$no_restore" == "true" ]]; then
    build_args+=(--no-restore)
  fi

  dotnet "${build_args[@]}"
fi

playwright_runner_sh="$repo_root/tests/Pkcs11Wrapper.Admin.E2E/bin/Release/net10.0/playwright.sh"
playwright_runner_ps1="$repo_root/tests/Pkcs11Wrapper.Admin.E2E/bin/Release/net10.0/playwright.ps1"
playwright_command=()

if [[ -f "$playwright_runner_sh" ]]; then
  chmod +x "$playwright_runner_sh" 2>/dev/null || true
  playwright_command=("$playwright_runner_sh")
elif [[ -f "$playwright_runner_ps1" && -x "$(command -v pwsh 2>/dev/null || true)" ]]; then
  playwright_command=(pwsh "$playwright_runner_ps1")
elif command -v npx >/dev/null 2>&1; then
  playwright_command=(npx --yes playwright@1.54.0)
else
  printf 'No supported Playwright installer bootstrap was found (playwright.sh / pwsh + playwright.ps1 / npx).
' >&2
  exit 1
fi

playwright_install_args=(install chromium)
if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  playwright_install_args=(install --with-deps chromium)
fi

"${playwright_command[@]}" "${playwright_install_args[@]}" 2>&1 | tee "$artifact_root/playwright-install.log"

admin_data_root="$(mktemp -d -t pkcs11wrapper-admin-storage-XXXXXX)"
admin_user="ci-admin"
admin_password="AdminE2E!Pass123"
admin_device_name="CI Seeded SoftHSM"
admin_port="$(select_free_port)"
admin_base_url="http://127.0.0.1:${admin_port}"

export ADMIN_DATA_ROOT_SEED="$admin_data_root"
export ADMIN_DEVICE_NAME_SEED="$admin_device_name"

python3 - <<'PY2'
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

root = Path(os.environ['ADMIN_DATA_ROOT_SEED'])
root.mkdir(parents=True, exist_ok=True)
now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
profiles = [
    {
        'Id': str(uuid.uuid4()),
        'Name': os.environ['ADMIN_DEVICE_NAME_SEED'],
        'ModulePath': os.environ['PKCS11_MODULE_PATH'],
        'DefaultTokenLabel': os.environ['PKCS11_TOKEN_LABEL'],
        'Notes': 'Seeded CI device profile for admin runtime E2E',
        'IsEnabled': True,
        'CreatedUtc': now,
        'UpdatedUtc': now,
    }
]
(root / 'device-profiles.json').write_text(json.dumps(profiles, indent=2), encoding='utf-8')
PY2

export ASPNETCORE_URLS="$admin_base_url"
export ASPNETCORE_ENVIRONMENT="Development"
export AdminRuntime__DisableHttpsRedirection="true"
export AdminStorage__DataRoot="$admin_data_root"
export LocalAdminBootstrap__UserName="$admin_user"
export LocalAdminBootstrap__Password="$admin_password"
export LocalAdminLoginThrottle__MaxFailures="100"

(
  cd "$repo_root"
  dotnet run --project src/Pkcs11Wrapper.Admin.Web/Pkcs11Wrapper.Admin.Web.csproj -c Release --no-build --no-launch-profile
) > "$artifact_root/admin-web.log" 2>&1 &
server_pid="$!"
server_running=true

if ! wait_for_http "$admin_base_url/health/ready"; then
  printf 'Admin runtime failed to become ready at %s\n' "$admin_base_url/health/ready" >&2
  tail -n 200 "$artifact_root/admin-web.log" >&2 || true
  exit 1
fi

curl -fsS "$admin_base_url/health/live" > "$artifact_root/admin-health-live.json"
curl -fsS "$admin_base_url/health/ready" > "$artifact_root/admin-health-ready.json"

export ADMIN_E2E_BASE_URL="$admin_base_url"
export ADMIN_E2E_USERNAME="$admin_user"
export ADMIN_E2E_PASSWORD="$admin_password"
export ADMIN_E2E_DEVICE_NAME="$admin_device_name"
export ADMIN_E2E_MODULE_PATH="$PKCS11_MODULE_PATH"
export ADMIN_E2E_TOKEN_LABEL="$PKCS11_TOKEN_LABEL"
export ADMIN_E2E_USER_PIN="$PKCS11_USER_PIN"
export ADMIN_E2E_FIND_LABEL="$PKCS11_FIND_LABEL"
export ADMIN_E2E_ARTIFACT_ROOT="$artifact_root"

(
  cd "$repo_root"
  dotnet run --project tests/Pkcs11Wrapper.Admin.E2E/Pkcs11Wrapper.Admin.E2E.csproj -c Release --no-build
) 2>&1 | tee "$artifact_root/admin-e2e.log"

find "$artifact_root" -maxdepth 1 -type f | sort > "$artifact_root/artifact-files.txt"
printf 'Admin runtime E2E completed successfully. Artifacts: %s\n' "$artifact_root"
