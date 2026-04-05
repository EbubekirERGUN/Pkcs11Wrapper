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
artifact_root=""
crypto_api_shared_connection_string=""
postgres_container_id=""
postgres_container_managed=false
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

wait_for_postgres_container() {
  local container_id="$1"
  local database_user="$2"
  local database_name="$3"
  local database_password="$4"
  local attempts="${5:-90}"
  local bootstrap_complete=false
  local initialization_skipped=false
  local bootstrap_complete_marker='PostgreSQL init process complete; ready for start up.'
  local initialization_skipped_marker='PostgreSQL Database directory appears to contain a database; Skipping initialization'
  local consecutive_sql_successes=0
  local required_consecutive_sql_successes_without_bootstrap=3

  for ((i=1; i<=attempts; i++)); do
    if ! docker inspect "$container_id" >/dev/null 2>&1; then
      printf 'Managed PostgreSQL container exited before readiness check completed.\n' >&2
      return 1
    fi

    if [[ "$bootstrap_complete" != "true" && "$initialization_skipped" != "true" ]]; then
      local postgres_logs
      postgres_logs="$(docker logs "$container_id" 2>&1 || true)"

      if [[ "$postgres_logs" == *"$bootstrap_complete_marker"* ]]; then
        bootstrap_complete=true
      elif [[ "$postgres_logs" == *"$initialization_skipped_marker"* ]]; then
        initialization_skipped=true
      fi
    fi

    if [[ "$bootstrap_complete" == "true" || "$initialization_skipped" == "true" ]]; then
      # Fresh postgres:* containers briefly accept connections during entrypoint bootstrap,
      # then shut that temporary server down before the final post-init server comes up.
      # Wait for the bootstrap marker plus one real SQL round-trip against the target DB.
      if docker exec \
        -e PGPASSWORD="$database_password" \
        "$container_id" \
        psql --username "$database_user" --dbname "$database_name" --no-psqlrc --tuples-only --no-align --quiet -c 'SELECT 1' \
        2>/dev/null | tr -d '[:space:]' | grep -qx '1'; then
        return 0
      fi
    elif docker exec \
      -e PGPASSWORD="$database_password" \
      "$container_id" \
      psql --username "$database_user" --dbname "$database_name" --no-psqlrc --tuples-only --no-align --quiet -c 'SELECT 1' \
      2>/dev/null | tr -d '[:space:]' | grep -qx '1'; then
      ((consecutive_sql_successes+=1))
      if (( consecutive_sql_successes >= required_consecutive_sql_successes_without_bootstrap )); then
        return 0
      fi
    else
      consecutive_sql_successes=0
    fi

    sleep 1
  done

  return 1
}

configure_shared_persistence() {
  local configured_connection_string="${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_CONNECTION_STRING:-${PKCS11WRAPPER_TEST_POSTGRES_CONNECTION_STRING:-${CryptoApiSharedPersistence__ConnectionString:-}}}"

  if [[ -n "$configured_connection_string" ]]; then
    crypto_api_shared_connection_string="$configured_connection_string"
    printf 'Using configured PostgreSQL shared persistence for admin E2E.\n'
    return
  fi

  case "${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_PROVISION:-auto}" in
    0|false|False|FALSE|no|No|NO)
      printf 'Missing PostgreSQL shared persistence for admin E2E. Set PKCS11WRAPPER_ADMIN_E2E_POSTGRES_CONNECTION_STRING (or PKCS11WRAPPER_TEST_POSTGRES_CONNECTION_STRING / CryptoApiSharedPersistence__ConnectionString), or allow Docker auto-provisioning.\n' >&2
      exit 1
      ;;
  esac

  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is required to auto-provision PostgreSQL for admin E2E when no connection string is configured. Set PKCS11WRAPPER_ADMIN_E2E_POSTGRES_CONNECTION_STRING or install Docker.\n' >&2
    exit 1
  fi

  local postgres_image="${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_IMAGE:-postgres:17-alpine}"
  local postgres_database="${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_DB:-pkcs11wrapper_admin_e2e}"
  local postgres_user="${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_USER:-cryptoapi}"
  local postgres_password="${PKCS11WRAPPER_ADMIN_E2E_POSTGRES_PASSWORD:-ChangeMe!Postgres123}"

  printf 'Starting ephemeral PostgreSQL container for admin E2E (%s).\n' "$postgres_image"
  postgres_container_id="$(docker run -d --rm \
    -e POSTGRES_DB="$postgres_database" \
    -e POSTGRES_USER="$postgres_user" \
    -e POSTGRES_PASSWORD="$postgres_password" \
    -p 127.0.0.1::5432 \
    "$postgres_image")"
  postgres_container_managed=true

  local postgres_port
  postgres_port="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$postgres_container_id")"
  if [[ -z "$postgres_port" ]]; then
    printf 'Failed to resolve mapped PostgreSQL port for container %s.\n' "$postgres_container_id" >&2
    exit 1
  fi

  if ! wait_for_postgres_container "$postgres_container_id" "$postgres_user" "$postgres_database" "$postgres_password"; then
    if [[ -n "$artifact_root" ]]; then
      docker logs "$postgres_container_id" > "$artifact_root/postgres.log" 2>&1 || true
    fi
    printf 'Ephemeral PostgreSQL container did not become ready in time.\n' >&2
    exit 1
  fi

  crypto_api_shared_connection_string="Host=127.0.0.1;Port=$postgres_port;Database=$postgres_database;Username=$postgres_user;Password=$postgres_password;SSL Mode=Disable"
  printf 'Provisioned ephemeral PostgreSQL on 127.0.0.1:%s for admin E2E.\n' "$postgres_port"
}

cleanup() {
  if [[ "$server_running" == "true" && -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi

  if [[ -n "$postgres_container_id" ]]; then
    if [[ -n "$artifact_root" ]]; then
      docker logs "$postgres_container_id" > "$artifact_root/postgres.log" 2>&1 || true
    fi

    if [[ "$postgres_container_managed" == "true" ]]; then
      docker stop "$postgres_container_id" >/dev/null 2>&1 || true
    fi
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

configure_shared_persistence

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
export CryptoApiSharedPersistence__Provider="Postgres"
export CryptoApiSharedPersistence__ConnectionString="$crypto_api_shared_connection_string"
export CryptoApiSharedPersistence__AutoInitialize="true"

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
