#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
setup_script="$script_dir/setup-softhsm-fixture.sh"

use_existing_env=false
no_restore=false
no_build=false
update_docs=false
profile="baseline"
fixture_root=""
fixture_env=""
artifact_root=""
crypto_api_shared_connection_string=""
postgres_container_id=""
postgres_container_managed=false
host_a_pid=""
host_b_pid=""
gateway_pid=""

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
    --update-docs)
      update_docs=true
      ;;
    --profile=*)
      profile="${arg#*=}"
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

select_free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
}

wait_for_http() {
  local url="$1"
  local pid="$2"
  local attempts="${3:-90}"
  local delay="${4:-0.25}"

  for ((i=1; i<=attempts; i++)); do
    if curl -fsS -o /dev/null "$url"; then
      return 0
    fi

    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      printf 'Process %s exited before readiness check completed for %s.\n' "$pid" "$url" >&2
      return 1
    fi

    sleep "$delay"
  done

  return 1
}

wait_for_postgres_container() {
  local container_id="$1"
  local database_user="$2"
  local database_name="$3"
  local attempts="${4:-60}"

  for ((i=1; i<=attempts; i++)); do
    if docker exec "$container_id" pg_isready -U "$database_user" -d "$database_name" >/dev/null 2>&1; then
      return 0
    fi

    if ! docker inspect "$container_id" >/dev/null 2>&1; then
      printf 'Managed PostgreSQL container exited before readiness check completed.\n' >&2
      return 1
    fi

    sleep 1
  done

  return 1
}

configure_shared_persistence() {
  local configured_connection_string="${PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_CONNECTION_STRING:-${PKCS11WRAPPER_TEST_POSTGRES_CONNECTION_STRING:-${CryptoApiSharedPersistence__ConnectionString:-}}}"

  if [[ -n "$configured_connection_string" ]]; then
    crypto_api_shared_connection_string="$configured_connection_string"
    printf 'Using configured PostgreSQL shared persistence for Crypto API perf.\n'
    return
  fi

  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is required when no PostgreSQL connection string is configured. Set PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_CONNECTION_STRING or install Docker.\n' >&2
    exit 1
  fi

  local postgres_image="${PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_IMAGE:-postgres:17-alpine}"
  local postgres_database="${PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_DB:-pkcs11wrapper_cryptoapi_perf}"
  local postgres_user="${PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_USER:-cryptoapi}"
  local postgres_password="${PKCS11WRAPPER_CRYPTOAPI_PERF_POSTGRES_PASSWORD:-ChangeMe!Postgres123}"

  printf 'Starting ephemeral PostgreSQL container for Crypto API perf (%s).\n' "$postgres_image"
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

  if ! wait_for_postgres_container "$postgres_container_id" "$postgres_user" "$postgres_database"; then
    docker logs "$postgres_container_id" > "$artifact_root/postgres.log" 2>&1 || true
    printf 'Ephemeral PostgreSQL container did not become ready in time.\n' >&2
    exit 1
  fi

  crypto_api_shared_connection_string="Host=127.0.0.1;Port=$postgres_port;Database=$postgres_database;Username=$postgres_user;Password=$postgres_password;SSL Mode=Disable"
  printf 'Provisioned ephemeral PostgreSQL on 127.0.0.1:%s for Crypto API perf.\n' "$postgres_port"
}

cleanup() {
  for pid in "$gateway_pid" "$host_b_pid" "$host_a_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done

  if [[ -n "$postgres_container_id" ]]; then
    docker logs "$postgres_container_id" > "$artifact_root/postgres.log" 2>&1 || true
    if [[ "$postgres_container_managed" == "true" ]]; then
      docker stop "$postgres_container_id" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -n "$fixture_root" && -d "$fixture_root" ]]; then
    rm -rf "$fixture_root"
  fi
}

trap cleanup EXIT

require_command dotnet
require_command curl
require_command python3
require_command pkcs11-tool

export CI="${CI:-true}"
export DOTNET_CLI_TELEMETRY_OPTOUT="${DOTNET_CLI_TELEMETRY_OPTOUT:-true}"
export DOTNET_NOLOGO="${DOTNET_NOLOGO:-true}"
export PKCS11_CRYPTO_API_PERF_REPO_ROOT="$repo_root"
export PKCS11_CRYPTO_API_PERF_SDK_VERSION="$(dotnet --version)"
export PKCS11_CRYPTO_API_PERF_RUNTIME_VERSION="$(dotnet --list-runtimes | awk '/Microsoft.NETCore.App/ {print $2; exit}')"
export TMPDIR="$repo_root/.tmp-msbuild"
export TMP="$TMPDIR"
export TEMP="$TMPDIR"
mkdir -p "$TMPDIR"

artifact_root="${PKCS11_CRYPTO_API_PERF_ARTIFACT_ROOT:-$repo_root/artifacts/crypto-api-perf/latest}"
mkdir -p "$artifact_root/logs"

configure_shared_persistence

if [[ "$use_existing_env" == "true" || "${PKCS11_USE_EXISTING_ENV:-0}" == "1" ]]; then
  printf 'Using existing PKCS#11 environment (SoftHSM fixture setup skipped).\n'
else
  fixture_root="$(mktemp -d -t pkcs11wrapper-cryptoapi-perf-XXXXXX)"
  fixture_env="$fixture_root/pkcs11-fixture.env"
  "$setup_script" "$fixture_env" 2>&1 | tee "$artifact_root/fixture-setup.log"
  # shellcheck disable=SC1090
  source "$fixture_env"
fi

: "${PKCS11_MODULE_PATH:?PKCS11_MODULE_PATH must be set}"
: "${PKCS11_TOKEN_LABEL:?PKCS11_TOKEN_LABEL must be set}"
: "${PKCS11_USER_PIN:?PKCS11_USER_PIN must be set}"
: "${PKCS11_SIGN_FIND_LABEL:?PKCS11_SIGN_FIND_LABEL must be set}"
: "${PKCS11_SIGN_FIND_ID_HEX:?PKCS11_SIGN_FIND_ID_HEX must be set}"
: "${SOFTHSM2_CONF:?SOFTHSM2_CONF must be set}"

pkcs11-tool --module "$PKCS11_MODULE_PATH" --token-label "$PKCS11_TOKEN_LABEL" --login --pin "$PKCS11_USER_PIN" --list-objects > "$artifact_root/fixture-objects.log"

if [[ "$no_restore" != "true" ]]; then
  dotnet restore "$repo_root/Pkcs11Wrapper.sln"
fi

if [[ "$no_build" != "true" ]]; then
  build_args=(build "$repo_root/Pkcs11Wrapper.sln" -c Release -m:1 -nr:false /p:UseSharedCompilation=false /p:RunAnalyzers=false /p:BuildInParallel=false)
  if [[ "$no_restore" == "true" ]]; then
    build_args+=(--no-restore)
  fi

  dotnet "${build_args[@]}"
fi

host_a_port="$(select_free_port)"
host_b_port="$(select_free_port)"
gateway_port="$(select_free_port)"

start_crypto_api_host() {
  local host_name="$1"
  local port="$2"
  local auto_initialize="$3"
  local log_path="$4"

  (
    cd "$repo_root"
    export ASPNETCORE_URLS="http://127.0.0.1:$port"
    export ASPNETCORE_ENVIRONMENT="Development"
    export CryptoApiHost__ServiceName="$host_name"
    export CryptoApiHost__ApiBasePath="/api/v1"
    export CryptoApiRuntime__DisableHttpsRedirection="true"
    export CryptoApiRuntime__ModulePath="$PKCS11_MODULE_PATH"
    export CryptoApiRuntime__UserPin="$PKCS11_USER_PIN"
    export CryptoApiRuntime__MaxRetainedSessionsPerSlot="64"
    export CryptoApiRateLimiting__Enabled="false"
    export CryptoApiSharedPersistence__Provider="Postgres"
    export CryptoApiSharedPersistence__ConnectionString="$crypto_api_shared_connection_string"
    export CryptoApiSharedPersistence__AutoInitialize="$auto_initialize"
    export SOFTHSM2_CONF="$SOFTHSM2_CONF"
    dotnet run --project src/Pkcs11Wrapper.CryptoApi/Pkcs11Wrapper.CryptoApi.csproj -c Release --no-build --no-launch-profile
  ) > "$log_path" 2>&1 &
  echo $!
}

host_a_pid="$(start_crypto_api_host "Pkcs11Wrapper.CryptoApi.PerfHostA" "$host_a_port" "true" "$artifact_root/logs/crypto-api-host-a.log")"

single_base_url="http://127.0.0.1:${host_a_port}"
multi_host_a_url="http://127.0.0.1:${host_a_port}"
multi_host_b_url="http://127.0.0.1:${host_b_port}"
gateway_base_url="http://127.0.0.1:${gateway_port}"

if ! wait_for_http "$single_base_url/health/ready" "$host_a_pid"; then
  tail -n 200 "$artifact_root/logs/crypto-api-host-a.log" >&2 || true
  exit 1
fi

host_b_pid="$(start_crypto_api_host "Pkcs11Wrapper.CryptoApi.PerfHostB" "$host_b_port" "false" "$artifact_root/logs/crypto-api-host-b.log")"

if ! wait_for_http "$multi_host_b_url/health/ready" "$host_b_pid"; then
  tail -n 200 "$artifact_root/logs/crypto-api-host-b.log" >&2 || true
  exit 1
fi

(
  cd "$repo_root"
  export ASPNETCORE_URLS="$gateway_base_url"
  export ASPNETCORE_ENVIRONMENT="Development"
  export CryptoApiGateway__ServiceName="Pkcs11Wrapper.CryptoApi.Gateway.Perf"
  export CryptoApiGateway__ApiBasePath="/api/v1"
  export CryptoApiGateway__ClusterId="perf-cluster"
  export CryptoApiGateway__LoadBalancingPolicy="RoundRobin"
  export CryptoApiGateway__Destinations__0__Name="host-a"
  export CryptoApiGateway__Destinations__0__Address="$multi_host_a_url/"
  export CryptoApiGateway__Destinations__0__Health="$multi_host_a_url/health/ready"
  export CryptoApiGateway__Destinations__1__Name="host-b"
  export CryptoApiGateway__Destinations__1__Address="$multi_host_b_url/"
  export CryptoApiGateway__Destinations__1__Health="$multi_host_b_url/health/ready"
  dotnet run --project src/Pkcs11Wrapper.CryptoApi.Gateway/Pkcs11Wrapper.CryptoApi.Gateway.csproj -c Release --no-build --no-launch-profile
) > "$artifact_root/logs/crypto-api-gateway.log" 2>&1 &
gateway_pid="$!"

if ! wait_for_http "$gateway_base_url/health/ready" "$gateway_pid"; then
  tail -n 200 "$artifact_root/logs/crypto-api-gateway.log" >&2 || true
  exit 1
fi

export PKCS11_CRYPTO_API_PERF_RESULTS_ROOT="$artifact_root"
if [[ "$update_docs" == "true" ]]; then
  export PKCS11_CRYPTO_API_PERF_CANONICAL_MARKDOWN_PATH="$repo_root/docs/crypto-api-performance/latest-linux-softhsm.md"
  export PKCS11_CRYPTO_API_PERF_CANONICAL_JSON_PATH="$repo_root/docs/crypto-api-performance/latest-linux-softhsm.json"
fi

(
  cd "$repo_root"
  dotnet run --project benchmarks/Pkcs11Wrapper.CryptoApiPerf/Pkcs11Wrapper.CryptoApiPerf.csproj -c Release --no-build -- \
    --profile "$profile" \
    --shared-connection-string "$crypto_api_shared_connection_string" \
    --single-base-url "$single_base_url" \
    --multi-base-url "$gateway_base_url" \
    --module-path "$PKCS11_MODULE_PATH" \
    --token-label "$PKCS11_TOKEN_LABEL" \
    --user-pin "$PKCS11_USER_PIN" \
    --sign-object-label "$PKCS11_SIGN_FIND_LABEL" \
    --sign-object-id-hex "$PKCS11_SIGN_FIND_ID_HEX" \
    --results-root "$artifact_root"
) 2>&1 | tee "$artifact_root/crypto-api-perf.log"

find "$artifact_root" -maxdepth 3 -type f | sort > "$artifact_root/artifact-files.txt"
printf 'Crypto API performance regression suite completed successfully. Artifacts: %s\n' "$artifact_root"
